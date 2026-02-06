//! Reference policy evaluator. Correctness-first, not optimized.

use crate::ast::{EvalRequest, EvalResult, MatchBlock, Policy, PolicyFile};

/// Evaluate a request against a policy file.
///
/// Returns the result with matched policy info or default.
pub fn evaluate(policy_file: &PolicyFile, request: &EvalRequest) -> EvalResult {
    // Try each policy in order
    for (index, policy) in policy_file.policies.iter().enumerate() {
        if matches_policy(policy, request) {
            return EvalResult::from_policy(policy, index);
        }
    }

    // No match - use default
    EvalResult::default_policy(&policy_file.default)
}

/// Check if a request matches a policy's conditions.
fn matches_policy(policy: &Policy, request: &EvalRequest) -> bool {
    let m = &policy.match_block;

    // If no triggers defined, policy matches anyone (open policy)
    if !m.has_triggers() {
        return check_filters(m, request);
    }

    // Phase 1: At least one OR trigger must match
    let trigger_matched = check_oidc_groups(&m.oidc_groups, &request.oidc_groups)
        || check_fnmatch(&m.emails, request.email.as_deref())
        || check_fnmatch(&m.local_usernames, request.local_username.as_deref());

    if !trigger_matched {
        return false;
    }

    // Phase 2: All AND filters must pass
    check_filters(m, request)
}

/// Check AND filters (all must pass).
fn check_filters(m: &MatchBlock, request: &EvalRequest) -> bool {
    // source_ip: CIDR match
    if !m.source_ip.is_empty() {
        if !check_cidr(&m.source_ip, request.source_ip.as_deref()) {
            return false;
        }
    }

    // hours: time range
    if !m.hours.is_empty() {
        if !check_time_range(&m.hours, request.current_time.as_deref()) {
            return false;
        }
    }

    // webauthn_ids: exact match
    if !m.webauthn_ids.is_empty() {
        if !check_exact(&m.webauthn_ids, request.webauthn_id.as_deref()) {
            return false;
        }
    }

    true
}

/// OIDC groups: any group in request matches any in policy.
pub fn check_oidc_groups(policy_groups: &[String], request_groups: &[String]) -> bool {
    if policy_groups.is_empty() {
        return false;
    }
    for pg in policy_groups {
        for rg in request_groups {
            if pg == rg {
                return true;
            }
        }
    }
    false
}

/// fnmatch-style wildcard matching.
/// Supports * (any sequence) and ? (single char).
pub fn check_fnmatch(patterns: &[String], value: Option<&str>) -> bool {
    let value = match value {
        Some(v) => v,
        None => return false,
    };

    for pattern in patterns {
        if fnmatch(pattern, value) {
            return true;
        }
    }
    false
}

/// Simple fnmatch implementation.
pub fn fnmatch(pattern: &str, value: &str) -> bool {
    let mut p_chars = pattern.chars().peekable();
    let mut v_chars = value.chars().peekable();

    while let Some(pc) = p_chars.next() {
        match pc {
            '*' => {
                // * matches zero or more characters
                if p_chars.peek().is_none() {
                    return true; // trailing * matches everything
                }
                // Try matching rest of pattern at each position
                let rest: String = p_chars.collect();
                let mut remaining: String = v_chars.collect();
                loop {
                    if fnmatch(&rest, &remaining) {
                        return true;
                    }
                    if remaining.is_empty() {
                        return false;
                    }
                    remaining = remaining[1..].to_string();
                }
            }
            '?' => {
                // ? matches exactly one character
                if v_chars.next().is_none() {
                    return false;
                }
            }
            c => {
                // literal character
                if v_chars.next() != Some(c) {
                    return false;
                }
            }
        }
    }

    // Pattern exhausted - value should also be exhausted
    v_chars.next().is_none()
}

/// CIDR matching (simplified - just checks if IP starts with prefix).
/// A proper implementation would parse IP addresses and check bit masks.
pub fn check_cidr(cidrs: &[String], ip: Option<&str>) -> bool {
    let ip = match ip {
        Some(v) => v,
        None => return false,
    };

    for cidr in cidrs {
        // Simple prefix match for now
        // TODO: proper CIDR parsing
        let prefix = cidr.split('/').next().unwrap_or(cidr);
        let prefix_parts: Vec<&str> = prefix.split('.').collect();
        let ip_parts: Vec<&str> = ip.split('.').collect();

        let mut matches = true;
        for (i, pp) in prefix_parts.iter().enumerate() {
            if *pp == "0" {
                continue; // wildcard octet
            }
            if ip_parts.get(i) != Some(pp) {
                matches = false;
                break;
            }
        }
        if matches {
            return true;
        }
    }
    false
}

/// Time range check (HH:MM-HH:MM format).
pub fn check_time_range(ranges: &[String], current: Option<&str>) -> bool {
    let current = match current {
        Some(v) => v,
        None => return false,
    };

    for range in ranges {
        if let Some((start, end)) = range.split_once('-') {
            if current >= start && current <= end {
                return true;
            }
        }
    }
    false
}

/// Exact match check.
pub fn check_exact(allowed: &[String], value: Option<&str>) -> bool {
    let value = match value {
        Some(v) => v,
        None => return false,
    };

    allowed.iter().any(|a| a == value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::parse_policy;

    #[test]
    fn test_fnmatch_exact() {
        assert!(fnmatch("hello", "hello"));
        assert!(!fnmatch("hello", "world"));
    }

    #[test]
    fn test_fnmatch_star() {
        assert!(fnmatch("*@example.com", "user@example.com"));
        assert!(fnmatch("admin*", "administrator"));
        assert!(fnmatch("*", "anything"));
    }

    #[test]
    fn test_fnmatch_question() {
        assert!(fnmatch("user?", "user1"));
        assert!(!fnmatch("user?", "user12"));
    }

    #[test]
    fn test_evaluate_default() {
        let yaml = r#"
default:
  principals: ["sandbox"]
  max_duration: "15m"
policies: []
"#;
        let policy = parse_policy(yaml).unwrap();
        let request = EvalRequest::default();
        let result = evaluate(&policy, &request);
        
        assert!(!result.matched);
        assert_eq!(result.principals, vec!["sandbox"]);
    }

    #[test]
    fn test_evaluate_oidc_match() {
        let yaml = r#"
default:
  principals: ["sandbox"]
  max_duration: "15m"
policies:
  - name: "AdminAccess"
    match:
      oidc_groups: ["admins"]
    principals: ["root"]
    max_duration: "60m"
"#;
        let policy = parse_policy(yaml).unwrap();
        let mut request = EvalRequest::default();
        request.oidc_groups = vec!["admins".to_string()];
        
        let result = evaluate(&policy, &request);
        
        assert!(result.matched);
        assert_eq!(result.policy_name, Some("AdminAccess".to_string()));
        assert_eq!(result.principals, vec!["root"]);
    }
}
