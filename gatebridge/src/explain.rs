//! Step-by-step policy evaluation for debugging.

use crate::ast::{EvalRequest, MatchBlock, Policy, PolicyFile};
use crate::reference_eval::{check_cidr, check_exact, check_fnmatch, check_oidc_groups, check_time_range};

/// Result of explaining a single condition check.
#[derive(Debug)]
pub struct ConditionExplain {
    pub field: String,
    pub pattern: String,
    pub request_value: String,
    pub matched: bool,
}

/// Result of explaining a single policy.
#[derive(Debug)]
pub struct PolicyExplain {
    pub name: String,
    pub index: usize,
    pub triggers: Vec<ConditionExplain>,
    pub filters: Vec<ConditionExplain>,
    pub trigger_passed: bool,
    pub filter_passed: bool,
    pub overall_matched: bool,
}

/// Result of explaining the full evaluation.
#[derive(Debug)]
pub struct ExplainResult {
    pub policies: Vec<PolicyExplain>,
    pub matched_policy: Option<String>,
    pub matched_index: Option<usize>,
}

/// Explain why a request matches (or doesn't match) the policy file.
pub fn explain(policy_file: &PolicyFile, request: &EvalRequest) -> ExplainResult {
    let mut policies = Vec::new();
    let mut matched_policy = None;
    let mut matched_index = None;

    for (index, policy) in policy_file.policies.iter().enumerate() {
        let policy_explain = explain_policy(index, policy, request);
        
        if policy_explain.overall_matched && matched_policy.is_none() {
            matched_policy = Some(policy.name.clone());
            matched_index = Some(index);
        }
        
        policies.push(policy_explain);
    }

    ExplainResult {
        policies,
        matched_policy,
        matched_index,
    }
}

fn explain_policy(index: usize, policy: &Policy, request: &EvalRequest) -> PolicyExplain {
    let m = &policy.match_block;
    
    let mut triggers = Vec::new();
    let mut filters = Vec::new();

    // Explain OR triggers
    if !m.oidc_groups.is_empty() {
        let matched = check_oidc_groups(&m.oidc_groups, &request.oidc_groups);
        triggers.push(ConditionExplain {
            field: "oidc_groups".to_string(),
            pattern: format!("{:?}", m.oidc_groups),
            request_value: format!("{:?}", request.oidc_groups),
            matched,
        });
    }

    if !m.emails.is_empty() {
        let matched = check_fnmatch(&m.emails, request.email.as_deref());
        triggers.push(ConditionExplain {
            field: "emails".to_string(),
            pattern: format!("{:?}", m.emails),
            request_value: request.email.clone().unwrap_or_else(|| "(none)".to_string()),
            matched,
        });
    }

    if !m.local_usernames.is_empty() {
        let matched = check_fnmatch(&m.local_usernames, request.local_username.as_deref());
        triggers.push(ConditionExplain {
            field: "local_usernames".to_string(),
            pattern: format!("{:?}", m.local_usernames),
            request_value: request.local_username.clone().unwrap_or_else(|| "(none)".to_string()),
            matched,
        });
    }

    // Explain AND filters
    if !m.source_ip.is_empty() {
        let matched = check_cidr(&m.source_ip, request.source_ip.as_deref());
        filters.push(ConditionExplain {
            field: "source_ip".to_string(),
            pattern: format!("{:?}", m.source_ip),
            request_value: request.source_ip.clone().unwrap_or_else(|| "(none)".to_string()),
            matched,
        });
    }

    if !m.hours.is_empty() {
        let matched = check_time_range(&m.hours, request.current_time.as_deref());
        filters.push(ConditionExplain {
            field: "hours".to_string(),
            pattern: format!("{:?}", m.hours),
            request_value: request.current_time.clone().unwrap_or_else(|| "(none)".to_string()),
            matched,
        });
    }

    if !m.webauthn_ids.is_empty() {
        let matched = check_exact(&m.webauthn_ids, request.webauthn_id.as_deref());
        filters.push(ConditionExplain {
            field: "webauthn_ids".to_string(),
            pattern: format!("{:?}", m.webauthn_ids),
            request_value: request.webauthn_id.clone().unwrap_or_else(|| "(none)".to_string()),
            matched,
        });
    }

    // Compute pass/fail
    let trigger_passed = if triggers.is_empty() {
        true // No triggers = open policy
    } else {
        triggers.iter().any(|t| t.matched)
    };

    let filter_passed = filters.iter().all(|f| f.matched);

    let overall_matched = trigger_passed && filter_passed;

    PolicyExplain {
        name: policy.name.clone(),
        index,
        triggers,
        filters,
        trigger_passed,
        filter_passed,
        overall_matched,
    }
}

/// Format explain result for display.
pub fn format_explain(result: &ExplainResult) -> String {
    let mut out = String::new();

    for policy in &result.policies {
        out.push_str(&format!("━━━ Policy [{}]: {} ━━━\n", policy.index, policy.name));

        // Triggers
        if policy.triggers.is_empty() {
            out.push_str("  Triggers: (none - open policy)\n");
        } else {
            out.push_str("  Triggers (OR - any must match):\n");
            for t in &policy.triggers {
                let mark = if t.matched { "✓" } else { "✗" };
                out.push_str(&format!(
                    "    {} {}: {} → {}\n",
                    mark, t.field, t.pattern, t.request_value
                ));
            }
            let trigger_result = if policy.trigger_passed { "PASSED" } else { "FAILED" };
            out.push_str(&format!("  Trigger result: {}\n", trigger_result));
        }

        // Filters
        if policy.filters.is_empty() {
            out.push_str("  Filters: (none)\n");
        } else {
            out.push_str("  Filters (AND - all must match):\n");
            for f in &policy.filters {
                let mark = if f.matched { "✓" } else { "✗" };
                out.push_str(&format!(
                    "    {} {}: {} → {}\n",
                    mark, f.field, f.pattern, f.request_value
                ));
            }
            let filter_result = if policy.filter_passed { "PASSED" } else { "FAILED" };
            out.push_str(&format!("  Filter result: {}\n", filter_result));
        }

        // Overall
        let overall = if policy.overall_matched { "MATCH ✓" } else { "NO MATCH" };
        out.push_str(&format!("  Overall: {}\n\n", overall));
    }

    // Final result
    out.push_str("━━━ Result ━━━\n");
    match &result.matched_policy {
        Some(name) => {
            out.push_str(&format!(
                "Matched: {} (ReasonCode: {})\n",
                name,
                result.matched_index.unwrap()
            ));
        }
        None => {
            out.push_str("Matched: (default policy)\n");
        }
    }

    out
}
