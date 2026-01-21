//! Policy AST types
//!
//! These types represent the parsed YAML policy structure.
//! Kept deliberately simple - this is data, not behavior.

use serde::{Deserialize, Serialize};
use arbitrary::Arbitrary;

/// Root of a policy file.
#[derive(Debug, Clone, Deserialize, Serialize, Arbitrary)]
pub struct PolicyFile {
    pub default: DefaultPolicy,
    #[serde(default)]
    pub policies: Vec<Policy>,
}

/// Fallback when no policy matches.
#[derive(Debug, Clone, Deserialize, Serialize, Arbitrary)]
pub struct DefaultPolicy {
    pub principals: Vec<String>,
    pub max_duration: String,
}

/// A single policy entry.
#[derive(Debug, Clone, Deserialize, Serialize, Arbitrary)]
pub struct Policy {
    pub name: String,
    #[serde(default)]
    pub match_block: MatchBlock,
    pub principals: Vec<String>,
    pub max_duration: String,
}

// serde expects "match" but that's a keyword, so we rename it
impl Policy {
    pub fn match_conditions(&self) -> &MatchBlock {
        &self.match_block
    }
}

/// Match conditions for a policy.
/// First three are OR triggers, last three are AND filters.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct MatchBlock {
    // OR triggers - at least one must match
    #[serde(default)]
    pub oidc_groups: Vec<String>,
    #[serde(default)]
    pub emails: Vec<String>,
    #[serde(default)]
    pub local_usernames: Vec<String>,

    // AND filters - all specified must match
    #[serde(default)]
    pub source_ip: Vec<String>,
    #[serde(default)]
    pub hours: Vec<String>,
    #[serde(default)]
    pub webauthn_ids: Vec<String>,
}

impl<'a> Arbitrary<'a> for MatchBlock {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut m = MatchBlock::default();
        
        // 50% chance to have OIDC groups
        if u.ratio(1, 2)? {
            m.oidc_groups = vec!["developers".to_string(), "platform-admins".to_string()]
                .into_iter()
                .filter(|_| u.ratio(1, 4).unwrap_or(false))
                .collect();
        }

        // Shared pool of emails
        if u.ratio(3, 10)? {
            let email_pool = ["alice@example.com", "*@admin.example.com", "bob@admin.example.com"];
            m.emails.push(u.choose(&email_pool)?.to_string());
        }

        // Shared pool of IPs
        if u.ratio(4, 10)? {
            let ip_pool = ["10.0.0.0/8", "192.168.1.0/24", "127.0.0.1/32"];
            m.source_ip.push(u.choose(&ip_pool)?.to_string());
        }

        // Range generation (including overnight)
        if u.ratio(3, 10)? {
            let start = u.int_in_range(0..=23)?;
            let end = u.int_in_range(0..=23)?;
            m.hours.push(format!("{:02}:00-{:02}:00", start, end));
        }

        Ok(m)
    }
}

impl MatchBlock {
    /// True if any OR trigger is specified.
    pub fn has_triggers(&self) -> bool {
        !self.oidc_groups.is_empty()
            || !self.emails.is_empty()
            || !self.local_usernames.is_empty()
    }

    /// True if any AND filter is specified.
    pub fn has_filters(&self) -> bool {
        !self.source_ip.is_empty()
            || !self.hours.is_empty()
            || !self.webauthn_ids.is_empty()
    }
}

/// A request to evaluate against the policy.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EvalRequest {
    // Identity
    pub oidc_groups: Vec<String>,
    pub email: Option<String>,
    pub local_username: Option<String>,

    // Context
    pub source_ip: Option<String>,
    pub current_time: Option<String>, // HH:MM format
    pub webauthn_id: Option<String>,
}

impl<'a> Arbitrary<'a> for EvalRequest {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Use same pools as MatchBlock
        let oidc_groups = vec!["developers".to_string(), "platform-admins".to_string()]
            .into_iter()
            .filter(|_| u.ratio(1, 2).unwrap_or(false))
            .collect();

        let email = if u.ratio(7, 10)? {
            let pool = ["alice@example.com", "bob@admin.example.com", "charlie@contractor.example.com", "random@gmail.com"];
            Some(u.choose(&pool)?.to_string())
        } else {
            None
        };

        let source_ip = if u.ratio(7, 10)? {
            let pool = ["127.0.0.1", "10.0.0.5", "192.168.1.100", "203.0.113.1"];
            Some(u.choose(&pool)?.to_string())
        } else {
            None
        };

        let current_time = if u.ratio(7, 10)? {
            let hour = u.int_in_range(0..=23)?;
            Some(format!("{:02}:30", hour))
        } else {
            None
        };

        Ok(EvalRequest {
            oidc_groups,
            email,
            local_username: None,
            source_ip,
            current_time,
            webauthn_id: None,
        })
    }
}

impl Default for EvalRequest {
    fn default() -> Self {
        EvalRequest {
            oidc_groups: vec![],
            email: None,
            local_username: None,
            source_ip: None,
            current_time: None,
            webauthn_id: None,
        }
    }
}

/// Result of policy evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct EvalResult {
    pub matched: bool,
    pub policy_name: Option<String>,
    pub policy_index: Option<usize>,
    pub principals: Vec<String>,
    pub max_duration: String,
}

impl EvalResult {
    pub fn default_policy(default: &DefaultPolicy) -> Self {
        EvalResult {
            matched: false,
            policy_name: None,
            policy_index: None,
            principals: default.principals.clone(),
            max_duration: default.max_duration.clone(),
        }
    }

    pub fn from_policy(policy: &Policy, index: usize) -> Self {
        EvalResult {
            matched: true,
            policy_name: Some(policy.name.clone()),
            policy_index: Some(index),
            principals: policy.principals.clone(),
            max_duration: policy.max_duration.clone(),
        }
    }
}
