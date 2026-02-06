//! Policy AST types
//!
//! These types represent the parsed YAML policy structure.
//! Kept deliberately simple - this is data, not behavior.

use serde::Deserialize;

/// Root of a policy file.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyFile {
    pub default: DefaultPolicy,
    #[serde(default)]
    pub policies: Vec<Policy>,
}

/// Fallback when no policy matches.
#[derive(Debug, Clone, Deserialize)]
pub struct DefaultPolicy {
    pub principals: Vec<String>,
    pub max_duration: String,
}

/// A single policy entry.
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Default, Deserialize)]
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
#[derive(Debug, Clone, serde::Deserialize)]
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
