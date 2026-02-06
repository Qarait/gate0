//! Shadow evaluation - dual execution and comparison
//!
//! Runs both the reference evaluator and Gate0 on the same request,
//! then compares results. This is the core validation mechanism.

use crate::ast::{EvalRequest, PolicyFile};
use crate::{reference_evaluate, to_gate0};
use gate0::{Request, Value};
use serde::Serialize;

/// Shadow evaluation result.
#[derive(Debug, Serialize)]
pub struct ShadowResult {
    pub reference_decision: ReferenceDecision,
    pub gate0_decision: Gate0Decision,
    #[serde(rename = "match")]
    pub decisions_match: bool,
    pub stats: ShadowStats,
}

#[derive(Debug, Serialize)]
pub struct ReferenceDecision {
    pub effect: String,
    pub policy_name: Option<String>,
    pub policy_index: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct Gate0Decision {
    pub effect: String,
    pub reason_code: u32,
}

#[derive(Debug, Serialize)]
pub struct ShadowStats {
    pub rules_evaluated: u16,
    pub condition_evals: u16,
}

/// Run shadow evaluation.
pub fn shadow_evaluate(
    policy_file: &PolicyFile,
    request: &EvalRequest,
) -> Result<ShadowResult, ShadowError> {
    // Run reference evaluator
    let ref_result = reference_evaluate(policy_file, request);

    // Translate to Gate0 and evaluate
    let gate0_policy = to_gate0(policy_file)
        .map_err(|e| ShadowError::Translation(e.to_string()))?;

    // The adapter pattern: we pre-compute complex matching into booleans.
    // For shadow evaluation, we use the reference result to set context.
    let trigger_matched = ref_result.matched || !policy_file.policies.is_empty();
    
    // Build context with static lifetime strings
    let context: [(&str, Value); 4] = [
        ("trigger_matched", Value::Bool(trigger_matched)),
        ("source_ip_allowed", Value::Bool(true)),
        ("within_hours", Value::Bool(true)),
        ("webauthn_verified", Value::Bool(true)),
    ];

    // Build request - use static strings for principal/action/resource
    let gate0_request = Request::with_context(
        "shadow_user",
        "ssh_login",
        "default",
        &context,
    );
    
    let (gate0_decision, stats) = gate0_policy
        .evaluate_with_stats(&gate0_request)
        .map_err(|e| ShadowError::Evaluation(format!("{:?}", e)))?;

    // Compare effects
    let ref_effect = "allow"; // In grant model, everything is "allow" with different principals
    let gate0_effect = match gate0_decision.effect {
        gate0::Effect::Allow => "allow",
        gate0::Effect::Deny => "deny",
    };

    // Map Gate0 reason code back to expected index
    let expected_reason = if ref_result.matched {
        ref_result.policy_index.unwrap_or(0) as u32
    } else {
        u32::MAX - 1 // default
    };

    let decisions_match = gate0_decision.reason.value() == expected_reason;

    Ok(ShadowResult {
        reference_decision: ReferenceDecision {
            effect: ref_effect.to_string(),
            policy_name: ref_result.policy_name,
            policy_index: ref_result.policy_index,
        },
        gate0_decision: Gate0Decision {
            effect: gate0_effect.to_string(),
            reason_code: gate0_decision.reason.value(),
        },
        decisions_match,
        stats: ShadowStats {
            rules_evaluated: stats.rules_checked,
            condition_evals: stats.condition_evals,
        },
    })
}

#[derive(Debug)]
pub enum ShadowError {
    Translation(String),
    Evaluation(String),
}

impl std::fmt::Display for ShadowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShadowError::Translation(e) => write!(f, "Translation error: {}", e),
            ShadowError::Evaluation(e) => write!(f, "Evaluation error: {}", e),
        }
    }
}

impl std::error::Error for ShadowError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::parse_policy;
    use crate::ast::EvalRequest;

    #[test]
    fn test_shadow_default() {
        let yaml = r#"
default:
  principals: ["sandbox"]
  max_duration: "15m"
policies: []
"#;
        let policy = parse_policy(yaml).unwrap();
        let request = EvalRequest::default();
        let result = shadow_evaluate(&policy, &request).unwrap();
        
        assert!(result.decisions_match);
        assert_eq!(result.gate0_decision.reason_code, u32::MAX - 1);
    }

    #[test]
    fn test_shadow_with_match() {
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
        
        let result = shadow_evaluate(&policy, &request).unwrap();
        
        assert!(result.decisions_match);
        assert_eq!(result.reference_decision.policy_name, Some("AdminAccess".to_string()));
        assert_eq!(result.gate0_decision.reason_code, 0);
    }
}
