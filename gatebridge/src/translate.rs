//! Converts YAML policy AST into Gate0 rules.
//!
//! Each policy maps to a Gate0 rule where ReasonCode = policy index.

use crate::ast::{MatchBlock, PolicyFile};
use gate0::{
    Condition, Effect, Policy, ReasonCode, Rule, Target, Value,
};

/// Translation error.
#[derive(Debug)]
pub enum TranslateError {
    /// Policy build failed.
    BuildFailed(String),
    /// Feature not yet supported in translation.
    Unsupported(String),
}

impl std::fmt::Display for TranslateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TranslateError::BuildFailed(e) => write!(f, "Build failed: {}", e),
            TranslateError::Unsupported(e) => write!(f, "Unsupported: {}", e),
        }
    }
}

impl std::error::Error for TranslateError {}

/// Convert a PolicyFile to a Gate0 Policy.
///
/// Each Ephemera policy maps to a Gate0 rule with:
/// - ReasonCode = policy index (0, 1, 2, ...)
/// - Default policy = ReasonCode(u32::MAX - 1)
pub fn to_gate0(policy_file: &PolicyFile) -> Result<Policy<'static>, TranslateError> {
    let mut builder = Policy::builder();

    // Add each policy as a rule
    for (index, policy) in policy_file.policies.iter().enumerate() {
        let reason = ReasonCode(index as u32);
        let condition = build_condition(index, &policy.match_block)?;

        let rule = match condition {
            Some(cond) => Rule::new(Effect::Allow, Target::any(), Some(cond), reason),
            None => Rule::allow(Target::any(), reason),
        };

        builder = builder.rule(rule);
    }

    // Default deny at the end - will match if nothing else did
    // Use a distinctive reason code
    let default_reason = ReasonCode(u32::MAX - 1);
    builder = builder.rule(Rule::allow(Target::any(), default_reason));

    builder
        .build()
        .map_err(|e| TranslateError::BuildFailed(format!("{:?}", e)))
}

/// Build a Gate0 Condition from a MatchBlock.
fn build_condition(index: usize, m: &MatchBlock) -> Result<Option<Condition<'static>>, TranslateError> {
    if !m.has_triggers() && !m.has_filters() {
        return Ok(None); // No conditions = match all
    }

    let mut conditions: Vec<Condition<'static>> = Vec::new();

    // OR triggers: use rule-specific attribute
    if m.has_triggers() {
        let attr = format!("p{}_trigger", index);
        conditions.push(Condition::Equals {
            // Leak is fine here since this is a CLI tool, not a long-running service.
            attr: Box::leak(attr.into_boxed_str()),
            value: Value::Bool(true),
        });
    }

    // AND filters: use rule-specific attributes
    if !m.source_ip.is_empty() {
        let attr = format!("p{}_ip", index);
        conditions.push(Condition::Equals {
            attr: Box::leak(attr.into_boxed_str()),
            value: Value::Bool(true),
        });
    }
    if !m.hours.is_empty() {
        let attr = format!("p{}_time", index);
        conditions.push(Condition::Equals {
            attr: Box::leak(attr.into_boxed_str()),
            value: Value::Bool(true),
        });
    }
    if !m.webauthn_ids.is_empty() {
        let attr = format!("p{}_webauthn", index);
        conditions.push(Condition::Equals {
            attr: Box::leak(attr.into_boxed_str()),
            value: Value::Bool(true),
        });
    }

    if conditions.is_empty() {
        Ok(None)
    } else if conditions.len() == 1 {
        Ok(Some(conditions.remove(0)))
    } else {
        // AND all conditions by chaining
        let mut result = conditions.pop().unwrap();
        while let Some(c) = conditions.pop() {
            result = Condition::And(Box::new(c), Box::new(result));
        }
        Ok(Some(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::parse_policy;

    #[test]
    fn test_translate_empty() {
        let yaml = r#"
default:
  principals: ["sandbox"]
  max_duration: "15m"
policies: []
"#;
        let policy_file = parse_policy(yaml).unwrap();
        let gate0_policy = to_gate0(&policy_file).unwrap();
        
        // Should have just the default rule
        assert_eq!(gate0_policy.rule_count(), 1);
    }

    #[test]
    fn test_translate_with_policy() {
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
        let policy_file = parse_policy(yaml).unwrap();
        let gate0_policy = to_gate0(&policy_file).unwrap();
        
        // Policy rule + default rule
        assert_eq!(gate0_policy.rule_count(), 2);
    }
}
