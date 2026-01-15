//! Policy engine implementation.
//!
//! The core of the authorization system.
//! Evaluates rules in order, applies deny-overrides conflict resolution.

use crate::condition::Condition;
use crate::error::PolicyError;
use crate::target::Target;
use crate::types::{Decision, Effect, ReasonCode, Request, NO_MATCHING_RULE};
use crate::value::Value;

/// Configuration limits for policy construction and evaluation.
#[derive(Debug, Clone, Copy)]
pub struct PolicyConfig {
    /// Maximum number of rules allowed in a policy.
    pub max_rules: usize,
    /// Maximum depth of nested conditions (default: 10).
    pub max_condition_depth: usize,
    /// Maximum number of attributes allowed in request context (default: 64).
    pub max_context_attrs: usize,
    /// Maximum number of items in a Matcher::OneOf list (default: 64).
    pub max_matcher_options: usize,
    /// Maximum length of any string identifier or value (default: 256).
    pub max_string_len: usize,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig {
            max_rules: 1000,
            max_condition_depth: 10,
            max_context_attrs: 64,
            max_matcher_options: 64,
            max_string_len: 256,
        }
    }
}

/// A single authorization rule.
#[derive(Debug, Clone)]
pub struct Rule<'a> {
    /// The effect if this rule matches (Allow or Deny).
    pub effect: Effect,
    /// The target that determines if this rule applies.
    pub target: Target<'a>,
    /// Optional condition for additional matching logic.
    pub condition: Option<Condition<'a>>,
    /// The reason code for this rule's decision.
    pub reason: ReasonCode,
}

impl<'a> Rule<'a> {
    /// Create a new rule.
    pub fn new(
        effect: Effect,
        target: Target<'a>,
        condition: Option<Condition<'a>>,
        reason: ReasonCode,
    ) -> Self {
        Rule {
            effect,
            target,
            condition,
            reason,
        }
    }

    /// Create an Allow rule with no condition.
    pub fn allow(target: Target<'a>, reason: ReasonCode) -> Self {
        Rule::new(Effect::Allow, target, None, reason)
    }

    /// Create a Deny rule with no condition.
    pub fn deny(target: Target<'a>, reason: ReasonCode) -> Self {
        Rule::new(Effect::Deny, target, None, reason)
    }
}

/// A policy is an ordered collection of rules.
#[derive(Debug)]
pub struct Policy<'a> {
    rules: Vec<Rule<'a>>,
    config: PolicyConfig,
}

impl<'a> Policy<'a> {
    /// Create a new policy builder.
    pub fn builder() -> PolicyBuilder<'a> {
        PolicyBuilder::new()
    }

    /// Create a policy with the given rules and default config.
    pub fn new(rules: Vec<Rule<'a>>) -> Result<Self, PolicyError> {
        Self::with_config(rules, PolicyConfig::default())
    }

    /// Create a policy with the given rules and config.
    pub fn with_config(rules: Vec<Rule<'a>>, config: PolicyConfig) -> Result<Self, PolicyError> {
        // Validate rule count
        if rules.len() > config.max_rules {
            return Err(PolicyError::TooManyRules {
                max: config.max_rules,
                actual: rules.len(),
            });
        }

        // Validate rules and condition depths
        for rule in &rules {
            // Validate matcher options and string lengths
            rule.target
                .principal
                .validate(config.max_matcher_options, config.max_string_len)?;
            rule.target
                .action
                .validate(config.max_matcher_options, config.max_string_len)?;
            rule.target
                .resource
                .validate(config.max_matcher_options, config.max_string_len)?;

            // Validate condition depth and string lengths
            if let Some(cond) = &rule.condition {
                cond.validate(config.max_condition_depth, config.max_string_len)?;
            }
        }

        Ok(Policy { rules, config })
    }

    /// Get the number of rules in this policy.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get the configuration for this policy.
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Evaluate this policy against a request.
    ///
    /// Semantics:
    /// 1. Validate context size
    /// 2. Evaluate rules in declared order
    /// 3. Collect all matching (effect, reason) pairs
    /// 4. If any Deny exists → return first Deny's reason
    /// 5. Else if any Allow exists → return first Allow's reason
    /// 6. Else → Deny with NO_MATCHING_RULE
    pub fn evaluate(&self, request: &Request<'_>) -> Result<Decision, PolicyError> {
        // 1. Validate request string lengths
        validate_str(request.principal, self.config.max_string_len)?;
        validate_str(request.action, self.config.max_string_len)?;
        validate_str(request.resource, self.config.max_string_len)?;

        // 2. Validate context size
        if request.context.len() > self.config.max_context_attrs {
            return Err(PolicyError::ContextTooLarge {
                max: self.config.max_context_attrs,
                actual: request.context.len(),
            });
        }

        // 3. Validate context key/value lengths
        for (key, value) in request.context {
            validate_str(key, self.config.max_string_len)?;
            if let Value::String(s) = value {
                validate_str(s, self.config.max_string_len)?;
            }
        }

        let mut first_allow: Option<ReasonCode> = None;
        let mut first_deny: Option<ReasonCode> = None;

        // Evaluate rules in order
        for rule in &self.rules {
            // Check if target matches
            if !rule
                .target
                .matches(request.principal, request.action, request.resource)
            {
                continue;
            }

            // Check if condition matches (if present)
            let condition_matches = match &rule.condition {
                None => true,
                Some(cond) => cond.evaluate(request.context)?,
            };

            if !condition_matches {
                continue;
            }

            // Rule matches - record the effect
            match rule.effect {
                Effect::Allow => {
                    if first_allow.is_none() {
                        first_allow = Some(rule.reason);
                    }
                }
                Effect::Deny => {
                    if first_deny.is_none() {
                        first_deny = Some(rule.reason);
                    }
                }
            }
        }
        // Apply deny-overrides: Deny wins if any Deny matched
        if let Some(reason) = first_deny {
            Ok(Decision::deny(reason))
        } else if let Some(reason) = first_allow {
            Ok(Decision::allow(reason))
        } else {
            // No matching rules - default deny
            Ok(Decision::deny(NO_MATCHING_RULE))
        }
    }
}

/// Validate that a string does not exceed the maximum allowed length.
fn validate_str(s: &str, max_len: usize) -> Result<(), PolicyError> {
    if s.len() > max_len {
        Err(PolicyError::StringTooLong {
            max: max_len,
            actual: s.len(),
        })
    } else {
        Ok(())
    }
}

/// Builder for constructing policies.
#[derive(Debug)]
pub struct PolicyBuilder<'a> {
    rules: Vec<Rule<'a>>,
    config: PolicyConfig,
}

impl<'a> PolicyBuilder<'a> {
    /// Create a new policy builder.
    pub fn new() -> Self {
        PolicyBuilder {
            rules: Vec::new(),
            config: PolicyConfig::default(),
        }
    }

    /// Set the policy configuration.
    pub fn config(mut self, config: PolicyConfig) -> Self {
        self.config = config;
        self
    }

    /// Add a rule to the policy.
    pub fn rule(mut self, rule: Rule<'a>) -> Self {
        self.rules.push(rule);
        self
    }

    /// Build the policy.
    pub fn build(self) -> Result<Policy<'a>, PolicyError> {
        Policy::with_config(self.rules, self.config)
    }
}

impl<'a> Default for PolicyBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::Matcher;
    use crate::value::Value;

    const REASON_ADMIN_ACCESS: ReasonCode = ReasonCode(1);
    const REASON_BLOCKED_USER: ReasonCode = ReasonCode(2);
    const REASON_PUBLIC_READ: ReasonCode = ReasonCode(3);
    const REASON_WRITE_ALLOWED: ReasonCode = ReasonCode(4);

    #[test]
    fn test_empty_policy_denies() {
        let policy = Policy::new(vec![]).unwrap();
        let request = Request::new("alice", "read", "document.txt");
        let decision = policy.evaluate(&request).unwrap();

        assert!(decision.is_deny());
        assert_eq!(decision.reason, NO_MATCHING_RULE);
    }

    #[test]
    fn test_single_allow_rule() {
        let policy = Policy::builder()
            .rule(Rule::allow(Target::any(), REASON_PUBLIC_READ))
            .build()
            .unwrap();

        let request = Request::new("alice", "read", "anything");
        let decision = policy.evaluate(&request).unwrap();

        assert!(decision.is_allow());
        assert_eq!(decision.reason, REASON_PUBLIC_READ);
    }

    #[test]
    fn test_single_deny_rule() {
        let policy = Policy::builder()
            .rule(Rule::deny(Target::any(), REASON_BLOCKED_USER))
            .build()
            .unwrap();

        let request = Request::new("bob", "write", "secret");
        let decision = policy.evaluate(&request).unwrap();

        assert!(decision.is_deny());
        assert_eq!(decision.reason, REASON_BLOCKED_USER);
    }

    #[test]
    fn test_deny_overrides_allow() {
        // Allow rule comes first, but Deny should still win
        let policy = Policy::builder()
            .rule(Rule::allow(Target::any(), REASON_PUBLIC_READ))
            .rule(Rule::deny(Target::any(), REASON_BLOCKED_USER))
            .build()
            .unwrap();

        let request = Request::new("alice", "read", "doc");
        let decision = policy.evaluate(&request).unwrap();

        assert!(decision.is_deny());
        assert_eq!(decision.reason, REASON_BLOCKED_USER);
    }

    #[test]
    fn test_first_deny_reason_returned() {
        let policy = Policy::builder()
            .rule(Rule::deny(Target::any(), ReasonCode(100)))
            .rule(Rule::deny(Target::any(), ReasonCode(200)))
            .build()
            .unwrap();

        let request = Request::new("alice", "read", "doc");
        let decision = policy.evaluate(&request).unwrap();

        assert!(decision.is_deny());
        assert_eq!(decision.reason, ReasonCode(100));
    }

    #[test]
    fn test_first_allow_reason_returned() {
        let policy = Policy::builder()
            .rule(Rule::allow(Target::any(), ReasonCode(10)))
            .rule(Rule::allow(Target::any(), ReasonCode(20)))
            .build()
            .unwrap();

        let request = Request::new("alice", "read", "doc");
        let decision = policy.evaluate(&request).unwrap();

        assert!(decision.is_allow());
        assert_eq!(decision.reason, ReasonCode(10));
    }

    #[test]
    fn test_target_matching() {
        let policy = Policy::builder()
            .rule(Rule::allow(
                Target {
                    principal: Matcher::Exact("admin"),
                    action: Matcher::Any,
                    resource: Matcher::Any,
                },
                REASON_ADMIN_ACCESS,
            ))
            .build()
            .unwrap();

        // Admin matches
        let request = Request::new("admin", "delete", "everything");
        let decision = policy.evaluate(&request).unwrap();
        assert!(decision.is_allow());

        // Non-admin does not match
        let request = Request::new("user", "delete", "everything");
        let decision = policy.evaluate(&request).unwrap();
        assert!(decision.is_deny());
        assert_eq!(decision.reason, NO_MATCHING_RULE);
    }

    #[test]
    fn test_condition_evaluation() {
        let policy = Policy::builder()
            .rule(Rule::new(
                Effect::Allow,
                Target::any(),
                Some(Condition::Equals {
                    attr: "role",
                    value: Value::String("admin"),
                }),
                REASON_ADMIN_ACCESS,
            ))
            .build()
            .unwrap();

        // With admin role
        let ctx: &[(&str, Value)] = &[("role", Value::String("admin"))];
        let request = Request::with_context("alice", "read", "doc", ctx);
        let decision = policy.evaluate(&request).unwrap();
        assert!(decision.is_allow());

        // Without admin role
        let ctx: &[(&str, Value)] = &[("role", Value::String("user"))];
        let request = Request::with_context("alice", "read", "doc", ctx);
        let decision = policy.evaluate(&request).unwrap();
        assert!(decision.is_deny());
    }

    #[test]
    fn test_too_many_matcher_options() {
        let config = PolicyConfig {
            max_matcher_options: 2,
            ..PolicyConfig::default()
        };

        let target = Target {
            principal: Matcher::OneOf(&["a", "b", "c"]),
            action: Matcher::Any,
            resource: Matcher::Any,
        };

        let rule = Rule::allow(target, ReasonCode(1));
        let result = Policy::with_config(vec![rule], config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            PolicyError::TooManyMatcherOptions { max: 2, actual: 3 }
        ));
    }

    #[test]
    fn test_string_too_long_matcher() {
        let config = PolicyConfig {
            max_string_len: 5,
            ..PolicyConfig::default()
        };

        let target = Target {
            principal: Matcher::Exact("too-long-string"),
            action: Matcher::Any,
            resource: Matcher::Any,
        };

        let rule = Rule::allow(target, ReasonCode(1));
        let result = Policy::with_config(vec![rule], config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            PolicyError::StringTooLong { max: 5, actual: 15 }
        ));
    }

    #[test]
    fn test_string_too_long_condition() {
        let config = PolicyConfig {
            max_string_len: 5,
            ..PolicyConfig::default()
        };

        let cond = Condition::Equals {
            attr: "role",
            value: Value::String("administrator"),
        };

        let rule = Rule::new(Effect::Allow, Target::any(), Some(cond), ReasonCode(1));
        let result = Policy::with_config(vec![rule], config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            PolicyError::StringTooLong { max: 5, actual: 13 }
        ));
    }

    #[test]
    fn test_too_many_rules() {
        let config = PolicyConfig {
            max_rules: 2,
            ..Default::default()
        };

        let result = Policy::with_config(
            vec![
                Rule::allow(Target::any(), ReasonCode(1)),
                Rule::allow(Target::any(), ReasonCode(2)),
                Rule::allow(Target::any(), ReasonCode(3)),
            ],
            config,
        );

        assert_eq!(
            result.unwrap_err(),
            PolicyError::TooManyRules { max: 2, actual: 3 }
        );
    }

    #[test]
    fn test_context_too_large() {
        let config = PolicyConfig {
            max_context_attrs: 2,
            ..Default::default()
        };

        let policy =
            Policy::with_config(vec![Rule::allow(Target::any(), ReasonCode(1))], config).unwrap();

        let ctx: &[(&str, Value)] = &[
            ("a", Value::Int(1)),
            ("b", Value::Int(2)),
            ("c", Value::Int(3)),
        ];
        let request = Request::with_context("alice", "read", "doc", ctx);
        let result = policy.evaluate(&request);

        assert_eq!(
            result.unwrap_err(),
            PolicyError::ContextTooLarge { max: 2, actual: 3 }
        );
    }

    #[test]
    fn test_condition_too_deep() {
        let config = PolicyConfig {
            max_condition_depth: 2,
            ..Default::default()
        };

        let deep_condition = Condition::And(
            Box::new(Condition::True),
            Box::new(Condition::Not(Box::new(Condition::False))),
        );

        let result = Policy::with_config(
            vec![Rule::new(
                Effect::Allow,
                Target::any(),
                Some(deep_condition),
                ReasonCode(1),
            )],
            config,
        );

        assert_eq!(
            result.unwrap_err(),
            PolicyError::ConditionTooDeep { max: 2, actual: 3 }
        );
    }

    #[test]
    fn test_deterministic_evaluation() {
        let actions: &[&str] = &["read", "write"];
        let policy = Policy::builder()
            .rule(Rule::deny(
                Target {
                    principal: Matcher::Exact("blocked"),
                    action: Matcher::Any,
                    resource: Matcher::Any,
                },
                REASON_BLOCKED_USER,
            ))
            .rule(Rule::allow(
                Target {
                    principal: Matcher::Any,
                    action: Matcher::OneOf(actions),
                    resource: Matcher::Any,
                },
                REASON_WRITE_ALLOWED,
            ))
            .build()
            .unwrap();

        // Run the same evaluation 100 times - must be identical
        let request = Request::new("alice", "write", "doc");
        let expected = policy.evaluate(&request).unwrap();

        for _ in 0..100 {
            let result = policy.evaluate(&request).unwrap();
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_hostile_request_string_too_long() {
        let config = PolicyConfig {
            max_string_len: 10,
            ..PolicyConfig::default()
        };
        let policy =
            Policy::with_config(vec![Rule::allow(Target::any(), ReasonCode(1))], config).unwrap();

        // 1. Principal too long
        let req = Request::new("this-is-a-very-long-principal", "read", "doc");
        assert!(matches!(
            policy.evaluate(&req),
            Err(PolicyError::StringTooLong { max: 10, .. })
        ));

        // 2. Action too long
        let req = Request::new("alice", "very-long-action-name", "doc");
        assert!(matches!(
            policy.evaluate(&req),
            Err(PolicyError::StringTooLong { max: 10, .. })
        ));

        // 3. Context key too long
        let ctx: &[(&str, Value)] = &[("this-is-a-very-long-key", Value::Int(1))];
        let req = Request::with_context("alice", "read", "doc", ctx);
        assert!(matches!(
            policy.evaluate(&req),
            Err(PolicyError::StringTooLong { max: 10, .. })
        ));

        // 4. Context value too long
        let ctx: &[(&str, Value)] = &[("role", Value::String("administrator"))];
        let req = Request::with_context("alice", "read", "doc", ctx);
        assert!(matches!(
            policy.evaluate(&req),
            Err(PolicyError::StringTooLong { max: 10, .. })
        ));
    }
}
