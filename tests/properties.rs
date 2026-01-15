//! Property-based tests for Gate0.
//!
//! These tests use proptest to generate random inputs and verify
//! that core invariants hold under adversarial conditions.
//!
//! IMPORTANT: Property tests are intentionally bounded to prevent resource
//! exhaustion during local runs. See proptest.toml for configuration.

use gate0::{
    Condition, Effect, Matcher, Policy, PolicyConfig, PolicyError, ReasonCode, Request, Rule,
    Target, Value, NO_MATCHING_RULE,
};
use proptest::prelude::*;

// =============================================================================
// Strategies for generating random inputs
// =============================================================================

/// Generate a random effect.
fn arb_effect() -> impl Strategy<Value = Effect> {
    prop_oneof![Just(Effect::Allow), Just(Effect::Deny),]
}

/// Generate a random reason code.
fn arb_reason() -> impl Strategy<Value = ReasonCode> {
    (0u32..1000).prop_map(ReasonCode)
}

/// Generate a random string for identifiers.
fn arb_identifier() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,15}".prop_filter("non-empty", |s| !s.is_empty())
}

/// Generate a random condition with bounded depth.
/// Depth is capped at 5 to prevent exponential explosion.
fn arb_condition(max_depth: usize) -> impl Strategy<Value = Condition<'static>> {
    let effective_depth = max_depth.min(5); // Hard cap at 5

    if effective_depth <= 1 {
        prop_oneof![Just(Condition::True), Just(Condition::False),].boxed()
    } else {
        prop_oneof![
            4 => Just(Condition::True),
            4 => Just(Condition::False),
            1 => arb_condition(effective_depth - 1).prop_map(|c| Condition::Not(Box::new(c))),
            1 => (arb_condition(effective_depth - 1), arb_condition(effective_depth - 1))
                .prop_map(|(a, b)| Condition::And(Box::new(a), Box::new(b))),
        ]
        .boxed()
    }
}

/// Generate a simple target (no string fields to avoid leaks).
fn arb_target_simple() -> impl Strategy<Value = Target<'static>> {
    Just(Target {
        principal: Matcher::Any,
        action: Matcher::Any,
        resource: Matcher::Any,
    })
}

/// Generate a random rule with simple components.
fn arb_rule_simple() -> impl Strategy<Value = Rule<'static>> {
    (
        arb_effect(),
        arb_target_simple(),
        prop::option::of(arb_condition(4)),
        arb_reason(),
    )
        .prop_map(|(effect, target, condition, reason)| Rule {
            effect,
            target,
            condition,
            reason,
        })
}

// =============================================================================
// Property tests (bounded for safety)
// =============================================================================

proptest! {
    // Conservative case count for local development
    #![proptest_config(ProptestConfig::with_cases(25))]

    /// Invariant: Evaluation never panics, regardless of input.
    #[test]
    fn prop_no_panics(
        rules in prop::collection::vec(arb_rule_simple(), 0..20),
        principal in arb_identifier(),
        action in arb_identifier(),
        resource in arb_identifier(),
    ) {
        let policy = Policy::new(rules);
        if let Ok(policy) = policy {
            let request = Request::new(&principal, &action, &resource);
            // This should never panic
            let _ = policy.evaluate(&request);
        }
    }

    /// Invariant: Same input always produces same output (determinism).
    #[test]
    fn prop_determinism(
        rules in prop::collection::vec(arb_rule_simple(), 1..10),
        principal in arb_identifier(),
        action in arb_identifier(),
        resource in arb_identifier(),
    ) {
        let policy = Policy::new(rules);
        if let Ok(policy) = policy {
            let request = Request::new(&principal, &action, &resource);

            let decision1 = policy.evaluate(&request);
            let decision2 = policy.evaluate(&request);
            let decision3 = policy.evaluate(&request);

            prop_assert_eq!(&decision1, &decision2);
            prop_assert_eq!(&decision2, &decision3);
        }
    }

    /// Invariant: Empty policy always denies with NO_MATCHING_RULE.
    #[test]
    fn prop_empty_policy_denies(
        principal in arb_identifier(),
        action in arb_identifier(),
        resource in arb_identifier(),
    ) {
        let policy = Policy::new(vec![]).unwrap();
        let request = Request::new(&principal, &action, &resource);
        let decision = policy.evaluate(&request).unwrap();

        prop_assert!(decision.is_deny());
        prop_assert_eq!(decision.reason, NO_MATCHING_RULE);
    }

    /// Invariant: Deny always overrides Allow.
    #[test]
    fn prop_deny_overrides_allow(
        principal in arb_identifier(),
        action in arb_identifier(),
        resource in arb_identifier(),
        allow_reason in arb_reason(),
        deny_reason in arb_reason(),
    ) {
        // Policy with both Allow and Deny for same target
        let rules = vec![
            Rule::allow(Target::any(), allow_reason),
            Rule::deny(Target::any(), deny_reason),
        ];
        let policy = Policy::new(rules).unwrap();
        let request = Request::new(&principal, &action, &resource);
        let decision = policy.evaluate(&request).unwrap();

        prop_assert!(decision.is_deny());
        prop_assert_eq!(decision.reason, deny_reason);
    }

    /// Invariant: Decision is always Allow or Deny, never something else.
    #[test]
    fn prop_decision_is_binary(
        rules in prop::collection::vec(arb_rule_simple(), 0..15),
        principal in arb_identifier(),
        action in arb_identifier(),
        resource in arb_identifier(),
    ) {
        let policy = Policy::new(rules);
        if let Ok(policy) = policy {
            let request = Request::new(&principal, &action, &resource);
            if let Ok(decision) = policy.evaluate(&request) {
                prop_assert!(decision.is_allow() || decision.is_deny());
                prop_assert!(decision.is_allow() != decision.is_deny());
            }
        }
    }

    /// Invariant: Condition depth is enforced.
    #[test]
    fn prop_condition_depth_enforced(
        deep_condition in arb_condition(5),
    ) {
        let config = PolicyConfig {
            max_rules: 1000,
            max_condition_depth: 3, // Intentionally low to trigger rejection
            max_context_attrs: 64,
            max_matcher_options: 64,
            max_string_len: 256,
        };

        let rule = Rule::new(
            Effect::Allow,
            Target::any(),
            Some(deep_condition.clone()),
            ReasonCode(1),
        );

        let result = Policy::with_config(vec![rule], config);

        // If depth > 3, should fail; otherwise should succeed
        if deep_condition.depth() > 3 {
            prop_assert!(result.is_err(), "depth {} should fail", deep_condition.depth());
        }
    }

    /// Invariant: Rule count is enforced.
    #[test]
    fn prop_rule_count_enforced(
        rule_count in 1usize..60,
    ) {
        let config = PolicyConfig {
            max_rules: 30,
            max_condition_depth: 10,
            max_context_attrs: 64,
            max_matcher_options: 64,
            max_string_len: 256,
        };

        let rules: Vec<Rule> = (0..rule_count)
            .map(|i| Rule::allow(Target::any(), ReasonCode(i as u32)))
            .collect();

        let result = Policy::with_config(rules, config);

        if rule_count > 30 {
            prop_assert!(result.is_err());
        } else {
            prop_assert!(result.is_ok());
        }
    }
}

// =============================================================================
// Deterministic worst-case tests (non-proptest)
// =============================================================================

/// Test with maximum allowed bounds - proves designed-for-worst-case behavior.
#[test]
fn test_worst_case_policy() {
    let config = PolicyConfig {
        max_rules: 1000,
        max_condition_depth: 10,
        max_context_attrs: 64,
        max_matcher_options: 64,
        max_string_len: 256,
    };

    // Create a policy with maximum rules
    let rules: Vec<Rule> = (0..1000)
        .map(|i| {
            if i == 500 {
                // One deny rule in the middle
                Rule::deny(Target::any(), ReasonCode(999))
            } else {
                Rule::allow(Target::any(), ReasonCode(i as u32))
            }
        })
        .collect();

    let policy = Policy::with_config(rules, config).expect("should construct");
    assert_eq!(policy.rule_count(), 1000);

    // Create a request that triggers the deny rule
    let request = Request::new("anyone", "read", "anything");
    let decision = policy.evaluate(&request).expect("should evaluate");

    // Deny overrides - should get the deny reason
    assert!(decision.is_deny());
    assert_eq!(decision.reason, ReasonCode(999));
}

/// Test with maximum context size.
#[test]
fn test_max_context_size() {
    let policy = Policy::new(vec![Rule::allow(Target::any(), ReasonCode(1))]).unwrap();

    // Use simple string literals instead of leaked allocations
    let ctx: Vec<(&str, Value)> = vec![
        ("attr0", Value::Int(0)),
        ("attr1", Value::Int(1)),
        ("attr2", Value::Int(2)),
        ("attr3", Value::Int(3)),
        ("attr4", Value::Int(4)),
        ("attr5", Value::Int(5)),
        ("attr6", Value::Int(6)),
        ("attr7", Value::Int(7)),
        ("attr8", Value::Int(8)),
        ("attr9", Value::Int(9)),
    ];

    let request = Request::with_context("alice", "read", "doc", &ctx);
    let result = policy.evaluate(&request);
    assert!(result.is_ok());
}

/// Test that exceeding context limit returns error.
#[test]
fn test_context_too_large() {
    let config = PolicyConfig {
        max_rules: 1000,
        max_condition_depth: 10,
        max_context_attrs: 5, // Very small limit
        max_matcher_options: 64,
        max_string_len: 256,
    };

    let policy =
        Policy::with_config(vec![Rule::allow(Target::any(), ReasonCode(1))], config).unwrap();

    // Create context over the limit
    let ctx: Vec<(&str, Value)> = vec![
        ("a1", Value::Int(1)),
        ("a2", Value::Int(2)),
        ("a3", Value::Int(3)),
        ("a4", Value::Int(4)),
        ("a5", Value::Int(5)),
        ("a6", Value::Int(6)), // Over limit
    ];

    let request = Request::with_context("alice", "read", "doc", &ctx);
    let result = policy.evaluate(&request);
    assert!(matches!(result, Err(PolicyError::ContextTooLarge { .. })));
}

/// Test with maximum condition depth.
#[test]
fn test_max_condition_depth() {
    // Build a condition tree of depth exactly 10
    fn build_deep_condition(depth: usize) -> Condition<'static> {
        if depth <= 1 {
            Condition::True
        } else {
            Condition::Not(Box::new(build_deep_condition(depth - 1)))
        }
    }

    let cond = build_deep_condition(10);
    assert_eq!(cond.depth(), 10);

    let rule = Rule::new(Effect::Allow, Target::any(), Some(cond), ReasonCode(1));
    let policy = Policy::new(vec![rule]);
    assert!(policy.is_ok());

    // Depth 11 should fail
    let cond = build_deep_condition(11);
    assert_eq!(cond.depth(), 11);

    let rule = Rule::new(Effect::Allow, Target::any(), Some(cond), ReasonCode(1));
    let result = Policy::new(vec![rule]);
    assert!(matches!(
        result,
        Err(PolicyError::ConditionTooDeep {
            max: 10,
            actual: 11
        })
    ));
}
