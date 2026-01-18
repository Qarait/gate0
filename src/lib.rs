//! # Gate0
//!
//! A small, auditable, terminating, deterministic micro-policy engine.
//!
//! ## Overview
//!
//! Given a principal, action, resource, and context, this library returns
//! a deterministic Allow or Deny decision plus a stable reason code.
//!
//! ## Verification
//!
//! - **Unit Tests**: Comprehensive coverage in every module.
//! - **Property-Based Testing**: Validates invariants against random inputs.
//! - **Undefined Behavior Check**: Verified strictly with `cargo miri`.
//! - **Panic-Free**: Ensured via compile-time analysis and runtime tests.
//!
//! See `SECURITY.md` in the repository root for the full security model.
//!
//! ## Guarantees
//!
//! - **Termination**: Bounded rules, bounded condition depth, bounded context size
//! - **Determinism**: Ordered evaluation, stable conflict resolution
//! - **No panics**: All operations return `Result`
//! - **Explicit errors**: Typed `PolicyError` enum
//! - **Zero dependencies**: Pure `std` only
//!
//! ## Example
//!
//! ```
//! use gate0::{Policy, Rule, Target, Matcher, Effect, Request, ReasonCode};
//!
//! // Define reason codes
//! const BLOCKED_USER: ReasonCode = ReasonCode(1);
//! const PUBLIC_READ: ReasonCode = ReasonCode(2);
//!
//! // Build a policy
//! let policy = Policy::builder()
//!     .rule(Rule::deny(
//!         Target {
//!             principal: Matcher::Exact("blocked_user"),
//!             action: Matcher::Any,
//!             resource: Matcher::Any,
//!         },
//!         BLOCKED_USER,
//!     ))
//!     .rule(Rule::allow(
//!         Target {
//!             principal: Matcher::Any,
//!             action: Matcher::Exact("read"),
//!             resource: Matcher::Any,
//!         },
//!         PUBLIC_READ,
//!     ))
//!     .build()
//!     .expect("valid policy");
//!
//! // Evaluate a request
//! let request = Request::new("alice", "read", "document.txt");
//! let decision = policy.evaluate(&request).expect("evaluation succeeds");
//!
//! assert!(decision.is_allow());
//! assert_eq!(decision.reason, PUBLIC_READ);
//! ```
//!
//! ## Conflict Resolution
//!
//! Uses **Deny overrides Allow**:
//! 1. Evaluate rules in declared order
//! 2. Collect all matching rules
//! 3. If any Deny matches → return first Deny's reason
//! 4. Else if any Allow matches → return first Allow's reason
//! 5. Else → Deny with `NO_MATCHING_RULE`

mod condition;
mod error;
mod fixed_stack;
mod policy;
mod stats;
mod target;
mod types;
mod value;
mod macros;

// Public API exports
pub use condition::Condition;
pub use error::PolicyError;
pub use policy::{Policy, PolicyBuilder, PolicyConfig, Rule};
pub use stats::EvaluationStats;
pub use target::{Matcher, Target};
pub use types::{Decision, Effect, ReasonCode, Request, NO_MATCHING_RULE};
pub use value::Value;

#[cfg(test)]
mod integration_tests {
    use super::*;

    const REASON_ADMIN: ReasonCode = ReasonCode(1);
    const REASON_BLOCKED: ReasonCode = ReasonCode(2);
    const REASON_READ_OK: ReasonCode = ReasonCode(3);

    #[test]
    fn test_realistic_policy() {
        // A realistic policy:
        // 1. Deny blocked users
        // 2. Allow admins to do anything
        // 3. Allow anyone to read public resources
        // 4. Default deny

        let actions: &[&str] = &["read", "list"];
        let policy = Policy::builder()
            // Deny blocked users first
            .rule(Rule::deny(
                Target {
                    principal: Matcher::Exact("blocked_user"),
                    action: Matcher::Any,
                    resource: Matcher::Any,
                },
                REASON_BLOCKED,
            ))
            // Allow admins
            .rule(Rule::new(
                Effect::Allow,
                Target::any(),
                Some(Condition::Equals {
                    attr: "role",
                    value: Value::String("admin"),
                }),
                REASON_ADMIN,
            ))
            // Allow read/list for everyone
            .rule(Rule::allow(
                Target {
                    principal: Matcher::Any,
                    action: Matcher::OneOf(actions),
                    resource: Matcher::Any,
                },
                REASON_READ_OK,
            ))
            .build()
            .unwrap();

        // Blocked user is denied
        let request = Request::new("blocked_user", "read", "doc");
        let decision = policy.evaluate(&request).unwrap();
        assert!(decision.is_deny());
        assert_eq!(decision.reason, REASON_BLOCKED);

        // Admin can write
        let ctx: &[(&str, Value)] = &[("role", Value::String("admin"))];
        let request = Request::with_context("alice", "write", "secret", ctx);
        let decision = policy.evaluate(&request).unwrap();
        assert!(decision.is_allow());
        assert_eq!(decision.reason, REASON_ADMIN);

        // Regular user can read
        let request = Request::new("bob", "read", "public_doc");
        let decision = policy.evaluate(&request).unwrap();
        assert!(decision.is_allow());
        assert_eq!(decision.reason, REASON_READ_OK);

        // Regular user cannot write
        let request = Request::new("bob", "write", "any_doc");
        let decision = policy.evaluate(&request).unwrap();
        assert!(decision.is_deny());
        assert_eq!(decision.reason, NO_MATCHING_RULE);
    }

    #[test]
    fn test_deny_overrides_allow_complex() {
        // Even if Allow comes before Deny, Deny wins
        let policy = Policy::builder()
            .rule(Rule::allow(Target::any(), REASON_READ_OK))
            .rule(Rule::new(
                Effect::Deny,
                Target::any(),
                Some(Condition::Equals {
                    attr: "suspicious",
                    value: Value::Bool(true),
                }),
                REASON_BLOCKED,
            ))
            .build()
            .unwrap();

        // Normal user: allowed
        let request = Request::new("alice", "read", "doc");
        let decision = policy.evaluate(&request).unwrap();
        assert!(decision.is_allow());

        // Suspicious user: denied
        let ctx: &[(&str, Value)] = &[("suspicious", Value::Bool(true))];
        let request = Request::with_context("alice", "read", "doc", ctx);
        let decision = policy.evaluate(&request).unwrap();
        assert!(decision.is_deny());
        assert_eq!(decision.reason, REASON_BLOCKED);
    }
}
