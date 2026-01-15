//! Illustrative scenario: Complex Hierarchical Overrides.
//!
//! This example demonstrates the 'Deny-Overrides' philosophy:
//! 1. A broad 'Allow' rule for a team or directory.
//! 2. A specific 'Deny' rule for a sensitive sub-resource.
//! 3. Proving that specific Denies win regardless of order.

use gate0::{Policy, Rule, Target, Matcher, Request, ReasonCode, Value, Condition, Effect};

const TEAM_READ: ReasonCode = ReasonCode(1);
const SENSITIVE_DENY: ReasonCode = ReasonCode(99);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Define a policy where we allow general access but block a specific file.
    // NOTE: In Gate0, Deny ALWAYS overrides Allow if both rules match.
    let policy = Policy::builder()
        // Rule 1: Allow anyone in 'Engineering' to read 'Documentation/*'
        .rule(Rule::new(
            Effect::Allow,
            Target {
                principal: Matcher::Any,
                action: Matcher::Exact("read"),
                resource: Matcher::Any, // In a real app prefix matching might be done in Condition
            },
            Some(Condition::Equals {
                attr: "team",
                value: Value::String("engineering"),
            }),
            TEAM_READ,
        ))
        // Rule 2: Explicitly deny reading the 'salaries.pdf' for everyone
        .rule(Rule::deny(
            Target {
                principal: Matcher::Any,
                action: Matcher::Any,
                resource: Matcher::Exact("salaries.pdf"),
            },
            SENSITIVE_DENY,
        ))
        .build()?;

    println!("--- Gate0 Hierarchy & Overrides Example ---");

    // Scenario A: Engineer reading a manual (Allowed)
    let eng_ctx: &[(&str, Value)] = &[("team", Value::String("engineering"))];
    let req_a = Request::with_context("alice", "read", "architecture_manual.pdf", eng_ctx);
    let dec_a = policy.evaluate(&req_a)?;
    println!("Alice (Eng) read manual.pdf: {:?}", dec_a.effect);
    assert!(dec_a.is_allow());

    // Scenario B: Engineer reading salaries.pdf (Denied)
    // Even though Rule 1 matches (Eng + Read), Rule 2 also matches (salaries.pdf + Any).
    // Deny-Overrides ensures the result is Deny.
    let req_b = Request::with_context("alice", "read", "salaries.pdf", eng_ctx);
    let dec_b = policy.evaluate(&req_b)?;
    println!("Alice (Eng) read salaries.pdf: {:?} (Reason: {:?})", dec_b.effect, dec_b.reason);
    assert!(dec_b.is_deny());
    assert_eq!(dec_b.reason, SENSITIVE_DENY);

    Ok(())
}
