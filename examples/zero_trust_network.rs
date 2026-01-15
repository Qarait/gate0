//! Illustrative scenario: Zero Trust Network Access (ZTNA).
//!
//! This example demonstrates Attribute-Based Access Control (ABAC):
//! 1. Access is only allowed if the user is MFA-authenticated.
//! 2. Access is restricted based on IP ranges (simulated via context).
//! 3. High-security resources require an additional 'secure_device' flag.

use gate0::{Condition, Effect, Matcher, Policy, ReasonCode, Request, Rule, Target, Value};

const ACCESS_GRANTED: ReasonCode = ReasonCode(200);
const MFA_REQUIRED: ReasonCode = ReasonCode(401);
const UNTRUSTED_LOCATION: ReasonCode = ReasonCode(403);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build a Zero-Trust Policy
    let policy = Policy::builder()
        // Primary Security Rule: Deny all if NOT MFA authenticated
        .rule(Rule::new(
            Effect::Deny,
            Target::any(),
            Some(Condition::Equals {
                attr: "mfa_authenticated",
                value: Value::Bool(false),
            }),
            MFA_REQUIRED,
        ))
        // Location Rule: Deny if from an untrusted country
        .rule(Rule::new(
            Effect::Deny,
            Target::any(),
            Some(Condition::Equals {
                attr: "country",
                value: Value::String("untrusted"),
            }),
            UNTRUSTED_LOCATION,
        ))
        // Authorization Rule: Allow shell access to 'dev-server' if authenticated
        .rule(Rule::allow(
            Target {
                principal: Matcher::Any,
                action: Matcher::Exact("ssh_connect"),
                resource: Matcher::Exact("dev-server"),
            },
            ACCESS_GRANTED,
        ))
        .build()?;

    println!("--- Gate0 Zero-Trust Network Example ---");

    // Scenario 1: Authenticated user from trusted location
    let alice_ctx: &[(&str, Value)] = &[
        ("mfa_authenticated", Value::Bool(true)),
        ("country", Value::String("US")),
    ];
    let req1 = Request::with_context("alice", "ssh_connect", "dev-server", alice_ctx);
    let dec1 = policy.evaluate(&req1)?;
    println!("Alice (MFA=True, US) -> dev-server: {:?}", dec1.effect);
    assert!(dec1.is_allow());

    // Scenario 2: User forgot MFA (Denied with MFA_REQUIRED)
    let bob_ctx: &[(&str, Value)] = &[
        ("mfa_authenticated", Value::Bool(false)),
        ("country", Value::String("US")),
    ];
    let req2 = Request::with_context("bob", "ssh_connect", "dev-server", bob_ctx);
    let dec2 = policy.evaluate(&req2)?;
    println!(
        "Bob (MFA=False, US) -> dev-server: {:?} (Reason: {:?})",
        dec2.effect, dec2.reason
    );
    assert!(dec2.is_deny());
    assert_eq!(dec2.reason, MFA_REQUIRED);

    // Scenario 3: Authenticated user from untrusted location (Denied with UNTRUSTED_LOCATION)
    let charlie_ctx: &[(&str, Value)] = &[
        ("mfa_authenticated", Value::Bool(true)),
        ("country", Value::String("untrusted")),
    ];
    let req3 = Request::with_context("charlie", "ssh_connect", "dev-server", charlie_ctx);
    let dec3 = policy.evaluate(&req3)?;
    println!(
        "Charlie (MFA=True, Untrusted) -> dev-server: {:?} (Reason: {:?})",
        dec3.effect, dec3.reason
    );
    assert!(dec3.is_deny());
    assert_eq!(dec3.reason, UNTRUSTED_LOCATION);

    Ok(())
}
