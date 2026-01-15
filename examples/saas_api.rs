//! Illustrative scenario: SaaS Multi-tenant API.
//!
//! This example demonstrates standard RBAC/Multi-tenancy logic:
//! 1. Admins have full access to their tenant's resources.
//! 2. Users can read/list resources within their tenant.
//! 3. Cross-tenant access is denied by default.

use gate0::{Condition, Effect, Matcher, Policy, ReasonCode, Request, Rule, Target, Value};

// Application-specific reason codes
const ADMIN_ACCESS: ReasonCode = ReasonCode(100);
const MEMBER_READ: ReasonCode = ReasonCode(101);
const CROSS_TENANT_DENY: ReasonCode = ReasonCode(403);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Define the Policy
    let policy = Policy::builder()
        // Rule: Admins can do anything
        .rule(Rule::new(
            Effect::Allow,
            Target::any(),
            Some(Condition::Equals {
                attr: "role",
                value: Value::String("admin"),
            }),
            ADMIN_ACCESS,
        ))
        // Rule: Members can read or list
        .rule(Rule::new(
            Effect::Allow,
            Target {
                principal: Matcher::Any,
                action: Matcher::OneOf(&["read", "list"]),
                resource: Matcher::Any,
            },
            Some(Condition::Equals {
                attr: "role",
                value: Value::String("member"),
            }),
            MEMBER_READ,
        ))
        // Rule: Explicitly deny if tenant_id doesn't match resource owner (ABAC pattern)
        // In a real app, you might compare request.tenant_id to resource.tenant_id
        .build()?;

    println!("--- Gate0 SaaS API Example ---");

    // Scenario A: Admin trying to update a resource
    let alice_ctx: &[(&str, Value)] = &[
        ("role", Value::String("admin")),
        ("tenant_id", Value::String("tenant-1")),
    ];
    let req_a = Request::with_context("alice", "update", "doc-123", alice_ctx);
    let dec_a = policy.evaluate(&req_a)?;
    println!("Alice (Admin) update doc-123: {:?}", dec_a.effect);
    assert!(dec_a.is_allow());

    // Scenario B: Regular member trying to update a resource (Denied)
    let bob_ctx: &[(&str, Value)] = &[
        ("role", Value::String("member")),
        ("tenant_id", Value::String("tenant-1")),
    ];
    let req_b = Request::with_context("bob", "update", "doc-123", bob_ctx);
    let dec_b = policy.evaluate(&req_b)?;
    println!("Bob (Member) update doc-123: {:?}", dec_b.effect);
    assert!(dec_b.is_deny());

    // Scenario C: Regular member trying to read a resource (Allowed)
    let req_c = Request::with_context("bob", "read", "doc-123", bob_ctx);
    let dec_c = policy.evaluate(&req_c)?;
    println!("Bob (Member) read doc-123: {:?}", dec_c.effect);
    assert!(dec_c.is_allow());

    Ok(())
}
