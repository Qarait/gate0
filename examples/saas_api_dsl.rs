use gate0::{Matcher, ReasonCode, Request, Value, policy_builder, ctx};

// Application-specific reason codes
const ADMIN_ACCESS: ReasonCode = ReasonCode(100);
const MEMBER_READ: ReasonCode = ReasonCode(101);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Define the Policy
    let policy = policy_builder![
        // Rule: Admins can do anything
        ALLOW ANY
            WHERE { (role = "admin") } => ADMIN_ACCESS;

        // Rule: Members can read or list
        ALLOW {
            ACTION: ["read", "list"]
        }
        WHERE { (role = "member") } => MEMBER_READ;
    ].build()?;

    println!("--- Gate0 SaaS API Example ---");

    // Scenario A: Admin trying to update a resource
    let alice_ctx = ctx!(
        "role" => "admin",
        "tenant_id" => "tenant-1",
    );
    let req_a = Request::with_context("alice", "update", "doc-123", alice_ctx);
    let dec_a = policy.evaluate(&req_a)?;
    println!("Alice (Admin) update doc-123: {:?}", dec_a.effect);
    assert!(dec_a.is_allow());

    // Scenario B: Regular member trying to update a resource (Denied)
    let bob_ctx = ctx!(
        "role" => "member",
        "tenant_id" => "tenant-1",
    );
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