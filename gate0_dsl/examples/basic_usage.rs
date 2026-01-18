use gate0::{ctx, Policy, PolicyConfig, ReasonCode, Request};
use gate0_dsl::policy_builder;

const ADMIN_ACCESS: ReasonCode = ReasonCode(1);
const USER_BLOCKED: ReasonCode = ReasonCode(2);
const READ_ALLOWED: ReasonCode = ReasonCode(3);
const WRITE_ALLOWED: ReasonCode = ReasonCode(4);
const SENSITIVE_DENIED: ReasonCode = ReasonCode(5);

fn main() {
    println!("=== Policy DSL Examples ===\n");

    example_1_simple_wildcard();
    example_2_tuple_format();
    example_3_struct_format();
    example_4_with_config();
    example_5_with_conditions();
    example_6_external_builder();
    example_7_complete_policy();

    println!("\n=== All examples completed successfully! ===");
}

fn example_1_simple_wildcard() {
    println!("Example 1: Simple Wildcard Rules");

    let policy = policy_builder! {
        ALLOW * => 1;
        DENY ANY => 2;
    }
    .build()
    .unwrap();

    let request = Request::new("alice", "read", "doc");
    let decision = policy.evaluate(&request).unwrap();

    println!("  Decision: {:?}", decision.effect);
    println!("  Reason: {:?}", decision.reason);
    println!();
}

fn example_2_tuple_format() {
    println!("Example 2: Tuple Format");

    let policy = policy_builder! {
        ALLOW ("alice" "read" "doc1") => READ_ALLOWED;
        ALLOW ("bob" "write" "doc2") => WRITE_ALLOWED;
        DENY (["eve", "mallory"] * *) => USER_BLOCKED;
    }
    .build()
    .unwrap();

    // Alice can read doc1
    let request = Request::new("alice", "read", "doc1");
    let decision = policy.evaluate(&request).unwrap();
    println!(
        "  Alice reading doc1: {:?} (reason: {:?})",
        decision.effect, decision.reason
    );

    // Eve is blocked
    let request = Request::new("eve", "read", "anything");
    let decision = policy.evaluate(&request).unwrap();
    println!(
        "  Eve blocked: {:?} (reason: {:?})",
        decision.effect, decision.reason
    );
    println!();
}

fn example_3_struct_format() {
    println!("Example 3: Struct Format");

    let policy = policy_builder! {
        ALLOW {
            principal: ["alice", "bob"],
            action: "read",
            resource: *,
        } => READ_ALLOWED;

        DENY {
            principal: *,
            action: "delete",
            resource: ["sensitive1", "sensitive2"],
        } => SENSITIVE_DENIED;
    }
    .build()
    .unwrap();

    let request = Request::new("alice", "read", "anything");
    let decision = policy.evaluate(&request).unwrap();
    println!("  Alice reading: {:?}", decision.effect);

    let request = Request::new("charlie", "delete", "sensitive1");
    let decision = policy.evaluate(&request).unwrap();
    println!("  Deleting sensitive: {:?}", decision.effect);
    println!();
}

fn example_4_with_config() {
    println!("Example 4: With Configuration");

    let policy = policy_builder! {
        CONFIG {
            max_rules: 500,
            max_condition_depth: 10,
            max_context_attrs: 50,
        };

        ALLOW * => 1;
    }
    .build()
    .unwrap();

    println!("  Config max_rules: {}", policy.config().max_rules);
    println!(
        "  Config max_condition_depth: {}",
        policy.config().max_condition_depth
    );
    println!();
}

fn example_5_with_conditions() {
    println!("Example 5: With Conditions");

    let policy = policy_builder! {
        // Admins can do anything
        ALLOW ANY WHERE { (role EQ "admin") } => ADMIN_ACCESS;

        // Suspended users are blocked
        DENY ANY WHERE { (suspended EQ true) } => USER_BLOCKED;

        // High-level users can read
        ALLOW (ANY "read" ANY) WHERE { (level EQ 5) } => READ_ALLOWED;
    }
    .build()
    .unwrap();

    // Admin access
    let ctx = ctx! {
        "role" => "admin",
        "level" => 5
    };
    let request = Request::with_context("alice", "write", "sensitive", ctx);
    let decision = policy.evaluate(&request).unwrap();
    println!(
        "  Admin writing: {:?} (reason: {:?})",
        decision.effect, decision.reason
    );

    // Suspended user
    let ctx = ctx! {
        "suspended" => true,
        "role" => "admin"
    };
    let request = Request::with_context("bob", "read", "doc", ctx);
    let decision = policy.evaluate(&request).unwrap();
    println!(
        "  Suspended admin: {:?} (reason: {:?})",
        decision.effect, decision.reason
    );

    // High-level read
    let ctx = ctx! {
        "level" => 5
    };
    let request = Request::with_context("charlie", "read", "doc", ctx);
    let decision = policy.evaluate(&request).unwrap();
    println!(
        "  Level 5 reading: {:?} (reason: {:?})",
        decision.effect, decision.reason
    );
    println!();
}

fn example_6_external_builder() {
    println!("Example 6: External Builder");

    let builder = Policy::builder().config(PolicyConfig {
        max_rules: 200,
        ..PolicyConfig::default()
    });

    let policy = policy_builder! {
        USE builder;
        ALLOW * => 1;
        DENY ("eve" * *) => USER_BLOCKED;
    }
    .build()
    .unwrap();

    println!(
        "  Policy with external config max_rules: {}",
        policy.config().max_rules
    );
    println!();
}

fn example_7_complete_policy() {
    println!("Example 7: Complete Policy");

    const BLOCKED: ReasonCode = ReasonCode(10);
    const ADMIN_OK: ReasonCode = ReasonCode(20);
    const PUBLIC_READ: ReasonCode = ReasonCode(30);
    const OWNER_WRITE: ReasonCode = ReasonCode(40);

    let policy = policy_builder! {
        CONFIG {
            max_rules: 100,
            max_condition_depth: 5,
        };

        // 1. Block banned users first (deny overrides allow)
        DENY {
            principal: ["banned1", "banned2"],
            action: *,
            resource: *,
        } => BLOCKED;

        // 2. Admins can do anything
        ALLOW ANY WHERE { (role EQ "admin") } => ADMIN_OK;

        // 3. Anyone can read public resources
        ALLOW {
            principal: *,
            action: "read",
            resource: *,
        } WHERE { (resource_type EQ "public") } => PUBLIC_READ;

        // 4. Owners can write their own resources
        ALLOW {
            principal: *,
            action: ["write", "update"],
            resource: *,
        } WHERE { (is_owner EQ true) } => OWNER_WRITE;

        // 5. Default deny (implicit - no rule matches)
    }
    .build()
    .unwrap();

    println!("  Policy built with {} rules", policy.rule_count());

    // Test 1: Banned user denied
    let request = Request::new("banned1", "read", "anything");
    let decision = policy.evaluate(&request).unwrap();
    println!(
        "  Banned user: {:?} (reason: {:?})",
        decision.effect, decision.reason
    );
    assert_eq!(decision.reason, BLOCKED);

    // Test 2: Admin allowed
    let ctx = ctx! { "role" => "admin" };
    let request = Request::with_context("alice", "delete", "sensitive", ctx);
    let decision = policy.evaluate(&request).unwrap();
    println!(
        "  Admin deleting: {:?} (reason: {:?})",
        decision.effect, decision.reason
    );
    assert_eq!(decision.reason, ADMIN_OK);

    // Test 3: Public read allowed
    let ctx = ctx! { "resource_type" => "public" };
    let request = Request::with_context("guest", "read", "doc", ctx);
    let decision = policy.evaluate(&request).unwrap();
    println!(
        "  Public read: {:?} (reason: {:?})",
        decision.effect, decision.reason
    );
    assert_eq!(decision.reason, PUBLIC_READ);

    // Test 4: Owner write allowed
    let ctx = ctx! {
        "is_owner" => true,
        "resource_type" => "private"
    };
    let request = Request::with_context("bob", "write", "doc", ctx);
    let decision = policy.evaluate(&request).unwrap();
    println!(
        "  Owner writing: {:?} (reason: {:?})",
        decision.effect, decision.reason
    );
    assert_eq!(decision.reason, OWNER_WRITE);

    // Test 5: Default deny
    let request = Request::new("stranger", "delete", "private_doc");
    let decision = policy.evaluate(&request).unwrap();
    println!("  Unauthorized delete: {:?}", decision.effect);
    assert!(decision.is_deny());

    println!();
}
