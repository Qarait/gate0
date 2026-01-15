//! Allocation tracking tests to verify zero heap allocations during evaluation.
//!
//! Uses a custom global allocator to count allocations and assert that
//! Policy::evaluate performs zero heap allocations at request-time.
//!
//! **IMPORTANT**: These tests use a global allocator counter and MUST be run
//! single-threaded to avoid interference:
//! ```
//! cargo test --test allocations -- --test-threads=1
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use gate0::{Condition, Effect, Matcher, Policy, ReasonCode, Request, Rule, Target, Value};

/// A counting allocator that wraps the system allocator.
struct CountingAllocator;

static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::SeqCst);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::SeqCst);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn reset_alloc_count() {
    ALLOC_COUNT.store(0, Ordering::SeqCst);
}

fn get_alloc_count() -> usize {
    ALLOC_COUNT.load(Ordering::SeqCst)
}

/// Test that Policy::evaluate performs zero heap allocations.
/// We run 1000 iterations to catch any lazy initialization patterns.
#[test]
fn test_zero_allocations_allow_path() {
    // Setup: Build a policy (allocations here don't count)
    let policy = Policy::builder()
        .rule(Rule::allow(Target::any(), ReasonCode(1)))
        .build()
        .unwrap();

    let request = Request::new("alice", "read", "doc");

    // Warm-up: First call might trigger lazy init in std
    let _ = policy.evaluate(&request);

    // Measure
    reset_alloc_count();
    for _ in 0..1000 {
        let _ = policy.evaluate(&request);
    }
    let count = get_alloc_count();

    assert_eq!(
        count, 0,
        "evaluate() should perform zero allocations, but performed {count}"
    );
}

#[test]
fn test_zero_allocations_deny_path() {
    let policy = Policy::builder()
        .rule(Rule::deny(Target::any(), ReasonCode(99)))
        .build()
        .unwrap();

    let request = Request::new("alice", "read", "doc");

    // Warm-up
    let _ = policy.evaluate(&request);

    reset_alloc_count();
    for _ in 0..1000 {
        let _ = policy.evaluate(&request);
    }
    let count = get_alloc_count();

    assert_eq!(
        count, 0,
        "evaluate() should perform zero allocations, but performed {count}"
    );
}

#[test]
fn test_zero_allocations_no_match_path() {
    // A policy where no rule matches
    let policy = Policy::builder()
        .rule(Rule::allow(
            Target {
                principal: Matcher::Exact("admin"),
                action: Matcher::Any,
                resource: Matcher::Any,
            },
            ReasonCode(1),
        ))
        .build()
        .unwrap();

    let request = Request::new("alice", "read", "doc"); // alice != admin

    // Warm-up
    let _ = policy.evaluate(&request);

    reset_alloc_count();
    for _ in 0..1000 {
        let _ = policy.evaluate(&request);
    }
    let count = get_alloc_count();

    assert_eq!(
        count, 0,
        "evaluate() should perform zero allocations, but performed {count}"
    );
}

#[test]
fn test_zero_allocations_with_condition() {
    // Policy with a condition that requires context lookup
    let policy = Policy::builder()
        .rule(Rule::new(
            Effect::Allow,
            Target::any(),
            Some(Condition::Equals {
                attr: "role",
                value: Value::String("admin"),
            }),
            ReasonCode(1),
        ))
        .build()
        .unwrap();

    let ctx: &[(&str, Value)] = &[("role", Value::String("admin"))];
    let request = Request::with_context("alice", "read", "doc", ctx);

    // Warm-up
    let _ = policy.evaluate(&request);

    reset_alloc_count();
    for _ in 0..1000 {
        let _ = policy.evaluate(&request);
    }
    let count = get_alloc_count();

    assert_eq!(
        count, 0,
        "evaluate() with condition should perform zero allocations, but performed {count}"
    );
}

#[test]
fn test_zero_allocations_max_depth_condition() {
    // Build a max-depth condition tree (left-leaning And chain)
    fn make_deep_and(depth: usize) -> Condition<'static> {
        if depth <= 1 {
            Condition::Equals {
                attr: "x",
                value: Value::Bool(true),
            }
        } else {
            Condition::And(
                Box::new(make_deep_and(depth - 1)),
                Box::new(Condition::True),
            )
        }
    }

    let deep_cond = make_deep_and(10); // Depth 10 is within bounds

    let policy = Policy::builder()
        .rule(Rule::new(
            Effect::Allow,
            Target::any(),
            Some(deep_cond),
            ReasonCode(1),
        ))
        .build()
        .unwrap();

    let ctx: &[(&str, Value)] = &[("x", Value::Bool(true))];
    let request = Request::with_context("alice", "read", "doc", ctx);

    // Warm-up
    let _ = policy.evaluate(&request);

    reset_alloc_count();
    for _ in 0..1000 {
        let _ = policy.evaluate(&request);
    }
    let count = get_alloc_count();

    assert_eq!(
        count, 0,
        "evaluate() with deep condition should perform zero allocations, but performed {count}"
    );
}
