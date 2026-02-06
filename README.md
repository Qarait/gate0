# gate0

[![CI](https://github.com/Qarait/gate0/actions/workflows/ci.yml/badge.svg)](https://github.com/Qarait/gate0/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A small, auditable, terminating, deterministic micro-policy engine.

## Why Gate0?

I built Gate0 because I was tired of debugging RegEx-based policies in production. I wanted something that was boring, bounded, and impossible to crash. If you want a flexible, general-purpose policy engine, you should use OPA. If you want a policy engine that guarantees sub-50µs execution and zero allocations for security-critical pathways, you want Gate0.

## Security Model

Gate0 is designed for high-assurance environments where policy evaluation must be deterministic and resource-bounded. See the [Security Policy](SECURITY.md) for reporting vulnerabilities and the [Security Model](docs/SECURITY_MODEL.md) for the full threat model and mechanical guarantees.

## Architecture

Gate0 uses a linear, **Deny-Overrides** evaluation strategy. Each rule consists of a **Target** (fast-path match) and an optional **Condition** (deep logic).

```text
+----------+       +-------------+       +--------+
| Ephemera | ----> | GateBridge  | ----> | Gate0  |
| (Legacy) |       | (Normalize) |       | (Core) |
+----------+       +-------------+       +--------+
     |                    ^
     |                    |
     +----(Shadow Log)----+
```

## Verification

The correctness and safety of Gate0 are mechanically verified through unit tests covering core logic and edge cases, property-based testing via proptest with hundreds of generated scenarios, and MIRI verification for panic-free and UB-free operation. Worst-case inputs are tested to ensure bounded termination.

```bash
cargo test
cargo +nightly miri test --lib
```

## Safety and Cost Model

Gate0's evaluator uses fixed-size, stack-allocated buffers to guarantee zero heap allocations during evaluation. The default implementation uses `MaybeUninit` to avoid initializing unused slots, resulting in O(used) initialization cost rather than O(capacity).

The unsafe code is confined to a single module (`fixed_stack.rs`) with straightforward invariants: elements 0..len are initialized, elements len..N are not. All unsafe paths are verified with MIRI.

For users who prefer zero unsafe code, Gate0 provides `SafeFixedStack` behind the `safe-stack` feature flag. This variant uses `[T; N]` with `T: Default + Copy` and initializes all slots upfront. The tradeoff is O(capacity) initialization on every evaluation call.

```bash
cargo build --features safe-stack
```

Both implementations provide identical semantics and the same zero-allocation guarantee during evaluation. The choice is between performance (O(used)) and absolute safety (O(capacity)). For small stacks with cheap Default types like bool, the difference is negligible.

## Integration Architecture

Gate0 is designed to function as a Policy Decision Point (PDP) within a larger host application. To maintain determinism and strict bounds, Gate0 does not handle I/O, networking, or object lifecycles.

The recommended integration pattern separates concerns across three layers. The host application (API gateway, SSH server, etc.) manages state, identity, and side effects. An adapter layer normalizes this complex state into primitives that Gate0 understands (strings, bools, ints). Gate0 evaluates the flattened context purely and returns a Decision.

```
Host Application (User Request)
        │
        ▼
  [Adapter Layer]  →  Pre-computes context (time, IP ranges, MFA status)
        │              Converts "complex" to "primitive"
        ▼
  [Gate0 Engine]   →  Pure evaluation (0 allocations, bounded stack)
        │
        ▼
  Decision::Allow / Deny
```

This separation explains why Gate0 does not include complex matchers like IP range checks or regex. The adapter layer handles domain-specific logic and presents Gate0 with pre-computed boolean or string attributes. Gate0 stays small, auditable, and deterministic.

## Example

```rust
use gate0::{Policy, Rule, Target, Request, ReasonCode};

let policy = Policy::builder()
    .rule(Rule::allow(Target::any(), ReasonCode(1)))
    .build()?;

let decision = policy.evaluate(&Request::new("alice", "read", "doc"))?;
assert!(decision.is_allow());
```

## Examples

The `examples/` directory contains illustrative scenarios demonstrating common Gate0 usage patterns:

**SaaS API**: Standard RBAC/Multi-tenancy logic.
**Zero Trust Network**: Attribute-Based Access Control (ABAC) with MFA and location checks.
**Complex Overrides**: Demonstrating Deny-Overrides conflict resolution.

Run them with:
```bash
cargo run --example saas_api
cargo run --example zero_trust_network
cargo run --example complex_overrides
```

## Limitations
 
Gate0 is intentionally constrained to remain predictable and performant. 
 
**No Complex Matchers**: Logic like full Bit-Mask CIDR or advanced Regex remains the responsibility of the adapter layer. Gate0 evaluates pre-processed primitives.
 
**No Native Multithreading**: The current FFI implementation for Python is not thread-safe. High-concurrency users should use multiprocessing or wait for the Phase 4 FFI stabilization which will address global locks.
 
**No Overlapping Decisions**: Within a single effect class (Allow/Deny), only the first matching rule is returned. Conflict resolution is strictly order-dependent.

## Community Extensions

The following projects extend the Gate0 engine for specialized use cases.

**gate0_dsl**: A Rust-native Domain Specific Language for Gate0 developed by **hardliner66**. It leverages Rust macros to provide a clean and readable syntax for defining policies directly in code. You can find the implementation and documentation at [hardliner66/gate0_dsl](https://github.com/hardliner66/gate0_dsl).

## License

MIT
