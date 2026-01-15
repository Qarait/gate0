# gate0

A small, auditable, terminating, deterministic micro-policy engine.

## Security Model

Gate0 is designed for high-assurance environments where policy evaluation must be deterministic and resource-bounded. See [SECURITY.md](SECURITY.md) for the full threat model, system invariants, and mechanical guarantees.

## Architecture

Gate0 uses a linear, **Deny-Overrides** evaluation strategy. Each rule consists of a **Target** (fast-path match) and an optional **Condition** (deep logic).

```mermaid
graph TD
    REQ([Request]) ==> POL
    
    subgraph POL [Policy: Ordered Rules]
        direction TB
        R1[Rule 1: Deny]
        R2[Rule 2: Allow]
        R3[Rule 3: Allow]
    end

    POL ==> MATCH{Match?}
    
    subgraph EVAL [Evaluation Logic]
        direction LR
        MATCH -- "Target + Condition" --> DECIDE
        DECIDE{Effect?}
        DECIDE -- "Deny" --> D_WIN[Deny Wins]
        DECIDE -- "Allow" --> A_PEND[Allow Pending]
    end

    D_WIN ==> FIN([Final Decision])
    A_PEND -- "Next Rule" --> MATCH
    MATCH -- "No more rules" --> NO_M
    NO_M[No Match] ==> D_DEF[Default Deny]
    D_DEF ==> FIN
```

## Verification

The correctness and safety of Gate0 are mechanically verified:

- **Unit Tests**: Full coverage of core logic and edge cases.
- **Property-Based Testing**: Hundreds of adversarial scenarios generated via `proptest`.
- **Undefined Behavior Check**: Verified panic-free and UB-free using `cargo miri`.
- **Bounded Evaluation**: Worst-case inputs are tested to ensure termination.

```bash
cargo test
cargo +nightly miri test --lib
```

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

- **SaaS API**: Standard RBAC/Multi-tenancy logic.
- **Zero Trust Network**: Attribute-Based Access Control (ABAC) with MFA and location checks.
- **Complex Overrides**: Demonstrating Deny-Overrides conflict resolution.

Run them with:
```bash
cargo run --example saas_api
cargo run --example zero_trust_network
cargo run --example complex_overrides
```

## License

MIT
