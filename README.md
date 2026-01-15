# gate0

A small, auditable, terminating, deterministic micro-policy engine.

## Guarantees

- **Termination**: Bounded rules, bounded condition depth, bounded context
- **Determinism**: Ordered evaluation, stable conflict resolution
- **No panics**: All operations return `Result`
- **Zero dependencies**: Pure `std` only

## Non-goals

- Policy language / DSL
- Serialization (add `serde` yourself if needed)
- Dynamic policy reloading
- Performance optimization

## Example

```rust
use gate0::{Policy, Rule, Target, Request, ReasonCode};

let policy = Policy::builder()
    .rule(Rule::allow(Target::any(), ReasonCode(1)))
    .build()?;

let decision = policy.evaluate(&Request::new("alice", "read", "doc"))?;
assert!(decision.is_allow());
```

## License

MIT
