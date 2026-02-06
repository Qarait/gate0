# ADR 001: Adoption of GateBridge for Policy Migration

## Status
Accepted

## Context
The Ephemera project required a transition from its legacy YAML-based policy engine to the high-assurance Gate0 Rust engine. A direct cutover posed an unacceptable risk of authentication outages and security regressions. We needed a period of validation where real production traffic could be evaluated against the new engine without making it the authority.

## Decision
We implemented a specialized adapter layer called **GateBridge** to facilitate a "Shadow Mode" evaluation strategy. 

Instead of embedding Gate0 directly into the Python host, GateBridge operates as a standalone Rust CLI that:
1. Translates legacy YAML policies into Gate0 intermediate representation.
2. Normalizes complex Python-side attributes (Regex, CIDR) into boolean primitives.
3. Performs dual-evaluation of every request, comparing the legacy decision against the Gate0 decision.

## Consequences
- **Complexity**: We now maintain two evaluation paths (Reference and Gate0) and a translation layer.
- **Latency**: Evaluation overhead increased by ~10ms due to the subprocess boundary.
- **Reliability**: We achieved a zero-risk migration path. Shadow mismatches are logged for analysis without affecting user access.
- **Verification**: We unlocked the ability to run differential fuzzing between the legacy semantics and the new engine.
