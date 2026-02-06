# Ephemera + Gate0 Integration Status

## Goal

Transition Ephemera from legacy YAML-based policy evaluation to the high-assurance **Gate0** Rust engine without risking production downtime or certificate issuance outages.

## Architecture: The GateBridge Sidecar

We have implemented **GateBridge**, a specialized standalone tool that acts as the validation bridge between Ephemera and Gate0.

```
Ephemera (Python/Legacy)
    │
    ├── Authoritative Decision (YAML)
    │
    └── GateBridge Sidecar (Rust)
            │
            ├── Translate: YAML -> Gate0
            ├── Evaluate:  Gate0 Shadow Result
            └── Audit:     Differential Analysis
```

## The Shadow Strategy

Current operational status is **OBSERVATION_MODE**. Ephemera continues to use the legacy engine for authority while invoking GateBridge for shadow evaluation.

### 1. Dual-Evaluation
Every certificate request is processed by both engines. The decisions are compared, and any mismatches are logged to `policy-shadow.log`.

### 2. Forensic Analysis
If a mismatch occurs, we use the following toolchain:
- `gatebridge explain`: Provides a step-by-step breakdown of why a policy matched or failed.
- `analyze_shadow.py`: Automatically clusters mismatches to identify "Safety Wins" (Gate0 is stricter) versus "Security Drifts" (Gate0 is buggy).

## Progress & Pedigree

- **Phase 1-3 (Hardening)**: Complete.
- **Differential Fuzzing**: Passed 100,000 iterations with 0 implementation mismatches.
- **Documentation**: ADRs for the shadow mode decision and security models are live in `docs/`.
- **Ecosystem**: Community extensions (like hardliner66's DSL) are integrated for future native development.

## 7-Day Observation Success Criteria

We are currently in a 7-day observation window. Success is defined by:
1. **0 Critical Drifts**: No instances where the legacy engine denied but Gate0 allowed.
2. **Pedigree Verification**: Confirmation of semantic convergence against live production traffic.

## Next Steps

1. **Monitor Logs**: Perform daily analysis using `./scripts/analyze_shadow.py`.
2. **Phase 4 (Native FFI)**: Once 100% agreement is proven, implement PyO3 bindings to replace the subprocess call with a zero-allocation library call.
3. **Phase 5 (Cutover)**: Deprecate the legacy YAML engine and make Gate0 the authoritative decision point.
