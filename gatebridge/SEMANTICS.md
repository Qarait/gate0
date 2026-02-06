# GateBridge Policy Semantics

**Version:** 0.1 (unstable)  
**Status:** Phase 1 — Shadow Evaluation Only

This document defines the semantics of Ephemera's YAML policy language as interpreted by GateBridge. The reference evaluator and Gate0 translation must both conform to this specification.

> **Warning:** This is an unstable specification. Semantics may change based on real-world validation feedback.

---

## Scope and Non-Goals

**In scope:**
- Ephemera YAML policy translation to Gate0
- Shadow evaluation for validation
- Mismatch detection and logging

**Non-goals (Phase 1):**
- Production authorization (shadow mode only)
- Generic policy schema support
- Native FFI bindings (CLI subprocess only)
- Real-time policy reloading

---

## Policy Structure

A policy file contains a `default` block and a list of `policies`.

```yaml
default:
  principals: ["sandbox"]
  max_duration: "15m"

policies:
  - name: "PolicyName"
    match:
      oidc_groups: ["group1"]
    principals: ["root"]
    max_duration: "60m"
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `default` | Yes | Fallback when no policy matches |
| `default.principals` | Yes | SSH principals for default case |
| `default.max_duration` | Yes | Max certificate validity |
| `policies` | No | List of policy entries (can be empty) |
| `policies[].name` | Yes | Policy identifier |
| `policies[].match` | No | Match conditions (if absent, matches all) |
| `policies[].principals` | Yes | SSH principals if matched |
| `policies[].max_duration` | Yes | Max certificate validity |

---

## Evaluation Order

Policies are evaluated in **declaration order**. The first matching policy wins.

```
for each policy in policies:
    if matches(policy, request):
        return policy
return default
```

If no policy matches, the `default` block is used.

---

## Match Semantics

Matching uses a **two-phase approach**: OR triggers followed by AND filters.

### Phase 1: OR Triggers

At least one of these must match to proceed:

| Field | Match Type | Behavior |
|-------|------------|----------|
| `oidc_groups` | Set intersection | Any policy group in request groups |
| `emails` | fnmatch wildcard | Any pattern matches request email |
| `local_usernames` | fnmatch wildcard | Any pattern matches request username |

If **no triggers are specified**, the policy matches all requests (subject to AND filters).

If triggers are specified but **none match**, the policy is skipped entirely.

### Phase 2: AND Filters

If an OR trigger matched (or no triggers were specified), all specified AND filters must pass:

| Field | Match Type | Behavior |
|-------|------------|----------|
| `source_ip` | Simplified CIDR | See CIDR Matching below |
| `hours` | Time range | See Time Range Matching below |
| `webauthn_ids` | Exact match | Request value in list |

If **any AND filter fails**, the policy is skipped.

If a filter is **not specified**, it passes by default.

---

## Matching Functions

### fnmatch (Wildcard Matching)

Used for `emails` and `local_usernames`.

| Pattern | Meaning |
|---------|---------|
| `*` | Matches zero or more characters |
| `?` | Matches exactly one character |
| other | Matches literally (case-sensitive) |

**Examples:**
- `*@example.com` matches `user@example.com`
- `admin*` matches `administrator`
- `user?` matches `user1` but not `user12`

**Edge cases:**
- If request value is `null`/missing → no match
- Empty pattern list → no match
- Matching is case-sensitive

### CIDR Matching (Simplified)

> **Warning:** Current implementation uses simplified prefix matching, not proper CIDR bit-mask parsing. This is a known limitation.

Current behavior:
- Extract IP prefix (before `/`)
- Split by `.` into octets
- Compare octets left-to-right
- Octet `0` is treated as wildcard

**Example:** `10.0.0.0/8` matches `10.1.2.3` (first octet matches, rest are `0` wildcards)

**Edge cases:**
- If request IP is `null`/missing → no match
- Empty CIDR list → filter passes (not specified)

### Time Range Matching

Format: `HH:MM-HH:MM` (24-hour format)

Comparison is **lexicographic string comparison** on `HH:MM` format.

**Example:** `09:00-18:00` matches if `current_time >= "09:00" && current_time <= "18:00"`

**Edge cases:**
- If request time is `null`/missing → no match
- Overnight ranges (e.g., `22:00-06:00`) are **not supported** — will fail
- Empty hours list → filter passes (not specified)

### Exact Matching

Used for `webauthn_ids`.

Request value must exactly equal one of the listed values (case-sensitive).

**Edge cases:**
- If request value is `null`/missing → no match
- Empty list → filter passes (not specified)

---

## Field Access Semantics

When a field is missing from the request:
- The condition evaluates to **false**
- No error is raised
- Evaluation continues to next policy

This makes policy evaluation **total** (always produces a result, never crashes).

---

## Gate0 Mapping

### ReasonCode Semantics

> **Warning:** ReasonCode mapping is unstable. Do not rely on specific values across policy file edits.

Each Ephemera policy maps to a Gate0 rule with `ReasonCode` = policy index:

| Policy | ReasonCode |
|--------|------------|
| `policies[0]` | `ReasonCode(0)` |
| `policies[1]` | `ReasonCode(1)` |
| ... | ... |
| default | `ReasonCode(u32::MAX - 1)` |

When Gate0 returns `Allow + ReasonCode(i)`, the caller looks up `policies[i]` to retrieve principals and max_duration.

### Adapter Pattern

Gate0 does not implement fnmatch, CIDR, or time matching natively. Complex matching is **pre-computed by the adapter** into boolean context attributes:

| Attribute | Meaning |
|-----------|---------|
| `trigger_matched` | At least one OR trigger matched |
| `source_ip_allowed` | CIDR check passed |
| `within_hours` | Time range check passed |
| `webauthn_verified` | WebAuthn ID matched |

Gate0 evaluates these booleans. This keeps Gate0 pure and bounded.

---

## Shadow Evaluation

Shadow mode runs both evaluators and compares results:

```
reference_decision = reference_evaluate(policy, request)
gate0_decision = gate0_evaluate(policy, request)

if reference_decision.policy_index != gate0_decision.reason_code:
    log_mismatch()
```

### Match Definition

Decisions match if:
- `reference_decision.policy_index == gate0_decision.reason_code`

Effect is not currently compared (both are "allow" in grant model).

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Decisions match |
| 1 | Decisions mismatch |
| 2 | Error (parse failure, evaluation error) |

---

## Error Model

### Load-Time Errors (Hard Fail)

These abort policy loading:
- Invalid YAML structure
- Missing required fields (`default`, `principals`, `max_duration`)
- Unknown/malformed field values

### Runtime Errors (Soft Fail)

These evaluate to `false`, not error:
- Missing request fields
- Type mismatches
- Values not in expected format

Runtime errors never abort evaluation. Policy evaluation is total.

---

## Phase 1 Constraints

These constraints apply during shadow-mode validation:

1. **CLI subprocess only** — Python calls `gatebridge shadow` via subprocess, not FFI
2. **No production cutover** — Shadow results are logged, not used for authorization
3. **CIDR matching is simplified** — Not proper bit-mask parsing
4. **Overnight time ranges unsupported** — Will produce incorrect results
5. **ReasonCode mapping is unstable** — Will change if policies are reordered

---

## Determinism Guarantees

For identical policy file and request:
- Same decision every time
- Same ReasonCode every time
- No randomness
- No time-dependent behavior (except explicit `hours` field)
- No external I/O during evaluation

This is required for reproducible shadow evaluation.
