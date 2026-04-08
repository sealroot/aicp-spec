# Verification Engine

**AICP Specification**  
**Version:** 0.2  
**Status:** Draft  
**Authors:** Sealroot Contributors

---

## 1. Introduction

This document specifies the 10-step verification process for validating a Signed Intent Envelope (SIE). The verification engine is the core security mechanism of AICP — it determines whether an agent's action request is authorized.

The engine is designed for:
- **Sub-50ms latency** — all checks are optimized for real-time verification.
- **Fail-fast evaluation** — steps execute sequentially; the first failure terminates the process.
- **Deterministic results** — given the same input and state, the result is always the same.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 2. Verification Chain

The verification engine MUST execute the following steps in order. If any step fails, the engine MUST immediately return `deny` with the appropriate reason. No subsequent steps are executed.

```
Step 1:  Certificate Chain Validation     → Proves agent identity is legitimate
Step 2:  Capability Token Validation       → Proves authorization is valid
Step 3:  Capability Scope Matching         → Proves action matches authorization
Step 4:  Token Binding Verification        → Proves token belongs to this agent
Step 5:  SIE Version Check                 → Proves protocol compatibility
Step 6:  SIE Signature Verification        → Proves agent signed this request
Step 7:  Policy Evaluation (RBAC/ABAC)     → Proves organizational policy allows action
Step 8:  Timestamp Freshness               → Proves request is recent
Step 9:  Nonce + Revocation Check          → Proves not replayed, not revoked
Step 10: Risk Scoring (advisory)           → Assesses behavioral anomalies
```

---

## 3. Step Details

### Step 1: Certificate Chain Validation

**Purpose:** Verify the trust chain from Root CA → Org CA → Agent.

**Process:**

1. Extract the `org_ca_certificate` from the AIC.
2. Verify the Org CA certificate:
   a. `type` MUST be `"OrgCACertificate"`.
   b. `version` MUST be `"0.2"`.
   c. `expires_at` MUST be in the future (`now < expires_at`).
   d. Reconstruct the Org CA signing input (exclude `signature`, `signing_algorithm`, `signed_by`).
   e. Canonicalize using JCS.
   f. Verify the Root CA's signature over the canonical bytes.
      - If `signing_algorithm` is `"ECDSA_SHA_256"`: use ECDSA P-256 verification.
      - If `signing_algorithm` is `"ED25519_SHA_512"`: use Ed25519 verification.
3. Verify the AIC:
   a. `type` MUST be `"AgentIdentityCertificate"`.
   b. `version` MUST be `"0.2"`.
   c. `expires_at` MUST be in the future (`now < expires_at`).
   d. `org_ca_cert_id` MUST match `org_ca_certificate.cert_id`.
   e. Reconstruct the AIC signing input (exclude `signature`, `signing_algorithm`).
   f. Canonicalize using JCS.
   g. Verify the Org CA's Ed25519 signature over the canonical bytes.

**Failure reasons:** `invalid_certificate`

### Step 2: Capability Token Validation

**Purpose:** Verify the ACT (JWT) is authentic and not expired.

**Process:**

1. Decode the JWT header. `alg` MUST be `"ES256"` or `"EdDSA"`.
2. Verify the JWT signature using the Root CA's public key.
3. Decode the JWT payload.
4. Verify `exp > now` (not expired).
5. Verify `jti` is present and non-empty.
6. Verify `sub` matches the `agent_id` in the AIC.
7. Verify `org_id` matches the `org_id` in the AIC.

**Failure reasons:** `invalid_capability_token`, `capability_expired`, `missing_jti`, `token_subject_mismatch`

### Step 3: Capability Scope Matching

**Purpose:** Verify the SIE's declared intent matches the ACT's granted capability.

**Process:**

1. Extract `capability` from the ACT payload.
2. Extract `capability` from `sie.intent`.
3. They MUST be equal (exact string match).

**Failure reason:** `capability_scope_mismatch`

### Step 4: Token Binding Verification

**Purpose:** Verify the ACT is bound to this agent's key (proof of possession).

**Process:**

1. Extract the agent's public key from the AIC (`agent_certificate.public_key`).
2. Compute the JWK Thumbprint (see CRYPTO.md Section 8).
3. Extract `cnf.jwk_thumbprint` from the ACT payload.
4. They MUST be equal.

**Failure reason:** `token_binding_failed`

### Step 5: SIE Version Check

**Purpose:** Ensure protocol version compatibility.

**Process:**

1. `sie.version` MUST be `"0.2"`.

**Failure reason:** `unsupported_version`

### Step 6: SIE Signature Verification

**Purpose:** Prove the agent signed this specific envelope.

**Process:**

1. Extract the agent's Ed25519 public key from the AIC.
2. Reconstruct the signing input: all SIE fields EXCEPT `signature`, canonicalized via JCS.
3. Verify the Ed25519 signature.

**Failure reason:** `invalid_signature`

### Step 7: Policy Evaluation (RBAC/ABAC)

**Purpose:** Evaluate organizational access control policies.

**Process:**

1. Query applicable policy rules based on agent, capability, and parameters.
2. Evaluate RBAC rules (role-based): does the agent's role allow this capability?
3. Evaluate ABAC rules (attribute-based): do the request attributes satisfy policy conditions?
4. If no explicit `allow` rule matches, the default is `deny`.

**Policy rule structure:**

```json
{
  "rule_type": "allow" | "deny",
  "target_type": "agent" | "role" | "org",
  "target_id": "<uuid>",
  "capability_pattern": "data:*" | "data:read",
  "conditions": {
    "time_range": { "start": "09:00", "end": "17:00" },
    "ip_range": ["10.0.0.0/8"],
    "parameters": { "table": ["orders", "products"] }
  }
}
```

**Evaluation order:**
1. Explicit `deny` rules are checked first. If any match, return `deny`.
2. Explicit `allow` rules are checked. If any match, proceed.
3. If no rules match, return `deny` (default deny).

**Failure reason:** `policy_engine_error`

### Step 8: Timestamp Freshness

**Purpose:** Prevent use of stale SIEs.

**Process:**

1. Parse the SIE `timestamp` (ISO 8601).
2. Compute `|now - timestamp|`.
3. If the absolute difference exceeds the configured window (default: 60 seconds), deny.

**Configurable:** `SIE_TIMESTAMP_WINDOW_SECONDS` (default: 60)

**Failure reason:** `timestamp_expired`

### Step 9: Nonce Uniqueness + Revocation Check

**Purpose:** Detect replay attacks and revoked agents.

**Process (executed as an atomic pipeline):**

1. **CRL check:** Query the Certificate Revocation List for the `agent_id`.
   ```
   is_revoked = CACHE_MEMBER_CHECK("crl:agents", agent_id)
   ```
   If revoked, return `deny` with `"agent_revoked"`.

2. **Nonce check:** Attempt to store the nonce atomically.
   ```
   is_new = CACHE_SET_IF_NOT_EXISTS("nonce:{nonce}", "1", ttl=NONCE_TTL)
   ```
   If the nonce already exists, return `deny` with `"nonce_replay"`.

**Configurable:** `NONCE_TTL_SECONDS` (default: 60)

**Failure reasons:** `agent_revoked`, `nonce_replay`

### Step 10: Risk Scoring (Advisory)

**Purpose:** Assess behavioral anomalies. This step is advisory — it does NOT block verification.

**Signals:**

| Signal | Computation | Weight |
|--------|------------|--------|
| Deny velocity | `deny_count / total_count` in 5-minute window | 0.4 |
| Request velocity | `request_count > 10` in 5-minute window (anomaly flag) | 0.3 |
| Capability diversity | `distinct_capabilities > 10` in 5-minute window | 0.3 |

**Risk levels:**

| Score Range | Level |
|-------------|-------|
| 0.0 – 0.3 | `low` |
| 0.3 – 0.7 | `medium` |
| 0.7 – 1.0 | `high` |

Risk scoring MUST NOT affect the verification result. It is returned in the response for the consuming application to act on as appropriate.

---

## 4. Audit Trail

### 4.1 Audit Record Structure

Every verification MUST produce an audit record with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Auto-incrementing primary key |
| `previous_hash` | string | SHA-256 hex hash of the previous audit record (hash chain) |
| `agent_id` | string or null | Agent identifier (null if certificate parsing failed) |
| `verification_id` | string | Unique verification identifier (UUID) |
| `result` | string | `"allow"` or `"deny"` |
| `reason` | string or null | Denial reason (null if allowed) |
| `sie_hash` | string | SHA-256 hex hash of the canonical SIE |
| `timestamp` | string | Server timestamp of the verification |
| `record_hash` | string | SHA-256 hex hash of this record (for chain integrity) |

### 4.2 Hash Chain

Each audit record contains the hash of the previous record, forming an append-only hash chain:

```
record_hash = SHA256(id + previous_hash + verification_id + result + reason + sie_hash + timestamp)
next_record.previous_hash = record_hash
```

This ensures:
- **Tamper evidence** — any modification to a record breaks the chain.
- **Ordering** — records have a cryptographic ordering that cannot be reordered.
- **Completeness** — gaps in the chain are detectable.

### 4.3 Write Guarantees

- Audit records MUST be written asynchronously (not blocking the verification response).
- Audit records MUST be INSERT-ONLY — updates and deletes are not permitted.
- Implementations SHOULD use database-level constraints to enforce append-only behavior.

---

## 5. Performance Requirements

| Operation | Target Latency | Notes |
|-----------|---------------|-------|
| Full 10-step verification | < 50ms (p95) | End-to-end, including cache lookups |
| Certificate chain validation | < 5ms | CPU-bound (Ed25519 + ECDSA verification) |
| JWT validation | < 3ms | CPU-bound (signature verification) |
| Nonce + CRL check | < 5ms | Network-bound (Redis pipeline) |
| Policy evaluation | < 10ms | Depends on rule complexity |
| Risk scoring | < 5ms | Redis-backed counters |
| Audit write | Async | Not on critical path |

### 5.1 Optimization Strategies

- **Cache Root CA public key** in memory — avoid KMS call per verification.
- **Use Redis pipeline** for nonce + CRL check — single round trip.
- **Pre-warm** CRL on startup — load from database into Redis.
- **Connection pooling** for database and cache connections.
- **Short-circuit** on first failure — do not execute remaining steps.

---

## 6. Error Handling

### 6.1 Internal Errors

If the verification engine encounters an internal error (database unavailable, cache timeout, unexpected exception), it MUST:

1. Return `deny` with reason `"verification_unavailable"`.
2. Log the error for operational alerting.
3. NOT return `allow` under any error condition.

### 6.2 Malformed Input

If the SIE is structurally invalid (missing fields, wrong types, unparseable JSON), the engine MUST return `deny` with the most specific applicable reason.

### 6.3 Principle: Fail Closed

The verification engine operates on a fail-closed principle. Any ambiguity, error, or unexpected condition results in `deny`. There is no "soft fail" or "warn" mode in production.
