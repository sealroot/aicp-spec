# SIE — Signed Intent Envelope

**AICP Specification**  
**Version:** 0.2  
**Status:** Draft  
**Authors:** Sealroot Contributors

---

## 1. Introduction

A Signed Intent Envelope (SIE) is a self-contained, cryptographically signed request that an AI agent submits when performing an action. It bundles the agent's identity (AIC), authorization (ACT), declared intent, and a cryptographic signature into a single verifiable envelope.

The SIE answers the question: *"Can you prove this specific agent, with this specific authorization, requested this specific action at this specific moment?"*

An SIE is designed for one-time use. Each execution request requires a fresh SIE with a unique nonce.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 2. Envelope Structure

An SIE is a JSON object with the following fields:

### 2.1 SIE Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | REQUIRED | MUST be `"0.2"` |
| `agent_certificate` | object | REQUIRED | The agent's full AIC (see AIC.md). Enables self-contained verification. |
| `capability_token` | string | REQUIRED | The ACT (JWT string) authorizing this action (see ACT.md). |
| `intent` | object | REQUIRED | The declared action the agent intends to perform (see Section 3). |
| `nonce` | string | REQUIRED | Cryptographic nonce. MUST be 32 hexadecimal characters (128-bit random value). MUST be unique per SIE. |
| `timestamp` | string | REQUIRED | Time of SIE creation (ISO 8601 with timezone). |
| `signature` | string | REQUIRED | Agent's Ed25519 signature over the canonical envelope body, base64url-encoded (64 bytes decoded). |
| `reasoning_hash` | string | OPTIONAL | Hash of the agent's reasoning chain. Format: `"sha256:{64-hex-chars}"`. Provides tamper-evident binding to the agent's decision process. |

### 2.2 Intent Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `capability` | string | REQUIRED | The capability being exercised. MUST match the `capability` claim in the ACT. |
| `parameters` | object | REQUIRED | Action-specific parameters. MAY be empty `{}`. |

### 2.3 Example SIE

```json
{
  "version": "0.2",
  "agent_certificate": {
    "type": "AgentIdentityCertificate",
    "version": "0.2",
    "cert_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "agent_id": "f7e6d5c4-b3a2-1098-fedc-ba0987654321",
    "org_id": "11111111-2222-3333-4444-555555555555",
    "agent_name": "payment-processor-agent",
    "public_key": "KLl6vGSr8JzQOk9M1X2pVhNqRtY3wUiEfDcBbA7gHjI",
    "issued_at": "2026-01-15T10:30:00+00:00",
    "expires_at": "2026-01-16T10:30:00+00:00",
    "issuer": "OrgCA:11111111-2222-3333-4444-555555555555",
    "org_ca_cert_id": "99999999-8888-7777-6666-555544443333",
    "org_ca_certificate": { "..." },
    "signature": "mN7kR2xLpQoYvWz1tS3uA5bCdEfGhIjKlMnOpQrStUv...",
    "signing_algorithm": "Ed25519"
  },
  "capability_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3Mi...",
  "intent": {
    "capability": "data:read",
    "parameters": {
      "table": "orders",
      "query": "SELECT * FROM orders WHERE status = 'pending'"
    }
  },
  "nonce": "a3f7c2e91b4d06f8e5a2c7d3b9f01e4a",
  "timestamp": "2026-01-15T14:22:35+00:00",
  "signature": "qR4sT5uV6wX7yZ8aB9cD0eF1gH2iJ3kL4mN5oP6qR7s...",
  "reasoning_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

---

## 3. Envelope Construction

### 3.1 Construction Steps

An agent MUST construct the SIE as follows:

1. **Assemble the envelope body** — include `version`, `agent_certificate`, `capability_token`, `intent`, `nonce`, `timestamp`, and optionally `reasoning_hash`.
2. **Generate nonce** — produce 128 bits of cryptographically secure randomness, encoded as 32 lowercase hex characters.
3. **Set timestamp** — record the current time in ISO 8601 format with timezone.
4. **Canonicalize** — serialize the envelope body (all fields except `signature`) using [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785).
5. **Sign** — compute Ed25519 signature over the canonical bytes using the agent's private key.
6. **Encode** — base64url-encode the 64-byte signature and add as the `signature` field.

### 3.2 Nonce Generation

```
nonce = hex_encode(cryptographic_random_bytes(16))  // 128 bits → 32 hex chars
```

- The nonce MUST be generated using a cryptographically secure random number generator (`secrets.token_hex(16)` in Python, `crypto.randomBytes(16)` in Node.js).
- The nonce MUST NOT be reused across SIEs.
- The nonce MUST be exactly 32 lowercase hexadecimal characters.

### 3.3 Reasoning Hash (Optional)

If the agent tracks its reasoning or decision chain, it MAY include a hash:

```
reasoning_hash = "sha256:" + hex_encode(SHA256(reasoning_text))
```

This provides tamper-evident binding between the agent's decision process and the action it takes. It does not reveal the reasoning content — only a commitment to it.

---

## 4. Signature Generation

### 4.1 Signing Input

The signing input is the JCS-canonicalized JSON of the entire SIE EXCLUDING the `signature` field:

```
fields_to_sign = {
  "version": ...,
  "agent_certificate": ...,
  "capability_token": ...,
  "intent": ...,
  "nonce": ...,
  "timestamp": ...,
  "reasoning_hash": ...  // if present
}

signing_input = JCS_canonicalize(fields_to_sign)
```

### 4.2 Signing Process

```
signature = Ed25519_sign(agent_private_key, signing_input)
sie.signature = base64url_encode(signature)  // 64 bytes → ~86 chars
```

The agent MUST use the same Ed25519 private key that corresponds to the `public_key` in its AIC.

---

## 5. Verification

SIE verification is a multi-step, fail-fast process. The full verification chain is specified in [VERIFICATION.md](VERIFICATION.md). This section covers the SIE-specific steps.

### 5.1 Structural Validation

1. The `version` MUST be `"0.2"`.
2. All REQUIRED fields MUST be present.
3. The `nonce` MUST be exactly 32 hexadecimal characters.
4. If `reasoning_hash` is present, it MUST match the format `"sha256:{64-hex-chars}"`.

### 5.2 Signature Verification

1. Extract the agent's public key from `agent_certificate.public_key`.
2. Reconstruct the signing input: canonicalize all SIE fields EXCEPT `signature`.
3. Verify the Ed25519 signature using the agent's public key.
4. If verification fails, return `deny` with reason `"invalid_signature"`.

### 5.3 Capability Scope Match

1. Extract the `capability` claim from the ACT (JWT payload).
2. Compare with `intent.capability`.
3. If they do not match, return `deny` with reason `"capability_scope_mismatch"`.

### 5.4 Timestamp Freshness

1. Compute the absolute difference between the SIE `timestamp` and the current server time.
2. If the difference exceeds the configured window (default: 60 seconds), return `deny` with reason `"timestamp_expired"`.

```
|now - sie.timestamp| <= TIMESTAMP_WINDOW  // default 60s
```

### 5.5 Nonce Uniqueness

1. Attempt to store the nonce in the cache with a TTL equal to the timestamp window:
   ```
   result = CACHE_SET_IF_NOT_EXISTS("nonce:{nonce}", value="1", ttl=60)
   ```
2. If the nonce already exists (SET returned false), return `deny` with reason `"nonce_replay"`.

---

## 6. Verification Response

The verification endpoint returns a structured response:

### 6.1 Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `result` | string | `"allow"` or `"deny"` |
| `reason` | string or null | Denial reason (null if allowed). See Section 6.2. |
| `verification_id` | string | Unique identifier for this verification (UUID) |
| `latency_ms` | number | Verification latency in milliseconds |
| `risk_score` | number | Advisory risk score (0.0–1.0) |
| `risk_level` | string | `"low"`, `"medium"`, or `"high"` |

### 6.2 Denial Reasons

| Reason | Description |
|--------|-------------|
| `invalid_certificate` | AIC or Org CA certificate is malformed or has invalid structure |
| `invalid_capability_token` | ACT JWT signature is invalid or claims are malformed |
| `capability_expired` | ACT has expired (`now >= exp`) |
| `capability_scope_mismatch` | SIE intent does not match ACT capability |
| `invalid_signature` | SIE signature verification failed |
| `agent_revoked` | Agent is on the Certificate Revocation List |
| `nonce_replay` | Nonce has been seen before within the freshness window |
| `timestamp_expired` | SIE timestamp is outside the acceptable window |
| `token_binding_failed` | ACT's JWK thumbprint does not match the agent's public key |
| `unsupported_version` | SIE version is not supported |
| `unsupported_algorithm` | Signing algorithm is not recognized |
| `missing_jti` | ACT is missing the `jti` claim |
| `token_subject_mismatch` | ACT `sub` does not match AIC `agent_id` |
| `policy_engine_error` | RBAC/ABAC policy evaluation denied the action |
| `invalid_reasoning_hash` | Reasoning hash format is invalid |
| `verification_unavailable` | Internal error during verification |

---

## 7. Audit Trail

Every SIE verification MUST produce an audit record. See [VERIFICATION.md](VERIFICATION.md) for the audit log specification.

The audit record includes:
- `verification_id` — links the response to the audit entry
- `sie_hash` — SHA-256 hash of the canonical SIE (for tamper detection)
- `result` — allow or deny
- `reason` — denial reason if applicable
- `previous_hash` — hash of the previous audit record (hash chain)

---

## 8. Security Considerations

### 8.1 One-Time Use

Each SIE is designed for single use. The nonce ensures that replaying an SIE will be detected and rejected. Agents MUST generate a fresh nonce for every SIE.

### 8.2 Self-Contained Verification

The SIE includes the full AIC (with embedded Org CA certificate) and the ACT. This means verification requires only:
- The Root CA's public key (to verify the Org CA and ACT signatures)
- Access to the CRL (to check revocation status)
- Access to the nonce cache (to detect replay)

No database lookup of the agent or capability is required during verification, enabling <50ms latency.

### 8.3 Envelope Integrity

The agent's signature covers the entire envelope (certificate, token, intent, nonce, timestamp). Any modification to any field will invalidate the signature. This prevents:
- **Intent substitution** — changing the action after signing
- **Token swapping** — substituting a different ACT
- **Identity spoofing** — substituting a different AIC
- **Timestamp manipulation** — backdating or forward-dating the request

### 8.4 Reasoning Hash

The optional `reasoning_hash` creates a binding between the agent's internal decision process and the action. This is useful for:
- **Audit compliance** — proving the agent had a documented reason for the action
- **Forensic analysis** — after an incident, the reasoning can be produced and verified against the hash
- **Accountability** — the agent commits to its reasoning at the time of action, preventing post-hoc rationalization
