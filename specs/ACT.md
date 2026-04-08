# ACT — Agent Capability Token

**AICP Specification**  
**Version:** 0.2  
**Status:** Draft  
**Authors:** Sealroot Contributors

---

## 1. Introduction

An Agent Capability Token (ACT) is a scoped, time-bound authorization credential issued to an AI agent. It answers the question: *"What is this agent allowed to do, and until when?"*

An ACT is implemented as a JSON Web Token (JWT) signed by the platform Root CA. It encodes a specific capability (e.g., `"data:read"`, `"payment:execute"`), optional scoping parameters, and a cryptographic binding to the agent's public key via JWK Thumbprint.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

### 1.2 References

- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) — JSON Web Token (JWT)
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) — JSON Web Signature (JWS)
- [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) — JSON Web Key (JWK) Thumbprint
- [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) — CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE (Ed25519/Ed448)

---

## 2. Token Structure

An ACT is a standard JWT consisting of three base64url-encoded segments: `{header}.{payload}.{signature}`.

### 2.1 JWT Header

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `alg` | string | REQUIRED | Signing algorithm. MUST be `"ES256"` (for ECDSA P-256) or `"EdDSA"` (for Ed25519). |
| `typ` | string | REQUIRED | MUST be `"JWT"` |

The algorithm is determined by the Root CA's key type:
- Root CA key `ECC_NIST_P256` → `alg: "ES256"`
- Root CA key `Ed25519` → `alg: "EdDSA"`

### 2.2 JWT Payload (Claims)

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | string | REQUIRED | Issuer. MUST be `"aia"` |
| `sub` | string | REQUIRED | Subject. MUST be the `agent_id` (UUID) |
| `org_id` | string | REQUIRED | Organization identifier (UUID) |
| `capability` | string | REQUIRED | The capability being granted. 1–255 characters. SHOULD use a namespaced format (e.g., `"data:read"`, `"payment:execute"`, `"code:deploy"`) |
| `parameters` | object | REQUIRED | Scoping parameters for the capability. MAY be empty `{}`. Used to restrict the capability to specific resources, conditions, or boundaries. |
| `iat` | number | REQUIRED | Issued-at timestamp (Unix seconds) |
| `exp` | number | REQUIRED | Expiration timestamp (Unix seconds). MUST be greater than `iat`. |
| `jti` | string | REQUIRED | Unique token identifier (UUID). Used for revocation and replay detection. |
| `cnf` | object | REQUIRED | Confirmation claim per [RFC 7800](https://www.rfc-editor.org/rfc/rfc7800). Contains `jwk_thumbprint`. |
| `cnf.jwk_thumbprint` | string | REQUIRED | JWK Thumbprint ([RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)) of the agent's Ed25519 public key. Binds this token to a specific agent key. |

### 2.3 Example ACT Payload

```json
{
  "iss": "aia",
  "sub": "f7e6d5c4-b3a2-1098-fedc-ba0987654321",
  "org_id": "11111111-2222-3333-4444-555555555555",
  "capability": "data:read",
  "parameters": {
    "table": "orders",
    "max_rows": 1000
  },
  "iat": 1768464600,
  "exp": 1768468200,
  "jti": "c0d1e2f3-a4b5-6789-0123-456789abcdef",
  "cnf": {
    "jwk_thumbprint": "Rt5FmKQz_2Y8qL7pNvXwZ1sO3gHtUiEaBcDeFgHiJk0"
  }
}
```

### 2.4 Full JWT Example

```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhaWEiLCJzdWIiOi...
```

---

## 3. Token Binding (Proof of Possession)

### 3.1 JWK Thumbprint Computation

The `cnf.jwk_thumbprint` binds the ACT to a specific agent key. This ensures that only the agent holding the corresponding private key can use this token.

Computation follows [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638):

1. Construct the JWK representation of the agent's Ed25519 public key:
   ```json
   {
     "crv": "Ed25519",
     "kty": "OKP",
     "x": "<base64url-encoded-public-key>"
   }
   ```
2. Serialize the JWK using the required members in lexicographic order: `crv`, `kty`, `x`.
3. Compute SHA-256 over the serialized bytes.
4. Base64url-encode the hash (no padding).

### 3.2 Verification of Token Binding

During SIE verification, the verifier MUST:

1. Extract the agent's public key from the AIC.
2. Compute the JWK Thumbprint of that public key.
3. Compare the computed thumbprint with the `cnf.jwk_thumbprint` claim in the ACT.
4. If they do not match, verification MUST return `deny` with reason `"token_binding_failed"`.

This prevents token theft — a stolen ACT is useless without the corresponding agent private key.

---

## 4. Capability Naming

### 4.1 Format

Capabilities SHOULD follow a namespaced convention:

```
{domain}:{action}
```

Examples:
- `data:read` — Read data from a data source
- `data:write` — Write data to a data source
- `payment:execute` — Execute a payment transaction
- `code:deploy` — Deploy code to a target environment
- `email:send` — Send email on behalf of a user
- `api:invoke` — Invoke an external API

### 4.2 Parameters

The `parameters` object provides fine-grained scoping. Its structure is capability-specific:

```json
// data:read — restrict to a specific table
{ "table": "orders", "max_rows": 1000 }

// payment:execute — restrict amount and currency
{ "max_amount": 500.00, "currency": "USD", "merchant_id": "acme-corp" }

// api:invoke — restrict to specific endpoints
{ "endpoint": "/api/v1/users", "methods": ["GET"] }
```

### 4.3 Scope Matching

During verification, the verifier checks that the SIE's declared intent matches the ACT's capability:

```
sie.intent.capability == act_claims.capability
```

If they do not match, verification MUST return `deny` with reason `"capability_scope_mismatch"`.

Parameter matching is handled by the policy engine (see VERIFICATION.md).

---

## 5. Token Issuance

### 5.1 Issuance Flow

1. The client sends a request with `agent_id`, `capability_name`, `parameters`, and `validity_seconds`.
2. The platform verifies that the agent exists, is active, and belongs to the requesting organization.
3. The platform generates a unique `jti` (UUID).
4. The platform computes the JWK Thumbprint of the agent's public key (stored during registration).
5. The platform constructs the JWT claims.
6. The Root CA signs the JWT via KMS.
7. The signed JWT is returned to the client.

### 5.2 Validity Constraints

- Maximum validity: 3600 seconds (1 hour)
- Implementations SHOULD use the shortest practical validity.
- An expired ACT MUST be rejected during verification.
- There is no minimum validity, but tokens with less than 5 seconds of validity are not useful.

### 5.3 Multiple Capabilities

Each ACT grants exactly ONE capability. To grant multiple capabilities to an agent, issue multiple ACTs. This enforces the principle of least privilege — each action requires its own scoped authorization.

---

## 6. Token Revocation

### 6.1 Revocation Mechanisms

An ACT can be invalidated through:

1. **Expiration** — The token naturally expires at `exp`. No action needed.
2. **Agent revocation** — Revoking the agent invalidates all its ACTs (the agent is added to the CRL).
3. **Capability revocation** — Individual capabilities can be revoked by `jti`.

### 6.2 CRL Check

During verification, the verifier checks:

1. The agent (`sub`) is not in the agent CRL.
2. The token (`jti`) is not in the capability revocation list.

If either check fails, verification MUST return `deny`.

### 6.3 Revocation Propagation

- Revocation MUST propagate to the CRL within 10ms.
- The CRL SHOULD be maintained in a distributed real-time cache.
- Revocation is permanent — a revoked token cannot be un-revoked.

---

## 7. Security Considerations

### 7.1 Root CA Signing

The ACT is signed by the Root CA (not the Org CA or agent). This means:
- Only the platform can issue valid ACTs.
- Organizations cannot forge capability tokens.
- Token validity can be verified using only the Root CA's public key.

### 7.2 Token Theft Mitigation

The `cnf.jwk_thumbprint` claim binds the ACT to a specific agent key. Even if an ACT is intercepted:
- The attacker cannot use it without the agent's Ed25519 private key.
- The verifier will reject any SIE where the signing key doesn't match the thumbprint.

### 7.3 Replay Prevention

ACTs are protected against replay by:
- **Expiration** — Short-lived tokens (max 1 hour) limit the replay window.
- **JTI uniqueness** — Each token has a unique identifier for revocation tracking.
- **SIE nonce** — Each use of an ACT in an SIE requires a fresh nonce (see SIE.md).

### 7.4 Scope Inflation

Implementations MUST NOT allow wildcard or overly broad capabilities. Capabilities SHOULD be:
- Specific to a single action type.
- Scoped with parameters to the minimum necessary resources.
- Time-bound to the minimum necessary duration.
