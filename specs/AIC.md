# AIC — Agent Identity Certificate

**AICP Specification**  
**Version:** 0.2  
**Status:** Draft  
**Authors:** Sealroot Contributors

---

## 1. Introduction

An Agent Identity Certificate (AIC) is a cryptographically signed document that binds an AI agent's public key to its identity within an organization. The AIC serves as the foundational identity primitive in AICP — it answers the question: *"Who is this agent, and who vouches for it?"*

An AIC is issued by an Organization CA (Org CA), which is itself certified by the platform Root CA. This creates a three-level trust chain: Root CA → Org CA → Agent.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

### 1.2 Notation

- All JSON examples use [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785) canonical form for signing purposes.
- Base64url encoding follows [RFC 4648 Section 5](https://www.rfc-editor.org/rfc/rfc4648#section-5), without padding.
- Timestamps follow [ISO 8601](https://www.iso.org/iso-8601-date-and-time-format.html) with timezone designator.

---

## 2. Certificate Structure

An AIC is a JSON object with the following fields:

### 2.1 AIC Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | REQUIRED | MUST be `"AgentIdentityCertificate"` |
| `version` | string | REQUIRED | MUST be `"0.2"` |
| `cert_id` | string | REQUIRED | Unique certificate identifier (UUID) |
| `agent_id` | string | REQUIRED | Unique agent identifier (UUID) |
| `org_id` | string | REQUIRED | Organization identifier (UUID) |
| `agent_name` | string | REQUIRED | Human-readable agent name. MUST be 1–255 ASCII characters. MUST be unique within the organization. |
| `public_key` | string | REQUIRED | Agent's Ed25519 public key, base64url-encoded (32 bytes decoded) |
| `issued_at` | string | REQUIRED | Certificate issuance timestamp (ISO 8601 with timezone) |
| `expires_at` | string | REQUIRED | Certificate expiration timestamp (ISO 8601 with timezone) |
| `issuer` | string | REQUIRED | Issuer identifier. MUST be formatted as `"OrgCA:{org_id}"` |
| `org_ca_cert_id` | string | REQUIRED | The `cert_id` of the Org CA certificate that signed this AIC |
| `org_ca_certificate` | object | REQUIRED | The full Org CA certificate (see Section 3) |
| `signature` | string | REQUIRED | Org CA's Ed25519 signature over the canonical certificate body, base64url-encoded (64 bytes decoded) |
| `signing_algorithm` | string | REQUIRED | MUST be `"Ed25519"` |

### 2.2 Example AIC

```json
{
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
  "org_ca_certificate": { "...see Section 3..." },
  "signature": "mN7kR2xLpQoYvWz1tS3uA5bCdEfGhIjKlMnOpQrStUv...",
  "signing_algorithm": "Ed25519"
}
```

---

## 3. Org CA Certificate Structure

Each organization has an Org CA that is authorized by the Root CA to issue AICs. The Org CA certificate is embedded in every AIC to enable self-contained verification.

### 3.1 Org CA Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | REQUIRED | MUST be `"OrgCACertificate"` |
| `version` | string | REQUIRED | MUST be `"0.2"` |
| `cert_id` | string | REQUIRED | Unique certificate identifier (UUID) |
| `org_id` | string | REQUIRED | Organization identifier (UUID) |
| `public_key` | string | REQUIRED | Org CA's Ed25519 public key, base64url-encoded (32 bytes decoded) |
| `issued_at` | string | REQUIRED | Certificate issuance timestamp (ISO 8601 with timezone) |
| `expires_at` | string | REQUIRED | Certificate expiration timestamp (ISO 8601 with timezone) |
| `issuer` | string | REQUIRED | MUST be `"AIA Root CA"` |
| `signature` | string | REQUIRED | Root CA's signature over the canonical certificate body, base64url-encoded |
| `signing_algorithm` | string | REQUIRED | MUST be one of: `"ECDSA_SHA_256"`, `"ED25519_SHA_512"` |
| `signed_by` | string | REQUIRED | MUST be `"kms:root_ca"` |

### 3.2 Example Org CA Certificate

```json
{
  "type": "OrgCACertificate",
  "version": "0.2",
  "cert_id": "99999999-8888-7777-6666-555544443333",
  "org_id": "11111111-2222-3333-4444-555555555555",
  "public_key": "xYzAbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD",
  "issued_at": "2026-01-01T00:00:00+00:00",
  "expires_at": "2027-01-01T00:00:00+00:00",
  "issuer": "AIA Root CA",
  "signature": "MEUCIQDk3p9f...",
  "signing_algorithm": "ECDSA_SHA_256",
  "signed_by": "kms:root_ca"
}
```

---

## 4. Certificate Issuance

### 4.1 Agent Registration Flow

1. The client sends a registration request to the platform with `agent_name` and optional `validity_hours`.
2. The platform generates a fresh Ed25519 keypair for the agent.
3. The platform constructs the AIC body (all fields except `signature` and `signing_algorithm`).
4. The body is canonicalized using [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785).
5. The Org CA signs the canonical bytes using its Ed25519 private key.
6. The signature is base64url-encoded and added to the certificate.
7. The certificate, public key, and private key are returned to the client.
8. The private key MUST NOT be stored by the platform after this response.

### 4.2 Validity Constraints

- Default validity: 24 hours
- Maximum validity: 168 hours (7 days)
- Implementations SHOULD use short-lived certificates and rotate regularly.
- An expired AIC MUST be rejected during verification.

### 4.3 Agent Name Constraints

- MUST be 1–255 characters
- MUST be ASCII-only
- MUST be unique within the organization
- SHOULD be descriptive of the agent's purpose (e.g., `"payment-processor"`, `"data-analyst"`)

---

## 5. Signature Generation

### 5.1 Canonical Form

To produce the signing input:

1. Construct a JSON object containing ALL AIC fields EXCEPT `signature` and `signing_algorithm`.
2. Canonicalize this object using RFC 8785 JCS.
3. The result is a deterministic byte sequence.

### 5.2 Signing Process

```
signing_input = JCS_canonicalize(aic_body_without_signature_fields)
signature = Ed25519_sign(org_ca_private_key, signing_input)
aic.signature = base64url_encode(signature)  // 64 bytes → ~86 chars
aic.signing_algorithm = "Ed25519"
```

### 5.3 Org CA Certificate Signing

The Org CA certificate is signed by the Root CA using KMS:

```
signing_input = JCS_canonicalize(org_ca_body_without_signature_fields)
signature = KMS_sign(root_ca_key, signing_input)  // ECDSA_SHA_256 or ED25519_SHA_512
org_ca.signature = base64url_encode(signature)
```

---

## 6. Certificate Verification

To verify an AIC, a verifier MUST perform the following steps in order. If any step fails, the certificate MUST be rejected.

### 6.1 Structural Validation

1. The `type` field MUST be `"AgentIdentityCertificate"`.
2. The `version` field MUST be a supported version (`"0.2"`).
3. All REQUIRED fields MUST be present and non-empty.
4. The `signing_algorithm` MUST be `"Ed25519"`.

### 6.2 Org CA Chain Validation

1. Extract the embedded `org_ca_certificate`.
2. Verify the Org CA's `type` is `"OrgCACertificate"`.
3. Verify the Org CA's `signing_algorithm` is one of: `"ECDSA_SHA_256"`, `"ED25519_SHA_512"`.
4. Verify the Org CA has not expired: `now < org_ca.expires_at`.
5. Reconstruct the Org CA signing input (all fields except `signature`, `signing_algorithm`, `signed_by`).
6. Verify the Root CA's signature over the canonical Org CA body using the Root CA's public key.

### 6.3 AIC Signature Validation

1. Verify the AIC's `org_ca_cert_id` matches the embedded `org_ca_certificate.cert_id`.
2. Verify the AIC has not expired: `now < aic.expires_at`.
3. Reconstruct the AIC signing input (all fields except `signature` and `signing_algorithm`).
4. Verify the Org CA's Ed25519 signature over the canonical AIC body using the Org CA's public key.

### 6.4 Key Binding

The `public_key` in the AIC is the authoritative public key for this agent. All subsequent signature verifications (e.g., SIE signatures) MUST use this key.

---

## 7. Revocation

### 7.1 Agent Revocation

An agent MAY be revoked by the issuing organization at any time. Revocation MUST:

1. Set the agent's status to `"revoked"` in the platform database.
2. Add the `agent_id` to the Certificate Revocation List (CRL) in the real-time cache.
3. Record the revocation in an append-only revocation log, signed by the Root CA.

### 7.2 Revocation Check

During verification, the verifier MUST check whether the agent has been revoked:

```
is_revoked = CRL_check(agent_id)  // Redis: SISMEMBER crl:agents {agent_id}
```

If the agent is revoked, verification MUST return `deny` with reason `"agent_revoked"`.

### 7.3 Revocation Propagation

- Revocation MUST propagate to the CRL within 10ms.
- Implementations SHOULD use a real-time distributed cache (e.g., Redis) for the CRL.
- The revocation log entry MUST be signed by the Root CA to prevent tampering.

---

## 8. Security Considerations

### 8.1 Private Key Protection

The agent's Ed25519 private key is the critical secret. Implementations MUST:
- Return the private key exactly once during registration.
- Never store the private key on the platform after the registration response.
- Advise clients to store the private key in a secure enclave, HSM, or encrypted storage.

### 8.2 Certificate Lifetime

Short-lived certificates (24 hours default) limit the damage window if a private key is compromised. Organizations SHOULD:
- Use the shortest practical validity period.
- Implement automated certificate rotation.
- Monitor for certificates approaching expiration.

### 8.3 Org CA Key Security

The Org CA private key is stored server-side using envelope encryption:
- The key is encrypted using AES-256-GCM with a data encryption key (DEK).
- The DEK is wrapped by a KMS-managed key specific to the organization.
- The wrapped key, nonce, and ciphertext are stored together in the database.

### 8.4 Root CA Key Security

The Root CA key MUST be stored in a Hardware Security Module (HSM) or equivalent:
- AWS KMS with `ECC_NIST_P256` or `Ed25519` key spec.
- The key material MUST NOT be exportable.
- All signing operations MUST go through the KMS API.
