# Certificate Trust Chain

**AICP Specification**  
**Version:** 0.2  
**Status:** Draft  
**Authors:** Sealroot Contributors

---

## 1. Introduction

AICP uses a three-level certificate hierarchy to establish agent identity. This document specifies the trust chain structure, key management at each level, and the certificate lifecycle.

---

## 2. Trust Hierarchy

```
Level 0 ─ Root CA (Platform-wide)
  │
  │  Signs Org CA certificates
  │  Key: HSM-backed (ECDSA P-256 or Ed25519)
  │  Lifetime: Years (managed by platform operator)
  │
Level 1 ─ Organization CA (Per-organization)
  │
  │  Signs Agent Identity Certificates
  │  Key: Ed25519 (encrypted at rest via AES-256-GCM + KMS)
  │  Lifetime: 1 year (renewable)
  │
Level 2 ─ Agent (Per-agent)
     
     Signs Signed Intent Envelopes
     Key: Ed25519 (private key held by agent, never stored by platform)
     Lifetime: 24 hours default, 7 days maximum
```

### 2.1 Design Rationale

**Why three levels instead of two?**

A two-level hierarchy (Root CA → Agent) would require the Root CA to sign every agent certificate. This creates:
- A single point of failure if the Root CA is temporarily unavailable.
- A performance bottleneck — every agent registration requires a KMS call.
- No organizational isolation — all agents are peers under a single CA.

The three-level hierarchy introduces organizational CAs that can independently issue agent certificates. This provides:
- **Isolation:** Organizations manage their own agent populations.
- **Scalability:** Agent registration only requires Org CA signing (in-process Ed25519), not KMS calls.
- **Delegation:** Organizations can be granted and revoked CA authority independently.

**Why not more levels?**

Additional levels (e.g., team CAs, project CAs) add verification complexity without proportional security benefit. Organizations can achieve fine-grained control through the RBAC/ABAC policy engine instead of deeper certificate hierarchies.

---

## 3. Level 0: Root CA

### 3.1 Key Specification

| Property | Value |
|----------|-------|
| Algorithm | ECDSA P-256 (`ECC_NIST_P256`) or Ed25519 |
| Storage | Hardware Security Module (HSM) or equivalent |
| Exportable | MUST NOT be exportable |
| Access | Platform operator only, via IAM-authenticated API |

### 3.2 Responsibilities

The Root CA:
1. Signs Org CA certificates when an organization is onboarded.
2. Signs Agent Capability Tokens (ACTs) to authorize specific actions.
3. Signs revocation records to ensure revocation authenticity.

### 3.3 Key Rotation

Root CA key rotation is a critical operation:
1. Generate a new Root CA key in the HSM.
2. Begin issuing new Org CA certificates signed by the new key.
3. Maintain the old key for verification of existing certificates until they expire.
4. After all certificates signed by the old key have expired, retire the old key.

Implementations SHOULD support multiple active Root CA keys during rotation periods.

### 3.4 Public Key Distribution

The Root CA public key MUST be distributed to all verifiers through a trusted channel:
- Embedded in the verification service at deployment.
- Fetched from a trusted configuration endpoint at startup.
- MUST NOT be fetched from an untrusted source or derived from SIE content.

---

## 4. Level 1: Organization CA

### 4.1 Key Specification

| Property | Value |
|----------|-------|
| Algorithm | Ed25519 |
| Storage | Platform database, encrypted at rest |
| Encryption | AES-256-GCM with KMS-managed data encryption key (per-org) |
| Lifetime | 1 year (renewable) |

### 4.2 Provisioning

When an organization is onboarded:
1. Generate an Ed25519 keypair for the Org CA.
2. Construct the Org CA certificate body.
3. Sign the certificate with the Root CA (via KMS).
4. Encrypt the Org CA private key using envelope encryption (see CRYPTO.md Section 10).
5. Store the encrypted private key and certificate in the database.

### 4.3 Certificate Fields

See [AIC.md Section 3](AIC.md#3-org-ca-certificate-structure) for the complete Org CA certificate structure.

### 4.4 Key Usage

The Org CA private key is decrypted on-demand when signing agent certificates:
1. Retrieve the encrypted key envelope from the database.
2. Decrypt the data encryption key via KMS.
3. Decrypt the Org CA private key using AES-256-GCM.
4. Sign the agent certificate.
5. Erase the decrypted key from memory.

Implementations SHOULD cache the decrypted Org CA key in memory for a short duration (e.g., 5 minutes) to reduce KMS call frequency.

### 4.5 Renewal

Before an Org CA certificate expires:
1. Generate a new Ed25519 keypair.
2. Issue a new Org CA certificate signed by the Root CA.
3. Begin issuing new AICs with the new Org CA.
4. The old Org CA remains valid for verification until all AICs it signed have expired.

---

## 5. Level 2: Agent

### 5.1 Key Specification

| Property | Value |
|----------|-------|
| Algorithm | Ed25519 |
| Storage | Client-side only (agent runtime) |
| Platform storage | Public key only — private key NEVER stored by platform |
| Lifetime | Matches AIC validity (24 hours default, 7 days max) |

### 5.2 Provisioning

When an agent is registered:
1. The platform generates an Ed25519 keypair.
2. The platform constructs and signs the AIC using the Org CA.
3. The platform returns the AIC, public key, and private key to the client.
4. The platform stores the public key and AIC. The private key is discarded.
5. The client MUST securely store the private key.

### 5.3 Key Custody

The agent's private key is held exclusively by the agent runtime. This means:
- The platform cannot sign SIEs on the agent's behalf.
- Only the entity holding the private key can act as the agent.
- If the private key is lost, the agent must be re-registered with a new keypair.

### 5.4 Certificate Renewal

Before an AIC expires, the agent (or its managing application) should:
1. Register a new agent identity (new keypair, new AIC).
2. Transition active capabilities to the new identity.
3. Allow the old identity to expire naturally.

Implementations MAY provide an automated renewal flow that:
1. Generates a new keypair.
2. Re-registers the agent with the same name (the platform reuses the agent record).
3. Returns the new AIC and private key.
4. The old AIC remains valid until expiration but no new ACTs should be issued against it.

---

## 6. Certificate Embedding

### 6.1 Self-Contained Verification

AICs embed the full Org CA certificate. SIEs embed the full AIC (which includes the Org CA certificate). This design enables self-contained verification:

```
SIE
 └── agent_certificate (AIC)
      └── org_ca_certificate (Org CA cert)
```

A verifier needs only:
1. The Root CA public key (pre-distributed).
2. The CRL cache (for revocation checks).
3. The nonce cache (for replay detection).

No database lookup of the agent or Org CA is needed during verification.

### 6.2 Size Implications

The embedding increases SIE size:

| Component | Approximate Size |
|-----------|-----------------|
| AIC (without Org CA) | ~500 bytes |
| Org CA certificate | ~400 bytes |
| AIC (with embedded Org CA) | ~900 bytes |
| ACT (JWT) | ~400 bytes |
| SIE overhead (nonce, timestamp, signature, intent) | ~300 bytes |
| **Total SIE** | **~1,600 bytes** |

This size is acceptable for API calls and message payloads. For bandwidth-constrained environments, implementations MAY define a compact SIE format in future protocol versions that references certificates by ID instead of embedding them.

---

## 7. Revocation

### 7.1 Revocation Scope

| Level | Revocation Effect |
|-------|-------------------|
| Agent | All ACTs for this agent become invalid. The agent cannot create valid SIEs. |
| Org CA | All agents under this Org CA become invalid. The organization loses agent capabilities. |
| Root CA | All certificates in the system become invalid. Emergency-only operation. |

### 7.2 Revocation Propagation

```
Revocation Request
    │
    ├──► Database: agent.status = 'revoked'
    │    Revocation log entry (signed by Root CA)
    │
    └──► Cache: SADD crl:agents {agent_id}
         Propagation target: < 10ms
```

### 7.3 CRL Bootstrap

On startup, the verification service MUST:
1. Load all revoked agent IDs from the database.
2. Populate the CRL cache.
3. Begin accepting verification requests only after the CRL is populated.

This ensures no revoked agent can pass verification during a cache cold start.

---

## 8. Clock Synchronization

### 8.1 Requirements

The verification engine relies on accurate timestamps for:
- Certificate expiration checks.
- ACT expiration checks.
- SIE timestamp freshness checks.

### 8.2 Tolerance

The 60-second timestamp freshness window accommodates:
- Network latency (typically <100ms).
- Reasonable clock skew between agent and server (up to ~30 seconds).
- Processing delays.

### 8.3 Recommendations

- Platform servers SHOULD synchronize clocks via NTP with <1 second accuracy.
- Agent runtimes SHOULD synchronize clocks via NTP or system time services.
- Implementations SHOULD NOT tighten the timestamp window below 30 seconds without ensuring clock synchronization is in place.
