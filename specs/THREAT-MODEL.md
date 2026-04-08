# Threat Model

**AICP Specification**  
**Version:** 0.2  
**Status:** Draft  
**Authors:** Sealroot Contributors

---

## 1. Introduction

This document enumerates the threats that AICP is designed to mitigate, the attack surfaces of the protocol, and the defensive mechanisms in place. It is intended for security reviewers, implementers, and organizations evaluating AICP for deployment.

---

## 2. Threat Actors

| Actor | Capability | Goal |
|-------|-----------|------|
| **External attacker** | Network access, public knowledge of the protocol | Forge agent actions, steal data, disrupt operations |
| **Compromised agent** | Valid AIC + private key, valid ACTs | Exceed authorized scope, exfiltrate data, perform unauthorized actions |
| **Rogue insider** | Organization admin access, API keys | Issue unauthorized capabilities, suppress audit records, revoke legitimate agents |
| **Compromised platform** | Access to platform database and services | Forge certificates, issue backdoor ACTs, tamper with audit logs |

---

## 3. Attack Categories and Mitigations

### 3.1 Identity Attacks

| Attack | Description | Mitigation |
|--------|-------------|------------|
| **Identity forgery** | Attacker creates a fake AIC without Org CA signing | AIC MUST be signed by Org CA, which MUST be signed by Root CA. Forging requires compromising the Root CA HSM. |
| **Identity theft** | Attacker obtains an agent's private key | Short-lived certificates (24h default) limit the damage window. Compromised keys can be revoked in <10ms. |
| **Org CA impersonation** | Attacker creates a fake Org CA certificate | Org CA MUST be signed by the Root CA (HSM-backed). Forgery requires KMS access. |
| **Agent name collision** | Attacker registers an agent with a confusingly similar name | Agent names are unique per organization (database constraint). Cross-org impersonation is detectable via `org_id`. |

### 3.2 Authorization Attacks

| Attack | Description | Mitigation |
|--------|-------------|------------|
| **Token forgery** | Attacker creates a fake ACT | ACTs are JWTs signed by the Root CA (KMS). Forgery requires KMS access. |
| **Token theft** | Attacker intercepts an ACT in transit | Token binding (JWK Thumbprint) ensures the ACT is useless without the agent's private key. |
| **Scope escalation** | Agent uses an ACT for a broader action than authorized | Capability scope matching (Step 3) requires exact match between ACT capability and SIE intent. |
| **Token replay** | Attacker reuses a previously observed ACT | Each SIE requires a unique nonce (Step 9). The ACT itself has expiration (max 1 hour). |
| **Privilege accumulation** | Agent accumulates many ACTs to build broad access | Each ACT is independently scoped and time-bound. Policy engine (Step 7) can enforce cumulative limits. |

### 3.3 Replay and Timing Attacks

| Attack | Description | Mitigation |
|--------|-------------|------------|
| **SIE replay** | Attacker captures and replays a complete SIE | Four-layer defense (see Section 4). |
| **Nonce prediction** | Attacker pre-generates nonces to bypass replay detection | Nonces MUST be 128-bit CSPRNG output. Prediction is computationally infeasible. |
| **Timestamp manipulation** | Agent backdates or forward-dates an SIE | Timestamp freshness check (Step 8) enforces ±60s window. Server clock is authoritative. |
| **Clock skew exploitation** | Attacker exploits differences between agent and server clocks | The 60-second window accommodates reasonable clock skew while limiting replay exposure. |

### 3.4 Infrastructure Attacks

| Attack | Description | Mitigation |
|--------|-------------|------------|
| **CRL cache poisoning** | Attacker corrupts the revocation list to allow revoked agents | CRL is populated from signed revocation records. Cache is rebuilt from the database on startup. |
| **Audit log tampering** | Attacker modifies audit records to hide unauthorized actions | Hash-chained audit log — any modification breaks the chain. Records are INSERT-ONLY (database-enforced). |
| **Audit log deletion** | Attacker deletes audit records | Append-only database constraints prevent DELETE. Hash chain detects gaps. |
| **Nonce cache failure** | Redis cache goes down, allowing replay | Verification engine fails closed — if nonce check cannot be performed, result is `deny`. |
| **Root CA key compromise** | Attacker obtains the Root CA private key | Root CA key is stored in HSM (non-exportable). KMS access requires IAM authentication + CloudTrail audit. |

### 3.5 Protocol-Level Attacks

| Attack | Description | Mitigation |
|--------|-------------|------------|
| **Downgrade attack** | Attacker forces use of a weaker protocol version | Version is embedded in signed structures. Verifier MUST reject unsupported versions. |
| **Algorithm substitution** | Attacker changes `signing_algorithm` to bypass verification | Algorithm field is outside the signed payload — but verifier uses a fixed, trusted algorithm for each level (Ed25519 for agents, configured algorithm for Root CA). |
| **JSON canonicalization bypass** | Attacker crafts JSON that produces different canonical forms | JCS (RFC 8785) is deterministic. Implementation MUST use a conformant JCS library. |
| **Intent substitution** | Attacker modifies the intent after the agent signs the SIE | The agent's signature covers the entire envelope including the intent. Any modification invalidates the signature. |

---

## 4. Anti-Replay Defense (Four Layers)

AICP implements defense-in-depth against replay attacks with four independent layers:

### Layer 1: Nonce (Primary)

- Each SIE contains a 128-bit cryptographically random nonce.
- The nonce is stored in the cache with a TTL (default 60s) using atomic SET-IF-NOT-EXISTS.
- A repeated nonce within the TTL window is rejected with `"nonce_replay"`.

**Strength:** Prevents exact replay of any SIE within the freshness window.

### Layer 2: Timestamp (Time-Bound)

- Each SIE contains an ISO 8601 timestamp.
- The server rejects SIEs where `|now - timestamp| > 60 seconds`.

**Strength:** Prevents replay of old SIEs even if the nonce cache is cleared.

### Layer 3: Token Binding (Cryptographic)

- Each ACT contains a JWK Thumbprint binding it to a specific agent key.
- Verification checks that the SIE's signing key matches the ACT's thumbprint.

**Strength:** A stolen ACT cannot be used by a different agent. An intercepted SIE cannot be re-signed by a different key.

### Layer 4: Intent Hash (Content-Bound)

- The optional `reasoning_hash` field binds the SIE to the agent's decision chain.
- The agent's signature covers the intent, preventing modification.

**Strength:** Even if an attacker could somehow bypass layers 1-3, the signed intent prevents the SIE from being repurposed for a different action.

### Combined Guarantee

To successfully replay an attack, an adversary would need to:
1. Obtain a valid nonce that hasn't been seen (Layer 1) — but nonces are 128-bit random
2. Submit within the timestamp window (Layer 2) — but the window is 60 seconds
3. Possess the agent's private key (Layer 3) — but the key is only held by the agent
4. Construct a valid intent (Layer 4) — but the intent is signed

Breaking all four layers simultaneously is computationally infeasible under standard cryptographic assumptions.

---

## 5. Trust Boundaries

```
┌───────────────────────────────────────────────────────┐
│                  UNTRUSTED ZONE                       │
│                                                       │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐     │
│  │  Agent    │     │ Network  │     │ Consumer │     │
│  │ Runtime   │     │          │     │ Service  │     │
│  └──────────┘     └──────────┘     └──────────┘     │
│       │                │                │             │
├───────┼────────────────┼────────────────┼─────────────┤
│       │           TRUST BOUNDARY        │             │
├───────┼────────────────┼────────────────┼─────────────┤
│       ▼                ▼                ▼             │
│  ┌─────────────────────────────────────────────┐     │
│  │          AICP Verification Engine            │     │
│  │                                              │     │
│  │  ┌──────────────────────────────────────┐   │     │
│  │  │         TRUSTED ZONE                  │   │     │
│  │  │                                       │   │     │
│  │  │  Root CA Public Key (in-memory)       │   │     │
│  │  │  CRL Cache (Redis)                    │   │     │
│  │  │  Nonce Cache (Redis)                  │   │     │
│  │  │  Policy Rules (PostgreSQL)            │   │     │
│  │  │  Audit Log (PostgreSQL, append-only)  │   │     │
│  │  └───────────────────────────────────────┘   │     │
│  └─────────────────────────────────────────────┘     │
│                                                       │
│  ┌─────────────────────────────────────────────┐     │
│  │         HARDWARE TRUST ROOT                  │     │
│  │  Root CA Private Key (HSM / KMS)             │     │
│  └─────────────────────────────────────────────┘     │
└───────────────────────────────────────────────────────┘
```

### Boundary Rules

1. **Agent runtimes are untrusted.** The verification engine validates every claim cryptographically — it does not trust the agent's assertions.
2. **The network is untrusted.** SIEs are self-contained and tamper-evident. Transport-layer security (TLS) is recommended but not relied upon for integrity.
3. **Consumer services are untrusted.** The verification response provides a definitive answer. Consumer services should not implement their own verification logic.
4. **The verification engine is trusted.** It has access to the Root CA public key, CRL, nonce cache, and policy rules. Compromise of the verification engine is a critical security incident.
5. **The HSM is the root of trust.** If the Root CA key in the HSM is compromised, the entire trust chain is invalidated.

---

## 6. Residual Risks

These are risks that AICP does not fully mitigate:

| Risk | Description | Recommendation |
|------|-------------|----------------|
| **Root CA compromise** | If the HSM is compromised, all certificates and tokens can be forged | Use multi-party access controls on KMS. Enable CloudTrail logging. Implement key rotation. |
| **Platform database compromise** | Attacker with database access can read Org CA wrapped keys (but not decrypt without KMS) | Enforce encryption at rest. Restrict database access. Use separate KMS keys per org. |
| **Covert channel via parameters** | A compromised agent could encode exfiltrated data in SIE parameters | Application-level monitoring of parameter content. Policy rules can restrict parameter values. |
| **Denial of service** | Flooding the verification endpoint with invalid SIEs | Rate limiting (4-tier sliding window). Fail-fast verification rejects malformed input cheaply. |
| **Side-channel timing** | Verification latency may leak information about which step failed | Use constant-time comparison for signatures. Normalize response timing where feasible. |

---

## 7. Compliance Mapping

| Requirement | AICP Mechanism |
|-------------|---------------|
| **SOC 2 — Access Control** | Scoped ACTs, RBAC/ABAC policy engine, agent-level identity |
| **SOC 2 — Audit Logging** | Hash-chained, append-only audit trail with every verification |
| **HIPAA — Access Controls** | Per-agent, per-capability authorization with time bounds |
| **HIPAA — Audit Trail** | Tamper-evident audit log with agent identification |
| **EU AI Act — Traceability** | Full chain: who created the agent, what it's authorized to do, what it did, when |
| **PCI-DSS — Authentication** | Cryptographic agent identity (AIC) with proof of possession |
| **SOX — Financial Controls** | Scoped financial capabilities, audit trail of all agent actions |
