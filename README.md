# AICP — Agent Identity and Capability Protocol

**Version:** 0.2  
**Status:** Draft  
**License:** CC-BY 4.0

## Overview

The Agent Identity and Capability Protocol (AICP) defines a cryptographic trust framework for AI agents operating in distributed systems. It provides three core primitives:

| Primitive | Document | Purpose |
|-----------|----------|---------|
| **AIC** — Agent Identity Certificate | [specs/AIC.md](specs/AIC.md) | Cryptographic identity for an AI agent |
| **ACT** — Agent Capability Token | [specs/ACT.md](specs/ACT.md) | Scoped, time-bound permission token |
| **SIE** — Signed Intent Envelope | [specs/SIE.md](specs/SIE.md) | Signed execution request with full verification chain |

Supporting documents:

| Document | Description |
|----------|-------------|
| [specs/CRYPTO.md](specs/CRYPTO.md) | Cryptographic primitives and algorithms |
| [specs/VERIFICATION.md](specs/VERIFICATION.md) | 10-step verification engine specification |
| [specs/THREAT-MODEL.md](specs/THREAT-MODEL.md) | Threat model and anti-replay mechanisms |
| [specs/TRUST-CHAIN.md](specs/TRUST-CHAIN.md) | Certificate trust chain (Root CA → Org CA → Agent) |

## Problem Statement

AI agents are increasingly performing real-world actions — payments, code execution, data access, API calls — on behalf of humans and organizations. There is no standardized way to answer:

> "Who authorized this agent to perform this action at this moment?"

AICP answers this question with cryptographic proof. Every agent action carries:
1. **Identity** — a certificate proving which agent is acting and who issued it
2. **Authorization** — a capability token proving what the agent is allowed to do
3. **Intent** — a signed envelope proving the agent requested this specific action
4. **Verification** — a deterministic process to validate all three in <50ms

## Design Principles

1. **Cryptographic proof over trust assumptions.** Every claim is signed and verifiable.
2. **Least privilege by default.** Capabilities are scoped, time-bound, and bound to a specific agent key.
3. **Fail closed.** If any verification step fails, the result is `deny`.
4. **Replay resistant.** Four-layer anti-replay: nonce, timestamp, token binding, intent hash.
5. **Auditable.** Every verification produces a tamper-evident, hash-chained audit record.
6. **Revocation is instant.** Agent and capability revocation propagates in <10ms.

## Certificate Trust Chain

```
┌─────────────────────┐
│   AIA Root CA       │  HSM-backed (ECDSA P-256 or Ed25519)
│   (Platform-wide)   │  Signs Org CA certificates
└─────────┬───────────┘
          │ signs
┌─────────▼───────────┐
│   Org CA            │  Ed25519 (key wrapped via AES-256-GCM)
│   (Per organization)│  Signs Agent Identity Certificates
└─────────┬───────────┘
          │ signs
┌─────────▼───────────┐
│   Agent (AIC)       │  Ed25519 (private key held by agent)
│   (Per agent)       │  Signs Signed Intent Envelopes
└─────────────────────┘
```

## Protocol Flow

```
1. Registration     Organization registers an agent → receives AIC + Ed25519 keypair
2. Authorization    Organization issues a capability token (ACT) scoped to specific actions
3. Execution        Agent constructs a Signed Intent Envelope (SIE) for each action
4. Verification     Verifier validates the full chain: AIC → ACT → SIE in <50ms
5. Audit            Every verification result is recorded in a hash-chained audit log
```

## Specification Format

Each spec follows RFC-style conventions:
- **MUST**, **MUST NOT**, **SHOULD**, **MAY** per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
- All examples use JSON with field-level annotations
- Cryptographic operations reference specific algorithm identifiers

## Contributing

This protocol is open for review and contribution. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
