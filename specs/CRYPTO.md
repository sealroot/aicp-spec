# Cryptographic Primitives

**AICP Specification**  
**Version:** 0.2  
**Status:** Draft  
**Authors:** Sealroot Contributors

---

## 1. Introduction

This document specifies all cryptographic algorithms, encoding formats, and key management requirements used by the Agent Identity and Capability Protocol (AICP). Implementations MUST conform to these specifications to ensure interoperability and security.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 2. Algorithm Summary

| Component | Algorithm | Standard | Key Size | Output Size |
|-----------|-----------|----------|----------|-------------|
| Agent keypair | Ed25519 | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | 32-byte seed / 32-byte public | — |
| Agent signing | Ed25519 | RFC 8032 | 32-byte private | 64-byte signature |
| Org CA keypair | Ed25519 | RFC 8032 | 32-byte seed / 32-byte public | — |
| Org CA signing | Ed25519 | RFC 8032 | 32-byte private | 64-byte signature |
| Root CA signing | ECDSA P-256 + SHA-256 OR Ed25519 | [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) / RFC 8032 | P-256 or Ed25519 | DER-encoded or 64-byte |
| Org CA key wrapping | AES-256-GCM | [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) | 256-bit | Ciphertext + 12-byte nonce + 16-byte tag |
| JSON canonicalization | JCS | [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) | — | UTF-8 bytes |
| Hashing | SHA-256 | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) | — | 32 bytes (256 bits) |
| Binary encoding | Base64url | [RFC 4648 Section 5](https://www.rfc-editor.org/rfc/rfc4648#section-5) | — | Variable |
| Token binding | JWK Thumbprint | [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) | — | 43-char base64url |
| Capability tokens | JWT / JWS | [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) / [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) | — | Variable |
| Nonce generation | CSPRNG | OS-provided | 128 bits | 32 hex chars |

---

## 3. Ed25519 (Agent and Org CA)

### 3.1 Key Generation

Implementations MUST use Ed25519 as specified in [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032).

- **Private key (seed):** 32 bytes of cryptographically secure random data.
- **Public key:** 32 bytes, derived from the seed per RFC 8032 Section 5.1.5.
- Implementations SHOULD use established libraries: libsodium (PyNaCl), @noble/ed25519 (Node.js), CryptoKit (Swift).

### 3.2 Signing

```
signature = Ed25519_Sign(private_key, message)
```

- **Input:** Arbitrary-length message (bytes).
- **Output:** 64-byte signature.
- The message is NOT pre-hashed — Ed25519 performs internal SHA-512 hashing per RFC 8032.

### 3.3 Verification

```
valid = Ed25519_Verify(public_key, message, signature)
```

- Returns `true` if the signature is valid for the given public key and message, `false` otherwise.
- Implementations MUST reject signatures that are not exactly 64 bytes.
- Implementations MUST reject public keys that are not exactly 32 bytes.

### 3.4 Why Ed25519

- **Performance:** Verification in ~70μs (vs ~200μs for ECDSA P-256). Critical for <50ms SIE verification.
- **Deterministic:** No per-signature randomness needed, eliminating a class of implementation bugs.
- **Small keys and signatures:** 32-byte keys, 64-byte signatures — minimal overhead in JSON certificates.
- **Widely supported:** libsodium, OpenSSL 1.1.1+, CryptoKit, Web Crypto API.

---

## 4. ECDSA P-256 (Root CA Alternative)

### 4.1 Usage

When the Root CA uses an HSM that does not support Ed25519, ECDSA with the NIST P-256 curve and SHA-256 hash MAY be used instead.

- Algorithm identifier: `ECDSA_SHA_256`
- JWT header `alg`: `ES256`
- Key spec: `ECC_NIST_P256` (in AWS KMS terminology)

### 4.2 Signature Format

- HSMs typically return DER-encoded ECDSA signatures.
- For base64url encoding in certificates, the raw DER bytes are encoded directly.
- For JWT signatures, the signature MUST be in the JWS-defined format (R || S, each 32 bytes, big-endian).

### 4.3 Verification

```
valid = ECDSA_Verify(public_key_der, message, signature_der)
```

The Root CA public key MUST be distributed to verifiers in DER or PEM format.

---

## 5. JSON Canonicalization (JCS)

### 5.1 Purpose

All signed objects in AICP (AICs, Org CA certificates, SIEs) use JSON Canonicalization Scheme ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) to produce a deterministic byte representation before signing.

### 5.2 Process

1. **Exclude signature fields.** Remove `signature` and `signing_algorithm` (and `signed_by` for Org CA) from the object.
2. **Canonicalize.** Apply JCS:
   - Object keys are sorted lexicographically.
   - Numbers use shortest representation.
   - Strings use minimal escape sequences.
   - No whitespace between tokens.
   - Output is UTF-8 bytes.
3. **Sign.** The canonical bytes are the signing input.

### 5.3 Implementation Notes

- Libraries: `jsoncanon` (Python), `canonicalize` (npm), custom (Swift — follow RFC 8785 exactly).
- Implementations MUST NOT use `JSON.stringify()` or equivalent without JCS processing — JSON serialization is not deterministic across languages.

---

## 6. SHA-256 Hashing

### 6.1 Usage in AICP

SHA-256 is used for:
- JWK Thumbprint computation (RFC 7638)
- SIE hash in audit records (`sie_hash`)
- Audit log hash chaining (`previous_hash`, `record_hash`)
- Reasoning hash (`reasoning_hash`)

### 6.2 Output Format

- **Binary:** 32 bytes (256 bits)
- **Hex encoding:** 64 lowercase hexadecimal characters
- **Base64url encoding:** 43 characters (for JWK Thumbprint)

The format depends on context:
- Audit hashes: hex encoding
- JWK Thumbprint: base64url encoding
- Reasoning hash: `"sha256:"` prefix + hex encoding

---

## 7. Base64url Encoding

### 7.1 Specification

All binary data in AICP JSON structures MUST be encoded using base64url ([RFC 4648 Section 5](https://www.rfc-editor.org/rfc/rfc4648#section-5)):

- Alphabet: `A-Z`, `a-z`, `0-9`, `-`, `_`
- Padding (`=`) MUST be omitted.

### 7.2 Reference Sizes

| Data | Raw Size | Base64url Size |
|------|----------|---------------|
| Ed25519 public key | 32 bytes | 43 characters |
| Ed25519 signature | 64 bytes | 86 characters |
| SHA-256 hash | 32 bytes | 43 characters |

### 7.3 Decoding

When decoding, implementations MUST restore padding before decoding:

```
padding = 4 - (len(encoded) % 4)
if padding != 4:
    encoded += "=" * padding
decoded = base64url_decode(encoded)
```

---

## 8. JWK Thumbprint

### 8.1 Computation

Per [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638), the JWK Thumbprint for an Ed25519 public key is computed as:

1. Construct the JWK with required members in lexicographic order:
   ```json
   {"crv":"Ed25519","kty":"OKP","x":"<base64url-public-key>"}
   ```
2. Serialize to UTF-8 bytes (no whitespace).
3. Compute SHA-256 hash.
4. Base64url-encode the hash (no padding).

### 8.2 Example

```
Public key (hex): 28b97abc64abf09cd03a4f4cd57da956136a46d637c14884
JWK: {"crv":"Ed25519","kty":"OKP","x":"KLl6vGSr8JzQOk9M1X2pVhNqRtY3wUiE"}
SHA-256(JWK): <32 bytes>
Thumbprint: "Rt5FmKQz_2Y8qL7pNvXwZ1sO3gHtUiEaBcDeFgHiJk0"
```

---

## 9. Nonce Generation

### 9.1 Requirements

- MUST use a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG).
- MUST produce 128 bits (16 bytes) of randomness.
- MUST encode as 32 lowercase hexadecimal characters.

### 9.2 Platform-Specific Implementations

| Platform | Function |
|----------|----------|
| Python | `secrets.token_hex(16)` |
| Node.js | `crypto.randomBytes(16).toString('hex')` |
| Swift | `Data(count: 16).map { String(format: "%02x", $0) }.joined()` with `SecRandomCopyBytes` |
| Browser | `crypto.getRandomValues(new Uint8Array(16))` + hex encoding |

---

## 10. Envelope Encryption (Org CA Key Wrapping)

### 10.1 Purpose

The Org CA's Ed25519 private key is stored server-side encrypted using AES-256-GCM with a KMS-managed data encryption key (DEK).

### 10.2 Envelope Structure

```json
{
  "v": 1,
  "kms_key_id": "arn:aws:kms:region:account:key/key-id",
  "encrypted_data_key": "<base64-encoded-wrapped-DEK>",
  "nonce": "<base64-encoded-12-byte-GCM-nonce>",
  "ciphertext": "<base64-encoded-encrypted-private-key>"
}
```

### 10.3 Encryption Flow

1. Generate a 256-bit DEK via KMS `GenerateDataKey` API.
2. KMS returns plaintext DEK + wrapped (encrypted) DEK.
3. Generate a 12-byte random nonce for AES-GCM.
4. Encrypt the Org CA private key using AES-256-GCM with the plaintext DEK and nonce.
5. Securely erase the plaintext DEK from memory.
6. Store the wrapped DEK, nonce, and ciphertext.

### 10.4 Decryption Flow

1. Retrieve the envelope from the database.
2. Decrypt the wrapped DEK via KMS `Decrypt` API → plaintext DEK.
3. Decrypt the ciphertext using AES-256-GCM with the plaintext DEK and stored nonce.
4. The result is the Org CA's Ed25519 private key (32 bytes).
5. Securely erase the plaintext DEK from memory after use.

---

## 11. Security Requirements

### 11.1 Random Number Generation

All random values (keys, nonces, UUIDs) MUST be generated using a CSPRNG. Implementations MUST NOT use non-cryptographic random functions (e.g., `Math.random()`, `random.random()`).

### 11.2 Constant-Time Comparison

Signature verification and hash comparisons MUST use constant-time comparison to prevent timing attacks. Most cryptographic libraries handle this internally, but implementations MUST verify this property.

### 11.3 Key Erasure

Private keys and decrypted key material MUST be erased from memory as soon as they are no longer needed. Implementations SHOULD use secure memory allocation where available (e.g., `sodium_memzero` in libsodium).

### 11.4 Algorithm Agility

AICP v0.2 fixes the agent/Org CA algorithm to Ed25519. Future versions MAY introduce additional algorithms. Verifiers MUST reject certificates or SIEs with unrecognized `signing_algorithm` values.
