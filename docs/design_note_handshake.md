# Design note: DIT handshake architecture (revision, Step 2)

**Decision:** Option A. DIT runs as an authentication layer over an unmodified TLS 1.3 handshake. The custom handshake and the `DIT_AES_256_GCM_SHA3_384` ciphersuite are withdrawn.

**Date:** 2026-10-09. **Addresses:** R1.4, R3.3; also R3.2 (code/paper mismatch) and part of R1.6.

## What changes

| Aspect | Submitted version | Revised version (Option A) |
|---|---|---|
| Key exchange | Custom TLS-like messages; hybrid `ss_mlkem ‖ ss_x25519` fed into an HKDF-SHA3-384 key schedule | Standard TLS 1.3 `key_share` with the X25519MLKEM768 group (RFC 10024, code point 0x11EC) |
| Ciphersuite / key schedule | `DIT_AES_256_GCM_SHA3_384` (new) | `TLS_AES_256_GCM_SHA384` (RFC 8446). HKDF and HMAC are instantiated with SHA-384 |
| Server authentication | `σ_server` by EAK inside a **cleartext** ServerHello | Standard `CertificateVerify` (ML-DSA-65, code point 0x0905, draft-ietf-tls-mldsa) signed with `EAK_priv`, sent **encrypted** under the handshake traffic key |
| EAK delivery | Custom field | RFC 7250 raw public key: the `Certificate` message carries the EAK's RFC 9881 SubjectPublicKeyInfo; `server_certificate_type = RawPublicKey` |
| IK → EAK binding, identity, log proof | Fetched over HTTPS (needs a CA certificate) | DIT extension (private-use code point `0xff5d`) on the `CertificateEntry`, also encrypted. Warm path: epoch credential only (omitted when the client has it cached). First contact: also the log entry that installed the identity, its inclusion proof and a q-of-m cosigned STH |
| Bootstrapping | `https://domain/.well-known/dit/identity` | In-handshake delivery. Integrity comes from the 48-byte SHA3-384 commitment in the DNSSEC-signed `_dit` record. Optionally, the DNSSEC chain itself can travel in-handshake (RFC 9102) |
| SHA3-384 | Hash for everything | Used for DIT objects only: identity commitment, log Merkle tree, credentials. TLS uses SHA-384 |

## Why

1. **Security of the hybrid combiner is inherited, not re-proved.** X25519MLKEM768 in TLS 1.3 is analysed in RFC 9954/RFC 10024. Their argument rests on the TLS 1.3 transcript binding and on HKDF-Extract (HMAC-SHA-384) acting as a dual-PRF. The dual-PRF results of Backendal–Bellare–Günther–Scarlata (CRYPTO 2023) cover HMAC over Merkle–Damgård hashes such as SHA-384. They did **not** obviously cover HMAC-SHA3-384, which the submitted version would have needed as an extra assumption. Option A removes that assumption.
2. **Privacy.** In the submitted design `σ_server` and the epoch identifier were sent in the clear. Option A encrypts every authentication message, as in standard TLS 1.3.
3. **Adoption (R1.4).** No new ciphersuite, no new key-exchange group. The changes are a new certificate type use (RFC 7250, already standardised), a new signature algorithm (being standardised), and one extension. A server can offer DIT and X.509 side by side and select by the client's `server_certificate_type` and DIT extension (coexistence, Section 4.7).
4. **Identity at a higher layer?** R1.4 suggests verifying identity above TLS. We keep authentication inside the handshake, as `CertificateVerify`, for two reasons. It binds the server's signature to the transcript and therefore to the session key, which is the property Theorem 1 needs. And it avoids a second round trip. The DIT-specific verification (identity commitment, log proof, pins) is a client-side policy layered on top of a standard TLS authentication message, which is close in spirit to the reviewer's suggestion.

## What the PoC implements

`handshake/` implements the RFC 8446 messages, record layer and key schedule needed for this flow: ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished, AES-256-GCM records, and fragmentation at 2^14 bytes. It uses real X25519MLKEM768 and ML-DSA-65. It omits HelloRetryRequest, PSK resumption, client authentication, alerts and middlebox-compatibility mode. It does not interoperate with unmodified TLS stacks: Go's `crypto/tls` supports neither ML-DSA CertificateVerify nor RFC 7250 raw public keys. Baselines (a) and (b) use `crypto/tls` itself. Baseline (c), a fully post-quantum X.509 chain, uses the same handshake implementation as DIT, so DIT and (c) differ only in the authentication messages.

## Consequences for the paper

- Layer 5 and its figure (Fig. 5) are rewritten as a TLS 1.3 message sequence.
- The "hybrid secure if either component is secure" sentence is removed. Section 5.4 states the reliance on the RFC 9954 / TLS 1.3 argument and the assumptions it needs.
- The ciphersuite name `DIT_AES_256_GCM_SHA3_384` no longer appears.
