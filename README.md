# DIT Protocol — Proof of Concept

This directory contains a Go proof-of-concept implementation of the DIT
(Decentralized Identity and Trust) protocol, a CA-free web authentication
protocol designed to replace the CA-based browser trust model.

## What DIT Is

DIT anchors domain identity in DNSSEC-signed DNS TXT records containing a
post-quantum Identity Key (ML-DSA-65 / CRYSTALS-Dilithium). A three-level key
hierarchy (Identity Key → Epoch Key → Session Key) separates long-term identity
from ephemeral session material, eliminating annual certificate renewals. A
BLAKE3 Merkle transparency log audits all key publications and rotations. A
FROST (3-of-5) threshold ceremony governs Identity Key rotation safely.

## Cryptographic Placeholders

This PoC uses the following substitutions for primitives not yet in the Go
standard library:

| Production (DIT spec)      | PoC substitute       | Why                          |
|----------------------------|----------------------|------------------------------|
| ML-DSA-65 (FIPS 204)       | Ed25519              | No Go stdlib ML-DSA yet      |
| ML-KEM-768 (FIPS 203)      | X25519 ECDH          | No Go stdlib ML-KEM yet      |
| FROST threshold signing     | Simple vote counting | Full FROST requires MPC lib  |

All substitution points are marked with `// PRODUCTION:` comments in the code.
For production use, replace with liboqs Go bindings or a FIPS 204/203 Go library.

## Directory Structure

```
poc/
├── go.mod                    # Module definition
├── main.go                   # End-to-end demo + benchmark runner
├── protocol/
│   └── dit.go                # Core types, handshake, key hierarchy
├── transparency/
│   └── log.go                # BLAKE3 Merkle tree, transparency log
├── ceremony/
│   └── ceremony.go           # FROST key rotation ceremony (simulated)
└── bench/
    └── bench_test.go         # Go benchmarks
```

## Running the Demo

```bash
# Install dependencies
go mod tidy

# Run end-to-end demonstration
go run .

# Run benchmarks (10,000 iterations each)
go test -bench=. -benchmem ./bench/

# Run all tests
go test ./...
```

## What the Demo Does

1. **Identity Key generation**: Generates an Ed25519 key pair representing the
   domain owner's ML-DSA-65 Identity Key.

2. **DNS record creation**: Formats a `_dit.bank.com` TXT record with the IK
   public key, witness endpoint, timestamp, and placeholder witness signature.

3. **Epoch Key derivation**: Derives a 24-hour Epoch Key from the IK using
   HKDF-SHA3-256 keyed on the current UTC day.

4. **DIT handshake**: Runs a complete client-server handshake over `net.Pipe`
   in parallel goroutines: server sends DIT_HELLO with signed EK, client
   sends DIT_KEYX with its KEM public key, server responds with the
   encapsulated secret, both sides derive the same Session Key.

5. **Transparency log**: Submits key publication events to an in-memory BLAKE3
   Merkle tree log, queries an entry with its Merkle proof, and verifies the
   proof.

6. **Key ceremony**: Simulates a 5-peer FROST ceremony: initiates rotation,
   waits the mandatory period, collects 3-of-5 peer signatures, and finalizes
   the rotation.

7. **Benchmarks**: Reports median latency for 10,000 handshakes.

## Expected Output

```
=== DIT Protocol Proof of Concept ===

[1/7] Generating Identity Key (Ed25519 placeholder for ML-DSA-65)...
      IK public key: 32 bytes
      DNS record: _dit.bank.com TXT v=dit1 ik=... tw=witness.webtrust.org ...

[2/7] Deriving Epoch Key via HKDF-SHA3-256...
      EK timestamp: 2026-03-20 00:00:00 UTC (24hr epoch)

[3/7] Running DIT handshake (client + server over net.Pipe)...
      Session key derived: [32 bytes, hex omitted]
      Handshake: OK

[4/7] Transparency log operations...
      Submitted 3 entries, Merkle root: [hex]
      Proof verification: OK

[5/7] Key ceremony simulation (FROST 3-of-5 placeholder)...
      Ceremony: COMPLETE (3/5 peers signed)

[6/7] Benchmarking 10,000 handshakes...
      Median latency: ~XX µs per handshake

[7/7] All components verified successfully.
```

## Security Notes

- This PoC is for demonstration and research purposes only.
- Do NOT use this code in production.
- The Ed25519 and X25519 substitutions are classical; the full protocol
  requires ML-DSA-65 and ML-KEM-768 for post-quantum security.
- The in-memory transparency log does not implement the gossip protocol;
  production requires a distributed BFT log network.
