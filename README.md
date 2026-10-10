# DIT proof of concept

Reference implementation and measurement harness for the paper *Domain identities anchored in DNS and a witnessed key-event log enable post-quantum web server authentication without certificate authorities* (Tripathy and P; the protocol is called DIT).

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23275009.svg)](https://doi.org/10.5281/zenodo.23275009)

Release `v1.2-paper` (<https://github.com/DebasishTripathy13/dit-poc/tree/v1.2-paper>) is the artifact for the paper, archived on Zenodo with **DOI [10.5281/zenodo.23275009](https://doi.org/10.5281/zenodo.23275009)**. Earlier releases: `v1.1-paper` / `v1.1.1-paper` (same code and data, older figure typography) and `v1.0-paper` (without baseline b' and the network-emulation data).

## What is implemented

| Package | Content |
|---|---|
| `pqc/` | ML-DSA-65 (FIPS 204, Cloudflare CIRCL), ML-KEM-768 (FIPS 203, Go `crypto/mlkem`), X25519MLKEM768 (RFC 10024), SHA3-384 (Go `crypto/sha3`). Nothing is simulated. |
| `identity/` | Identity object, its 48-byte SHA3-384 DNS commitment, IK → EAK epoch credentials; canonical TLV encoding plus a JSON encoding for size comparison. |
| `tlog/` | RFC 9162 Merkle tree over SHA3-384 (inclusion and consistency proofs), signed tree heads, witnesses that check consistency and entry validity before cosigning, q-of-m client verification. |
| `rotation/` | Key-event log entries and the deterministic state machine run by witnesses and clients: normal rotation (waiting period, σ_old/σ_new, recovery configuration immutable), recovery rotation (peer-sponsored requests, waiting period, k-of-n signed cancels, FROST σ_rot), precedence of recovery over normal rotation, EAK revocation, pin-conflict resolution. |
| `frost/` | FROST(Ed25519, SHA-512) per RFC 9591, trusted-dealer key generation. Aggregate signatures verify with `crypto/ed25519`. |
| `handshake/` | DIT over TLS 1.3 (paper, design Option A): X25519MLKEM768 key share, TLS 1.3 key schedule (SHA-384), EAK as RFC 7250 raw public key, ML-DSA-65 CertificateVerify, DIT extension inside the encrypted Certificate message. Also baseline (c): a fully post-quantum X.509 chain on the same implementation. |
| `baseline/` | Baselines (a) and (b) on Go `crypto/tls`: ECDSA P-256 chain with X25519 or X25519MLKEM768. Baseline (b') is the same configuration as (b) on our own TLS implementation (`handshake/x509chain.go`). |
| `sim/` | In-memory deployment (log, 7 witnesses, a published domain) used by tests and benchmarks; end-to-end handshake tests. |
| `cmd/ditbench/` | Produces every number in the paper (see below). |
| `bench/` | `go test` benchmarks for quick regression checks. |
| `formal/` | Tamarin model of the handshake and both rotation paths; `tamarin_summary.txt` is the prover output. |

**Not implemented / limitations:** the handshake follows RFC 8446 encodings but omits HelloRetryRequest, resumption, client authentication, alerts and middlebox-compatibility mode, and it does not interoperate with unmodified TLS stacks. DNSSEC validation is not performed; the client receives the DNS commitment as an input. The log, witnesses and recovery peers run in one process. Secure erasure of keys is best effort, since Go gives no zeroisation guarantee. FROST uses a trusted dealer, not DKG. The "monitor" mode of the coexistence policy (paper, Section 4.7) is specified but not implemented.

## Reproducing the paper

Requirements: Go 1.25.6, Python ≥ 3.10 with matplotlib (`pip install matplotlib`), Linux with `taskset` (util-linux) for CPU pinning. For the formal model: tamarin-prover 1.12 and Maude 3.5.

| Paper item | Source data | Command |
|---|---|---|
| Table 3 (bytes, signature checks, properties) | `results/handshakes.csv` | `make figures` → `results/generated/table1.tex` |
| Supplementary Table S3 (latency, client/server CPU, single-core handshakes/s) | `results/handshakes.csv` | `make figures` → `results/generated/table_cpu.tex` |
| Figure 5 | `results/handshakes.csv`, `results/netem.csv` | `make figures` → `results/generated/fig8.pdf` |
| Supplementary Table S6 (object sizes, TLV vs JSON) | `results/sizes.csv` | `make figures` → `results/generated/table_sizes.tex` |
| Baseline (c) certificate sizes (Supplementary Note *Byte counts and round trips*) | `results/certificates.csv` | `make figures` → macros in `numbers.tex` |
| Supplementary Table S7 (primitive microbenchmarks) | `results/primitives.csv` | `make figures` → `results/generated/table_prims.tex` |
| Every number quoted in the text | all of the above | `make figures` → `results/generated/numbers.tex` |
| Supplementary Table S4 and Figure 5c (network emulation) | `results/netem.csv`, `results/netem_env.csv` | `make figures` → `results/generated/table_netem.tex`, `fig8.pdf` |
| Re-measure everything (≈ 35 min) | — | `make bench && make bench-netem && make figures` |
| Symbolic analysis (Supplementary Table S2) | `formal/dit.spthy` | `make formal` |
| Unit and scenario tests | — | `make test` |

`make figures` is deterministic: a fresh clone regenerates the committed tables and number macros (`results/generated/*.tex`) byte for byte from the committed CSVs, and CI checks this. `fig8.pdf` is regenerated from the same CSV; its bytes can differ across matplotlib and font versions (the committed file was made with matplotlib 3.11.2), but its content does not. `results/previous/` holds an earlier complete run on the same machine, used in the paper to report run-to-run variation. `make bench` re-measures. Absolute timings depend on the machine; `results/env.csv` records the machine, Go version, commit and parameters of the committed run.

### Measurement setup

The server runs as a separate process pinned to one logical CPU (`-server-cpu`, default 4) with `GOMAXPROCS=1`. The load generator runs on the remaining CPUs (`-client-cpus`). Traffic goes over TCP on the loopback interface without emulated delay or loss, so these latencies are computation plus loopback cost. `make bench-netem` measures handshake completion times under network emulation: it runs in an unprivileged user and network namespace (`unshare -rn`, no root needed), sets the loopback MTU to 1500 bytes and applies `tc netem` with half the RTT as one-way delay and 0.1% loss per direction, at RTTs of 10, 40 and 150 ms (1,000 handshakes per configuration and RTT, 8 concurrent). Client and server share one machine. Each variant gets one handshake to count bytes, 1,000 warm-up handshakes, 10,000 measured sequential handshakes (latency percentiles and client CPU), and three 5-second windows with 12 concurrent clients that saturate the single-core server (server CPU per handshake from `/proc/<pid>/stat`; median reported, minimum and maximum kept in the CSV).

## Tests

```
make test
```

These cover: FROST signatures verify as Ed25519 for every t-subset and fail below threshold; Merkle inclusion and consistency proofs for all tree sizes up to 70; witness refusal of equivocating or invalid heads, and q-of-m quorum checks; every rotation rule, including the stolen-IK race (recovery supersedes a pending normal rotation), late detection (recovery still possible after the attacker's normal rotation), cancel quorum, bounded recovery-request spam, replay and rollback; pin resolution; and handshakes on the warm, new-epoch and cold paths in both encodings, with rejection of a wrong DNS commitment, a stale STH, q−1 cosignatures, a bad inclusion proof, foreign credentials, an EAK mismatch, tampered bytes and expired grace periods.

## History

The version submitted with the first manuscript (commit `82e8e8e`) did not match the paper. It used Ed25519 in place of ML-DSA-65 and X25519 in place of ML-KEM-768, `bench/bench_test.go` did not compile, and the reported numbers were not produced by the code. That version is superseded by this one. See the response to reviewers, comments R1.6 and R3.2.

## License

See `LICENSE`.
