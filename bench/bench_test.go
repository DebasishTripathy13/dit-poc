// Package bench provides Go benchmarks for the core DIT protocol operations.
// Run with: go test -bench=. -benchmem ./bench/
//
// These benchmarks measure the cryptographic cost of DIT operations in
// isolation (over net.Pipe, zero network latency). Production latency adds:
//   - DNS resolution: ~5ms (cold), <1ms (cached)
//   - Transparency log query: ~15-30ms (3 independent nodes)
//   - Network RTT: ~20-100ms depending on geography
package bench

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"testing"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/hkdf"

	"github.com/dit-protocol/poc/protocol"
	"github.com/dit-protocol/poc/transparency"
)

// ─── Setup helpers ─────────────────────────────────────────────────────────────

func mustGenerateIK(b *testing.B) protocol.IdentityKey {
	b.Helper()
	ik, err := protocol.GenerateIdentityKey()
	if err != nil {
		b.Fatalf("generate identity key: %v", err)
	}
	return ik
}

func mustDITRecord(b *testing.B, ik protocol.IdentityKey, domain string) protocol.DITRecord {
	b.Helper()
	return protocol.NewDITRecord(domain, ik, "witness.webtrust.org", "log1.webtrust.org")
}

// ─── BenchmarkDITHandshake ─────────────────────────────────────────────────────

// BenchmarkDITHandshake measures the full DIT handshake latency including:
//   - DIT_HELLO generation and signature verification
//   - Epoch Key derivation (if not cached — here we pre-derive for isolation)
//   - Client ephemeral KEM key generation
//   - X25519 key exchange (ML-KEM-768 placeholder)
//   - Session key derivation via HKDF
//
// Both client and server run in goroutines over a synchronous net.Pipe.
// This measures pure cryptographic cost with zero network latency.
func BenchmarkDITHandshake(b *testing.B) {
	const domain = "bench.example.com"
	ik := mustGenerateIK(b)
	record := mustDITRecord(b, ik, domain)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		clientConn, serverConn := net.Pipe()

		errCh := make(chan error, 2)

		go func() {
			_, err := protocol.Accept(serverConn, ik, domain)
			serverConn.Close()
			errCh <- err
		}()

		_, err := protocol.Handshake(clientConn, record)
		clientConn.Close()
		if err != nil {
			b.Fatalf("client handshake: %v", err)
		}

		if err := <-errCh; err != nil {
			b.Fatalf("server accept: %v", err)
		}
	}
}

// ─── BenchmarkEpochKeyDerivation ──────────────────────────────────────────────

// BenchmarkEpochKeyDerivation measures the cost of deriving an Epoch Key from
// an Identity Key using HKDF-SHA-256 (SHA3-256 in production) and generating
// an X25519 key pair (ML-KEM-768 key gen in production).
//
// This operation is performed once per 24 hours per domain, so its latency
// is not critical. The benchmark confirms it is fast enough to be non-blocking.
func BenchmarkEpochKeyDerivation(b *testing.B) {
	const domain = "bench.example.com"
	ik := mustGenerateIK(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := protocol.DeriveEpochKey(ik, domain)
		if err != nil {
			b.Fatalf("derive epoch key: %v", err)
		}
	}
}

// ─── BenchmarkSessionKeyDerivation ────────────────────────────────────────────

// BenchmarkSessionKeyDerivation measures the cost of the HKDF-based session
// key derivation step in isolation:
//   SK = HKDF(kem_secret || client_random || server_random, "DIT-SK:<domain>")
//
// This is called once per connection after the KEM exchange.
//
// PRODUCTION: Use HKDF-SHA3-256 as specified. Here SHA-256 is used as a stand-in.
func BenchmarkSessionKeyDerivation(b *testing.B) {
	// Simulate a 32-byte KEM shared secret (X25519 DH output).
	kemSecret := make([]byte, 32)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)
	rand.Read(kemSecret)
	rand.Read(clientRandom)
	rand.Read(serverRandom)

	info := []byte("DIT-SK:bench.example.com")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ikm := append(kemSecret, append(clientRandom, serverRandom...)...)
		reader := hkdf.New(sha256.New, ikm, nil, info)
		key := make([]byte, 32)
		if _, err := io.ReadFull(reader, key); err != nil {
			b.Fatalf("hkdf: %v", err)
		}
	}
}

// ─── BenchmarkMerkleProofVerify ────────────────────────────────────────────────

// BenchmarkMerkleProofVerify measures the cost of verifying a Merkle inclusion
// proof in the DIT transparency log. The tree is pre-populated with 1,000
// entries to exercise realistic tree depth (~10 levels).
//
// Merkle proof verification is O(log n) in the number of entries. For a log
// with 1M entries (~13 years of global IK rotations at estimated rates), proof
// depth is ~20 BLAKE3 hash operations, each taking ~100ns → ~2µs total.
func BenchmarkMerkleProofVerify(b *testing.B) {
	const treeSize = 1000
	const targetDomain = "bench.example.com"

	// Pre-populate the log.
	log := transparency.NewTransparencyLog()
	for i := 0; i < treeSize-1; i++ {
		_ = log.Submit(transparency.LogEntry{
			Type:     transparency.EntryKeyPublication,
			Domain:   "domain" + string(rune('0'+i%10)) + ".example.com",
			IKPublic: []byte("placeholder-key"),
		})
	}
	// Target entry is the last one.
	_ = log.Submit(transparency.LogEntry{
		Type:     transparency.EntryKeyPublication,
		Domain:   targetDomain,
		IKPublic: []byte("bench-ik-public-key"),
	})

	entry, proof, err := log.Query(targetDomain)
	if err != nil {
		b.Fatalf("query log: %v", err)
	}
	root := log.Root()

	// Sanity check before benchmarking.
	if !transparency.Verify(entry, proof, root) {
		b.Fatal("pre-benchmark verification failed")
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if !transparency.Verify(entry, proof, root) {
			b.Fatal("verification failed during benchmark")
		}
	}
}

// ─── BenchmarkBLAKE3Hash ──────────────────────────────────────────────────────

// BenchmarkBLAKE3Hash measures raw BLAKE3 hash throughput for 1KB input.
// BLAKE3 is the hash function used for all Merkle tree nodes in the DIT log.
// It is significantly faster than SHA-256 on modern hardware.
func BenchmarkBLAKE3Hash(b *testing.B) {
	data := make([]byte, 1024)
	rand.Read(data)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		h := blake3.New()
		h.Write(data)
		_ = h.Sum(nil)
	}
}

// ─── BenchmarkX25519ECDH ──────────────────────────────────────────────────────

// BenchmarkX25519ECDH measures the cost of a single X25519 key exchange,
// which is the KEM placeholder used in this PoC.
//
// PRODUCTION: Replace with ML-KEM-768 Encaps + Decaps benchmark.
// Expected ML-KEM-768 performance: ~50µs Encaps, ~50µs Decaps on modern CPUs.
func BenchmarkX25519ECDH(b *testing.B) {
	curve := ecdh.X25519()

	// Pre-generate the "server" static key (epoch key).
	serverKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("generate server key: %v", err)
	}
	serverPub := serverKey.PublicKey()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Generate ephemeral client key pair (done once per connection).
		clientKey, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatalf("generate client key: %v", err)
		}

		// Client performs ECDH with server's epoch public key.
		_, err = clientKey.ECDH(serverPub)
		if err != nil {
			b.Fatalf("client ECDH: %v", err)
		}

		// Server performs ECDH with client's ephemeral public key.
		_, err = serverKey.ECDH(clientKey.PublicKey())
		if err != nil {
			b.Fatalf("server ECDH: %v", err)
		}
	}
}

// ─── TestHandshakeCorrectness ──────────────────────────────────────────────────

// TestHandshakeCorrectness verifies that client and server derive identical
// session keys after a complete handshake. This is a functional correctness
// test, not a benchmark.
func TestHandshakeCorrectness(t *testing.T) {
	const domain = "test.example.com"
	ik, err := protocol.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("generate identity key: %v", err)
	}
	record := protocol.NewDITRecord(domain, ik, "witness.webtrust.org", "log1.webtrust.org")

	clientConn, serverConn := net.Pipe()

	type result struct {
		sk  protocol.SessionKey
		err error
	}
	serverCh := make(chan result, 1)
	clientCh := make(chan result, 1)

	go func() {
		sk, err := protocol.Accept(serverConn, ik, domain)
		serverConn.Close()
		serverCh <- result{sk, err}
	}()

	go func() {
		sk, err := protocol.Handshake(clientConn, record)
		clientConn.Close()
		clientCh <- result{sk, err}
	}()

	clientRes := <-clientCh
	serverRes := <-serverCh

	if clientRes.err != nil {
		t.Fatalf("client: %v", clientRes.err)
	}
	if serverRes.err != nil {
		t.Fatalf("server: %v", serverRes.err)
	}

	if len(clientRes.sk.Key) != 32 {
		t.Errorf("client session key length: got %d, want 32", len(clientRes.sk.Key))
	}
	if len(serverRes.sk.Key) != 32 {
		t.Errorf("server session key length: got %d, want 32", len(serverRes.sk.Key))
	}

	// The core correctness property: both sides must derive the same key.
	for i := range clientRes.sk.Key {
		if clientRes.sk.Key[i] != serverRes.sk.Key[i] {
			t.Errorf("session key mismatch at byte %d", i)
			break
		}
	}
}

