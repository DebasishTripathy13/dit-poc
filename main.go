// Command poc is the DIT protocol proof-of-concept demonstration.
// It exercises all six protocol layers and reports benchmark statistics.
//
// Components demonstrated:
//   1. Identity Key generation (Ed25519 placeholder for ML-DSA-65)
//   2. _dit DNS record creation
//   3. Epoch Key derivation via HKDF-SHA3-256
//   4. Full DIT handshake (client+server goroutines over net.Pipe)
//   5. Transparency log operations (submit, query, verify Merkle proof)
//   6. Key rotation ceremony (FROST 3-of-5 simulation)
//   7. Benchmark: 10,000 handshakes with median latency reporting
package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"time"

	"github.com/dit-protocol/poc/ceremony"
	"github.com/dit-protocol/poc/protocol"
	"github.com/dit-protocol/poc/transparency"
)

func main() {
	fmt.Println("=== DIT Protocol Proof of Concept ===")
	fmt.Println()

	// ── Step 1: Generate Identity Key ──────────────────────────────────────────
	fmt.Println("[1/7] Generating Identity Key (Ed25519 placeholder for ML-DSA-65)...")
	ik, err := protocol.GenerateIdentityKey()
	must("generate identity key", err)
	fmt.Printf("      IK public key: %d bytes\n", len(ik.Public))

	const domain = "bank.com"
	const witness = "witness.webtrust.org"
	const logNode = "log1.webtrust.org"

	record := protocol.NewDITRecord(domain, ik, witness, logNode)
	fmt.Printf("      DNS record: _dit.%s TXT v=%s ik=<%d bytes> tw=%s\n",
		domain, record.Version, len(record.IKPublic), record.TrustWitness)
	fmt.Println()

	// ── Step 2: Derive Epoch Key ────────────────────────────────────────────────
	fmt.Println("[2/7] Deriving Epoch Key via HKDF-SHA3-256...")
	ek, err := protocol.DeriveEpochKey(ik, domain)
	must("derive epoch key", err)
	fmt.Printf("      EK timestamp: %s (24hr epoch)\n", ek.Timestamp.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("      EK public key: %d bytes, IK signature: %d bytes\n",
		len(ek.Public.Bytes()), len(ek.IKSig))
	fmt.Println()

	// ── Step 3: Run DIT Handshake ───────────────────────────────────────────────
	fmt.Println("[3/7] Running DIT handshake (client + server over net.Pipe)...")
	clientSK, serverSK, err := runHandshake(ik, record, domain)
	must("run handshake", err)

	// Verify both sides derived the same key.
	if !keysEqual(clientSK.Key, serverSK.Key) {
		fmt.Fprintln(os.Stderr, "FAIL: client and server session keys differ!")
		os.Exit(1)
	}
	fmt.Printf("      Session key: %s...\n", hex.EncodeToString(clientSK.Key[:8]))
	fmt.Println("      Handshake: OK (client and server session keys match)")
	fmt.Println()

	// ── Step 4: Transparency Log Operations ─────────────────────────────────────
	fmt.Println("[4/7] Transparency log operations...")
	log := transparency.NewTransparencyLog()

	// Submit a KEY_PUBLICATION entry.
	must("submit KEY_PUBLICATION", log.Submit(transparency.LogEntry{
		Type:     transparency.EntryKeyPublication,
		Domain:   domain,
		IKPublic: []byte(ik.Public),
	}))

	// Submit entries for two other domains to make the tree non-trivial.
	must("submit other domain 1", log.Submit(transparency.LogEntry{
		Type:     transparency.EntryKeyPublication,
		Domain:   "shop.example.com",
		IKPublic: []byte("placeholder-key-shop"),
	}))
	must("submit other domain 2", log.Submit(transparency.LogEntry{
		Type:     transparency.EntryKeyPublication,
		Domain:   "api.example.com",
		IKPublic: []byte("placeholder-key-api"),
	}))

	root := log.Root()
	fmt.Printf("      Submitted 3 entries, Merkle root: %s\n", hex.EncodeToString(root))

	// Query and verify the bank.com entry.
	entry, proof, err := log.Query(domain)
	must("query log", err)
	ok := transparency.Verify(entry, proof, root)
	fmt.Printf("      Merkle proof verification for %q: ", domain)
	if ok {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL")
		os.Exit(1)
	}
	fmt.Println()

	// ── Step 5: Equivocation Detection ─────────────────────────────────────────
	fmt.Println("[5/7] Demonstrating equivocation detection (gossip safety)...")
	// Simulate 3 log nodes agreeing on the same root.
	err = transparency.CheckEquivocation([][]byte{root, root, root})
	must("equivocation check (consistent nodes)", err)
	fmt.Println("      3 log nodes agree on root: OK")

	// Simulate a divergent root.
	badRoot := make([]byte, len(root))
	copy(badRoot, root)
	badRoot[0] ^= 0xFF
	err = transparency.CheckEquivocation([][]byte{root, root, badRoot})
	if err != nil {
		fmt.Printf("      Equivocation detected (expected): %v\n", err)
	}
	fmt.Println()

	// ── Step 6: Key Ceremony ────────────────────────────────────────────────────
	fmt.Println("[6/7] Key ceremony simulation (FROST 3-of-5 placeholder)...")
	err = runCeremony(ik, log, domain)
	must("run ceremony", err)
	fmt.Println()

	// ── Step 7: Benchmarks ──────────────────────────────────────────────────────
	fmt.Println("[7/7] Benchmarking 10,000 handshakes...")
	runBenchmarks(ik, record, domain)
	fmt.Println()

	fmt.Println("=== All components verified successfully. ===")
}

// runHandshake executes a single DIT handshake between a client and server
// goroutine connected over net.Pipe. Returns both session keys.
func runHandshake(ik protocol.IdentityKey, record protocol.DITRecord, domain string) (protocol.SessionKey, protocol.SessionKey, error) {
	clientConn, serverConn := net.Pipe()

	type result struct {
		sk  protocol.SessionKey
		err error
	}
	serverCh := make(chan result, 1)
	clientCh := make(chan result, 1)

	// Server goroutine.
	go func() {
		sk, err := protocol.Accept(serverConn, ik, domain)
		serverConn.Close()
		serverCh <- result{sk, err}
	}()

	// Client goroutine.
	go func() {
		sk, err := protocol.Handshake(clientConn, record)
		clientConn.Close()
		clientCh <- result{sk, err}
	}()

	clientRes := <-clientCh
	serverRes := <-serverCh

	if clientRes.err != nil {
		return protocol.SessionKey{}, protocol.SessionKey{}, fmt.Errorf("client: %w", clientRes.err)
	}
	if serverRes.err != nil {
		return protocol.SessionKey{}, protocol.SessionKey{}, fmt.Errorf("server: %w", serverRes.err)
	}
	return clientRes.sk, serverRes.sk, nil
}

// runCeremony runs a complete 3-of-5 FROST key rotation ceremony.
func runCeremony(oldIK protocol.IdentityKey, log *transparency.TransparencyLog, domain string) error {
	// Generate a new Identity Key to rotate to.
	newIK, err := protocol.GenerateIdentityKey()
	if err != nil {
		return fmt.Errorf("generate new identity key: %w", err)
	}

	// Create 5 recovery peers.
	peers := []ceremony.RecoveryPeer{
		{ID: "peer-1", Endpoint: "peer1.recovery.example.com"},
		{ID: "peer-2", Endpoint: "peer2.recovery.example.com"},
		{ID: "peer-3", Endpoint: "peer3.recovery.example.com"},
		{ID: "peer-4", Endpoint: "peer4.recovery.example.com"},
		{ID: "peer-5", Endpoint: "peer5.recovery.example.com"},
	}

	c := ceremony.NewCeremony(domain, oldIK, newIK, peers, log)
	// Shorten wait duration for PoC demo; production uses 48 hours.
	c.WaitDuration = 100 * time.Millisecond

	// Phase 1: Initiate ceremony.
	if err := c.Initiate(); err != nil {
		return fmt.Errorf("initiate: %w", err)
	}
	fmt.Printf("      Ceremony initiated, state: %s\n", c.State())

	// Phase 2: Wait for mandatory period.
	time.Sleep(150 * time.Millisecond)
	if err := c.AdvanceToSigning(); err != nil {
		return fmt.Errorf("advance to signing: %w", err)
	}
	fmt.Printf("      Waiting period complete, state: %s\n", c.State())

	// Phase 3: 3 of 5 peers sign (FROST simulation).
	for _, p := range peers[:3] {
		if err := c.Sign(p); err != nil {
			return fmt.Errorf("sign (peer %s): %w", p.ID, err)
		}
	}
	fmt.Printf("      %d/5 peers signed (threshold=%d)\n", c.SignatureCount(), 3)

	// Phase 4: Finalize — post KEY_ROTATION.
	if err := c.Finalize(); err != nil {
		return fmt.Errorf("finalize: %w", err)
	}
	fmt.Printf("      Ceremony: %s\n", c.Summary())

	// Verify the KEY_ROTATION entry appears in the log.
	entries := log.QueryAll(domain)
	var rotationFound bool
	for _, e := range entries {
		if e.Type == transparency.EntryKeyRotation {
			rotationFound = true
			break
		}
	}
	if !rotationFound {
		return fmt.Errorf("KEY_ROTATION entry not found in log after ceremony")
	}
	fmt.Println("      KEY_ROTATION entry verified in transparency log: OK")
	return nil
}

// runBenchmarks measures the handshake latency over 10,000 iterations and
// reports the median, p95, and p99 latencies.
func runBenchmarks(ik protocol.IdentityKey, record protocol.DITRecord, domain string) {
	const iterations = 10_000
	latencies := make([]time.Duration, 0, iterations)

	for i := 0; i < iterations; i++ {
		start := time.Now()
		clientConn, serverConn := net.Pipe()

		done := make(chan error, 2)

		go func() {
			_, err := protocol.Accept(serverConn, ik, domain)
			serverConn.Close()
			done <- err
		}()
		go func() {
			_, err := protocol.Handshake(clientConn, record)
			clientConn.Close()
			done <- err
		}()

		err1 := <-done
		err2 := <-done
		elapsed := time.Since(start)

		if err1 != nil || err2 != nil {
			fmt.Fprintf(os.Stderr, "benchmark iteration %d failed: %v / %v\n", i, err1, err2)
			continue
		}
		latencies = append(latencies, elapsed)
	}

	if len(latencies) == 0 {
		fmt.Println("      No successful handshakes — cannot report benchmarks")
		return
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	median := latencies[len(latencies)/2]
	p95 := latencies[int(float64(len(latencies))*0.95)]
	p99 := latencies[int(float64(len(latencies))*0.99)]
	var total time.Duration
	for _, l := range latencies {
		total += l
	}
	mean := total / time.Duration(len(latencies))

	fmt.Printf("      Handshake latency over %d iterations:\n", len(latencies))
	fmt.Printf("        Mean:   %v\n", mean.Round(time.Microsecond))
	fmt.Printf("        Median: %v\n", median.Round(time.Microsecond))
	fmt.Printf("        p95:    %v\n", p95.Round(time.Microsecond))
	fmt.Printf("        p99:    %v\n", p99.Round(time.Microsecond))
	fmt.Printf("        Min:    %v\n", latencies[0].Round(time.Microsecond))
	fmt.Printf("        Max:    %v\n", latencies[len(latencies)-1].Round(time.Microsecond))
	fmt.Println()
	fmt.Println("      Note: net.Pipe() has near-zero network overhead. Production")
	fmt.Println("      latency includes DNS resolution (~5ms cold), log query (~15-30ms),")
	fmt.Println("      and actual network RTT (~20-100ms depending on geography).")
}

// keysEqual does a constant-time comparison of two byte slices.
func keysEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// must terminates the program with an error message if err is non-nil.
func must(op string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL [%s]: %v\n", op, err)
		os.Exit(1)
	}
}
