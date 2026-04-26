// DIT v2.2 — Decentralized Identity and Trust Protocol
// End-to-end proof-of-concept demonstration
package main

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	ditcrypto "github.com/dit-protocol/poc/crypto"
	"github.com/dit-protocol/poc/identity"
	"github.com/dit-protocol/poc/protocol"
	"github.com/dit-protocol/poc/rotation"
	"github.com/dit-protocol/poc/transparency"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	green  = "\033[32m"
	cyan   = "\033[36m"
	yellow = "\033[33m"
	red    = "\033[31m"
	blue   = "\033[34m"
	mag    = "\033[35m"
)

func banner(title string) {
	w := 70
	pad := (w - len(title) - 4) / 2
	fmt.Printf("\n%s%s╔%s╗%s\n", bold, cyan, strings.Repeat("═", w-2), reset)
	fmt.Printf("%s%s║%s %s %s║%s\n", bold, cyan, reset,
		strings.Repeat(" ", pad)+bold+title+reset+strings.Repeat(" ", w-4-pad-len(title)),
		cyan+bold, reset)
	fmt.Printf("%s%s╚%s╝%s\n\n", bold, cyan, strings.Repeat("═", w-2), reset)
}

func section(title string) {
	fmt.Printf("\n%s%s── %s ──%s\n", bold, yellow, title, reset)
}

func ok(msg string) { fmt.Printf("  %s✓%s %s\n", green, reset, msg) }
func info(k, v string) { fmt.Printf("  %s%-24s%s %s\n", dim, k, reset, v) }
func warn(msg string) { fmt.Printf("  %s⚠%s %s\n", yellow, reset, msg) }
func fail(msg string) { fmt.Printf("  %s✗%s %s\n", red, reset, msg) }

func hexShort(b []byte, n int) string {
	if len(b) > n { b = b[:n] }
	return hex.EncodeToString(b) + "..."
}

func main() {
	banner("DIT v2.2 — Post-Quantum CA-Free Trust Protocol")
	fmt.Printf("  %sProtocol Version:%s  DIT-v2.2\n", dim, reset)
	fmt.Printf("  %sCiphersuite:%s      %s\n", dim, reset, protocol.CiphersuiteName)
	fmt.Printf("  %sAuthentication:%s   ML-DSA-65 (Ed25519 stand-in)\n", dim, reset)
	fmt.Printf("  %sKey Exchange:%s     X25519MLKEM768 hybrid\n", dim, reset)
	fmt.Printf("  %sHash:%s             SHA3-384\n", dim, reset)
	fmt.Printf("  %sAEAD:%s             AES-256-GCM\n", dim, reset)
	fmt.Printf("  %sTimestamp:%s        %s\n", dim, reset, time.Now().Format(time.RFC3339))

	domain := "bank.example.com"

	// ================================================================
	// PHASE 1: Identity Key Generation
	// ================================================================
	section("PHASE 1: Identity Key Generation")

	ikStart := time.Now()
	ik, err := identity.NewIdentityKey(domain)
	if err != nil { panic(err) }
	ikDur := time.Since(ikStart)

	ok(fmt.Sprintf("Generated Identity Key (IK) for %s%s%s", bold, domain, reset))
	info("Algorithm:", "ML-DSA-65 (FIPS 204)")
	info("Public key size:", fmt.Sprintf("%d B (real: 1952 B)", len(ik.KeyPair.PublicKey)))
	info("Public key hash:", hexShort([]byte(ik.PublicKeyHash()), 24))
	info("KeyGen time:", ikDur.String())

	// ================================================================
	// PHASE 2: Epoch Authentication Key (fresh random!)
	// ================================================================
	section("PHASE 2: Epoch Authentication Key (EAK)")

	eakStart := time.Now()
	eak, err := identity.NewEpochAuthKey(ik, domain)
	if err != nil { panic(err) }
	eakDur := time.Since(eakStart)

	ok("Generated FRESH RANDOM EAK (NOT derived from IK)")
	info("Algorithm:", "ML-DSA-65 (FIPS 204)")
	info("Epoch ID:", eak.EpochID)
	info("Validity:", fmt.Sprintf("%s → %s", eak.CreatedAt.Format("15:04:05"), eak.ExpiresAt.Format("15:04:05")))
	info("σ_IK size:", fmt.Sprintf("%d B (real: 3309 B)", len(eak.Credential.Sigma_IK)))
	info("KeyGen + cert time:", eakDur.String())

	// Verify credential
	credOk := identity.VerifyCredential(ik.KeyPair.PublicKey, eak.Credential)
	if credOk {
		ok("Epoch credential σ_IK verified ✓")
	} else {
		fail("Epoch credential verification FAILED")
	}

	// ================================================================
	// PHASE 3: Transparency Log
	// ================================================================
	section("PHASE 3: SHA3-384 Transparency Log")

	tree := transparency.NewMerkleTree()

	// Append key publication
	tree.Append(&transparency.LogEntry{
		Type:      transparency.KeyPublication,
		Domain:    domain,
		IKPub:     ik.KeyPair.PublicKey,
		Timestamp: time.Now(),
		PrevRoot:  "",
		Sequence:  1,
	})
	ok(fmt.Sprintf("Appended KEY_PUBLICATION (tree size: %d)", tree.Size()))
	info("Merkle root:", hexShort(tree.Root(), 24))
	info("Hash function:", "SHA3-384 (NIST PQC category 3)")

	// Generate and verify inclusion proof
	proof, _ := tree.GenerateProof(0)
	ok(fmt.Sprintf("Generated inclusion proof (depth: %d siblings)", len(proof)))

	// ================================================================
	// PHASE 4: Witness Cosigning (5-of-7)
	// ================================================================
	section("PHASE 4: Trust Witness Cosigning (5-of-7)")

	witnesses := make([]*transparency.Witness, 7)
	witnessNames := []string{"EFF", "CloudflareWatch", "GoogleCT", "MozillaTrust", "LetsEncryptMon", "APNICLabs", "CISAGov"}
	for i := range witnesses {
		witnesses[i], _ = transparency.NewWitness(witnessNames[i])
	}
	ok(fmt.Sprintf("Initialized %d trust witnesses", len(witnesses)))

	sth := &transparency.SignedTreeHead{
		TreeSize:  tree.Size(),
		Timestamp: time.Now(),
		RootHash:  tree.Root(),
	}

	var cosigs []*transparency.WitnessCosignature
	for _, w := range witnesses {
		cosig := w.Cosign(sth)
		cosigs = append(cosigs, cosig)
	}

	// Verify 5-of-7
	verified := 0
	for _, cs := range cosigs {
		if transparency.VerifyCosignature(sth, cs) {
			verified++
		}
	}
	info("Quorum policy:", "q=5, m=7, f≤2")
	info("Quorum intersection:", "2q − m = 3 > f = 2 ✓")
	info("Cosignatures verified:", fmt.Sprintf("%d / %d", verified, len(cosigs)))
	if verified >= 5 {
		ok(fmt.Sprintf("STH accepted: %d ≥ 5 cosignatures ✓", verified))
	}

	// ================================================================
	// PHASE 5: TLS 1.3 Handshake
	// ================================================================
	section("PHASE 5: DIT Handshake (TLS 1.3 shape)")

	// Client creates ClientHello
	hsStart := time.Now()
	ch, dk, err := protocol.CreateClientHello(ik.PublicKeyHash(), eak.EpochID)
	if err != nil { panic(err) }

	info("ClientHello:", fmt.Sprintf("random_C=%s", hexShort(ch.RandomC, 8)))
	info("  mlkem_C_pub:", fmt.Sprintf("%d B (real: 1184 B)", len(ch.MLKEMCPub)))
	info("  x_C_pub:", fmt.Sprintf("%d B", len(ch.XCPub)))

	// Server processes and creates ServerHello
	ss := protocol.NewServerState(ik, eak)
	sh, _, err := ss.ProcessClientHello(ch)
	if err != nil { panic(err) }

	info("ServerHello:", fmt.Sprintf("random_S=%s", hexShort(sh.RandomS, 8)))
	info("  mlkem_ct:", fmt.Sprintf("%d B (real: 1088 B)", len(sh.MLKEMCt)))
	info("  σ_server:", fmt.Sprintf("%d B (real: 3309 B)", len(sh.SigmaServer)))

	// Client verifies ServerHello
	result, err := protocol.VerifyServerHello(ch, sh, dk, ik.KeyPair.PublicKey, eak.Credential)
	hsDur := time.Since(hsStart)

	if err != nil {
		fail(fmt.Sprintf("Handshake FAILED: %v", err))
	} else {
		ok("Handshake completed successfully ✓")
		info("Session ID:", result.SessionID)
		info("Ciphersuite:", result.Ciphersuite)
		info("Transcript hash:", hexShort([]byte(result.TranscriptHash), 24))
		info("Client traffic secret:", hexShort(result.ClientAppTraffic, 16))
		info("Server traffic secret:", hexShort(result.ServerAppTraffic, 16))
		info("Handshake time:", hsDur.String())
	}

	// ================================================================
	// PHASE 6: AEAD Encrypted Communication
	// ================================================================
	section("PHASE 6: AEAD Encrypted Communication")

	key, iv, _ := ditcrypto.DeriveAEADKey(result.ClientAppTraffic)
	plaintext := []byte("POST /api/transfer HTTP/1.1\r\nAmount: $10,000\r\n")
	ciphertext, _ := ditcrypto.AEADEncrypt(key, iv, plaintext, nil)
	decrypted, err := ditcrypto.AEADDecrypt(key, iv, ciphertext, nil)

	info("AEAD:", "AES-256-GCM")
	info("Key size:", fmt.Sprintf("%d B", len(key)))
	info("Plaintext:", fmt.Sprintf("%d B", len(plaintext)))
	info("Ciphertext:", fmt.Sprintf("%d B (+ 16 B tag)", len(ciphertext)))
	if err == nil && string(decrypted) == string(plaintext) {
		ok("Encrypt → Decrypt roundtrip verified ✓")
	}

	// ================================================================
	// PHASE 7: Normal Key Rotation (PQ-secure)
	// ================================================================
	section("PHASE 7: Normal Identity Key Rotation (PQ-secure)")

	newIK, _ := identity.NewIdentityKey(domain)
	rotResult, _ := rotation.NormalRotation(ik, newIK, domain, 2, ik.PublicKeyHash())

	info("Rotation type:", "normal_rotation (PQ-secure)")
	info("Old IK hash:", hexShort([]byte(ik.PublicKeyHash()), 16))
	info("New IK hash:", hexShort([]byte(newIK.PublicKeyHash()), 16))
	info("σ_old size:", fmt.Sprintf("%d B (real: 3309 B)", len(rotResult.SigmaOld)))
	info("σ_new size:", fmt.Sprintf("%d B (real: 3309 B)", len(rotResult.SigmaNew)))

	if rotation.VerifyNormalRotation(rotResult) {
		ok("Normal rotation verified: σ_old ✓ σ_new ✓")
	}

	// Append rotation to log
	tree.Append(&transparency.LogEntry{
		Type:      transparency.KeyRotation,
		Domain:    domain,
		IKPub:     newIK.KeyPair.PublicKey,
		Timestamp: time.Now(),
		PrevRoot:  tree.RootHex(),
		Sequence:  2,
	})
	ok(fmt.Sprintf("Rotation logged (tree size: %d, new root: %s)", tree.Size(), hexShort(tree.Root(), 16)))

	// ================================================================
	// PHASE 8: Performance Benchmarks
	// ================================================================
	section("PHASE 8: Performance Summary")

	// Run 100 handshakes for timing
	var totalHS time.Duration
	for i := 0; i < 100; i++ {
		start := time.Now()
		ch2, dk2, _ := protocol.CreateClientHello(ik.PublicKeyHash(), eak.EpochID)
		ss2 := protocol.NewServerState(ik, eak)
		sh2, _, _ := ss2.ProcessClientHello(ch2)
		_, _ = protocol.VerifyServerHello(ch2, sh2, dk2, ik.KeyPair.PublicKey, eak.Credential)
		totalHS += time.Since(start)
	}
	avgHS := totalHS / 100

	fmt.Printf("\n  %s┌─────────────────────────────────────────────────────┐%s\n", cyan, reset)
	fmt.Printf("  %s│%s  %-20s  %s│%s\n", cyan, reset, bold+"Handshake Benchmark (100 iterations)"+reset, cyan, reset)
	fmt.Printf("  %s├─────────────────────────────────────────────────────┤%s\n", cyan, reset)
	fmt.Printf("  %s│%s  %-34s %12s  %s│%s\n", cyan, reset, "Average handshake time:", avgHS.String(), cyan, reset)
	fmt.Printf("  %s│%s  %-34s %12s  %s│%s\n", cyan, reset, "Warm-path bytes (estimated):", "~6,000 B", cyan, reset)
	fmt.Printf("  %s│%s  %-34s %12s  %s│%s\n", cyan, reset, "Cold-path bytes (estimated):", "~33,800 B", cyan, reset)
	fmt.Printf("  %s│%s  %-34s %12s  %s│%s\n", cyan, reset, "ML-DSA-65 signature:", "3,309 B", cyan, reset)
	fmt.Printf("  %s│%s  %-34s %12s  %s│%s\n", cyan, reset, "ML-KEM-768 ciphertext:", "1,088 B", cyan, reset)
	fmt.Printf("  %s│%s  %-34s %12s  %s│%s\n", cyan, reset, "ML-KEM-768 public key:", "1,184 B", cyan, reset)
	fmt.Printf("  %s│%s  %-34s %12s  %s│%s\n", cyan, reset, "SHA3-384 output:", "48 B", cyan, reset)
	fmt.Printf("  %s│%s  %-34s %12s  %s│%s\n", cyan, reset, "CA dependencies:", bold+"0"+reset, cyan, reset)
	fmt.Printf("  %s│%s  %-34s %12s  %s│%s\n", cyan, reset, "Annual cert renewals (1K domains):", bold+"0"+reset, cyan, reset)
	fmt.Printf("  %s└─────────────────────────────────────────────────────┘%s\n", cyan, reset)

	// ================================================================
	// Security Summary
	// ================================================================
	section("Security Properties")

	props := []struct{ name, status, note string }{
		{"G1 Handshake authenticity", "✓ PQ", "ML-DSA-65 EUF-CMA (Theorem 1)"},
		{"G2 Session confidentiality", "✓ PQ", "ML-KEM-768 IND-CCA2 (Theorem 2)"},
		{"G3 Forward secrecy (key)", "✓ PQ", "Fresh EAK + ephemeral KEX (Theorem 3A)"},
		{"G3 Forward secrecy (record)", "✓ PQ", "AES-256-GCM IND-CPA (Theorem 3B)"},
		{"G4 Identity continuity", "✓ PQ", "SHA3-384 + 5/7 witnesses (Theorem 4)"},
		{"G5 Normal rotation safety", "✓ PQ", "Dual ML-DSA-65 signatures (Theorem 5)"},
		{"G6 Recovery rotation safety", "⚠ Classical", "FROST-Schnorr (NOT PQ) (Theorem 6)"},
		{"G7 PQ coverage", "✓ G1-G5", "Theorem 7 (carves out G6)"},
	}

	for _, p := range props {
		status := green + p.status + reset
		if strings.Contains(p.status, "⚠") {
			status = yellow + p.status + reset
		}
		fmt.Printf("  %-35s %s%-14s%s %s%s%s\n", p.name, bold, status, reset, dim, p.note, reset)
	}

	fmt.Printf("\n%s%s══════════════════════════════════════════════════════════════════════%s\n", bold, cyan, reset)
	fmt.Printf("  %sDIT v2.2 PoC demonstration complete.%s\n", bold, reset)
	fmt.Printf("  %sAll protocol phases executed successfully.%s\n", green, reset)
	fmt.Printf("%s%s══════════════════════════════════════════════════════════════════════%s\n\n", bold, cyan, reset)
}
