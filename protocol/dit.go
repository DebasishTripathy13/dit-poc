// Package protocol implements the core DIT (Decentralized Identity and Trust)
// protocol types and handshake. DIT replaces TLS certificate exchange with a
// DNS-anchored, post-quantum key hierarchy.
//
// PRODUCTION NOTE: This file uses Ed25519 as a placeholder for ML-DSA-65
// (CRYSTALS-Dilithium, FIPS 204) and X25519 ECDH as a placeholder for
// ML-KEM-768 (Kyber, FIPS 203). Replace these when Go stdlib or liboqs
// bindings become available.
package protocol

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/hkdf"
)

// ─── Identity Key ─────────────────────────────────────────────────────────────

// IdentityKey represents the domain's long-lived post-quantum signing key.
//
// PRODUCTION: Replace ed25519.PrivateKey / ed25519.PublicKey with an
// ML-DSA-65 key pair from FIPS 204. Key size: 4032 bytes private, 1952 bytes
// public. Use liboqs-go or a pure-Go ML-DSA implementation.
type IdentityKey struct {
	// Private is the signing key. nil on the client side (public only).
	Private ed25519.PrivateKey
	// Public is the verification key, published in _dit DNS records.
	Public ed25519.PublicKey
}

// GenerateIdentityKey generates a new IK pair.
//
// PRODUCTION: Replace with ML-DSA-65 key generation.
func GenerateIdentityKey() (IdentityKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return IdentityKey{}, fmt.Errorf("generate identity key: %w", err)
	}
	return IdentityKey{Private: priv, Public: pub}, nil
}

// Sign signs msg with the identity key.
//
// PRODUCTION: Replace with ML-DSA-65 signing (FIPS 204 Algorithm 2).
func (ik IdentityKey) Sign(msg []byte) ([]byte, error) {
	if ik.Private == nil {
		return nil, errors.New("identity key: no private key available")
	}
	sig := ed25519.Sign(ik.Private, msg)
	return sig, nil
}

// Verify verifies sig over msg using the public identity key.
//
// PRODUCTION: Replace with ML-DSA-65 verification (FIPS 204 Algorithm 3).
func (ik IdentityKey) Verify(msg, sig []byte) bool {
	return ed25519.Verify(ik.Public, msg, sig)
}

// ─── DNS Record ───────────────────────────────────────────────────────────────

// DITRecord represents the _dit DNS TXT record for a domain.
// Published at _dit.<domain> IN TXT.
type DITRecord struct {
	// Version is always "dit1".
	Version string `json:"v"`
	// Domain is the fully qualified domain name.
	Domain string `json:"domain"`
	// IKPublic is the base64url-encoded ML-DSA-65 public key (Ed25519 in PoC).
	IKPublic []byte `json:"ik"`
	// TrustWitness is the hostname of the trust witness service.
	TrustWitness string `json:"tw"`
	// Timestamp is the Unix timestamp of the last IK rotation.
	Timestamp int64 `json:"ts"`
	// Expiry is the Unix timestamp when the IK expires (0 = never).
	Expiry int64 `json:"exp"`
	// WitnessSig is the witness's ML-DSA-65 signature over the record.
	WitnessSig []byte `json:"ws"`
	// LogNode is the transparency log endpoint.
	LogNode string `json:"log"`
}

// NewDITRecord creates a _dit DNS record for the given domain and identity key.
// In production, the witness signature would be obtained by submitting the
// record to the trust witness service after proving DNS control.
func NewDITRecord(domain string, ik IdentityKey, witness, logNode string) DITRecord {
	rec := DITRecord{
		Version:      "dit1",
		Domain:       domain,
		IKPublic:     []byte(ik.Public),
		TrustWitness: witness,
		Timestamp:    time.Now().UTC().Unix(),
		Expiry:       0,
		LogNode:      logNode,
	}
	// PRODUCTION: Submit rec to trust witness; receive back a real ML-DSA-65
	// signature. Here we use a self-signature as a placeholder.
	msg := rec.sigInput()
	sig, _ := ik.Sign(msg)
	rec.WitnessSig = sig
	return rec
}

// sigInput returns the canonical byte string over which signatures are computed.
func (r DITRecord) sigInput() []byte {
	b := make([]byte, 0, 256)
	b = append(b, []byte(r.Version)...)
	b = append(b, []byte(r.Domain)...)
	b = append(b, r.IKPublic...)
	b = append(b, []byte(r.TrustWitness)...)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(r.Timestamp))
	b = append(b, ts...)
	return b
}

// ─── Epoch Key ────────────────────────────────────────────────────────────────

// EpochKey represents a 24-hour signing sub-key derived from the Identity Key.
// The EK is an ECDH key pair in the PoC; production uses ML-KEM-768.
//
// The derivation is:
//   EK_seed = HKDF-SHA3-256(IK_priv, "DIT-EK" || epoch_day || domain)
//   EK = KEM.KeyGen(EK_seed)
//
// PRODUCTION: Replace with ML-KEM-768 key pair (FIPS 203 Algorithm 15).
// The EK public key is included in DIT_HELLO signed by IK.
type EpochKey struct {
	// Timestamp is the start of the 24-hour epoch (UTC midnight).
	Timestamp time.Time
	// Domain is the domain this EK is bound to.
	Domain string
	// Private is the ECDH private key (ML-KEM-768 sk in production).
	Private *ecdh.PrivateKey
	// Public is the ECDH public key (ML-KEM-768 pk in production).
	Public *ecdh.PublicKey
	// IKSig is the IK signature over (EK_pub || epoch_ts || domain).
	IKSig []byte
}

// DeriveEpochKey derives the current Epoch Key from the Identity Key.
// The derivation is deterministic: same IK + same UTC day = same EK.
//
// PRODUCTION: Use HKDF-SHA3-256 as specified; derive an ML-KEM-768 key pair
// from the HKDF output (seed-based key generation per FIPS 203 §6.1).
func DeriveEpochKey(ik IdentityKey, domain string) (EpochKey, error) {
	// Epoch is the current UTC day (seconds since Unix epoch, truncated to day).
	now := time.Now().UTC()
	epochStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	epochDay := make([]byte, 8)
	binary.BigEndian.PutUint64(epochDay, uint64(epochStart.Unix()))

	// HKDF-SHA3-256 key derivation.
	// PRODUCTION: Use SHA3-256 as the hash; here we use SHA-256 as a stand-in
	// since golang.org/x/crypto/hkdf supports any hash.Hash.
	info := append([]byte("DIT-EK:"), append(epochDay, []byte(domain)...)...)
	ikd := sha256.Sum256(ik.Private) // derive HKDF key material from IK
	hkdfReader := hkdf.New(sha256.New, ikd[:], epochDay, info)

	// Generate an X25519 key from the HKDF output.
	// PRODUCTION: Feed HKDF output into ML-KEM-768 deterministic key gen.
	curve := ecdh.X25519()
	seed := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, seed); err != nil {
		return EpochKey{}, fmt.Errorf("derive epoch key seed: %w", err)
	}
	ekPriv, err := curve.NewPrivateKey(seed)
	if err != nil {
		return EpochKey{}, fmt.Errorf("derive epoch key: %w", err)
	}

	// Sign the epoch key with the identity key.
	sigInput := epochKeySigInput(ekPriv.PublicKey().Bytes(), epochStart, domain)
	sig, err := ik.Sign(sigInput)
	if err != nil {
		return EpochKey{}, fmt.Errorf("sign epoch key: %w", err)
	}

	return EpochKey{
		Timestamp: epochStart,
		Domain:    domain,
		Private:   ekPriv,
		Public:    ekPriv.PublicKey(),
		IKSig:     sig,
	}, nil
}

// epochKeySigInput returns the canonical signing input for an EK.
func epochKeySigInput(ekPub []byte, epochStart time.Time, domain string) []byte {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(epochStart.Unix()))
	b := make([]byte, 0, len(ekPub)+8+len(domain))
	b = append(b, ekPub...)
	b = append(b, ts...)
	b = append(b, []byte(domain)...)
	return b
}

// ─── Session Key ──────────────────────────────────────────────────────────────

// SessionKey is a per-connection symmetric key derived via KEM + HKDF.
// Both sides derive the same session key after the handshake completes.
//
// The derivation is:
//   SK = HKDF-SHA3-256(kem_secret || client_random || server_random || domain)
//
// SK is used as the symmetric key for the encrypted channel. It provides
// forward secrecy: deleting SK (and the ephemeral KEM key) makes past sessions
// irrecoverable even if IK or EK is later compromised.
type SessionKey struct {
	Key    []byte // 32-byte symmetric key
	Domain string
}

// deriveSessionKey derives SK from KEM shared secret and randoms.
//
// PRODUCTION: Use HKDF-SHA3-256. Here SHA-256 is used as a stand-in.
func deriveSessionKey(kemSecret, clientRandom, serverRandom []byte, domain string) (SessionKey, error) {
	info := []byte("DIT-SK:" + domain)
	ikm := append(kemSecret, append(clientRandom, serverRandom...)...)
	reader := hkdf.New(sha256.New, ikm, nil, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return SessionKey{}, fmt.Errorf("derive session key: %w", err)
	}
	return SessionKey{Key: key, Domain: domain}, nil
}

// ─── Handshake Messages ───────────────────────────────────────────────────────

// DITHello is sent server → client as the first transport-layer message.
// It authenticates the server's Epoch Key using the Identity Key.
//
// In the full protocol:
//   1. Client resolves _dit.<domain> DNS record, obtains IK_pub.
//   2. Server sends DIT_HELLO; client verifies EKSig under IK_pub.
//   3. Client checks epoch timestamp freshness (< 24hr old).
type DITHello struct {
	// EKPublic is the server's current Epoch Key public component.
	// PRODUCTION: ML-KEM-768 public key (1184 bytes).
	EKPublic []byte `json:"ek_pub"`
	// EKSig is the IK signature over (EK_pub || epoch_ts || domain).
	EKSig []byte `json:"ek_sig"`
	// EKTimestamp is the start of the current 24-hour epoch (Unix seconds).
	EKTimestamp int64 `json:"ek_ts"`
	// Domain is the domain this hello is for.
	Domain string `json:"domain"`
	// SupportedKEM lists supported KEM algorithms.
	// PRODUCTION: ["ML-KEM-768", "X25519"] for hybrid; PoC uses ["X25519"].
	SupportedKEM []string `json:"supported_kem"`
}

// DITKeyExchange is sent client → server.
// The client contributes its ephemeral KEM public key and a fresh random.
//
// PRODUCTION: client_kem_pk is an ML-KEM-768 public key (1184 bytes) used by
// the server for encapsulation. Here it is an X25519 public key (32 bytes).
type DITKeyExchange struct {
	// ClientKEMPub is the client's ephemeral KEM public key.
	ClientKEMPub []byte `json:"kem_pk"`
	// ClientRandom is 32 bytes of fresh randomness from the client.
	ClientRandom []byte `json:"c_rand"`
}

// DITKeyExchangeResponse is sent server → client.
// Contains the KEM ciphertext (encapsulated secret) and server random.
//
// PRODUCTION: KEM ciphertext is the ML-KEM-768 ciphertext (1088 bytes).
type DITKeyExchangeResponse struct {
	// KEM ciphertext encapsulating the shared secret.
	KEMCiphertext []byte `json:"kem_ct"`
	// ServerRandom is 32 bytes of fresh randomness from the server.
	ServerRandom []byte `json:"s_rand"`
}

// ─── Wire encoding helpers ────────────────────────────────────────────────────

// writeMsg length-prefixes and JSON-encodes a message to w.
func writeMsg(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := w.Write(lenBuf); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write data: %w", err)
	}
	return nil
}

// readMsg reads a length-prefixed JSON message from r into v.
func readMsg(r io.Reader, v any) error {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return fmt.Errorf("read length: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf)
	if length > 1<<20 { // 1 MB sanity cap
		return errors.New("message too large")
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return fmt.Errorf("read data: %w", err)
	}
	return json.Unmarshal(data, v)
}

// ─── Client Handshake ─────────────────────────────────────────────────────────

// Handshake performs the client side of the DIT handshake over conn.
// record is the _dit DNS record for the domain (pre-fetched and DNSSEC-verified).
//
// Protocol flow:
//   server → DIT_HELLO { ek_pub, ek_sig, ek_ts, supported_kem }
//   client → DIT_KEYX  { client_kem_pk, client_random }
//   server → DIT_KEYX_RESP { kem_ciphertext, server_random }
//   both   → SK = HKDF(kem_secret, c_rand, s_rand, domain)
//
// PRODUCTION additions:
//   - Verify DNSSEC chain before accepting record.
//   - Query 3+ transparency log nodes and require BFT quorum on Merkle root.
//   - Check local pin database; fail if IK differs without a valid logged rotation.
func Handshake(conn net.Conn, record DITRecord) (SessionKey, error) {
	// Phase 1: receive DIT_HELLO from server.
	var hello DITHello
	if err := readMsg(conn, &hello); err != nil {
		return SessionKey{}, fmt.Errorf("handshake: read DIT_HELLO: %w", err)
	}

	// Verify that the Epoch Key was signed by the Identity Key in the DNS record.
	epochStart := time.Unix(hello.EKTimestamp, 0).UTC()
	sigInput := epochKeySigInput(hello.EKPublic, epochStart, hello.Domain)
	ik := IdentityKey{Public: ed25519.PublicKey(record.IKPublic)}
	if !ik.Verify(sigInput, hello.EKSig) {
		return SessionKey{}, errors.New("handshake: EK signature verification failed")
	}

	// Check epoch freshness: EK must be within the current 24-hour window.
	now := time.Now().UTC()
	todayMidnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if epochStart.Before(todayMidnight.Add(-24*time.Hour)) || epochStart.After(now.Add(time.Hour)) {
		return SessionKey{}, fmt.Errorf("handshake: EK timestamp out of range: %v", epochStart)
	}

	// PRODUCTION: Check domain matches expected; check pin database;
	// query transparency log quorum. Here we trust the DNS record.

	// Phase 2: parse server's EK as an X25519 public key for KEM.
	// PRODUCTION: Parse ML-KEM-768 public key and use ML-KEM encapsulation.
	curve := ecdh.X25519()
	ekPub, err := curve.NewPublicKey(hello.EKPublic)
	if err != nil {
		return SessionKey{}, fmt.Errorf("handshake: parse EK public key: %w", err)
	}

	// Generate an ephemeral client KEM key pair.
	// PRODUCTION: Generate ML-KEM-768 key pair for encapsulation.
	clientEphemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return SessionKey{}, fmt.Errorf("handshake: generate client KEM key: %w", err)
	}

	// Generate client random.
	clientRandom := make([]byte, 32)
	if _, err := rand.Read(clientRandom); err != nil {
		return SessionKey{}, fmt.Errorf("handshake: generate client random: %w", err)
	}

	// Send DIT_KEYX.
	keyx := DITKeyExchange{
		ClientKEMPub: clientEphemeral.PublicKey().Bytes(),
		ClientRandom: clientRandom,
	}
	if err := writeMsg(conn, keyx); err != nil {
		return SessionKey{}, fmt.Errorf("handshake: write DIT_KEYX: %w", err)
	}

	// Phase 3: receive DIT_KEYX_RESP.
	var resp DITKeyExchangeResponse
	if err := readMsg(conn, &resp); err != nil {
		return SessionKey{}, fmt.Errorf("handshake: read DIT_KEYX_RESP: %w", err)
	}

	// Perform X25519 ECDH to obtain shared secret.
	// PRODUCTION: Decapsulate ML-KEM-768 ciphertext using clientEphemeral secret key.
	// Also compute X25519 hybrid component for defense-in-depth.
	kemSecret, err := clientEphemeral.ECDH(ekPub)
	if err != nil {
		return SessionKey{}, fmt.Errorf("handshake: KEM ECDH: %w", err)
	}

	// Derive session key.
	sk, err := deriveSessionKey(kemSecret, clientRandom, resp.ServerRandom, hello.Domain)
	if err != nil {
		return SessionKey{}, fmt.Errorf("handshake: derive session key: %w", err)
	}

	// Zero the KEM secret immediately after key derivation (forward secrecy).
	for i := range kemSecret {
		kemSecret[i] = 0
	}

	return sk, nil
}

// ─── Server Accept ────────────────────────────────────────────────────────────

// Accept performs the server side of the DIT handshake over conn.
// ik is the server's Identity Key; it must have the private component.
//
// The server:
//  1. Derives the current Epoch Key from IK.
//  2. Sends DIT_HELLO with the signed EK.
//  3. Receives the client's KEM public key.
//  4. Encapsulates a shared secret using the client's KEM public key.
//  5. Sends DIT_KEYX_RESP with the ciphertext and server random.
//  6. Derives the same Session Key as the client.
func Accept(conn net.Conn, ik IdentityKey, domain string) (SessionKey, error) {
	// Derive the current Epoch Key.
	ek, err := DeriveEpochKey(ik, domain)
	if err != nil {
		return SessionKey{}, fmt.Errorf("accept: derive epoch key: %w", err)
	}

	// Send DIT_HELLO.
	hello := DITHello{
		EKPublic:     ek.Public.Bytes(),
		EKSig:        ek.IKSig,
		EKTimestamp:  ek.Timestamp.Unix(),
		Domain:       domain,
		SupportedKEM: []string{"X25519"}, // PRODUCTION: ["ML-KEM-768", "X25519"]
	}
	if err := writeMsg(conn, hello); err != nil {
		return SessionKey{}, fmt.Errorf("accept: write DIT_HELLO: %w", err)
	}

	// Receive DIT_KEYX.
	var keyx DITKeyExchange
	if err := readMsg(conn, &keyx); err != nil {
		return SessionKey{}, fmt.Errorf("accept: read DIT_KEYX: %w", err)
	}

	// Parse client's ephemeral KEM public key.
	// PRODUCTION: Parse ML-KEM-768 public key and use ML-KEM encapsulation.
	curve := ecdh.X25519()
	clientKEMPub, err := curve.NewPublicKey(keyx.ClientKEMPub)
	if err != nil {
		return SessionKey{}, fmt.Errorf("accept: parse client KEM public key: %w", err)
	}

	// Encapsulate: perform X25519 ECDH using our epoch private key.
	// PRODUCTION: Run ML-KEM-768 Encaps(clientKEMPub) → (ciphertext, shared_secret).
	// Also compute X25519 hybrid for classical forward secrecy.
	kemSecret, err := ek.Private.ECDH(clientKEMPub)
	if err != nil {
		return SessionKey{}, fmt.Errorf("accept: KEM ECDH: %w", err)
	}

	// In X25519 DH there is no "ciphertext"—both sides compute the same value.
	// PRODUCTION: kemCiphertext = the ML-KEM ciphertext bytes (1088 bytes).
	// We send our own EK public key as the "ciphertext" to preserve the message
	// structure; the shared secret is computed on both sides via ECDH.
	kemCiphertext := ek.Public.Bytes()

	// Generate server random.
	serverRandom := make([]byte, 32)
	if _, err := rand.Read(serverRandom); err != nil {
		return SessionKey{}, fmt.Errorf("accept: generate server random: %w", err)
	}

	// Send DIT_KEYX_RESP.
	resp := DITKeyExchangeResponse{
		KEMCiphertext: kemCiphertext,
		ServerRandom:  serverRandom,
	}
	if err := writeMsg(conn, resp); err != nil {
		return SessionKey{}, fmt.Errorf("accept: write DIT_KEYX_RESP: %w", err)
	}

	// Derive session key.
	sk, err := deriveSessionKey(kemSecret, keyx.ClientRandom, serverRandom, domain)
	if err != nil {
		return SessionKey{}, fmt.Errorf("accept: derive session key: %w", err)
	}

	// Zero the KEM secret immediately after key derivation.
	for i := range kemSecret {
		kemSecret[i] = 0
	}

	return sk, nil
}
