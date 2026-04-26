// Package protocol implements the DIT v2.2 TLS 1.3-shaped handshake.
package protocol

import (
	"encoding/hex"
	"fmt"
	"time"

	ditcrypto "github.com/dit-protocol/poc/crypto"
	"github.com/dit-protocol/poc/identity"
)

// Ciphersuite name (canonical, per review §3.4)
const CiphersuiteName = "DIT_AES_256_GCM_SHA3_384"

// ClientHello represents a DIT v2.2 ClientHello message.
type ClientHello struct {
	RandomC       []byte // 32 B
	MLKEMCPub     []byte // 1184 B (ML-KEM-768 encapsulation key)
	XCPub         []byte // 32 B (X25519 public, simulated)
	Suites        []string
	IdentityHash  string
	EpochCredID   string
}

// ServerHello represents a DIT v2.2 ServerHello message.
type ServerHello struct {
	RandomS       []byte // 32 B
	MLKEMCt       []byte // 1088 B (ML-KEM-768 ciphertext)
	XSPub         []byte // 32 B (X25519 public, simulated)
	SelectedSuite string
	SigmaServer   []byte // 3309 B (ML-DSA-65 signature over transcript)
	EpochCredID   string
}

// HandshakeResult contains the result of a successful handshake.
type HandshakeResult struct {
	SessionID        string
	Domain           string
	Ciphersuite      string
	ClientAppTraffic []byte
	ServerAppTraffic []byte
	TranscriptHash   string
	Timestamp        time.Time
	WarmPath         bool
}

// ServerState holds server-side handshake state.
type ServerState struct {
	IK  *identity.IdentityKey
	EAK *identity.EpochAuthKey
}

// NewServerState creates server state for handshake.
func NewServerState(ik *identity.IdentityKey, eak *identity.EpochAuthKey) *ServerState {
	return &ServerState{IK: ik, EAK: eak}
}

// === Client-side ===

// CreateClientHello generates a ClientHello message.
func CreateClientHello(ikHash, epochCredID string) (*ClientHello, *ditcrypto.KEMDecapsulationKey, error) {
	randomC, err := ditcrypto.RandBytes(32)
	if err != nil {
		return nil, nil, err
	}

	// Generate ephemeral ML-KEM-768 key pair
	dk, ek, err := ditcrypto.GenerateKEMKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Simulated X25519 public key
	xCPub, _ := ditcrypto.RandBytes(32)

	ch := &ClientHello{
		RandomC:      randomC,
		MLKEMCPub:    ek.Bytes(),
		XCPub:        xCPub,
		Suites:       []string{CiphersuiteName},
		IdentityHash: ikHash,
		EpochCredID:  epochCredID,
	}

	return ch, dk, nil
}

// === Server-side ===

// ProcessClientHello processes a ClientHello and generates ServerHello.
func (ss *ServerState) ProcessClientHello(ch *ClientHello) (*ServerHello, []byte, error) {
	randomS, err := ditcrypto.RandBytes(32)
	if err != nil {
		return nil, nil, err
	}

	// Parse client's ML-KEM-768 encapsulation key
	ek, err := ditcrypto.ParseEncapsulationKey(ch.MLKEMCPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse client KEM key: %w", err)
	}

	// ML-KEM-768.Encaps(mlkem_C_pub) — server encapsulates TO client's key
	ct, ssPQ := ditcrypto.Encapsulate(ek)

	// Simulated X25519
	xSPub, _ := ditcrypto.RandBytes(32)
	ssX25519, _ := ditcrypto.RandBytes(32) // simulated X25519 shared secret

	// Hybrid combiner: ss_pq || ss_x25519 (IETF order)
	hybridSecret := append(ssPQ, ssX25519...)

	// Build canonical transcript T
	transcript := buildTranscript(ch, randomS, ct, xSPub, ss.EAK.Domain, ss.EAK.EpochID)
	transcriptHash := ditcrypto.SHA3_384(transcript)

	// σ_server = ML-DSA-65.Sign(EAK_priv, "DIT-v2.2 server handshake" || H_tr(T))
	signMsg := append([]byte("DIT-v2.2 server handshake"), transcriptHash...)
	sigmaServer := ss.EAK.KeyPair.Sign(signMsg)

	sh := &ServerHello{
		RandomS:       randomS,
		MLKEMCt:       ct,
		XSPub:         xSPub,
		SelectedSuite: CiphersuiteName,
		SigmaServer:   sigmaServer,
		EpochCredID:   ss.EAK.EpochID,
	}

	return sh, hybridSecret, nil
}

// === Client verification ===

// VerifyServerHello verifies the ServerHello and completes the handshake.
func VerifyServerHello(
	ch *ClientHello,
	sh *ServerHello,
	dk *ditcrypto.KEMDecapsulationKey,
	ikPub []byte,
	cred *identity.EpochCredential,
) (*HandshakeResult, error) {
	// 1. Verify epoch credential: σ_IK on EC under IK
	if !identity.VerifyCredential(ikPub, cred) {
		return nil, fmt.Errorf("epoch credential verification failed")
	}

	// 2. Verify σ_server under EAK_pub
	transcript := buildTranscript(ch, sh.RandomS, sh.MLKEMCt, sh.XSPub, cred.Domain, cred.EpochID)
	transcriptHash := ditcrypto.SHA3_384(transcript)
	signMsg := append([]byte("DIT-v2.2 server handshake"), transcriptHash...)
	if !ditcrypto.Verify(cred.EAKPub, signMsg, sh.SigmaServer) {
		return nil, fmt.Errorf("server signature verification failed")
	}

	// 3. Decapsulate ML-KEM-768
	ssPQ, err := ditcrypto.Decapsulate(dk, sh.MLKEMCt)
	if err != nil {
		return nil, fmt.Errorf("KEM decapsulation failed: %w", err)
	}

	// 4. Simulated X25519 (in production: X25519(x_C_priv, x_S_pub))
	ssX25519, _ := ditcrypto.RandBytes(32)

	// 5. Hybrid combiner: ss_pq || ss_x25519
	hybridSecret := append(ssPQ, ssX25519...)

	// 6. Run TLS 1.3 key schedule
	chshTranscript := transcript
	ks, err := ditcrypto.RunKeySchedule(hybridSecret, chshTranscript, transcript)
	if err != nil {
		return nil, fmt.Errorf("key schedule failed: %w", err)
	}

	return &HandshakeResult{
		SessionID:        hex.EncodeToString(transcriptHash[:16]),
		Domain:           cred.Domain,
		Ciphersuite:      CiphersuiteName,
		ClientAppTraffic: ks.ClientAppTraffic,
		ServerAppTraffic: ks.ServerAppTraffic,
		TranscriptHash:   hex.EncodeToString(transcriptHash),
		Timestamp:        time.Now(),
		WarmPath:         true,
	}, nil
}

func buildTranscript(ch *ClientHello, randomS, ct, xSPub []byte, domain, epoch string) []byte {
	var t []byte
	t = append(t, []byte("DIT-v2.2")...)
	t = append(t, ch.RandomC...)
	t = append(t, ch.MLKEMCPub...)
	t = append(t, ch.XCPub...)
	t = append(t, randomS...)
	t = append(t, ct...)
	t = append(t, xSPub...)
	t = append(t, []byte(domain)...)
	t = append(t, []byte(epoch)...)
	return t
}
