package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// ============================================================
// HKDF-SHA3-384 Key Derivation
// ============================================================

// HKDFExtract performs HKDF-Extract with SHA3-384.
func HKDFExtract(salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, 48) // zero salt
	}
	prk := make([]byte, 48) // SHA3-384 output = 48 bytes
	r := hkdf.Extract(sha3.New384, ikm, salt)
	copy(prk, r)
	return prk
}

// HKDFExpand performs HKDF-Expand with SHA3-384.
func HKDFExpand(prk, info []byte, length int) ([]byte, error) {
	r := hkdf.Expand(sha3.New384, prk, info)
	out := make([]byte, length)
	_, err := io.ReadFull(r, out)
	if err != nil {
		return nil, fmt.Errorf("HKDF expand failed: %w", err)
	}
	return out, nil
}

// DeriveSecret implements TLS 1.3 Derive-Secret.
// Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, Hash(Messages), Hash.length)
func DeriveSecret(secret []byte, label string, messages []byte) ([]byte, error) {
	hash := SHA3_384(messages) // H(Messages)
	return HKDFExpandLabel(secret, label, hash, 48)
}

// HKDFExpandLabel implements TLS 1.3 HKDF-Expand-Label.
func HKDFExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	// HkdfLabel struct per RFC 8446 §7.1
	fullLabel := "tls13 " + label
	hkdfLabel := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
	hkdfLabel = append(hkdfLabel, byte(len(fullLabel)))
	hkdfLabel = append(hkdfLabel, []byte(fullLabel)...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)
	return HKDFExpand(secret, hkdfLabel, length)
}

// ============================================================
// TLS 1.3 Key Schedule (literal, per RFC 8446 §7.1)
// ============================================================

// KeyScheduleResult holds derived traffic secrets.
type KeyScheduleResult struct {
	HandshakeSecret      []byte
	ClientHSTraffic      []byte
	ServerHSTraffic      []byte
	MasterSecret         []byte
	ClientAppTraffic     []byte
	ServerAppTraffic     []byte
}

// RunKeySchedule runs the full TLS 1.3 key schedule.
func RunKeySchedule(hybridSecret, chShTranscript, fullTranscript []byte) (*KeyScheduleResult, error) {
	// early_secret = HKDF-Extract(0, 0)
	earlySecret := HKDFExtract(nil, make([]byte, 48))

	// derived_early = Derive-Secret(early_secret, "derived", "")
	derivedEarly, err := DeriveSecret(earlySecret, "derived", nil)
	if err != nil {
		return nil, err
	}

	// handshake_secret = HKDF-Extract(derived_early, hybrid_secret)
	handshakeSecret := HKDFExtract(derivedEarly, hybridSecret)

	// c_hs_traffic = Derive-Secret(handshake_secret, "c hs traffic", CH||SH)
	cHSTraffic, err := DeriveSecret(handshakeSecret, "c hs traffic", chShTranscript)
	if err != nil {
		return nil, err
	}

	// s_hs_traffic = Derive-Secret(handshake_secret, "s hs traffic", CH||SH)
	sHSTraffic, err := DeriveSecret(handshakeSecret, "s hs traffic", chShTranscript)
	if err != nil {
		return nil, err
	}

	// derived_hs = Derive-Secret(handshake_secret, "derived", "")
	derivedHS, err := DeriveSecret(handshakeSecret, "derived", nil)
	if err != nil {
		return nil, err
	}

	// master_secret = HKDF-Extract(derived_hs, 0)
	masterSecret := HKDFExtract(derivedHS, make([]byte, 48))

	// c_ap_traffic = Derive-Secret(master_secret, "c ap traffic", full_transcript)
	cAppTraffic, err := DeriveSecret(masterSecret, "c ap traffic", fullTranscript)
	if err != nil {
		return nil, err
	}

	// s_ap_traffic = Derive-Secret(master_secret, "s ap traffic", full_transcript)
	sAppTraffic, err := DeriveSecret(masterSecret, "s ap traffic", fullTranscript)
	if err != nil {
		return nil, err
	}

	return &KeyScheduleResult{
		HandshakeSecret:  handshakeSecret,
		ClientHSTraffic:  cHSTraffic,
		ServerHSTraffic:  sHSTraffic,
		MasterSecret:     masterSecret,
		ClientAppTraffic: cAppTraffic,
		ServerAppTraffic: sAppTraffic,
	}, nil
}

// DeriveAEADKey derives an AES-256-GCM key and IV from a traffic secret.
func DeriveAEADKey(trafficSecret []byte) (key []byte, iv []byte, err error) {
	key, err = HKDFExpandLabel(trafficSecret, "key", nil, 32) // AES-256 key
	if err != nil {
		return
	}
	iv, err = HKDFExpandLabel(trafficSecret, "iv", nil, 12) // GCM nonce
	return
}

// ============================================================
// AES-256-GCM AEAD
// ============================================================

// AEADEncrypt encrypts plaintext with AES-256-GCM.
func AEADEncrypt(key, iv, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	copy(nonce, iv)
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// AEADDecrypt decrypts ciphertext with AES-256-GCM.
func AEADDecrypt(key, iv, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	copy(nonce, iv)
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// SecureErase zeros a byte slice (best-effort memory erasure for T11).
func SecureErase(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// In production: use mmap + mlock + memory barrier
	_, _ = rand.Read(b) // overwrite with random to defeat compiler optimization
	for i := range b {
		b[i] = 0
	}
}
