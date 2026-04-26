// Package crypto provides post-quantum cryptographic primitives for DIT v2.2.
//
// ML-KEM-768: via Go stdlib crypto/mlkem (Go 1.24+)
// ML-DSA-65:  via Ed25519 stand-in (production: Cloudflare CIRCL dilithium/mode3)
// SHA3-384:   via crypto/sha3
// HKDF:       via golang.org/x/crypto/hkdf with SHA3-384
package crypto

import (
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// ============================================================
// ML-DSA-65 (simulated via Ed25519 — production uses CIRCL)
// ============================================================

// DSAKeyPair represents an ML-DSA-65 signing key pair.
// In production, this wraps cloudflare/circl/sign/dilithium/mode3.
type DSAKeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	// Simulated sizes matching real ML-DSA-65
	PubKeySize int
	SigSize    int
}

// GenerateDSAKeyPair generates a fresh ML-DSA-65 key pair.
func GenerateDSAKeyPair() (*DSAKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("DSA keygen failed: %w", err)
	}
	return &DSAKeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
		PubKeySize: 1952,  // Real ML-DSA-65 public key size
		SigSize:    3309,  // Real ML-DSA-65 signature size (RFC 9881)
	}, nil
}

// Sign signs a message with ML-DSA-65.
func (kp *DSAKeyPair) Sign(message []byte) []byte {
	return ed25519.Sign(kp.PrivateKey, message)
}

// Verify verifies an ML-DSA-65 signature.
func Verify(publicKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}

// ============================================================
// ML-KEM-768 (via Go stdlib crypto/mlkem)
// ============================================================

// KEMEncapsulationKey wraps mlkem.EncapsulationKey768.
type KEMEncapsulationKey = mlkem.EncapsulationKey768

// KEMDecapsulationKey wraps mlkem.DecapsulationKey768.
type KEMDecapsulationKey = mlkem.DecapsulationKey768

// GenerateKEMKeyPair generates an ML-KEM-768 key pair.
func GenerateKEMKeyPair() (*KEMDecapsulationKey, *KEMEncapsulationKey, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, fmt.Errorf("KEM keygen failed: %w", err)
	}
	return dk, dk.EncapsulationKey(), nil
}

// Encapsulate performs ML-KEM-768 encapsulation against a public key.
// Returns (ciphertext, shared_secret).
func Encapsulate(ek *KEMEncapsulationKey) (ciphertext, sharedSecret []byte) {
	ss, ct := ek.Encapsulate()
	return ct, ss
}

// Decapsulate performs ML-KEM-768 decapsulation.
func Decapsulate(dk *KEMDecapsulationKey, ciphertext []byte) ([]byte, error) {
	ss, err := dk.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("KEM decaps failed: %w", err)
	}
	return ss, nil
}

// ============================================================
// SHA3-384 hashing
// ============================================================

// SHA3_384 computes SHA3-384 hash of data.
func SHA3_384(data []byte) []byte {
	h := sha3.New384()
	h.Write(data)
	return h.Sum(nil)
}

// SHA512Hash computes SHA-512 (used internally by Ed25519).
func SHA512Hash(data []byte) []byte {
	h := sha512.New()
	h.Write(data)
	return h.Sum(nil)
}

// RandBytes generates n cryptographically random bytes.
func RandBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	return buf, err
}
