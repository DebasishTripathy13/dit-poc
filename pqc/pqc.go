// Package pqc wraps the post-quantum and hybrid primitives used by DIT.
//
//   - ML-DSA-65 (FIPS 204) via github.com/cloudflare/circl/sign/mldsa/mldsa65
//   - ML-KEM-768 (FIPS 203) via the Go standard library crypto/mlkem
//   - X25519MLKEM768 (RFC 10024) built from crypto/mlkem and crypto/ecdh
//   - SHA3-384 (FIPS 202) via the Go standard library crypto/sha3
//
// No primitive in this package is simulated.
package pqc

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Sizes fixed by FIPS 203, FIPS 204 and RFC 10024.
const (
	MLDSA65PublicKeySize = mldsa65.PublicKeySize // 1952
	MLDSA65SignatureSize = mldsa65.SignatureSize // 3309
	MLKEM768EncapKeySize = mlkem.EncapsulationKeySize768
	MLKEM768CiphertextSz = mlkem.CiphertextSize768
	X25519Size           = 32
	// HybridClientShareSize is the X25519MLKEM768 client key_share: ek || x25519 pk.
	HybridClientShareSize = MLKEM768EncapKeySize + X25519Size // 1216
	// HybridServerShareSize is the X25519MLKEM768 server key_share: ct || x25519 pk.
	HybridServerShareSize = MLKEM768CiphertextSz + X25519Size // 1120
	SHA3384Size           = 48
)

// ─── ML-DSA-65 ────────────────────────────────────────────────────────────────

// SigningKey is an ML-DSA-65 key pair.
type SigningKey struct {
	pub  *mldsa65.PublicKey
	priv *mldsa65.PrivateKey
}

// GenerateSigningKey returns a fresh ML-DSA-65 key pair.
func GenerateSigningKey() (*SigningKey, error) {
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mldsa65 keygen: %w", err)
	}
	return &SigningKey{pub: pub, priv: priv}, nil
}

// PublicKey returns the packed public key (1952 B).
func (k *SigningKey) PublicKey() []byte { return k.pub.Bytes() }

// Sign signs msg under the FIPS 204 context string ctx (hedged signing).
func (k *SigningKey) Sign(ctx string, msg []byte) []byte {
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(k.priv, msg, []byte(ctx), true, sig); err != nil {
		panic(err) // only fails for ctx > 255 bytes, which is a programming error
	}
	return sig
}

// Erase drops the reference to the private key. Go cannot guarantee that the
// memory is zeroed; see the limitations section of the paper (T11).
func (k *SigningKey) Erase() { k.priv = nil }

// Verify checks an ML-DSA-65 signature under context string ctx.
func Verify(pub []byte, ctx string, msg, sig []byte) bool {
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(pub); err != nil {
		return false
	}
	return mldsa65.Verify(&pk, msg, []byte(ctx), sig)
}

// ─── X25519MLKEM768 (RFC 10024) ───────────────────────────────────────────────

// HybridClientKey is the client's ephemeral X25519MLKEM768 state.
type HybridClientKey struct {
	dk *mlkem.DecapsulationKey768
	xk *ecdh.PrivateKey
}

// GenerateHybridClientKey returns ephemeral state and the 1216-byte key_share.
func GenerateHybridClientKey() (*HybridClientKey, []byte, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	xk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	share := append(dk.EncapsulationKey().Bytes(), xk.PublicKey().Bytes()...)
	return &HybridClientKey{dk: dk, xk: xk}, share, nil
}

// HybridServerEncaps processes a client key_share and returns the server
// key_share (ct || x25519 pk) and the shared secret ss_mlkem || ss_x25519.
func HybridServerEncaps(clientShare []byte) (serverShare, secret []byte, err error) {
	if len(clientShare) != HybridClientShareSize {
		return nil, nil, errors.New("x25519mlkem768: bad client share length")
	}
	ek, err := mlkem.NewEncapsulationKey768(clientShare[:MLKEM768EncapKeySize])
	if err != nil {
		return nil, nil, err
	}
	ssKEM, ct := ek.Encapsulate()
	peer, err := ecdh.X25519().NewPublicKey(clientShare[MLKEM768EncapKeySize:])
	if err != nil {
		return nil, nil, err
	}
	xk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ssX, err := xk.ECDH(peer)
	if err != nil {
		return nil, nil, err
	}
	return append(ct, xk.PublicKey().Bytes()...), append(ssKEM, ssX...), nil
}

// Decaps completes the client side and returns ss_mlkem || ss_x25519.
func (c *HybridClientKey) Decaps(serverShare []byte) ([]byte, error) {
	if len(serverShare) != HybridServerShareSize {
		return nil, errors.New("x25519mlkem768: bad server share length")
	}
	ssKEM, err := c.dk.Decapsulate(serverShare[:MLKEM768CiphertextSz])
	if err != nil {
		return nil, err
	}
	peer, err := ecdh.X25519().NewPublicKey(serverShare[MLKEM768CiphertextSz:])
	if err != nil {
		return nil, err
	}
	ssX, err := c.xk.ECDH(peer)
	if err != nil {
		return nil, err
	}
	return append(ssKEM, ssX...), nil
}

// ─── SHA3-384 ─────────────────────────────────────────────────────────────────

// SHA3 returns SHA3-384 over the concatenation of parts.
func SHA3(parts ...[]byte) []byte {
	h := sha3.New384()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
