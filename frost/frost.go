// Package frost implements FROST(Ed25519, SHA-512) as specified in RFC 9591,
// with trusted-dealer key generation (RFC 9591 Appendix C).
//
// The aggregate signature is a standard Ed25519 signature (RFC 8032) and is
// verified with crypto/ed25519. FROST is a classical scheme: it is not secure
// against a quantum adversary (paper, Theorem 7 and Limitation L6).
package frost

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"sort"

	"filippo.io/edwards25519"
)

const contextString = "FROST-ED25519-SHA512-v1"

// ─── Hash functions (RFC 9591 §6.1) ───────────────────────────────────────────

func hashToScalar(parts ...[]byte) *edwards25519.Scalar {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	s, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		panic(err)
	}
	return s
}

func h1(m []byte) *edwards25519.Scalar { return hashToScalar([]byte(contextString+"rho"), m) }
func h2(m []byte) *edwards25519.Scalar { return hashToScalar(m) }
func h3(m []byte) *edwards25519.Scalar { return hashToScalar([]byte(contextString+"nonce"), m) }
func h4(m []byte) []byte {
	h := sha512.Sum512(append([]byte(contextString+"msg"), m...))
	return h[:]
}
func h5(m []byte) []byte {
	h := sha512.Sum512(append([]byte(contextString+"com"), m...))
	return h[:]
}

func scalarFromUint(i uint16) *edwards25519.Scalar {
	var b [32]byte
	b[0], b[1] = byte(i), byte(i>>8)
	s, err := edwards25519.NewScalar().SetCanonicalBytes(b[:])
	if err != nil {
		panic(err)
	}
	return s
}

func randomScalar() *edwards25519.Scalar {
	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	s, _ := edwards25519.NewScalar().SetUniformBytes(b[:])
	return s
}

// ─── Key generation ───────────────────────────────────────────────────────────

// KeyShare is participant i's long-lived signing share.
type KeyShare struct {
	ID          uint16
	Secret      *edwards25519.Scalar
	PublicShare *edwards25519.Point // Secret·G, used to verify signature shares
	GroupPublic *edwards25519.Point
}

// GroupPublicKey returns the 32-byte group key; it is an Ed25519 public key.
func (k *KeyShare) GroupPublicKey() []byte { return k.GroupPublic.Bytes() }

// TrustedDealerKeygen splits a fresh random secret into n shares with threshold t.
func TrustedDealerKeygen(t, n int) ([]*KeyShare, []byte, error) {
	if t < 2 || t > n || n > 0xffff {
		return nil, nil, fmt.Errorf("frost: invalid parameters t=%d n=%d", t, n)
	}
	coeffs := make([]*edwards25519.Scalar, t)
	for i := range coeffs {
		coeffs[i] = randomScalar()
	}
	group := new(edwards25519.Point).ScalarBaseMult(coeffs[0])
	shares := make([]*KeyShare, n)
	for i := 1; i <= n; i++ {
		x := scalarFromUint(uint16(i))
		// Horner evaluation of f(x).
		y := edwards25519.NewScalar().Set(coeffs[t-1])
		for j := t - 2; j >= 0; j-- {
			y.Multiply(y, x)
			y.Add(y, coeffs[j])
		}
		shares[i-1] = &KeyShare{
			ID:          uint16(i),
			Secret:      y,
			PublicShare: new(edwards25519.Point).ScalarBaseMult(y),
			GroupPublic: group,
		}
	}
	return shares, group.Bytes(), nil
}

// ─── Round one ────────────────────────────────────────────────────────────────

// Nonces is the secret per-signing state of round one. It must be used once.
type Nonces struct {
	hiding, binding *edwards25519.Scalar
}

// Commitment is the public output of round one.
type Commitment struct {
	ID      uint16
	Hiding  *edwards25519.Point
	Binding *edwards25519.Point
}

func nonceGenerate(secret *edwards25519.Scalar) *edwards25519.Scalar {
	var r [32]byte
	if _, err := rand.Read(r[:]); err != nil {
		panic(err)
	}
	return h3(append(r[:], secret.Bytes()...))
}

// Commit runs round one (RFC 9591 §5.1).
func Commit(k *KeyShare) (*Nonces, *Commitment) {
	n := &Nonces{hiding: nonceGenerate(k.Secret), binding: nonceGenerate(k.Secret)}
	c := &Commitment{
		ID:      k.ID,
		Hiding:  new(edwards25519.Point).ScalarBaseMult(n.hiding),
		Binding: new(edwards25519.Point).ScalarBaseMult(n.binding),
	}
	return n, c
}

// ─── Helpers shared by signers and the coordinator ────────────────────────────

func sortCommitments(cs []*Commitment) []*Commitment {
	out := append([]*Commitment(nil), cs...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func encodeCommitments(cs []*Commitment) []byte {
	var b []byte
	for _, c := range cs {
		b = append(b, scalarFromUint(c.ID).Bytes()...)
		b = append(b, c.Hiding.Bytes()...)
		b = append(b, c.Binding.Bytes()...)
	}
	return b
}

func bindingFactors(group *edwards25519.Point, cs []*Commitment, msg []byte) map[uint16]*edwards25519.Scalar {
	prefix := append(append(group.Bytes(), h4(msg)...), h5(encodeCommitments(cs))...)
	out := make(map[uint16]*edwards25519.Scalar, len(cs))
	for _, c := range cs {
		out[c.ID] = h1(append(append([]byte(nil), prefix...), scalarFromUint(c.ID).Bytes()...))
	}
	return out
}

func groupCommitment(cs []*Commitment, bf map[uint16]*edwards25519.Scalar) *edwards25519.Point {
	r := edwards25519.NewIdentityPoint()
	for _, c := range cs {
		t := new(edwards25519.Point).ScalarMult(bf[c.ID], c.Binding)
		r.Add(r, c.Hiding)
		r.Add(r, t)
	}
	return r
}

func lagrange(id uint16, cs []*Commitment) (*edwards25519.Scalar, error) {
	xi := scalarFromUint(id)
	num := scalarFromUint(1)
	den := scalarFromUint(1)
	found := false
	for _, c := range cs {
		if c.ID == id {
			found = true
			continue
		}
		xj := scalarFromUint(c.ID)
		num.Multiply(num, xj)
		den.Multiply(den, edwards25519.NewScalar().Subtract(xj, xi))
	}
	if !found {
		return nil, errors.New("frost: signer not in commitment list")
	}
	return num.Multiply(num, edwards25519.NewScalar().Invert(den)), nil
}

func challenge(r, group *edwards25519.Point, msg []byte) *edwards25519.Scalar {
	return h2(append(append(r.Bytes(), group.Bytes()...), msg...))
}

// ─── Round two ────────────────────────────────────────────────────────────────

// SignShare runs round two (RFC 9591 §5.2) and consumes the nonces.
func SignShare(k *KeyShare, n *Nonces, msg []byte, commitments []*Commitment) (*edwards25519.Scalar, error) {
	if n.hiding == nil {
		return nil, errors.New("frost: nonces already used")
	}
	cs := sortCommitments(commitments)
	bf := bindingFactors(k.GroupPublic, cs, msg)
	if _, ok := bf[k.ID]; !ok {
		return nil, errors.New("frost: signer not in commitment list")
	}
	r := groupCommitment(cs, bf)
	lambda, err := lagrange(k.ID, cs)
	if err != nil {
		return nil, err
	}
	c := challenge(r, k.GroupPublic, msg)
	z := edwards25519.NewScalar().Multiply(n.binding, bf[k.ID])
	z.Add(z, n.hiding)
	t := edwards25519.NewScalar().Multiply(lambda, k.Secret)
	t.Multiply(t, c)
	z.Add(z, t)
	n.hiding, n.binding = nil, nil
	return z, nil
}

// VerifyShare lets the coordinator identify a misbehaving signer (RFC 9591 §5.4).
func VerifyShare(id uint16, publicShare, group *edwards25519.Point, share *edwards25519.Scalar,
	msg []byte, commitments []*Commitment) bool {
	cs := sortCommitments(commitments)
	bf := bindingFactors(group, cs, msg)
	var own *Commitment
	for _, c := range cs {
		if c.ID == id {
			own = c
		}
	}
	if own == nil {
		return false
	}
	lambda, err := lagrange(id, cs)
	if err != nil {
		return false
	}
	c := challenge(groupCommitment(cs, bf), group, msg)
	commShare := new(edwards25519.Point).ScalarMult(bf[id], own.Binding)
	commShare.Add(commShare, own.Hiding)
	l := new(edwards25519.Point).ScalarBaseMult(share)
	rhs := new(edwards25519.Point).ScalarMult(edwards25519.NewScalar().Multiply(c, lambda), publicShare)
	rhs.Add(rhs, commShare)
	return l.Equal(rhs) == 1
}

// Aggregate combines t signature shares into a 64-byte Ed25519 signature.
func Aggregate(group *edwards25519.Point, msg []byte, commitments []*Commitment,
	shares []*edwards25519.Scalar) []byte {
	cs := sortCommitments(commitments)
	r := groupCommitment(cs, bindingFactors(group, cs, msg))
	z := edwards25519.NewScalar()
	for _, s := range shares {
		z.Add(z, s)
	}
	return append(r.Bytes(), z.Bytes()...)
}
