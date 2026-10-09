package frost

import (
	"crypto/ed25519"
	"testing"

	"filippo.io/edwards25519"
)

func signWith(t *testing.T, shares []*KeyShare, signers []int, msg []byte) []byte {
	t.Helper()
	nonces := make([]*Nonces, len(signers))
	comms := make([]*Commitment, len(signers))
	for i, s := range signers {
		nonces[i], comms[i] = Commit(shares[s])
	}
	var zs []*edwards25519.Scalar
	for i, s := range signers {
		z, err := SignShare(shares[s], nonces[i], msg, comms)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyShare(shares[s].ID, shares[s].PublicShare, shares[s].GroupPublic, z, msg, comms) {
			t.Fatalf("share %d failed verification", shares[s].ID)
		}
		zs = append(zs, z)
	}
	return Aggregate(shares[0].GroupPublic, msg, comms, zs)
}

// The aggregate must verify as a plain Ed25519 signature for every t-subset.
func TestThresholdSignaturesVerifyAsEd25519(t *testing.T) {
	shares, gpk, err := TrustedDealerKeygen(3, 5)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("DIT recovery rotation record")
	for _, set := range [][]int{{0, 1, 2}, {0, 2, 4}, {1, 3, 4}, {2, 3, 4}, {0, 1, 2, 3}} {
		sig := signWith(t, shares, set, msg)
		if !ed25519.Verify(gpk, msg, sig) {
			t.Fatalf("signer set %v: aggregate does not verify", set)
		}
		if ed25519.Verify(gpk, []byte("other message"), sig) {
			t.Fatal("signature verifies on a different message")
		}
	}
}

// t-1 signers cannot produce a valid signature by running the protocol.
func TestBelowThresholdFails(t *testing.T) {
	shares, gpk, _ := TrustedDealerKeygen(3, 5)
	msg := []byte("m")
	sig := signWith(t, shares, []int{0, 1}, msg)
	if ed25519.Verify(gpk, msg, sig) {
		t.Fatal("2-of-5 signature verified under a 3-of-5 key")
	}
}

func TestNonceReuseRejected(t *testing.T) {
	shares, _, _ := TrustedDealerKeygen(2, 3)
	n0, c0 := Commit(shares[0])
	_, c1 := Commit(shares[1])
	cs := []*Commitment{c0, c1}
	if _, err := SignShare(shares[0], n0, []byte("a"), cs); err != nil {
		t.Fatal(err)
	}
	if _, err := SignShare(shares[0], n0, []byte("b"), cs); err == nil {
		t.Fatal("nonce reuse not rejected")
	}
}
