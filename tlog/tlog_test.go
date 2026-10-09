package tlog

import (
	"fmt"
	"testing"
	"time"
)

func build(n int) *Tree {
	t := &Tree{}
	for i := 0; i < n; i++ {
		t.Append([]byte(fmt.Sprintf("entry-%d", i)))
	}
	return t
}

// Inclusion proofs verify for every leaf of every tree size up to 70 and fail
// for a wrong index or a tampered root.
func TestInclusionAllSizes(t *testing.T) {
	for n := uint64(1); n <= 70; n++ {
		tr := build(int(n))
		root := tr.Root()
		for m := uint64(0); m < n; m++ {
			p, err := tr.InclusionProof(m, n)
			if err != nil {
				t.Fatal(err)
			}
			lh := LeafHash([]byte(fmt.Sprintf("entry-%d", m)))
			if !VerifyInclusion(lh, m, n, p, root) {
				t.Fatalf("n=%d m=%d: valid proof rejected", n, m)
			}
			if n > 1 && VerifyInclusion(lh, (m+1)%n, n, p, root) {
				t.Fatalf("n=%d m=%d: proof accepted at wrong index", n, m)
			}
			bad := append([]byte(nil), root...)
			bad[0] ^= 1
			if VerifyInclusion(lh, m, n, p, bad) {
				t.Fatalf("n=%d m=%d: proof accepted under wrong root", n, m)
			}
		}
	}
}

func TestConsistencyAllSizes(t *testing.T) {
	tr := build(70)
	for n := uint64(1); n <= 70; n++ {
		for m := uint64(1); m <= n; m++ {
			p, err := tr.ConsistencyProof(m, n)
			if err != nil {
				t.Fatal(err)
			}
			if !VerifyConsistency(m, n, tr.RootAt(m), tr.RootAt(n), p) {
				t.Fatalf("m=%d n=%d: valid consistency proof rejected", m, n)
			}
			if m < n {
				other := build(int(m))
				other.Append([]byte("forked"))
				if VerifyConsistency(m, n, other.RootAt(m+1), tr.RootAt(n), p) {
					t.Fatalf("m=%d n=%d: forked root accepted", m, n)
				}
			}
		}
	}
}

// A witness cosigns an append-only extension but refuses a forked log, and a
// client accepts only q-of-m cosigned heads.
func TestWitnessQuorumAndEquivocation(t *testing.T) {
	log, _ := NewLog()
	now := time.Unix(1_800_000_000, 0)
	ws := map[uint8]*Witness{}
	pubs := map[uint8][]byte{}
	for i := uint8(1); i <= 7; i++ {
		w, _ := NewWitness(i, log.PublicKey(), nil)
		ws[i], pubs[i] = w, w.PublicKey()
	}
	e1 := []byte("e1")
	log.Append(e1)
	sth1 := log.SignHead(now)
	c := &CosignedSTH{STH: sth1}
	for i := uint8(1); i <= 5; i++ {
		cs, err := ws[i].Cosign(sth1, nil, [][]byte{e1}, now)
		if err != nil {
			t.Fatal(err)
		}
		c.Cosigns = append(c.Cosigns, *cs)
	}
	if err := VerifyCosigned(c, log.PublicKey(), pubs, 5); err != nil {
		t.Fatal(err)
	}
	c4 := &CosignedSTH{STH: sth1, Cosigns: c.Cosigns[:4]}
	if VerifyCosigned(c4, log.PublicKey(), pubs, 5) == nil {
		t.Fatal("4 cosignatures accepted under a 5-of-7 policy")
	}
	dup := &CosignedSTH{STH: sth1, Cosigns: append(c.Cosigns[:4:4], c.Cosigns[0])}
	if VerifyCosigned(dup, log.PublicKey(), pubs, 5) == nil {
		t.Fatal("duplicate cosignature counted twice")
	}

	// Honest extension, cosigned by witnesses 1..5.
	e2 := []byte("e2")
	log.Append(e2)
	sth2 := log.SignHead(now.Add(time.Minute))
	p, _ := log.Tree.ConsistencyProof(1, 2)
	for i := uint8(1); i <= 5; i++ {
		if _, err := ws[i].Cosign(sth2, p, [][]byte{e2}, now); err != nil {
			t.Fatal(err)
		}
	}
	// The log operator equivocates: a second head of size 2 with other content.
	fork := &Log{key: log.key, ID: log.ID}
	fork.Append(e1)
	fork.Append([]byte("evil"))
	sthFork := fork.SignHead(now.Add(2 * time.Minute))
	pf, _ := fork.Tree.ConsistencyProof(1, 2)
	// A witness that has not seen sth2 (witness 6) accepts the fork: a single
	// witness cannot detect a split view. Witnesses 6 and 7 model the f=2
	// corrupt witnesses.
	forkCosigns := []Cosignature{}
	for i := uint8(6); i <= 7; i++ {
		cs, err := ws[i].Cosign(sthFork, pf, [][]byte{e1, []byte("evil")}, now)
		if err != nil {
			t.Fatalf("witness %d: %v", i, err)
		}
		forkCosigns = append(forkCosigns, *cs)
	}
	// Every honest witness that cosigned sth2 refuses the fork.
	for i := uint8(1); i <= 5; i++ {
		if _, err := ws[i].Cosign(sthFork, pf, [][]byte{[]byte("evil")}, now); err == nil {
			t.Fatalf("witness %d cosigned an equivocating head", i)
		}
	}
	// So the fork collects 2 < q cosignatures and no client accepts it.
	if VerifyCosigned(&CosignedSTH{STH: sthFork, Cosigns: forkCosigns}, log.PublicKey(), pubs, 5) == nil {
		t.Fatal("client accepted an equivocating head")
	}
}
