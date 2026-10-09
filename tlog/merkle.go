// Package tlog implements DIT Layer 3: an RFC 9162 Merkle tree instantiated
// with SHA3-384, Signed Tree Heads (STHs), and q-of-m witness cosigning.
//
//	leaf hash:  MTH({d}) = SHA3-384(0x00 || d)
//	node hash:  MTH(D[n]) = SHA3-384(0x01 || MTH(D[0:k]) || MTH(D[k:n])),
//	            k the largest power of two smaller than n
//	empty tree: MTH({})  = SHA3-384()
package tlog

import (
	"bytes"
	"errors"
	"math/bits"

	"github.com/dit-protocol/poc/pqc"
)

// HashSize is the SHA3-384 output length.
const HashSize = pqc.SHA3384Size

// LeafHash returns SHA3-384(0x00 || data).
func LeafHash(data []byte) []byte { return pqc.SHA3([]byte{0x00}, data) }

// NodeHash returns SHA3-384(0x01 || left || right).
func NodeHash(l, r []byte) []byte { return pqc.SHA3([]byte{0x01}, l, r) }

// Tree is an in-memory append-only Merkle tree over leaf hashes.
type Tree struct{ leaves [][]byte }

// AppendLeafHash appends a precomputed leaf hash.
func (t *Tree) AppendLeafHash(h []byte) { t.leaves = append(t.leaves, h) }

// Append hashes data as a leaf and appends it; it returns the leaf index.
func (t *Tree) Append(data []byte) uint64 {
	t.leaves = append(t.leaves, LeafHash(data))
	return uint64(len(t.leaves) - 1)
}

// Size returns the number of leaves.
func (t *Tree) Size() uint64 { return uint64(len(t.leaves)) }

func splitPoint(n uint64) uint64 { return 1 << (bits.Len64(n-1) - 1) } // largest 2^i < n

func mth(l [][]byte) []byte {
	switch len(l) {
	case 0:
		return pqc.SHA3()
	case 1:
		return l[0]
	}
	k := splitPoint(uint64(len(l)))
	return NodeHash(mth(l[:k]), mth(l[k:]))
}

// RootAt returns the root of the first n leaves.
func (t *Tree) RootAt(n uint64) []byte { return mth(t.leaves[:n]) }

// Root returns the current root.
func (t *Tree) Root() []byte { return t.RootAt(t.Size()) }

// InclusionProof returns the audit path for leaf m in the tree of size n
// (RFC 9162 §2.1.3.1).
func (t *Tree) InclusionProof(m, n uint64) ([][]byte, error) {
	if n > t.Size() || m >= n {
		return nil, errors.New("tlog: inclusion proof out of range")
	}
	return path(m, t.leaves[:n]), nil
}

func path(m uint64, d [][]byte) [][]byte {
	n := uint64(len(d))
	if n <= 1 {
		return nil
	}
	k := splitPoint(n)
	if m < k {
		return append(path(m, d[:k]), mth(d[k:]))
	}
	return append(path(m-k, d[k:]), mth(d[:k]))
}

// VerifyInclusion checks an audit path (RFC 9162 §2.1.3.2).
func VerifyInclusion(leafHash []byte, index, size uint64, proof [][]byte, root []byte) bool {
	if index >= size {
		return false
	}
	fn, sn := index, size-1
	r := leafHash
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(r, root)
}

// ConsistencyProof proves that the tree of size m is a prefix of size n
// (RFC 9162 §2.1.4.1).
func (t *Tree) ConsistencyProof(m, n uint64) ([][]byte, error) {
	if m == 0 || m > n || n > t.Size() {
		return nil, errors.New("tlog: consistency proof out of range")
	}
	return subproof(m, t.leaves[:n], true), nil
}

func subproof(m uint64, d [][]byte, b bool) [][]byte {
	n := uint64(len(d))
	if m == n {
		if b {
			return nil
		}
		return [][]byte{mth(d)}
	}
	k := splitPoint(n)
	if m <= k {
		return append(subproof(m, d[:k], b), mth(d[k:]))
	}
	return append(subproof(m-k, d[k:], false), mth(d[:k]))
}

// VerifyConsistency checks a consistency proof (RFC 9162 §2.1.4.2).
func VerifyConsistency(m, n uint64, oldRoot, newRoot []byte, proof [][]byte) bool {
	if m == 0 || m > n {
		return false
	}
	if m == n {
		return len(proof) == 0 && bytes.Equal(oldRoot, newRoot)
	}
	if m&(m-1) == 0 { // m is a power of two: prepend first_hash
		proof = append([][]byte{oldRoot}, proof...)
	}
	if len(proof) == 0 {
		return false
	}
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(fr, oldRoot) && bytes.Equal(sr, newRoot)
}
