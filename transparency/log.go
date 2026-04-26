// Package transparency implements the SHA3-384 Merkle tree transparency log.
package transparency

import (
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/dit-protocol/poc/crypto"
)

// LogEntryType represents transparency log entry types.
type LogEntryType string

const (
	KeyPublication  LogEntryType = "KEY_PUBLICATION"
	RotationPending LogEntryType = "ROTATION_PENDING"
	KeyRotation     LogEntryType = "KEY_ROTATION"
)

// LogEntry represents a single transparency log entry.
type LogEntry struct {
	Type      LogEntryType
	Domain    string
	IKPub     []byte
	Timestamp time.Time
	PrevRoot  string
	Sequence  uint64
}

// MerkleTree implements a SHA3-384-hashed append-only Merkle tree.
type MerkleTree struct {
	mu     sync.RWMutex
	leaves [][]byte // leaf hashes
	root   []byte
}

// NewMerkleTree creates an empty Merkle tree.
func NewMerkleTree() *MerkleTree {
	return &MerkleTree{}
}

// leafHash computes domain-separated leaf hash: SHA3-384(0x00 || entry)
func leafHash(data []byte) []byte {
	msg := append([]byte{0x00}, data...)
	return crypto.SHA3_384(msg)
}

// nodeHash computes domain-separated internal node: SHA3-384(0x01 || left || right)
func nodeHash(left, right []byte) []byte {
	msg := append([]byte{0x01}, left...)
	msg = append(msg, right...)
	return crypto.SHA3_384(msg)
}

// Append adds an entry to the log and recomputes the root.
func (mt *MerkleTree) Append(entry *LogEntry) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	data := serializeEntry(entry)
	lh := leafHash(data)
	mt.leaves = append(mt.leaves, lh)
	mt.root = mt.computeRoot()
}

// Root returns the current Merkle root.
func (mt *MerkleTree) Root() []byte {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	result := make([]byte, len(mt.root))
	copy(result, mt.root)
	return result
}

// RootHex returns the root as a hex string.
func (mt *MerkleTree) RootHex() string {
	return hex.EncodeToString(mt.Root())
}

// Size returns the number of entries.
func (mt *MerkleTree) Size() int {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	return len(mt.leaves)
}

// GenerateProof generates a Merkle inclusion proof for leaf at index.
func (mt *MerkleTree) GenerateProof(index int) ([][]byte, error) {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	if index < 0 || index >= len(mt.leaves) {
		return nil, fmt.Errorf("index %d out of range [0, %d)", index, len(mt.leaves))
	}
	return mt.buildProof(index), nil
}

// VerifyProof verifies a Merkle inclusion proof.
func VerifyProof(root []byte, leafData []byte, index int, proof [][]byte, treeSize int) bool {
	hash := leafHash(leafData)
	idx := index
	size := treeSize

	for _, sibling := range proof {
		if idx%2 == 0 {
			hash = nodeHash(hash, sibling)
		} else {
			hash = nodeHash(sibling, hash)
		}
		idx /= 2
		size = (size + 1) / 2
	}

	if len(root) != len(hash) {
		return false
	}
	for i := range root {
		if root[i] != hash[i] {
			return false
		}
	}
	return true
}

func (mt *MerkleTree) computeRoot() []byte {
	if len(mt.leaves) == 0 {
		return crypto.SHA3_384(nil)
	}

	level := make([][]byte, len(mt.leaves))
	copy(level, mt.leaves)

	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, nodeHash(level[i], level[i+1]))
			} else {
				next = append(next, level[i])
			}
		}
		level = next
	}
	return level[0]
}

func (mt *MerkleTree) buildProof(index int) [][]byte {
	if len(mt.leaves) <= 1 {
		return nil
	}

	var proof [][]byte
	level := make([][]byte, len(mt.leaves))
	copy(level, mt.leaves)
	idx := index

	for len(level) > 1 {
		sibling := idx ^ 1
		if sibling < len(level) {
			proof = append(proof, level[sibling])
		}
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, nodeHash(level[i], level[i+1]))
			} else {
				next = append(next, level[i])
			}
		}
		level = next
		idx /= 2
	}
	return proof
}

func serializeEntry(e *LogEntry) []byte {
	s := fmt.Sprintf("%s|%s|%x|%d|%s|%d",
		e.Type, e.Domain, e.IKPub, e.Timestamp.Unix(), e.PrevRoot, e.Sequence)
	return []byte(s)
}

// ============================================================
// Signed Tree Head (STH) and Witness Cosigning
// ============================================================

// SignedTreeHead represents an STH signed by the log operator.
type SignedTreeHead struct {
	TreeSize  int
	Timestamp time.Time
	RootHash  []byte
	Signature []byte // σ_log
}

// WitnessCosignature represents a witness's cosignature on an STH.
type WitnessCosignature struct {
	WitnessID  string
	WitnessPub []byte
	Signature  []byte
}

// Witness represents a trust witness.
type Witness struct {
	ID      string
	KeyPair *crypto.DSAKeyPair
}

// NewWitness creates a new witness.
func NewWitness(id string) (*Witness, error) {
	kp, err := crypto.GenerateDSAKeyPair()
	if err != nil {
		return nil, err
	}
	return &Witness{ID: id, KeyPair: kp}, nil
}

// Cosign produces a cosignature on an STH.
func (w *Witness) Cosign(sth *SignedTreeHead) *WitnessCosignature {
	msg := buildSTHMessage(sth)
	sig := w.KeyPair.Sign(msg)
	return &WitnessCosignature{
		WitnessID:  w.ID,
		WitnessPub: w.KeyPair.PublicKey,
		Signature:  sig,
	}
}

// VerifyCosignature verifies a witness cosignature.
func VerifyCosignature(sth *SignedTreeHead, cosig *WitnessCosignature) bool {
	msg := buildSTHMessage(sth)
	return crypto.Verify(cosig.WitnessPub, msg, cosig.Signature)
}

func buildSTHMessage(sth *SignedTreeHead) []byte {
	msg := []byte("DIT-v2.2 STH cosign")
	msg = append(msg, sth.RootHash...)
	msg = append(msg, []byte(fmt.Sprintf("|%d|%d", sth.TreeSize, sth.Timestamp.Unix()))...)
	return msg
}
