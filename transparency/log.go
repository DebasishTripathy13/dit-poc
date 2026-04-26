// Package transparency implements the DIT transparency log: a BLAKE3-hashed,
// append-only Merkle tree with goroutine-safe access. In a full deployment,
// multiple log nodes gossip Merkle roots using a Byzantine-fault-tolerant
// protocol; clients query 3+ nodes and require quorum agreement before
// accepting a root.
//
// Log entry types:
//   KEY_PUBLICATION  - first publication of an Identity Key for a domain
//   ROTATION_PENDING - initiation of a key rotation ceremony
//   KEY_ROTATION     - completion of a key rotation ceremony
package transparency

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zeebo/blake3"
)

// ─── Entry types ──────────────────────────────────────────────────────────────

// EntryType identifies the kind of transparency log entry.
type EntryType string

const (
	EntryKeyPublication  EntryType = "KEY_PUBLICATION"
	EntryRotationPending EntryType = "ROTATION_PENDING"
	EntryKeyRotation     EntryType = "KEY_ROTATION"
)

// LogEntry is a single record in the DIT transparency log.
// The JSON encoding is the canonical form used for hashing.
type LogEntry struct {
	// Type is the entry category.
	Type EntryType `json:"type"`
	// Domain is the fully qualified domain name.
	Domain string `json:"domain"`
	// IKPublic is the base64url-encoded ML-DSA-65 public key being published
	// or rotated to.
	IKPublic []byte `json:"ik_pub"`
	// Timestamp is the Unix timestamp of the event.
	Timestamp int64 `json:"timestamp"`
	// PrevRoot is the hex-encoded BLAKE3 Merkle root just before this entry.
	PrevRoot string `json:"prev_root"`
	// WitnessSig is the trust witness's signature over the canonical entry.
	// PRODUCTION: ML-DSA-65 signature.
	WitnessSig []byte `json:"witness_sig,omitempty"`
	// RotationSig is the FROST threshold signature (KEY_ROTATION entries only).
	// PRODUCTION: FROST threshold signature.
	RotationSig []byte `json:"rotation_sig,omitempty"`
}

// hash returns the BLAKE3 leaf hash of the entry (with domain separation byte 0x00).
// Internal node hashes use domain separation byte 0x01 (see merkleHash).
func (e LogEntry) hash() ([]byte, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("marshal entry for hash: %w", err)
	}
	h := blake3.New()
	h.Write([]byte{0x00}) // domain separation: leaf
	h.Write(data)
	return h.Sum(nil), nil
}

// ─── Merkle Tree ──────────────────────────────────────────────────────────────

// merkleHash computes an internal Merkle node hash using domain separation byte 0x01.
// This follows the RFC 6962 convention to prevent second-preimage attacks.
func merkleHash(left, right []byte) []byte {
	h := blake3.New()
	h.Write([]byte{0x01}) // domain separation: internal node
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// MerkleProof is a list of sibling hashes along the path from a leaf to the root.
// leafIndex identifies which leaf the proof is for.
type MerkleProof struct {
	// LeafIndex is the 0-based index of the leaf.
	LeafIndex int
	// Siblings are the sibling hashes from leaf to root (left or right).
	// SiblingLeft[i] is true if the sibling at level i is to the left.
	Siblings   [][]byte
	SiblingLeft []bool
}

// MerkleTree is a complete binary Merkle tree over BLAKE3 leaf hashes.
// It is rebuilt from scratch on each append; a production implementation
// would maintain the tree incrementally.
type MerkleTree struct {
	leaves [][]byte // leaf hashes, one per log entry
}

// append adds a new leaf hash to the tree.
func (mt *MerkleTree) append(h []byte) {
	mt.leaves = append(mt.leaves, h)
}

// Root returns the current Merkle root, or a zero hash if the tree is empty.
func (mt *MerkleTree) Root() []byte {
	if len(mt.leaves) == 0 {
		zero := make([]byte, 32)
		return zero
	}
	return mt.buildRoot(mt.leaves)
}

// buildRoot recursively computes the Merkle root of a set of hashes.
func (mt *MerkleTree) buildRoot(hashes [][]byte) []byte {
	if len(hashes) == 1 {
		return hashes[0]
	}
	// Pad to even length by duplicating the last element.
	if len(hashes)%2 != 0 {
		hashes = append(hashes, hashes[len(hashes)-1])
	}
	var nextLevel [][]byte
	for i := 0; i < len(hashes); i += 2 {
		nextLevel = append(nextLevel, merkleHash(hashes[i], hashes[i+1]))
	}
	return mt.buildRoot(nextLevel)
}

// Proof returns a Merkle proof for the leaf at index idx.
func (mt *MerkleTree) Proof(idx int) (MerkleProof, error) {
	if idx < 0 || idx >= len(mt.leaves) {
		return MerkleProof{}, fmt.Errorf("proof: index %d out of range [0, %d)", idx, len(mt.leaves))
	}
	proof := MerkleProof{LeafIndex: idx}
	mt.buildProof(mt.leaves, idx, &proof)
	return proof, nil
}

// buildProof recursively builds the Merkle proof for leaf at position pos
// within the current level of hashes.
func (mt *MerkleTree) buildProof(hashes [][]byte, pos int, proof *MerkleProof) {
	if len(hashes) == 1 {
		return
	}
	// Pad to even length.
	if len(hashes)%2 != 0 {
		hashes = append(hashes, hashes[len(hashes)-1])
	}
	var nextLevel [][]byte
	for i := 0; i < len(hashes); i += 2 {
		nextLevel = append(nextLevel, merkleHash(hashes[i], hashes[i+1]))
	}
	pairIdx := pos ^ 1 // sibling index: XOR with 1 gives the pair
	proof.Siblings = append(proof.Siblings, hashes[pairIdx])
	proof.SiblingLeft = append(proof.SiblingLeft, pairIdx < pos)
	mt.buildProof(nextLevel, pos/2, proof)
}

// ─── Transparency Log ─────────────────────────────────────────────────────────

// TransparencyLog is an in-memory, goroutine-safe append-only DIT transparency
// log. In production this would be a distributed, BFT-replicated log with
// gossip propagation of Merkle roots between independent operators.
type TransparencyLog struct {
	mu      sync.RWMutex
	entries []LogEntry
	tree    MerkleTree
}

// NewTransparencyLog creates an empty transparency log.
func NewTransparencyLog() *TransparencyLog {
	return &TransparencyLog{}
}

// Submit appends a new entry to the log.
// The entry's PrevRoot is set to the current root before appending.
// Returns an error if the entry cannot be hashed.
//
// PRODUCTION additions:
//   - Require a valid witness signature on the entry.
//   - Replicate to all log nodes before returning.
//   - Return a signed receipt (STH - Signed Tree Head) to the submitter.
func (l *TransparencyLog) Submit(entry LogEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Record the root before this entry.
	entry.PrevRoot = hex.EncodeToString(l.tree.Root())
	entry.Timestamp = time.Now().UTC().Unix()

	h, err := entry.hash()
	if err != nil {
		return fmt.Errorf("submit: hash entry: %w", err)
	}
	l.tree.append(h)
	l.entries = append(l.entries, entry)
	return nil
}

// Query returns the log entry and a Merkle proof for the most recent entry
// for the given domain. Returns an error if no entry exists for the domain.
func (l *TransparencyLog) Query(domain string) (LogEntry, MerkleProof, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// Find the most recent entry for the domain.
	idx := -1
	for i := len(l.entries) - 1; i >= 0; i-- {
		if l.entries[i].Domain == domain {
			idx = i
			break
		}
	}
	if idx == -1 {
		return LogEntry{}, MerkleProof{}, fmt.Errorf("query: no entry found for domain %q", domain)
	}

	proof, err := l.tree.Proof(idx)
	if err != nil {
		return LogEntry{}, MerkleProof{}, fmt.Errorf("query: build proof: %w", err)
	}
	return l.entries[idx], proof, nil
}

// QueryAll returns all log entries for the given domain, oldest first.
func (l *TransparencyLog) QueryAll(domain string) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var result []LogEntry
	for _, e := range l.entries {
		if e.Domain == domain {
			result = append(result, e)
		}
	}
	return result
}

// Verify verifies that entry is included in the log with the given root,
// using proof as the Merkle inclusion proof.
//
// Returns true iff the proof is valid and the recomputed root matches root.
func Verify(entry LogEntry, proof MerkleProof, root []byte) bool {
	leafHash, err := entry.hash()
	if err != nil {
		return false
	}

	// Walk up the proof siblings to recompute the root.
	current := leafHash
	for i, sibling := range proof.Siblings {
		if proof.SiblingLeft[i] {
			current = merkleHash(sibling, current)
		} else {
			current = merkleHash(current, sibling)
		}
	}

	// Compare recomputed root with expected root.
	if len(current) != len(root) {
		return false
	}
	for i := range current {
		if current[i] != root[i] {
			return false
		}
	}
	return true
}

// GossipRoot returns the current Merkle root. In a full deployment, this value
// is gossiped between log nodes; clients query multiple nodes and require
// Byzantine-fault-tolerant quorum agreement before accepting a root.
//
// PRODUCTION: Also return a signed tree head (STH) with timestamp and log
// operator signature, compatible with RFC 6962 §3.5.
func (l *TransparencyLog) GossipRoot() []byte {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.tree.Root()
}

// Len returns the number of entries in the log.
func (l *TransparencyLog) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

// Root returns the current Merkle root (exported convenience wrapper).
func (l *TransparencyLog) Root() []byte {
	return l.GossipRoot()
}

// CheckEquivocation checks whether two claimed roots from different log nodes
// are consistent. If they differ, it means at least one node is equivocating,
// which is a security violation. Clients MUST refuse connections when
// equivocation is detected.
func CheckEquivocation(roots [][]byte) error {
	if len(roots) == 0 {
		return errors.New("check equivocation: no roots provided")
	}
	ref := roots[0]
	for i, r := range roots[1:] {
		if len(r) != len(ref) {
			return fmt.Errorf("check equivocation: root %d has different length", i+1)
		}
		for j := range r {
			if r[j] != ref[j] {
				return fmt.Errorf("check equivocation: root mismatch between node 0 and node %d — possible attack", i+1)
			}
		}
	}
	return nil
}
