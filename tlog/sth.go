package tlog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/dit-protocol/poc/pqc"
)

const (
	ctxSTH    = "DIT-v3 log STH"
	ctxCosign = "DIT-v3 witness cosignature"
)

// STH is a Signed Tree Head.
type STH struct {
	LogID     []byte // SHA3-384 of the log operator's public key
	Size      uint64
	Timestamp uint64 // Unix seconds
	Root      []byte
	LogSig    []byte // ML-DSA-65 by the log operator
}

func (s *STH) tbs() []byte {
	b := make([]byte, 0, 2*HashSize+16)
	b = append(b, s.LogID...)
	b = binary.BigEndian.AppendUint64(b, s.Size)
	b = binary.BigEndian.AppendUint64(b, s.Timestamp)
	return append(b, s.Root...)
}

// Cosignature is one witness's signature over an STH.
type Cosignature struct {
	WitnessID uint8
	Sig       []byte // ML-DSA-65, 3309 B
}

// CosignedSTH is what a client receives and checks against its witness policy.
type CosignedSTH struct {
	STH     STH
	Cosigns []Cosignature
}

// WireSize returns the encoded length in bytes of the cosigned STH
// (fixed-width fields; signatures carried with a 2-byte length).
func (c *CosignedSTH) WireSize() int {
	n := HashSize + 8 + 8 + HashSize + 2 + len(c.STH.LogSig) + 1
	for _, cs := range c.Cosigns {
		n += 1 + 2 + len(cs.Sig)
	}
	return n
}

// ─── Log operator ─────────────────────────────────────────────────────────────

// Log is a log operator: it appends entries and signs tree heads.
type Log struct {
	Tree    Tree
	Entries [][]byte
	key     *pqc.SigningKey
	ID      []byte
}

// NewLog creates an empty log with a fresh ML-DSA-65 signing key.
func NewLog() (*Log, error) {
	k, err := pqc.GenerateSigningKey()
	if err != nil {
		return nil, err
	}
	return &Log{key: k, ID: pqc.SHA3(k.PublicKey())}, nil
}

// PublicKey returns the log operator's verification key.
func (l *Log) PublicKey() []byte { return l.key.PublicKey() }

// Append adds an encoded entry and returns its index.
func (l *Log) Append(entry []byte) uint64 {
	l.Entries = append(l.Entries, entry)
	return l.Tree.Append(entry)
}

// SignHead signs the current tree head.
func (l *Log) SignHead(now time.Time) STH {
	s := STH{LogID: l.ID, Size: l.Tree.Size(), Timestamp: uint64(now.Unix()), Root: l.Tree.Root()}
	s.LogSig = l.key.Sign(ctxSTH, s.tbs())
	return s
}

// ─── Witness ──────────────────────────────────────────────────────────────────

// Validator checks that newly appended entries are valid state transitions
// (for DIT: the rotation rules of package rotation). It returns an error to
// make the witness refuse to cosign.
type Validator interface {
	Validate(entries [][]byte, now time.Time) error
}

// Witness cosigns STHs after checking append-only consistency (T10) and the
// validity of the new entries. The PoC witness is a full witness: it stores
// all leaf hashes. A production witness could store only the right frontier.
type Witness struct {
	ID        uint8
	key       *pqc.SigningKey
	logPub    []byte
	last      *STH
	tree      Tree // the witness's own copy of the log's leaf hashes
	validator Validator
}

// NewWitness creates a witness for the log with public key logPub.
func NewWitness(id uint8, logPub []byte, v Validator) (*Witness, error) {
	k, err := pqc.GenerateSigningKey()
	if err != nil {
		return nil, err
	}
	return &Witness{ID: id, key: k, logPub: logPub, validator: v}, nil
}

// PublicKey returns the witness verification key.
func (w *Witness) PublicKey() []byte { return w.key.PublicKey() }

// Errors returned by Cosign.
var (
	ErrBadLogSig      = errors.New("tlog: STH log signature invalid")
	ErrInconsistent   = errors.New("tlog: STH not consistent with last cosigned STH")
	ErrRollback       = errors.New("tlog: STH timestamp or size went backwards")
	ErrInvalidEntries = errors.New("tlog: new entries are not valid transitions")
)

// Cosign verifies sth against the witness's last cosigned STH using the
// supplied consistency proof and the newly added entries, then cosigns.
func (w *Witness) Cosign(sth STH, consistency [][]byte, newEntries [][]byte, now time.Time) (*Cosignature, error) {
	if !pqc.Verify(w.logPub, ctxSTH, sth.tbs(), sth.LogSig) {
		return nil, ErrBadLogSig
	}
	if w.last != nil {
		if sth.Size < w.last.Size || sth.Timestamp < w.last.Timestamp {
			return nil, ErrRollback
		}
		if sth.Size > w.last.Size && !VerifyConsistency(w.last.Size, sth.Size, w.last.Root, sth.Root, consistency) {
			return nil, ErrInconsistent
		}
		if sth.Size == w.last.Size && !bytes.Equal(sth.Root, w.last.Root) {
			return nil, ErrInconsistent
		}
	}
	// The new entries must be exactly the leaves between the two heads: the
	// witness appends them to its own copy of the tree and recomputes the root.
	if uint64(len(newEntries)) != sth.Size-w.tree.Size() {
		return nil, fmt.Errorf("%w: expected %d new entries", ErrInconsistent, sth.Size-w.tree.Size())
	}
	candidate := Tree{leaves: append([][]byte(nil), w.tree.leaves...)}
	for _, e := range newEntries {
		candidate.Append(e)
	}
	if !bytes.Equal(candidate.Root(), sth.Root) {
		return nil, ErrInconsistent
	}
	if w.validator != nil {
		if err := w.validator.Validate(newEntries, now); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidEntries, err)
		}
	}
	s := sth
	w.last = &s
	w.tree = candidate
	return &Cosignature{WitnessID: w.ID, Sig: w.key.Sign(ctxCosign, sth.tbs())}, nil
}

// VerifyCosigned checks an STH against a client witness policy: the log
// signature and at least q valid cosignatures from distinct trusted witnesses.
func VerifyCosigned(c *CosignedSTH, logPub []byte, witnesses map[uint8][]byte, q int) error {
	if !pqc.Verify(logPub, ctxSTH, c.STH.tbs(), c.STH.LogSig) {
		return ErrBadLogSig
	}
	seen := map[uint8]bool{}
	for _, cs := range c.Cosigns {
		pub, ok := witnesses[cs.WitnessID]
		if !ok || seen[cs.WitnessID] {
			continue
		}
		if pqc.Verify(pub, ctxCosign, c.STH.tbs(), cs.Sig) {
			seen[cs.WitnessID] = true
		}
	}
	if len(seen) < q {
		return fmt.Errorf("tlog: %d valid cosignatures, policy requires %d", len(seen), q)
	}
	return nil
}
