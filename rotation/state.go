package rotation

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/dit-protocol/poc/identity"
	"github.com/dit-protocol/poc/pqc"
)

// Default policy values written into identity objects by the PoC.
const (
	DefaultNormalWait   = 24 * time.Hour
	DefaultRecoveryWait = 48 * time.Hour
	// GracePeriod: after a NORMAL rotation, clients still accept epoch
	// credentials from the previous IK for this long. There is no grace period
	// after a recovery rotation, because the previous IK may be compromised.
	GracePeriod = 7 * 24 * time.Hour
)

type pending struct {
	digest  []byte
	fromSeq uint64
	at      uint64
	sponsor string          // recovery only: digest of the sponsoring peer key
	cancels map[string]bool // recovery only: digests of cancelling peer keys
}

// Domain is the replicated per-domain state.
type Domain struct {
	Current   *identity.IdentityObject
	Previous  *identity.IdentityObject // set after a normal rotation (grace period)
	RotatedAt uint64
	Normal    *pending
	// Recovery holds the live recovery requests, keyed by new-identity
	// digest. Several may be pending at once; each registered peer sponsors at
	// most one, so fewer than t corrupt peers cannot crowd out the owner.
	Recovery      map[string]*pending
	RevokedEAKs   map[string]bool
	CancelledRecs int // number of recovery attempts aborted by peer cancels
}

// State is the key-event state of every domain in a log.
type State struct {
	Domains map[string]*Domain
	lastTS  uint64
}

// NewState returns empty state.
func NewState() *State { return &State{Domains: map[string]*Domain{}} }

// Rejection reasons.
var (
	ErrUnknownDomain   = errors.New("rotation: unknown domain")
	ErrDuplicate       = errors.New("rotation: domain already published")
	ErrBadSig          = errors.New("rotation: signature invalid")
	ErrSeq             = errors.New("rotation: sequence number or identity chain mismatch")
	ErrBusy            = errors.New("rotation: a rotation of this kind is already pending")
	ErrRecoveryPending = errors.New("rotation: a recovery rotation is pending (it has precedence)")
	ErrNoPending       = errors.New("rotation: no matching pending rotation")
	ErrTooEarly        = errors.New("rotation: waiting period has not elapsed")
	ErrRecoveryConfig  = errors.New("rotation: a normal rotation may not change the recovery configuration")
	ErrNotPeer         = errors.New("rotation: not signed by a registered recovery peer")
	ErrSponsorBusy     = errors.New("rotation: this peer already sponsors a live recovery request")
	ErrTimestamp       = errors.New("rotation: log timestamps must be non-decreasing")
)

func recoveryConfigEqual(a, b *identity.IdentityObject) bool {
	if !bytes.Equal(a.RecoveryGroupKey, b.RecoveryGroupKey) || a.RecoveryThreshold != b.RecoveryThreshold ||
		!bytes.Equal(a.ContactDigest, b.ContactDigest) || a.NormalWait != b.NormalWait ||
		a.RecoveryWait != b.RecoveryWait || a.CancelQuorum != b.CancelQuorum ||
		len(a.PeerKeyDigests) != len(b.PeerKeyDigests) {
		return false
	}
	for i := range a.PeerKeyDigests {
		if !bytes.Equal(a.PeerKeyDigests[i], b.PeerKeyDigests[i]) {
			return false
		}
	}
	return true
}

// checkSuccessor verifies that the identity carried by a rotation entry
// extends cur: seq+1, PrevDigest = digest(cur), digest = NewDigest.
func checkSuccessor(cur *identity.IdentityObject, e *Entry) (*identity.IdentityObject, error) {
	next, err := identity.UnmarshalIdentityTLV(e.Identity)
	if err != nil {
		return nil, err
	}
	if next.Domain != e.Domain || next.Seq != cur.Seq+1 || !bytes.Equal(next.PrevDigest, cur.Digest()) ||
		!bytes.Equal(next.Digest(), e.NewDigest) || e.FromSeq != cur.Seq {
		return nil, ErrSeq
	}
	return next, nil
}

// Apply validates e as the next entry of the log and updates the state. It is
// deterministic: every witness, monitor and client computes the same result.
func (s *State) Apply(e *Entry) error {
	if e.Timestamp < s.lastTS {
		return ErrTimestamp
	}
	d := s.Domains[e.Domain]
	if e.Type != KeyPublication && d == nil {
		return ErrUnknownDomain
	}
	var cur *identity.IdentityObject
	if d != nil {
		cur = d.Current
		if e.Type != KeyPublication && e.FromSeq != cur.Seq {
			return ErrSeq
		}
	}
	tbs := e.TBS()
	switch e.Type {
	case KeyPublication:
		if d != nil {
			return ErrDuplicate
		}
		id, err := identity.UnmarshalIdentityTLV(e.Identity)
		if err != nil {
			return err
		}
		if id.Domain != e.Domain || id.Seq != 0 || !pqc.Verify(id.IKPub, CtxPublication, tbs, e.SigA) {
			return ErrBadSig
		}
		s.Domains[e.Domain] = &Domain{Current: id, RevokedEAKs: map[string]bool{}, Recovery: map[string]*pending{}}

	case PendingNormal:
		if len(d.Recovery) > 0 {
			return ErrRecoveryPending
		}
		if d.Normal != nil {
			return ErrBusy
		}
		if !pqc.Verify(cur.IKPub, CtxPendingNormal, tbs, e.SigA) {
			return ErrBadSig
		}
		d.Normal = &pending{digest: e.NewDigest, fromSeq: e.FromSeq, at: e.Timestamp}

	case PendingRecovery:
		if d.Recovery[string(e.NewDigest)] != nil {
			return ErrBusy
		}
		// The request carries the successor identity; SigA proves possession
		// of IK_new and SigB is the sponsoring peer's signature, given only
		// after out-of-band confirmation with the registered contact.
		next, err := checkSuccessor(cur, e)
		if err != nil {
			return err
		}
		sponsor, err := registeredPeer(cur, e.PeerPub)
		if err != nil {
			return err
		}
		for _, p := range d.Recovery {
			if p.sponsor == sponsor {
				return ErrSponsorBusy
			}
		}
		if !pqc.Verify(next.IKPub, CtxPendingRecov, tbs, e.SigA) || !pqc.Verify(e.PeerPub, CtxPendingRecov, tbs, e.SigB) {
			return ErrBadSig
		}
		// Precedence: a recovery request supersedes a pending normal rotation.
		d.Normal = nil
		d.Recovery[string(e.NewDigest)] = &pending{digest: e.NewDigest, fromSeq: e.FromSeq, at: e.Timestamp,
			sponsor: sponsor, cancels: map[string]bool{}}

	case CancelNormal:
		if d.Normal == nil || !bytes.Equal(d.Normal.digest, e.NewDigest) {
			return ErrNoPending
		}
		if !pqc.Verify(cur.IKPub, CtxCancelNormal, tbs, e.SigA) {
			return ErrBadSig
		}
		d.Normal = nil

	case CancelRecovery:
		p := d.Recovery[string(e.NewDigest)]
		if p == nil {
			return ErrNoPending
		}
		pk, err := registeredPeer(cur, e.PeerPub)
		if err != nil {
			return err
		}
		if !pqc.Verify(e.PeerPub, CtxCancelRecov, tbs, e.SigA) {
			return ErrBadSig
		}
		// A single cancel does not abort: CancelQuorum distinct peers must
		// cancel, so fewer than CancelQuorum corrupt peers cannot block recovery.
		p.cancels[pk] = true
		if len(p.cancels) >= int(cur.CancelQuorum) {
			delete(d.Recovery, string(e.NewDigest))
			d.CancelledRecs++
		}

	case RotationNormal:
		if len(d.Recovery) > 0 {
			return ErrRecoveryPending
		}
		if d.Normal == nil || !bytes.Equal(d.Normal.digest, e.NewDigest) {
			return ErrNoPending
		}
		if e.Timestamp < d.Normal.at+cur.NormalWait {
			return ErrTooEarly
		}
		next, err := checkSuccessor(cur, e)
		if err != nil {
			return err
		}
		if !recoveryConfigEqual(cur, next) {
			return ErrRecoveryConfig
		}
		if !pqc.Verify(cur.IKPub, CtxRotationOld, tbs, e.SigA) || !pqc.Verify(next.IKPub, CtxRotationNew, tbs, e.SigB) {
			return ErrBadSig
		}
		d.Previous, d.Current, d.RotatedAt, d.Normal = cur, next, e.Timestamp, nil

	case RotationRecovery:
		p := d.Recovery[string(e.NewDigest)]
		if p == nil {
			return ErrNoPending
		}
		if e.Timestamp < p.at+cur.RecoveryWait {
			return ErrTooEarly
		}
		next, err := checkSuccessor(cur, e)
		if err != nil {
			return err
		}
		if len(cur.RecoveryGroupKey) != ed25519.PublicKeySize ||
			!ed25519.Verify(cur.RecoveryGroupKey, RecoveryMessage(tbs), e.SigA) {
			return ErrBadSig
		}
		// No grace period: the previous IK may be in the adversary's hands.
		d.Previous, d.Current, d.RotatedAt = nil, next, e.Timestamp
		d.Recovery = map[string]*pending{} // all other requests are void
		d.RevokedEAKs = map[string]bool{}

	case EAKRevocation:
		if !pqc.Verify(cur.IKPub, CtxEAKRevocation, tbs, e.SigA) {
			return ErrBadSig
		}
		d.RevokedEAKs[string(e.EAKDigest)] = true

	default:
		return fmt.Errorf("rotation: unknown entry type %d", e.Type)
	}
	s.lastTS = e.Timestamp
	return nil
}

func registeredPeer(cur *identity.IdentityObject, peerPub []byte) (string, error) {
	pk := pqc.SHA3(peerPub)
	for _, pd := range cur.PeerKeyDigests {
		if bytes.Equal(pd, pk) {
			return string(pk), nil
		}
	}
	return "", ErrNotPeer
}

// RecoveryMessage is the message FROST peers sign for a recovery rotation.
func RecoveryMessage(tbs []byte) []byte { return append([]byte(CtxRecovery), tbs...) }

// Clone returns a deep copy, so a witness can validate without committing.
func (s *State) Clone() *State {
	c := &State{Domains: make(map[string]*Domain, len(s.Domains)), lastTS: s.lastTS}
	for k, d := range s.Domains {
		nd := *d
		nd.RevokedEAKs = make(map[string]bool, len(d.RevokedEAKs))
		for r := range d.RevokedEAKs {
			nd.RevokedEAKs[r] = true
		}
		if d.Normal != nil {
			p := *d.Normal
			nd.Normal = &p
		}
		nd.Recovery = make(map[string]*pending, len(d.Recovery))
		for k, r := range d.Recovery {
			p := *r
			p.cancels = make(map[string]bool, len(r.cancels))
			for x := range r.cancels {
				p.cancels[x] = true
			}
			nd.Recovery[k] = &p
		}
		c.Domains[k] = &nd
	}
	return c
}

// Validator adapts State to tlog.Validator: a witness refuses to cosign an
// STH whose new entries contain an invalid transition.
type Validator struct {
	State *State
	Skew  time.Duration // tolerated clock skew between log and witness
}

// Validate applies entries to a copy of the state and commits on success.
func (v *Validator) Validate(entries [][]byte, now time.Time) error {
	c := v.State.Clone()
	for i, raw := range entries {
		e, err := Unmarshal(raw)
		if err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		if e.Timestamp > uint64(now.Add(v.Skew).Unix()) {
			return fmt.Errorf("entry %d: timestamp in the future", i)
		}
		if err := c.Apply(e); err != nil {
			return fmt.Errorf("entry %d (%s): %w", i, e.Type, err)
		}
	}
	*v.State = *c
	return nil
}
