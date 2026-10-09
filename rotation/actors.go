package rotation

import (
	"time"

	"filippo.io/edwards25519"

	"github.com/dit-protocol/poc/frost"
	"github.com/dit-protocol/poc/identity"
	"github.com/dit-protocol/poc/pqc"
)

// Peer is a recovery peer: an ML-DSA-65 key for sponsoring and cancelling
// requests, and a FROST share of the domain's recovery key.
type Peer struct {
	Key   *pqc.SigningKey
	Share *frost.KeyShare
}

// Owner is a domain owner's view: its current IK and identity object.
type Owner struct {
	IK       *pqc.SigningKey
	Identity *identity.IdentityObject
}

// NewDomain creates an owner with a fresh IK, n recovery peers holding a
// t-of-n FROST recovery key, and the signed KEY_PUBLICATION entry.
func NewDomain(domain string, t, n int, contact []byte) (*Owner, []*Peer, *Entry, error) {
	ik, err := pqc.GenerateSigningKey()
	if err != nil {
		return nil, nil, nil, err
	}
	shares, gpk, err := frost.TrustedDealerKeygen(t, n)
	if err != nil {
		return nil, nil, nil, err
	}
	id := &identity.IdentityObject{
		Domain: domain, PrevDigest: make([]byte, pqc.SHA3384Size), IKPub: ik.PublicKey(),
		RecoveryGroupKey: gpk, RecoveryThreshold: uint8(t), ContactDigest: pqc.SHA3(contact),
		NormalWait:   uint64(DefaultNormalWait / time.Second),
		RecoveryWait: uint64(DefaultRecoveryWait / time.Second),
		CancelQuorum: uint8(t),
	}
	peers := make([]*Peer, n)
	for i := range peers {
		k, err := pqc.GenerateSigningKey()
		if err != nil {
			return nil, nil, nil, err
		}
		peers[i] = &Peer{Key: k, Share: shares[i]}
		id.PeerKeyDigests = append(id.PeerKeyDigests, pqc.SHA3(k.PublicKey()))
	}
	e := &Entry{Type: KeyPublication, Domain: domain, Identity: id.MarshalTLV()}
	e.SigA = ik.Sign(CtxPublication, e.TBS())
	return &Owner{IK: ik, Identity: id}, peers, e, nil
}

// Successor returns the identity object that replaces cur with IK newIK and
// otherwise unchanged configuration.
func Successor(cur *identity.IdentityObject, newIK []byte) *identity.IdentityObject {
	n := *cur
	n.Seq, n.PrevDigest, n.IKPub = cur.Seq+1, cur.Digest(), newIK
	return &n
}

func at(ts time.Time) uint64 { return uint64(ts.Unix()) }

// PendingNormal builds ROTATION_PENDING(normal), signed by the current IK.
func PendingNormalEntry(curIK *pqc.SigningKey, cur, next *identity.IdentityObject, ts time.Time) *Entry {
	e := &Entry{Type: PendingNormal, Domain: cur.Domain, FromSeq: cur.Seq, NewDigest: next.Digest(), Timestamp: at(ts)}
	e.SigA = curIK.Sign(CtxPendingNormal, e.TBS())
	return e
}

// CancelNormalEntry cancels a pending normal rotation (signed by current IK).
func CancelNormalEntry(curIK *pqc.SigningKey, cur, next *identity.IdentityObject, ts time.Time) *Entry {
	e := &Entry{Type: CancelNormal, Domain: cur.Domain, FromSeq: cur.Seq, NewDigest: next.Digest(), Timestamp: at(ts)}
	e.SigA = curIK.Sign(CtxCancelNormal, e.TBS())
	return e
}

// RotationNormalEntry builds KEY_ROTATION(normal) with sigma_old and sigma_new.
func RotationNormalEntry(oldIK, newIK *pqc.SigningKey, cur, next *identity.IdentityObject, ts time.Time) *Entry {
	e := &Entry{Type: RotationNormal, Domain: cur.Domain, FromSeq: cur.Seq, NewDigest: next.Digest(),
		Identity: next.MarshalTLV(), Timestamp: at(ts)}
	e.SigA = oldIK.Sign(CtxRotationOld, e.TBS())
	e.SigB = newIK.Sign(CtxRotationNew, e.TBS())
	return e
}

// PendingRecoveryEntry builds ROTATION_PENDING(recovery), signed by IK_new and
// by one sponsoring peer.
func PendingRecoveryEntry(newIK *pqc.SigningKey, sponsor *Peer, cur, next *identity.IdentityObject, ts time.Time) *Entry {
	e := &Entry{Type: PendingRecovery, Domain: cur.Domain, FromSeq: cur.Seq, NewDigest: next.Digest(),
		Identity: next.MarshalTLV(), PeerPub: sponsor.Key.PublicKey(), Timestamp: at(ts)}
	e.SigA = newIK.Sign(CtxPendingRecov, e.TBS())
	e.SigB = sponsor.Key.Sign(CtxPendingRecov, e.TBS())
	return e
}

// CancelRecoveryEntry is one peer's signed cancel of a recovery request.
func CancelRecoveryEntry(p *Peer, cur, next *identity.IdentityObject, ts time.Time) *Entry {
	e := &Entry{Type: CancelRecovery, Domain: cur.Domain, FromSeq: cur.Seq, NewDigest: next.Digest(),
		PeerPub: p.Key.PublicKey(), Timestamp: at(ts)}
	e.SigA = p.Key.Sign(CtxCancelRecov, e.TBS())
	return e
}

// RotationRecoveryEntry runs FROST among signers and builds
// KEY_ROTATION(recovery) carrying sigma_rot.
func RotationRecoveryEntry(signers []*Peer, cur, next *identity.IdentityObject, ts time.Time) (*Entry, error) {
	e := &Entry{Type: RotationRecovery, Domain: cur.Domain, FromSeq: cur.Seq, NewDigest: next.Digest(),
		Identity: next.MarshalTLV(), Timestamp: at(ts)}
	msg := RecoveryMessage(e.TBS())
	nonces := make([]*frost.Nonces, len(signers))
	comms := make([]*frost.Commitment, len(signers))
	for i, p := range signers {
		nonces[i], comms[i] = frost.Commit(p.Share)
	}
	var zs []*edwards25519.Scalar
	for i, p := range signers {
		z, err := frost.SignShare(p.Share, nonces[i], msg, comms)
		if err != nil {
			return nil, err
		}
		zs = append(zs, z)
	}
	e.SigA = frost.Aggregate(signers[0].Share.GroupPublic, msg, comms, zs)
	return e, nil
}
