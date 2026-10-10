// Package identity implements DIT Layers 1 and 2: the identity object, its
// DNS commitment, and the IK -> EAK epoch credential.
package identity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DebasishTripathy13/dit-poc/pqc"
)

// FIPS 204 context strings give domain separation between every IK signature.
const (
	CtxEpochCredential = "DIT-v3 epoch credential"
	CtxEAKRevocation   = "DIT-v3 eak revocation"
)

// IdentityObject is the full identity of a domain. Its SHA3-384 digest is
// published in the DNSSEC-signed _dit record and it is logged at every change.
type IdentityObject struct {
	Domain string
	Seq    uint64 // incremented on every IK rotation
	// PrevDigest is the digest of the previous identity object (48 zero bytes
	// for the first publication), so identities form a hash chain.
	PrevDigest []byte
	IKPub      []byte // ML-DSA-65, 1952 B
	// RecoveryGroupKey is the FROST(Ed25519, SHA-512) group public key used to
	// verify sigma_rot on a recovery rotation (32 B).
	RecoveryGroupKey  []byte
	RecoveryThreshold uint8
	// PeerKeyDigests commit to each recovery peer's ML-DSA-65 key, used to sign
	// CANCEL entries; the peer key itself is carried in the CANCEL entry.
	PeerKeyDigests [][]byte
	// ContactDigest commits to the out-of-band contact channel registered at
	// first publication (Section "Recovery authorization" of the paper).
	ContactDigest []byte
	// Waiting periods in seconds for normal and recovery rotation, and the
	// number k of distinct peer CANCELs needed to abort a recovery.
	NormalWait   uint64
	RecoveryWait uint64
	CancelQuorum uint8
}

// MarshalTLV returns the canonical binary encoding.
func (o *IdentityObject) MarshalTLV() []byte {
	w := &tlvWriter{}
	w.str(1, o.Domain)
	w.u64(2, o.Seq)
	w.bytes(3, o.PrevDigest)
	w.bytes(4, o.IKPub)
	w.bytes(5, o.RecoveryGroupKey)
	w.bytes(6, []byte{o.RecoveryThreshold})
	w.bytes(7, bytes.Join(o.PeerKeyDigests, nil))
	w.bytes(8, o.ContactDigest)
	w.u64(9, o.NormalWait)
	w.u64(10, o.RecoveryWait)
	w.bytes(11, []byte{o.CancelQuorum})
	return w.b
}

// UnmarshalIdentityTLV parses the canonical binary encoding.
func UnmarshalIdentityTLV(b []byte) (*IdentityObject, error) {
	r := &tlvReader{b: b}
	o := &IdentityObject{}
	var v []byte
	var err error
	if v, err = r.next(1); err != nil {
		return nil, err
	}
	o.Domain = string(v)
	if o.Seq, err = r.u64(2); err != nil {
		return nil, err
	}
	if o.PrevDigest, err = r.next(3); err != nil {
		return nil, err
	}
	if o.IKPub, err = r.next(4); err != nil {
		return nil, err
	}
	if o.RecoveryGroupKey, err = r.next(5); err != nil {
		return nil, err
	}
	if v, err = r.next(6); err != nil || len(v) != 1 {
		return nil, errTLV
	}
	o.RecoveryThreshold = v[0]
	if v, err = r.next(7); err != nil || len(v)%pqc.SHA3384Size != 0 {
		return nil, errTLV
	}
	for i := 0; i < len(v); i += pqc.SHA3384Size {
		o.PeerKeyDigests = append(o.PeerKeyDigests, v[i:i+pqc.SHA3384Size])
	}
	if o.ContactDigest, err = r.next(8); err != nil {
		return nil, err
	}
	if o.NormalWait, err = r.u64(9); err != nil {
		return nil, err
	}
	if o.RecoveryWait, err = r.u64(10); err != nil {
		return nil, err
	}
	if v, err = r.next(11); err != nil || len(v) != 1 {
		return nil, errTLV
	}
	o.CancelQuorum = v[0]
	return o, r.done()
}

// identityJSON is the JSON encoding used by the original PoC, kept only to
// measure the size difference against TLV (reviewer comment R2.4).
type identityJSON struct {
	Domain            string   `json:"domain"`
	Seq               uint64   `json:"seq"`
	PrevDigest        string   `json:"prev_digest"`
	IKPub             string   `json:"ik_pub"`
	RecoveryGroupKey  string   `json:"recovery_group_key"`
	RecoveryThreshold uint8    `json:"recovery_threshold"`
	PeerKeyDigests    []string `json:"peer_key_digests"`
	ContactDigest     string   `json:"contact_digest"`
	NormalWait        uint64   `json:"normal_wait"`
	RecoveryWait      uint64   `json:"recovery_wait"`
	CancelQuorum      uint8    `json:"cancel_quorum"`
}

var b64 = base64.RawURLEncoding

// MarshalJSON returns the JSON encoding (base64url byte fields).
func (o *IdentityObject) MarshalJSON() ([]byte, error) {
	j := identityJSON{
		Domain: o.Domain, Seq: o.Seq, PrevDigest: b64.EncodeToString(o.PrevDigest),
		IKPub: b64.EncodeToString(o.IKPub), RecoveryGroupKey: b64.EncodeToString(o.RecoveryGroupKey),
		RecoveryThreshold: o.RecoveryThreshold, ContactDigest: b64.EncodeToString(o.ContactDigest),
		NormalWait: o.NormalWait, RecoveryWait: o.RecoveryWait, CancelQuorum: o.CancelQuorum,
	}
	for _, d := range o.PeerKeyDigests {
		j.PeerKeyDigests = append(j.PeerKeyDigests, b64.EncodeToString(d))
	}
	return json.Marshal(j)
}

// Digest is the 48-byte SHA3-384 commitment published in DNS.
func (o *IdentityObject) Digest() []byte { return pqc.SHA3(o.MarshalTLV()) }

// DNSRecord renders the _dit SVCB record that carries the commitment.
func (o *IdentityObject) DNSRecord() string {
	return fmt.Sprintf("_dit.%s. 3600 IN SVCB 1 . key65400=%s",
		o.Domain, b64.EncodeToString(o.Digest()))
}

// VerifyAgainstCommitment checks that o matches the DNSSEC-validated commitment.
func (o *IdentityObject) VerifyAgainstCommitment(commitment []byte) bool {
	return bytes.Equal(o.Digest(), commitment)
}

// ─── Epoch credential (IK -> EAK) ─────────────────────────────────────────────

// EpochCredential certifies a fresh-random EAK for one epoch.
type EpochCredential struct {
	Domain    string
	IdentSeq  uint64 // identity object sequence number of the certifying IK
	EAKPub    []byte // ML-DSA-65, 1952 B
	NotBefore uint64 // Unix seconds
	NotAfter  uint64
	SigIK     []byte // ML-DSA-65 by IK, 3309 B
}

func (c *EpochCredential) tbs() []byte {
	w := &tlvWriter{}
	w.str(1, c.Domain)
	w.u64(2, c.IdentSeq)
	w.bytes(3, c.EAKPub)
	w.u64(4, c.NotBefore)
	w.u64(5, c.NotAfter)
	return w.b
}

// MarshalTLV returns the encoding sent on the wire.
func (c *EpochCredential) MarshalTLV() []byte {
	w := &tlvWriter{b: c.tbs()}
	w.bytes(6, c.SigIK)
	return w.b
}

// MarshalJSON returns the JSON encoding (for size comparison only).
func (c *EpochCredential) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"domain": c.Domain, "ident_seq": c.IdentSeq, "eak_pub": b64.EncodeToString(c.EAKPub),
		"not_before": c.NotBefore, "not_after": c.NotAfter, "sig_ik": b64.EncodeToString(c.SigIK),
	})
}

// UnmarshalCredentialTLV parses the wire encoding.
func UnmarshalCredentialTLV(b []byte) (*EpochCredential, error) {
	r := &tlvReader{b: b}
	c := &EpochCredential{}
	v, err := r.next(1)
	if err != nil {
		return nil, err
	}
	c.Domain = string(v)
	if c.IdentSeq, err = r.u64(2); err != nil {
		return nil, err
	}
	if c.EAKPub, err = r.next(3); err != nil {
		return nil, err
	}
	if c.NotBefore, err = r.u64(4); err != nil {
		return nil, err
	}
	if c.NotAfter, err = r.u64(5); err != nil {
		return nil, err
	}
	if c.SigIK, err = r.next(6); err != nil {
		return nil, err
	}
	return c, r.done()
}

// MaxEpoch is the maximum credential lifetime accepted by clients.
const MaxEpoch = 24 * time.Hour

// IssueEpochCredential generates a fresh-random EAK (independent of IK) and
// certifies it with IK.
func IssueEpochCredential(ik *pqc.SigningKey, domain string, identSeq uint64, now time.Time) (*pqc.SigningKey, *EpochCredential, error) {
	eak, err := pqc.GenerateSigningKey()
	if err != nil {
		return nil, nil, err
	}
	c := &EpochCredential{
		Domain: domain, IdentSeq: identSeq, EAKPub: eak.PublicKey(),
		NotBefore: uint64(now.Unix()), NotAfter: uint64(now.Add(MaxEpoch).Unix()),
	}
	c.SigIK = ik.Sign(CtxEpochCredential, c.tbs())
	return eak, c, nil
}

// Errors returned by VerifyCredential.
var (
	ErrCredSig     = errors.New("identity: epoch credential signature invalid")
	ErrCredDomain  = errors.New("identity: epoch credential domain mismatch")
	ErrCredExpired = errors.New("identity: epoch credential outside validity window")
	ErrCredSeq     = errors.New("identity: epoch credential certifies a superseded identity")
)

// VerifyCredential checks sigma_IK, domain binding, validity and that the
// credential was issued under the client's current identity object.
func VerifyCredential(id *IdentityObject, c *EpochCredential, now time.Time) error {
	if c.Domain != id.Domain {
		return ErrCredDomain
	}
	if c.IdentSeq != id.Seq {
		return ErrCredSeq
	}
	t := uint64(now.Unix())
	if t < c.NotBefore || t >= c.NotAfter || c.NotAfter-c.NotBefore > uint64(MaxEpoch/time.Second) {
		return ErrCredExpired
	}
	if !pqc.Verify(id.IKPub, CtxEpochCredential, c.tbs(), c.SigIK) {
		return ErrCredSig
	}
	return nil
}
