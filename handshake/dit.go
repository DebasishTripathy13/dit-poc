package handshake

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DebasishTripathy13/dit-poc/identity"
	"github.com/DebasishTripathy13/dit-poc/pqc"
	"github.com/DebasishTripathy13/dit-poc/rotation"
	"github.com/DebasishTripathy13/dit-poc/tlog"
)

// SPKI returns the RFC 9881 SubjectPublicKeyInfo DER encoding of an
// ML-DSA-65 public key (1974 bytes for a 1952-byte key).
func SPKI(pub []byte) []byte {
	algID := []byte{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12}
	bits := append([]byte{0x03, 0x82, byte((len(pub) + 1) >> 8), byte(len(pub) + 1), 0x00}, pub...)
	n := len(algID) + len(bits)
	return append(append([]byte{0x30, 0x82, byte(n >> 8), byte(n)}, algID...), bits...)
}

func spkiKey(spki []byte) ([]byte, error) {
	if len(spki) != 1974 || !bytes.Equal(spki[:22], SPKI(make([]byte, 1952))[:22]) {
		return nil, errors.New("handshake: not an ML-DSA-65 SPKI")
	}
	return spki[22:], nil
}

// Encoding selects how the DIT bundle is serialized (R2.4 comparison).
type Encoding int

const (
	TLV Encoding = iota
	JSON
)

// ─── DIT bundle ───────────────────────────────────────────────────────────────

// Bundle is the content of the DIT CertificateEntry extension.
type Bundle struct {
	Credential *identity.EpochCredential // nil if the client holds it already
	// First-contact material: the log entry that installed the current
	// identity, its inclusion proof, and a q-of-m cosigned STH.
	Entry  []byte
	Index  uint64
	Proof  [][]byte
	STH    *tlog.CosignedSTH
	Legacy bool // set when decoded from JSON
}

func (b *Bundle) marshalTLV() []byte {
	w := &builder{}
	if b.Credential != nil {
		w.u8(1)
		w.vec24(b.Credential.MarshalTLV())
	}
	if b.Entry != nil {
		w.u8(2)
		w.vec24(b.Entry)
		w.u8(3)
		w.raw(binary.BigEndian.AppendUint64(nil, b.Index))
		w.u8(4)
		w.vec16(bytes.Join(b.Proof, nil))
		w.u8(5)
		w.vec24(marshalSTH(b.STH))
	}
	return w.b
}

func marshalSTH(c *tlog.CosignedSTH) []byte {
	w := &builder{}
	w.raw(c.STH.LogID)
	w.raw(binary.BigEndian.AppendUint64(nil, c.STH.Size))
	w.raw(binary.BigEndian.AppendUint64(nil, c.STH.Timestamp))
	w.raw(c.STH.Root)
	w.vec16(c.STH.LogSig)
	w.u8(byte(len(c.Cosigns)))
	for _, cs := range c.Cosigns {
		w.u8(cs.WitnessID)
		w.vec16(cs.Sig)
	}
	return w.b
}

func unmarshalSTH(b []byte) (*tlog.CosignedSTH, error) {
	p := &parser{b: b}
	c := &tlog.CosignedSTH{}
	c.STH.LogID = p.take(tlog.HashSize)
	c.STH.Size = p.u64()
	c.STH.Timestamp = p.u64()
	c.STH.Root = p.take(tlog.HashSize)
	c.STH.LogSig = p.vec16()
	n := int(p.u8())
	for i := 0; i < n && !p.err; i++ {
		c.Cosigns = append(c.Cosigns, tlog.Cosignature{WitnessID: p.u8(), Sig: p.vec16()})
	}
	if p.err || len(p.b) != 0 {
		return nil, errDecode
	}
	return c, nil
}

func unmarshalBundleTLV(b []byte) (*Bundle, error) {
	p := &parser{b: b}
	out := &Bundle{}
	for len(p.b) > 0 && !p.err {
		switch p.u8() {
		case 1:
			c, err := identity.UnmarshalCredentialTLV(p.vec24())
			if err != nil {
				return nil, err
			}
			out.Credential = c
		case 2:
			out.Entry = p.vec24()
		case 3:
			out.Index = p.u64()
		case 4:
			raw := p.vec16()
			if len(raw)%tlog.HashSize != 0 {
				return nil, errDecode
			}
			for i := 0; i < len(raw); i += tlog.HashSize {
				out.Proof = append(out.Proof, raw[i:i+tlog.HashSize])
			}
		case 5:
			s, err := unmarshalSTH(p.vec24())
			if err != nil {
				return nil, err
			}
			out.STH = s
		default:
			return nil, errDecode
		}
	}
	if p.err {
		return nil, errDecode
	}
	return out, nil
}

// JSON mirror of the bundle, matching the encoding style of the original PoC
// (JSON objects, binary fields base64-encoded). Signed objects are converted
// back to their canonical TLV form before verification.
type credJSON struct {
	Domain    string `json:"domain"`
	IdentSeq  uint64 `json:"ident_seq"`
	EAKPub    []byte `json:"eak_pub"`
	NotBefore uint64 `json:"not_before"`
	NotAfter  uint64 `json:"not_after"`
	SigIK     []byte `json:"sig_ik"`
}
type idJSON struct {
	Domain            string   `json:"domain"`
	Seq               uint64   `json:"seq"`
	PrevDigest        []byte   `json:"prev_digest"`
	IKPub             []byte   `json:"ik_pub"`
	RecoveryGroupKey  []byte   `json:"recovery_group_key"`
	RecoveryThreshold uint8    `json:"recovery_threshold"`
	PeerKeyDigests    [][]byte `json:"peer_key_digests"`
	ContactDigest     []byte   `json:"contact_digest"`
	NormalWait        uint64   `json:"normal_wait"`
	RecoveryWait      uint64   `json:"recovery_wait"`
	CancelQuorum      uint8    `json:"cancel_quorum"`
}
type entryJSON struct {
	Type      uint8   `json:"type"`
	Domain    string  `json:"domain"`
	FromSeq   uint64  `json:"from_seq"`
	NewDigest []byte  `json:"new_digest"`
	Identity  *idJSON `json:"identity"`
	PeerPub   []byte  `json:"peer_pub"`
	EAKDigest []byte  `json:"eak_digest"`
	Timestamp uint64  `json:"timestamp"`
	SigA      []byte  `json:"sig_a"`
	SigB      []byte  `json:"sig_b"`
}
type cosignJSON struct {
	ID  uint8  `json:"witness_id"`
	Sig []byte `json:"sig"`
}
type sthJSON struct {
	LogID     []byte       `json:"log_id"`
	Size      uint64       `json:"tree_size"`
	Timestamp uint64       `json:"timestamp"`
	Root      []byte       `json:"root"`
	LogSig    []byte       `json:"log_sig"`
	Cosigns   []cosignJSON `json:"cosignatures"`
}
type bundleJSON struct {
	Credential *credJSON  `json:"credential,omitempty"`
	Entry      *entryJSON `json:"entry,omitempty"`
	Index      uint64     `json:"leaf_index,omitempty"`
	Proof      [][]byte   `json:"inclusion_proof,omitempty"`
	STH        *sthJSON   `json:"sth,omitempty"`
}

func toIDJSON(o *identity.IdentityObject) *idJSON {
	return &idJSON{o.Domain, o.Seq, o.PrevDigest, o.IKPub, o.RecoveryGroupKey, o.RecoveryThreshold,
		o.PeerKeyDigests, o.ContactDigest, o.NormalWait, o.RecoveryWait, o.CancelQuorum}
}

func fromIDJSON(j *idJSON) *identity.IdentityObject {
	return &identity.IdentityObject{Domain: j.Domain, Seq: j.Seq, PrevDigest: j.PrevDigest, IKPub: j.IKPub,
		RecoveryGroupKey: j.RecoveryGroupKey, RecoveryThreshold: j.RecoveryThreshold,
		PeerKeyDigests: j.PeerKeyDigests, ContactDigest: j.ContactDigest, NormalWait: j.NormalWait,
		RecoveryWait: j.RecoveryWait, CancelQuorum: j.CancelQuorum}
}

func (b *Bundle) marshalJSON() ([]byte, error) {
	j := bundleJSON{}
	if c := b.Credential; c != nil {
		j.Credential = &credJSON{c.Domain, c.IdentSeq, c.EAKPub, c.NotBefore, c.NotAfter, c.SigIK}
	}
	if b.Entry != nil {
		e, err := rotation.Unmarshal(b.Entry)
		if err != nil {
			return nil, err
		}
		ej := &entryJSON{uint8(e.Type), e.Domain, e.FromSeq, e.NewDigest, nil, e.PeerPub, e.EAKDigest,
			e.Timestamp, e.SigA, e.SigB}
		if len(e.Identity) > 0 {
			o, err := identity.UnmarshalIdentityTLV(e.Identity)
			if err != nil {
				return nil, err
			}
			ej.Identity = toIDJSON(o)
		}
		j.Entry, j.Index, j.Proof = ej, b.Index, b.Proof
		s := b.STH
		j.STH = &sthJSON{s.STH.LogID, s.STH.Size, s.STH.Timestamp, s.STH.Root, s.STH.LogSig, nil}
		for _, cs := range s.Cosigns {
			j.STH.Cosigns = append(j.STH.Cosigns, cosignJSON{cs.WitnessID, cs.Sig})
		}
	}
	return json.Marshal(j)
}

func unmarshalBundleJSON(raw []byte) (*Bundle, error) {
	var j bundleJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, err
	}
	b := &Bundle{Legacy: true}
	if c := j.Credential; c != nil {
		b.Credential = &identity.EpochCredential{Domain: c.Domain, IdentSeq: c.IdentSeq, EAKPub: c.EAKPub,
			NotBefore: c.NotBefore, NotAfter: c.NotAfter, SigIK: c.SigIK}
	}
	if e := j.Entry; e != nil {
		ent := &rotation.Entry{Type: rotation.EntryType(e.Type), Domain: e.Domain, FromSeq: e.FromSeq,
			NewDigest: e.NewDigest, PeerPub: e.PeerPub, EAKDigest: e.EAKDigest, Timestamp: e.Timestamp,
			SigA: e.SigA, SigB: e.SigB}
		if e.Identity != nil {
			ent.Identity = fromIDJSON(e.Identity).MarshalTLV()
		}
		b.Entry, b.Index, b.Proof = ent.Marshal(), j.Index, j.Proof
		if j.STH == nil {
			return nil, errDecode
		}
		s := &tlog.CosignedSTH{STH: tlog.STH{LogID: j.STH.LogID, Size: j.STH.Size, Timestamp: j.STH.Timestamp,
			Root: j.STH.Root, LogSig: j.STH.LogSig}}
		for _, cs := range j.STH.Cosigns {
			s.Cosigns = append(s.Cosigns, tlog.Cosignature{WitnessID: cs.ID, Sig: cs.Sig})
		}
		b.STH = s
	}
	return b, nil
}

// ─── Server side ──────────────────────────────────────────────────────────────

// DITServer holds a domain's current EAK, credential and first-contact bundle.
type DITServer struct {
	EAK        *pqc.SigningKey
	Credential *identity.EpochCredential
	Entry      []byte // log entry that installed the current identity
	Index      uint64
	Proof      [][]byte
	STH        *tlog.CosignedSTH
	Encoding   Encoding
}

// Certificate implements ServerAuth: one RFC 7250 raw public key entry
// carrying the EAK, with the DIT bundle as a CertificateEntry extension.
func (s *DITServer) Certificate(clientExt []byte) (byte, []byte, error) {
	req, err := parseClientExt(clientExt)
	if err != nil {
		return 0, nil, err
	}
	b := &Bundle{}
	if !bytes.Equal(req.cachedCred, pqc.SHA3(s.Credential.MarshalTLV())) {
		b.Credential = s.Credential
	}
	if !req.warm || req.pinnedSeq != s.Credential.IdentSeq {
		b.Entry, b.Index, b.Proof, b.STH = s.Entry, s.Index, s.Proof, s.STH
	}
	var data []byte
	if s.Encoding == JSON {
		if data, err = b.marshalJSON(); err != nil {
			return 0, nil, err
		}
	} else {
		data = b.marshalTLV()
	}
	ext := &builder{}
	ext.ext(extDIT, data)
	entry := &builder{}
	entry.vec24(SPKI(s.EAK.PublicKey()))
	entry.vec16(ext.b)
	body := &builder{}
	body.vec8(nil)
	body.vec24(entry.b)
	return certTypeRawPublicKey, body.b, nil
}

// SignCertificateVerify implements ServerAuth with the EAK.
func (s *DITServer) SignCertificateVerify(content []byte) []byte { return s.EAK.Sign("", content) }

// ─── Client side ──────────────────────────────────────────────────────────────

type clientExt struct {
	warm       bool
	pinnedSeq  uint64
	cachedCred []byte
}

func parseClientExt(b []byte) (*clientExt, error) {
	if len(b) == 0 {
		return &clientExt{}, nil
	}
	if len(b) != 1+8+48 {
		return nil, errDecode
	}
	return &clientExt{warm: b[0] == 1, pinnedSeq: binary.BigEndian.Uint64(b[1:9]), cachedCred: b[9:]}, nil
}

// WitnessPolicy is the client-side witness set (trust assumption T8/T9).
type WitnessPolicy struct {
	LogPub    []byte
	Witnesses map[uint8][]byte
	Q         int
	MaxAge    time.Duration // maximum STH age accepted on first contact
}

// DITClient verifies a DIT server. Set Pin for the warm path; otherwise
// DNSCommitment (the DNSSEC-validated _dit value) and Policy are used.
type DITClient struct {
	DNSCommitment []byte
	Policy        WitnessPolicy
	Pin           *identity.IdentityObject
	CachedCred    *identity.EpochCredential
	Revoked       map[string]bool // EAK digests revoked in the log (optional)
	// GracePrev is the identity replaced by a NORMAL rotation; epoch
	// credentials issued under it are accepted until GraceUntil (Layer 6).
	GracePrev  *identity.IdentityObject
	GraceUntil time.Time
	Now        func() time.Time

	// Outputs.
	Verifies  int                       // ML-DSA-65 verifications performed
	Presented *identity.IdentityObject  // identity learned on first contact
	Cred      *identity.EpochCredential // credential used in this handshake
}

// Errors returned by the DIT client.
var (
	ErrCommitment = errors.New("dit: identity does not match the DNSSEC commitment")
	ErrInclusion  = errors.New("dit: log inclusion proof invalid")
	ErrStaleSTH   = errors.New("dit: STH too old")
	ErrEAKMatch   = errors.New("dit: raw public key differs from the certified EAK")
	ErrRevoked    = errors.New("dit: EAK revoked in the log")
	// ErrPinMismatch is returned when the server presents a different
	// identity than the pinned one; the caller resolves it with
	// rotation.ResolvePin (Layer 4) and retries.
	ErrPinMismatch = errors.New("dit: presented identity differs from pin")
)

func (c *DITClient) CertType() byte { return certTypeRawPublicKey }

func (c *DITClient) Extension() []byte {
	b := make([]byte, 1+8+48)
	if c.Pin != nil {
		b[0] = 1
		binary.BigEndian.PutUint64(b[1:9], c.Pin.Seq)
	}
	if c.CachedCred != nil {
		copy(b[9:], pqc.SHA3(c.CachedCred.MarshalTLV()))
	}
	return b
}

func (c *DITClient) VerifyCertificate(body []byte) ([]byte, error) {
	c.Verifies = 0
	p := &parser{b: body}
	p.vec8()
	entries := &parser{b: p.vec24()}
	spki := entries.vec24()
	exts, err := parseExtensions(entries.vec16())
	if err != nil || p.err || entries.err || len(entries.b) != 0 {
		return nil, errDecode
	}
	raw := exts[extDIT]
	var b *Bundle
	if len(raw) > 0 && raw[0] == '{' {
		b, err = unmarshalBundleJSON(raw)
	} else {
		b, err = unmarshalBundleTLV(raw)
	}
	if err != nil {
		return nil, err
	}
	now := c.Now()

	id := c.Pin
	if b.Entry != nil {
		presented, err := c.verifyFirstContact(b, now)
		if err != nil {
			return nil, err
		}
		inGrace := c.GracePrev != nil && now.Before(c.GraceUntil) && bytes.Equal(presented.Digest(), c.GracePrev.Digest())
		if id != nil && !inGrace && !bytes.Equal(presented.Digest(), id.Digest()) {
			c.Presented = presented
			return nil, ErrPinMismatch
		}
		if id == nil {
			id = presented
		}
		c.Presented = presented
	}
	if id == nil {
		return nil, errors.New("dit: no pin and no first-contact bundle")
	}

	cred := b.Credential
	if cred == nil {
		if c.CachedCred == nil {
			return nil, errors.New("dit: credential omitted but none cached")
		}
		cred = c.CachedCred
		if err := checkValidity(id, cred, now); err != nil {
			return nil, err
		}
	} else {
		c.Verifies++
		certifier := id
		if g := c.GracePrev; g != nil && cred.IdentSeq == g.Seq && cred.IdentSeq+1 == id.Seq && now.Before(c.GraceUntil) {
			certifier = g
		}
		if err := identity.VerifyCredential(certifier, cred, now); err != nil {
			return nil, err
		}
	}
	eak, err := spkiKey(spki)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(eak, cred.EAKPub) {
		return nil, ErrEAKMatch
	}
	if c.Revoked[string(pqc.SHA3(cred.EAKPub))] {
		return nil, ErrRevoked
	}
	c.Cred = cred
	c.Verifies++ // CertificateVerify, performed by the engine
	return eak, nil
}

func checkValidity(id *identity.IdentityObject, cred *identity.EpochCredential, now time.Time) error {
	t := uint64(now.Unix())
	if cred.Domain != id.Domain || cred.IdentSeq != id.Seq {
		return identity.ErrCredSeq
	}
	if t < cred.NotBefore || t >= cred.NotAfter {
		return identity.ErrCredExpired
	}
	return nil
}

// verifyFirstContact checks the DNSSEC commitment, the log entry's inclusion
// under a fresh STH, and the q-of-m witness cosignatures.
func (c *DITClient) verifyFirstContact(b *Bundle, now time.Time) (*identity.IdentityObject, error) {
	e, err := rotation.Unmarshal(b.Entry)
	if err != nil {
		return nil, err
	}
	switch e.Type {
	case rotation.KeyPublication, rotation.RotationNormal, rotation.RotationRecovery:
	default:
		return nil, fmt.Errorf("dit: entry type %s does not install an identity", e.Type)
	}
	id, err := identity.UnmarshalIdentityTLV(e.Identity)
	if err != nil {
		return nil, err
	}
	if c.DNSCommitment != nil && !id.VerifyAgainstCommitment(c.DNSCommitment) {
		return nil, ErrCommitment
	}
	if b.STH == nil || !tlog.VerifyInclusion(tlog.LeafHash(b.Entry), b.Index, b.STH.STH.Size, b.Proof, b.STH.STH.Root) {
		return nil, ErrInclusion
	}
	if age := now.Sub(time.Unix(int64(b.STH.STH.Timestamp), 0)); age > c.Policy.MaxAge {
		return nil, ErrStaleSTH
	}
	if err := tlog.VerifyCosigned(b.STH, c.Policy.LogPub, c.Policy.Witnesses, c.Policy.Q); err != nil {
		return nil, err
	}
	c.Verifies += 1 + len(b.STH.Cosigns)
	return id, nil
}

// BundleSizes returns the encoded size of b in TLV and in JSON.
func BundleSizes(b *Bundle) (tlv, js int) {
	j, err := b.marshalJSON()
	if err != nil {
		panic(err)
	}
	return len(b.marshalTLV()), len(j)
}
