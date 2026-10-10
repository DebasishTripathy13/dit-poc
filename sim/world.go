// Package sim builds a complete DIT deployment in memory (log, witnesses, a
// published domain, its server and a client policy) for tests, benchmarks and
// the demonstration program.
package sim

import (
	"encoding/binary"
	"time"

	"github.com/DebasishTripathy13/dit-poc/handshake"
	"github.com/DebasishTripathy13/dit-poc/identity"
	"github.com/DebasishTripathy13/dit-poc/pqc"
	"github.com/DebasishTripathy13/dit-poc/rotation"
	"github.com/DebasishTripathy13/dit-poc/tlog"
)

// Parameters of the reference deployment.
const (
	Domain    = "bank.example"
	Witnesses = 7 // m
	Quorum    = 5 // q
	PeersN    = 5 // n recovery peers
	PeersT    = 3 // FROST threshold t
)

// World is a deployment with one DIT domain.
type World struct {
	Log        *tlog.Log
	Witnesses  []*tlog.Witness
	Policy     handshake.WitnessPolicy
	Owner      *rotation.Owner
	Peers      []*rotation.Peer
	Validator  *rotation.Validator
	Server     *handshake.DITServer
	Commitment []byte // value of the DNSSEC-signed _dit record
	PubEntry   []byte
	Now        time.Time
}

// NewWorld builds a log of logSize entries (logSize-1 filler entries from
// other domains, then this domain's KEY_PUBLICATION as the last leaf, so its
// inclusion proof has the full depth), has witnesses 1..q cosign the head, and
// issues an epoch credential.
func NewWorld(logSize int, enc handshake.Encoding) (*World, error) {
	now := time.Unix(1_800_000_000, 0)
	w := &World{Now: now}
	var err error
	if w.Log, err = tlog.NewLog(); err != nil {
		return nil, err
	}
	w.Policy = handshake.WitnessPolicy{LogPub: w.Log.PublicKey(), Witnesses: map[uint8][]byte{},
		Q: Quorum, MaxAge: 24 * time.Hour}
	for i := 1; i <= Witnesses; i++ {
		wt, err := tlog.NewWitness(uint8(i), w.Log.PublicKey(), nil)
		if err != nil {
			return nil, err
		}
		w.Witnesses = append(w.Witnesses, wt)
		w.Policy.Witnesses[uint8(i)] = wt.PublicKey()
	}
	var entries [][]byte
	for i := 0; i < logSize-1; i++ {
		filler := binary.BigEndian.AppendUint64([]byte("filler-entry-"), uint64(i))
		w.Log.Append(filler)
		entries = append(entries, filler)
	}
	var pub *rotation.Entry
	if w.Owner, w.Peers, pub, err = rotation.NewDomain(Domain, PeersT, PeersN, []byte("mailto:owner@bank.example")); err != nil {
		return nil, err
	}
	pub.Timestamp = uint64(now.Add(-time.Hour).Unix())
	w.PubEntry = pub.Marshal()
	idx := w.Log.Append(w.PubEntry)
	entries = append(entries, w.PubEntry)
	sth := w.Log.SignHead(now.Add(-time.Minute))
	cs := &tlog.CosignedSTH{STH: sth}
	for _, wt := range w.Witnesses[:Quorum] {
		c, err := wt.Cosign(sth, nil, entries, now)
		if err != nil {
			return nil, err
		}
		cs.Cosigns = append(cs.Cosigns, *c)
	}
	proof, err := w.Log.Tree.InclusionProof(idx, w.Log.Tree.Size())
	if err != nil {
		return nil, err
	}
	w.Commitment = w.Owner.Identity.Digest()
	eak, cred, err := identity.IssueEpochCredential(w.Owner.IK, Domain, w.Owner.Identity.Seq, now.Add(-30*time.Minute))
	if err != nil {
		return nil, err
	}
	w.Server = &handshake.DITServer{EAK: eak, Credential: cred, Entry: w.PubEntry, Index: idx,
		Proof: proof, STH: cs, Encoding: enc}
	return w, nil
}

// ColdClient returns a first-contact client for this world.
func (w *World) ColdClient() *handshake.DITClient {
	return &handshake.DITClient{DNSCommitment: w.Commitment, Policy: w.Policy, Now: func() time.Time { return w.Now }}
}

// WarmClient returns a client that has pinned the identity and, if withCred,
// cached the current epoch credential.
func (w *World) WarmClient(withCred bool) *handshake.DITClient {
	c := w.ColdClient()
	c.Pin = w.Owner.Identity
	if withCred {
		c.CachedCred = w.Server.Credential
	}
	return c
}

// NewEAK rotates the server to a fresh epoch key (a new epoch).
func (w *World) NewEAK() error {
	eak, cred, err := identity.IssueEpochCredential(w.Owner.IK, Domain, w.Owner.Identity.Seq, w.Now.Add(-time.Minute))
	if err != nil {
		return err
	}
	w.Server.EAK, w.Server.Credential = eak, cred
	return nil
}

// Unused guard so that pqc stays imported if fields change.
var _ = pqc.SHA3384Size
