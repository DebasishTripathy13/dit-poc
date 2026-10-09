package rotation

import (
	"errors"
	"testing"
	"time"

	"github.com/dit-protocol/poc/pqc"
	"github.com/dit-protocol/poc/tlog"
)

const dom = "bank.example"

var t0 = time.Unix(1_800_000_000, 0)

func setup(t *testing.T) (*State, *Owner, []*Peer) {
	t.Helper()
	o, peers, pub, err := NewDomain(dom, 3, 5, []byte("mailto:owner@bank.example"))
	if err != nil {
		t.Fatal(err)
	}
	pub.Timestamp = at(t0)
	s := NewState()
	must(t, s.Apply(pub))
	return s, o, peers
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustFail(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
}

func newIK(t *testing.T) *pqc.SigningKey {
	k, err := pqc.GenerateSigningKey()
	must(t, err)
	return k
}

func TestNormalRotationRequiresWaitingPeriod(t *testing.T) {
	s, o, _ := setup(t)
	ik2 := newIK(t)
	next := Successor(o.Identity, ik2.PublicKey())
	must(t, s.Apply(PendingNormalEntry(o.IK, o.Identity, next, t0.Add(time.Hour))))
	mustFail(t, s.Apply(RotationNormalEntry(o.IK, ik2, o.Identity, next, t0.Add(2*time.Hour))), ErrTooEarly)
	must(t, s.Apply(RotationNormalEntry(o.IK, ik2, o.Identity, next, t0.Add(26*time.Hour))))
	if s.Domains[dom].Current.Seq != 1 || s.Domains[dom].Previous == nil {
		t.Fatal("rotation not applied or grace state missing")
	}
}

func TestNormalRotationCannotChangeRecoveryConfig(t *testing.T) {
	s, o, _ := setup(t)
	ik2 := newIK(t)
	next := Successor(o.Identity, ik2.PublicKey())
	next.RecoveryGroupKey = make([]byte, 32) // attacker swaps the recovery key
	must(t, s.Apply(PendingNormalEntry(o.IK, o.Identity, next, t0.Add(time.Hour))))
	mustFail(t, s.Apply(RotationNormalEntry(o.IK, ik2, o.Identity, next, t0.Add(26*time.Hour))), ErrRecoveryConfig)
}

func TestNormalRotationNeedsBothSignatures(t *testing.T) {
	s, o, _ := setup(t)
	ik2, other := newIK(t), newIK(t)
	next := Successor(o.Identity, ik2.PublicKey())
	must(t, s.Apply(PendingNormalEntry(o.IK, o.Identity, next, t0.Add(time.Hour))))
	// sigma_new by a key other than IK_new (no proof of possession).
	mustFail(t, s.Apply(RotationNormalEntry(o.IK, other, o.Identity, next, t0.Add(26*time.Hour))), ErrBadSig)
	// sigma_old by a key other than the current IK.
	mustFail(t, s.Apply(RotationNormalEntry(other, ik2, o.Identity, next, t0.Add(26*time.Hour))), ErrBadSig)
}

// A7: the adversary holds IK and starts a normal rotation to its own key. The
// owner detects the pending entry and starts a recovery, which supersedes it.
// The adversary cannot complete its rotation, cannot cancel the recovery with
// IK, and the recovery completes after the recovery waiting period.
func TestStolenIKRaceRecoveryWins(t *testing.T) {
	s, o, peers := setup(t)
	evilIK := newIK(t)
	evil := Successor(o.Identity, evilIK.PublicKey())
	must(t, s.Apply(PendingNormalEntry(o.IK, o.Identity, evil, t0.Add(time.Hour))))

	ownerIK := newIK(t)
	good := Successor(o.Identity, ownerIK.PublicKey())
	must(t, s.Apply(PendingRecoveryEntry(ownerIK, peers[0], o.Identity, good, t0.Add(3*time.Hour))))

	mustFail(t, s.Apply(RotationNormalEntry(o.IK, evilIK, o.Identity, evil, t0.Add(26*time.Hour))), ErrRecoveryPending)
	mustFail(t, s.Apply(PendingNormalEntry(o.IK, o.Identity, evil, t0.Add(27*time.Hour))), ErrRecoveryPending)
	// IK is not a peer key, so the adversary cannot cancel the recovery.
	fake := &Peer{Key: o.IK}
	mustFail(t, s.Apply(CancelRecoveryEntry(fake, o.Identity, good, t0.Add(28*time.Hour))), ErrNotPeer)

	rec, err := RotationRecoveryEntry(peers[1:4], o.Identity, good, t0.Add(52*time.Hour))
	must(t, err)
	must(t, s.Apply(rec))
	d := s.Domains[dom]
	if d.Current.Seq != 1 || string(d.Current.IKPub) != string(ownerIK.PublicKey()) || d.Previous != nil {
		t.Fatal("recovery did not install the owner's key without grace period")
	}
}

// A7 detected late: the adversary's normal rotation completed. Because a
// normal rotation cannot change the recovery configuration, the owner can
// still recover from the adversary's identity.
func TestStolenIKLateDetectionStillRecoverable(t *testing.T) {
	s, o, peers := setup(t)
	evilIK := newIK(t)
	evil := Successor(o.Identity, evilIK.PublicKey())
	must(t, s.Apply(PendingNormalEntry(o.IK, o.Identity, evil, t0.Add(time.Hour))))
	must(t, s.Apply(RotationNormalEntry(o.IK, evilIK, o.Identity, evil, t0.Add(26*time.Hour))))

	ownerIK := newIK(t)
	good := Successor(evil, ownerIK.PublicKey())
	must(t, s.Apply(PendingRecoveryEntry(ownerIK, peers[2], evil, good, t0.Add(30*time.Hour))))
	rec, err := RotationRecoveryEntry([]*Peer{peers[0], peers[2], peers[4]}, evil, good, t0.Add(78*time.Hour))
	must(t, err)
	must(t, s.Apply(rec))
	if s.Domains[dom].Current.Seq != 2 || string(s.Domains[dom].Current.IKPub) != string(ownerIK.PublicKey()) {
		t.Fatal("owner did not regain control")
	}
}

func TestRecoveryNeedsThresholdAndWait(t *testing.T) {
	s, o, peers := setup(t)
	ik2 := newIK(t)
	next := Successor(o.Identity, ik2.PublicKey())
	must(t, s.Apply(PendingRecoveryEntry(ik2, peers[0], o.Identity, next, t0.Add(time.Hour))))
	early, _ := RotationRecoveryEntry(peers[:3], o.Identity, next, t0.Add(10*time.Hour))
	mustFail(t, s.Apply(early), ErrTooEarly)
	two, _ := RotationRecoveryEntry(peers[:2], o.Identity, next, t0.Add(50*time.Hour))
	mustFail(t, s.Apply(two), ErrBadSig)
	ok, _ := RotationRecoveryEntry(peers[2:], o.Identity, next, t0.Add(50*time.Hour))
	must(t, s.Apply(ok))
}

// Fewer than CancelQuorum (= t = 3) corrupt peers cannot block a recovery.
func TestCancelRequiresQuorum(t *testing.T) {
	s, o, peers := setup(t)
	ik2 := newIK(t)
	next := Successor(o.Identity, ik2.PublicKey())
	must(t, s.Apply(PendingRecoveryEntry(ik2, peers[0], o.Identity, next, t0.Add(time.Hour))))
	must(t, s.Apply(CancelRecoveryEntry(peers[3], o.Identity, next, t0.Add(2*time.Hour))))
	must(t, s.Apply(CancelRecoveryEntry(peers[4], o.Identity, next, t0.Add(3*time.Hour))))
	// Repeating a cancel does not count twice.
	must(t, s.Apply(CancelRecoveryEntry(peers[4], o.Identity, next, t0.Add(4*time.Hour))))
	if len(s.Domains[dom].Recovery) != 1 {
		t.Fatal("two corrupt peers aborted the recovery")
	}
	rec, _ := RotationRecoveryEntry(peers[:3], o.Identity, next, t0.Add(50*time.Hour))
	must(t, s.Apply(rec))

	// Three cancels abort.
	ik3 := newIK(t)
	cur := s.Domains[dom].Current
	n3 := Successor(cur, ik3.PublicKey())
	must(t, s.Apply(PendingRecoveryEntry(ik3, peers[1], cur, n3, t0.Add(51*time.Hour))))
	for i := 0; i < 3; i++ {
		must(t, s.Apply(CancelRecoveryEntry(peers[i], cur, n3, t0.Add(52*time.Hour))))
	}
	if len(s.Domains[dom].Recovery) != 0 || s.Domains[dom].CancelledRecs != 1 {
		t.Fatal("three cancels did not abort the recovery")
	}
}

// A corrupt peer can sponsor one bogus request but cannot occupy the slot of
// an honest sponsor, so the owner's request can always be opened.
func TestRecoverySpamBounded(t *testing.T) {
	s, o, peers := setup(t)
	bogusIK := newIK(t)
	bogus := Successor(o.Identity, bogusIK.PublicKey())
	must(t, s.Apply(PendingRecoveryEntry(bogusIK, peers[4], o.Identity, bogus, t0.Add(time.Hour))))
	b2IK := newIK(t)
	b2 := Successor(o.Identity, b2IK.PublicKey())
	mustFail(t, s.Apply(PendingRecoveryEntry(b2IK, peers[4], o.Identity, b2, t0.Add(time.Hour))), ErrSponsorBusy)
	ownerIK := newIK(t)
	good := Successor(o.Identity, ownerIK.PublicKey())
	must(t, s.Apply(PendingRecoveryEntry(ownerIK, peers[0], o.Identity, good, t0.Add(2*time.Hour))))
	rec, _ := RotationRecoveryEntry(peers[:3], o.Identity, good, t0.Add(51*time.Hour))
	must(t, s.Apply(rec))
	if len(s.Domains[dom].Recovery) != 0 {
		t.Fatal("bogus request survived the completed recovery")
	}
	// An unregistered key cannot sponsor.
	outsider := &Peer{Key: newIK(t)}
	cur := s.Domains[dom].Current
	n := Successor(cur, newIK(t).PublicKey())
	mustFail(t, s.Apply(PendingRecoveryEntry(ownerIK, outsider, cur, n, t0.Add(52*time.Hour))), ErrNotPeer)
}

func TestReplayAndRollbackRejected(t *testing.T) {
	s, o, _ := setup(t)
	ik2 := newIK(t)
	next := Successor(o.Identity, ik2.PublicKey())
	p := PendingNormalEntry(o.IK, o.Identity, next, t0.Add(time.Hour))
	must(t, s.Apply(p))
	r := RotationNormalEntry(o.IK, ik2, o.Identity, next, t0.Add(26*time.Hour))
	must(t, s.Apply(r))
	r.Timestamp = at(t0.Add(27 * time.Hour))
	mustFail(t, s.Apply(r), ErrSeq) // replay of an applied rotation
	old := PendingNormalEntry(o.IK, o.Identity, next, t0.Add(time.Minute))
	mustFail(t, s.Apply(old), ErrTimestamp)
}

// A witness running the validator refuses to cosign a head that contains an
// invalid transition, and the log remains usable afterwards.
func TestWitnessRefusesInvalidTransition(t *testing.T) {
	o, _, pub, err := NewDomain(dom, 3, 5, []byte("contact"))
	must(t, err)
	pub.Timestamp = at(t0)
	log, _ := tlog.NewLog()
	v := &Validator{State: NewState(), Skew: time.Minute}
	w, _ := tlog.NewWitness(1, log.PublicKey(), v)
	log.Append(pub.Marshal())
	sth := log.SignHead(t0)
	_, err = w.Cosign(sth, nil, [][]byte{pub.Marshal()}, t0)
	must(t, err)

	ik2 := newIK(t)
	next := Successor(o.Identity, ik2.PublicKey())
	early := RotationNormalEntry(o.IK, ik2, o.Identity, next, t0) // no pending, no wait
	log.Append(early.Marshal())
	sth2 := log.SignHead(t0)
	p, _ := log.Tree.ConsistencyProof(1, 2)
	if _, err := w.Cosign(sth2, p, [][]byte{early.Marshal()}, t0); !errors.Is(err, tlog.ErrInvalidEntries) {
		t.Fatalf("witness cosigned an invalid rotation: %v", err)
	}
}

func TestResolvePin(t *testing.T) {
	_, o, peers := setup(t)
	pin := o.Identity
	ik2 := newIK(t)
	next := Successor(pin, ik2.PublicKey())
	h := []*Entry{
		PendingNormalEntry(o.IK, pin, next, t0.Add(time.Hour)),
		RotationNormalEntry(o.IK, ik2, pin, next, t0.Add(26*time.Hour)),
	}
	d, err := ResolvePin(pin, next, h)
	must(t, err)
	if d.Previous == nil {
		t.Fatal("normal rotation should leave the previous identity for the grace period")
	}
	// Same presented identity without the rotation entry: rejected.
	mustFail(t, func() error { _, err := ResolvePin(pin, next, h[:1]); return err }(), ErrPinChain)
	// A rotation whose waiting period was skipped (e.g. a log that colluded
	// with the adversary) is rejected by the client's own replay.
	early := []*Entry{h[0], RotationNormalEntry(o.IK, ik2, pin, next, t0.Add(2*time.Hour))}
	mustFail(t, func() error { _, err := ResolvePin(pin, next, early); return err }(), ErrPinChain)
	// Rollback to the pinned predecessor or a same-seq fork: rejected.
	mustFail(t, func() error { _, err := ResolvePin(next, pin, nil); return err }(), ErrPinRollback)
	fork := Successor(pin, newIK(t).PublicKey())
	mustFail(t, func() error { _, err := ResolvePin(next, fork, nil); return err }(), ErrPinRollback)
	// Recovery path: no grace period.
	ik3 := newIK(t)
	n3 := Successor(pin, ik3.PublicKey())
	rec, _ := RotationRecoveryEntry(peers[:3], pin, n3, t0.Add(60*time.Hour))
	d, err = ResolvePin(pin, n3, []*Entry{PendingRecoveryEntry(ik3, peers[0], pin, n3, t0.Add(time.Hour)), rec})
	must(t, err)
	if d.Previous != nil {
		t.Fatal("recovery must not leave a grace period")
	}
}

// A log that backdates a pending entry (to make the waiting period appear to
// have elapsed) is caught by the witnesses' clock-window check.
func TestWitnessRejectsBackdatedEntry(t *testing.T) {
	o, _, pub, err := NewDomain(dom, 3, 5, []byte("contact"))
	must(t, err)
	pub.Timestamp = at(t0)
	v := &Validator{State: NewState(), Skew: 5 * time.Minute}
	must(t, v.Validate([][]byte{pub.Marshal()}, t0))
	ik2 := newIK(t)
	next := Successor(o.Identity, ik2.PublicKey())
	now := t0.Add(30 * 24 * time.Hour)
	backdated := PendingNormalEntry(o.IK, o.Identity, next, t0.Add(time.Minute))
	if err := v.Validate([][]byte{backdated.Marshal()}, now); err == nil {
		t.Fatal("backdated pending entry accepted")
	}
	honest := PendingNormalEntry(o.IK, o.Identity, next, now)
	must(t, v.Validate([][]byte{honest.Marshal()}, now))
	early := RotationNormalEntry(o.IK, ik2, o.Identity, next, now.Add(time.Hour))
	if err := v.Validate([][]byte{early.Marshal()}, now.Add(time.Hour)); err == nil {
		t.Fatal("rotation before the waiting period accepted")
	}
	must(t, v.Validate([][]byte{RotationNormalEntry(o.IK, ik2, o.Identity, next, now.Add(25*time.Hour)).Marshal()}, now.Add(25*time.Hour)))
}
