// Package ceremony implements the DIT Identity Key rotation ceremony.
// In the full protocol this uses FROST (Flexible Round-Optimized Schnorr
// Threshold Signatures) for (t,n) threshold signing. Here we simulate the
// threshold logic with a vote counter; replace Sign() with actual FROST
// round-1/round-2 execution using a real FROST library.
//
// Ceremony phases:
//   Phase 1  (Day 0)   - Domain owner initiates; ROTATION_PENDING posted to log
//   Phase 2  (Day 0-2) - Mandatory waiting period; any peer can cancel
//   Phase 3  (Day 2)   - t-of-n peers sign with FROST
//   Phase 4  (Day 2+)  - Witness posts KEY_ROTATION to log
//   Phase 5  (Day 2-9) - 7-day grace period; old IK still accepted
package ceremony

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dit-protocol/poc/protocol"
	"github.com/dit-protocol/poc/transparency"
)

// ─── State machine ────────────────────────────────────────────────────────────

// CeremonyState tracks the current phase of the key rotation ceremony.
type CeremonyState int

const (
	StateIdle     CeremonyState = iota // no ceremony in progress
	StatePending                       // ROTATION_PENDING posted; waiting period active
	StateSigning                       // waiting period complete; collecting peer signatures
	StateComplete                      // KEY_ROTATION posted; grace period active
	StateCancelled                     // ceremony was cancelled by a peer
)

func (s CeremonyState) String() string {
	switch s {
	case StateIdle:
		return "IDLE"
	case StatePending:
		return "PENDING"
	case StateSigning:
		return "SIGNING"
	case StateComplete:
		return "COMPLETE"
	case StateCancelled:
		return "CANCELLED"
	default:
		return "UNKNOWN"
	}
}

// ─── Recovery Peer ────────────────────────────────────────────────────────────

// RecoveryPeer represents one of the n recovery peers who participate in the
// FROST threshold key ceremony. In production, peers are identified by their
// own ML-DSA-65 keys and communicate over mutually authenticated channels.
//
// Geographic distribution of peers is strongly recommended to ensure
// availability and prevent collusion.
type RecoveryPeer struct {
	// ID is the peer's unique identifier (e.g., "peer-1").
	ID string
	// PublicKey is the peer's ML-DSA-65 verification key.
	// PRODUCTION: Replace []byte with a proper ML-DSA-65 public key type.
	PublicKey []byte
	// Endpoint is the peer's contact address for FROST protocol messages.
	Endpoint string
}

// ─── Ceremony Request ─────────────────────────────────────────────────────────

// CeremonyRequest encapsulates the domain owner's rotation request submitted
// to the Trust Witness to initiate Phase 1.
type CeremonyRequest struct {
	// Domain is the domain whose Identity Key is being rotated.
	Domain string
	// NewIKPublic is the new Identity Key public component.
	NewIKPublic []byte
	// DomainProof is evidence of DNS control (e.g., a signed DNS challenge).
	// PRODUCTION: ACME-style DNS-01 challenge response or similar.
	DomainProof []byte
	// RequestedAt is when the rotation was requested.
	RequestedAt time.Time
}

// ─── Ceremony ─────────────────────────────────────────────────────────────────

// Ceremony manages the lifecycle of a DIT Identity Key rotation ceremony.
// It is safe for concurrent use.
type Ceremony struct {
	mu sync.Mutex

	// Configuration
	domain       string
	oldIK        protocol.IdentityKey
	newIK        protocol.IdentityKey
	peers        []RecoveryPeer
	threshold    int // t in (t,n) threshold
	log          *transparency.TransparencyLog
	WaitDuration time.Duration // minimum wait before signing phase

	// State
	state       CeremonyState
	initiatedAt time.Time
	signatures  map[string][]byte // peerID → simulated FROST signature share
	cancelledBy string
}

// NewCeremony creates a new key rotation ceremony.
//
// domain: the domain whose key is being rotated
// oldIK:  the current active Identity Key (public component sufficient for logging)
// newIK:  the new Identity Key to rotate to (must have private key for signing)
// peers:  the n recovery peers
// log:    the transparency log to post entries to
//
// The default threshold is ceil(len(peers)/2)+1 (strict majority); use
// SetThreshold to override. The recommended (3,5) threshold is set when
// 5 peers are provided.
func NewCeremony(
	domain string,
	oldIK, newIK protocol.IdentityKey,
	peers []RecoveryPeer,
	log *transparency.TransparencyLog,
) *Ceremony {
	// Default: strict majority threshold.
	t := len(peers)/2 + 1
	if len(peers) == 5 {
		t = 3 // recommended DIT (3,5) threshold
	}
	return &Ceremony{
		domain:       domain,
		oldIK:        oldIK,
		newIK:        newIK,
		peers:        peers,
		threshold:    t,
		log:          log,
		WaitDuration: 48 * time.Hour, // PRODUCTION: 48 hours; tests override to 1s
		state:        StateIdle,
		signatures:   make(map[string][]byte),
	}
}

// SetThreshold overrides the default signing threshold.
// Must be called before Initiate().
func (c *Ceremony) SetThreshold(t int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != StateIdle {
		return errors.New("ceremony: cannot change threshold after initiation")
	}
	if t < 1 || t > len(c.peers) {
		return fmt.Errorf("ceremony: threshold %d out of range [1, %d]", t, len(c.peers))
	}
	c.threshold = t
	return nil
}

// Initiate starts Phase 1 of the ceremony: posts ROTATION_PENDING to the
// transparency log and notifies all recovery peers.
//
// The domain owner must prove DNS control to the Trust Witness before calling
// Initiate. In this PoC, we skip the witness interaction.
//
// PRODUCTION: Submit CeremonyRequest to trust witness endpoint; witness
// validates DNS control proof and posts ROTATION_PENDING with its signature.
func (c *Ceremony) Initiate() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateIdle {
		return fmt.Errorf("ceremony: cannot initiate in state %s", c.state)
	}

	// Post ROTATION_PENDING to the transparency log.
	entry := transparency.LogEntry{
		Type:      transparency.EntryRotationPending,
		Domain:    c.domain,
		IKPublic:  []byte(c.newIK.Public),
		Timestamp: 0, // filled by log.Submit
	}
	// PRODUCTION: Attach witness signature to entry before submitting.
	if err := c.log.Submit(entry); err != nil {
		return fmt.Errorf("ceremony: submit ROTATION_PENDING: %w", err)
	}

	c.initiatedAt = time.Now().UTC()
	c.state = StatePending

	// PRODUCTION: Notify all n recovery peers of the pending rotation via
	// their registered endpoints. Peers independently verify the log entry.
	return nil
}

// Cancel aborts the ceremony. Any single recovery peer (or the domain owner)
// can cancel during the waiting period. This implements the safety mechanism:
// if a domain owner sees an unexpected ROTATION_PENDING, they can immediately
// cancel it with any one authorized party.
//
// After cancellation, the old Identity Key remains active.
// A new ceremony can be initiated after a cooldown period.
func (c *Ceremony) Cancel(peer RecoveryPeer) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StatePending && c.state != StateSigning {
		return fmt.Errorf("ceremony: cannot cancel in state %s", c.state)
	}

	// Verify that peer is a registered recovery peer.
	if !c.isPeer(peer.ID) {
		return fmt.Errorf("ceremony: unknown peer %q", peer.ID)
	}

	c.state = StateCancelled
	c.cancelledBy = peer.ID

	// PRODUCTION: Post a ROTATION_CANCELLED entry to the transparency log
	// with the cancelling peer's signature.
	return nil
}

// WaitingPeriodComplete returns true if the mandatory waiting period has elapsed.
// This is checked before transitioning to the signing phase.
func (c *Ceremony) WaitingPeriodComplete() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != StatePending {
		return false
	}
	return time.Since(c.initiatedAt) >= c.WaitDuration
}

// AdvanceToSigning transitions from PENDING to SIGNING after the waiting period.
// Returns an error if the waiting period has not yet elapsed.
func (c *Ceremony) AdvanceToSigning() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StatePending {
		return fmt.Errorf("ceremony: cannot advance to signing in state %s", c.state)
	}
	if time.Since(c.initiatedAt) < c.WaitDuration {
		remaining := c.WaitDuration - time.Since(c.initiatedAt)
		return fmt.Errorf("ceremony: waiting period not complete; %v remaining", remaining)
	}
	c.state = StateSigning
	return nil
}

// Sign records a FROST threshold signature share from a recovery peer.
//
// In a real FROST implementation:
//   Round 1: Each participant broadcasts a commitment (two EC points).
//   Round 2: Each participant computes their signature share using the
//            aggregated commitments and broadcasts it.
//   Combine: The coordinator aggregates t shares into a final signature.
//
// Here we simulate this with a simple vote: Sign() records a "vote" from
// the peer, and Finalize() checks that t distinct peers have signed.
//
// PRODUCTION: Replace with actual FROST protocol execution:
//   1. Call frost.Round1(peerIndex, ...)  → commitment
//   2. Broadcast commitment to other t-1 participants
//   3. Call frost.Round2(peerIndex, commitments, ...) → share
//   4. Coordinator calls frost.Combine(shares) → threshold_sig
func (c *Ceremony) Sign(peer RecoveryPeer) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateSigning {
		return fmt.Errorf("ceremony: cannot sign in state %s (call AdvanceToSigning first)", c.state)
	}

	if !c.isPeer(peer.ID) {
		return fmt.Errorf("ceremony: unknown peer %q", peer.ID)
	}

	if _, already := c.signatures[peer.ID]; already {
		return fmt.Errorf("ceremony: peer %q has already signed", peer.ID)
	}

	// PRODUCTION: Execute FROST round-1/round-2 signing protocol.
	// Here we store a placeholder signature share.
	share := make([]byte, 32)
	// In a real implementation, this would be the FROST signature share bytes.
	// We use a deterministic fake: hash of peer ID + new IK public key.
	copy(share, []byte(peer.ID))
	c.signatures[peer.ID] = share

	return nil
}

// SignatureCount returns the number of peer signatures collected so far.
func (c *Ceremony) SignatureCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.signatures)
}

// ThresholdMet returns true if at least t peers have signed.
func (c *Ceremony) ThresholdMet() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.signatures) >= c.threshold
}

// Finalize completes the ceremony: assembles the FROST threshold signature
// and posts KEY_ROTATION to the transparency log. Transitions state to COMPLETE.
//
// After Finalize():
//   - The new IK is active and published in the DNS record.
//   - The old IK remains valid for a 7-day grace period.
//   - Clients with the old IK pinned will see the rotation in the log.
//
// PRODUCTION: Pass the assembled FROST threshold signature to the Trust
// Witness, which posts KEY_ROTATION to the log with its countersignature.
func (c *Ceremony) Finalize() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateSigning {
		return fmt.Errorf("ceremony: cannot finalize in state %s", c.state)
	}
	if len(c.signatures) < c.threshold {
		return fmt.Errorf("ceremony: threshold not met (%d/%d signatures)", len(c.signatures), c.threshold)
	}

	// PRODUCTION: Assemble FROST shares into a threshold signature.
	// rotationSig := frost.Combine(signatures, params)
	// Here we concatenate the share bytes as a placeholder.
	var rotationSig []byte
	for _, share := range c.signatures {
		rotationSig = append(rotationSig, share...)
	}

	// Post KEY_ROTATION to the transparency log.
	entry := transparency.LogEntry{
		Type:        transparency.EntryKeyRotation,
		Domain:      c.domain,
		IKPublic:    []byte(c.newIK.Public),
		RotationSig: rotationSig,
	}
	if err := c.log.Submit(entry); err != nil {
		return fmt.Errorf("ceremony: submit KEY_ROTATION: %w", err)
	}

	c.state = StateComplete

	// PRODUCTION:
	//   1. Update _dit DNS TXT record to new IK public key.
	//   2. Keep old IK active for 7-day grace period.
	//   3. Gossip new Merkle root to all log nodes.
	//   4. Old IK expires after grace period.

	return nil
}

// State returns the current ceremony state.
func (c *Ceremony) State() CeremonyState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Summary returns a human-readable description of the ceremony state.
func (c *Ceremony) Summary() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.state {
	case StateIdle:
		return "IDLE: no ceremony in progress"
	case StatePending:
		elapsed := time.Since(c.initiatedAt).Round(time.Second)
		remaining := c.WaitDuration - time.Since(c.initiatedAt)
		if remaining < 0 {
			remaining = 0
		}
		return fmt.Sprintf("PENDING: initiated %v ago; %v until signing phase",
			elapsed, remaining.Round(time.Second))
	case StateSigning:
		return fmt.Sprintf("SIGNING: %d/%d peers signed", len(c.signatures), c.threshold)
	case StateComplete:
		return fmt.Sprintf("COMPLETE: KEY_ROTATION posted to log (%d/%d peers signed)",
			len(c.signatures), c.threshold)
	case StateCancelled:
		return fmt.Sprintf("CANCELLED: by peer %q", c.cancelledBy)
	default:
		return "UNKNOWN"
	}
}

// isPeer returns true if peerID is in the registered recovery peer list.
// Caller must hold mu.
func (c *Ceremony) isPeer(peerID string) bool {
	for _, p := range c.peers {
		if p.ID == peerID {
			return true
		}
	}
	return false
}
