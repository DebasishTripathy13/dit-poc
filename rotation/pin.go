package rotation

import (
	"bytes"
	"errors"

	"github.com/DebasishTripathy13/dit-poc/identity"
)

// Pin-conflict resolution (Layer 4). A client that pinned identity P meets a
// server presenting identity I for the same domain:
//
//  1. digest(I) = digest(P): accept.
//  2. I.Seq <= P.Seq and digest(I) != digest(P): hard failure. Either the
//     server rolled back, or two identities with the same sequence number
//     exist, which is evidence of equivocation; the client reports both to
//     monitors. There is no user override.
//  3. I.Seq > P.Seq: the client obtains the domain's log entries after the
//     entry that installed P (each with an inclusion proof under a q-of-m
//     cosigned STH, checked by the caller) and replays them with the same
//     state machine the witnesses run. The pin is updated to I only if the
//     replay ends at exactly I. Otherwise: hard failure.
//
// Replaying, rather than trusting the witnesses' cosignatures alone, means a
// pinned client checks every sigma_old / sigma_new / sigma_rot signature and
// every waiting period itself.

// Pin-resolution errors.
var (
	ErrPinRollback = errors.New("pin: presented identity is not newer than the pin (rollback or equivocation)")
	ErrPinChain    = errors.New("pin: logged key events do not lead from the pin to the presented identity")
)

// ResolvePin returns the new pin, or an error that must abort the connection.
func ResolvePin(pin, presented *identity.IdentityObject, history []*Entry) (*Domain, error) {
	if bytes.Equal(pin.Digest(), presented.Digest()) {
		return &Domain{Current: pin}, nil
	}
	if presented.Domain != pin.Domain || presented.Seq <= pin.Seq {
		return nil, ErrPinRollback
	}
	s := NewState()
	s.Domains[pin.Domain] = &Domain{Current: pin, RevokedEAKs: map[string]bool{}, Recovery: map[string]*pending{}}
	for _, e := range history {
		if e.Domain != pin.Domain {
			continue
		}
		if err := s.Apply(e); err != nil {
			return nil, errors.Join(ErrPinChain, err)
		}
	}
	d := s.Domains[pin.Domain]
	if !bytes.Equal(d.Current.Digest(), presented.Digest()) {
		return nil, ErrPinChain
	}
	return d, nil
}
