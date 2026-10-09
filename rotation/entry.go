// Package rotation implements the DIT key-event log semantics (Layer 6): the
// log entry types and the deterministic state machine that witnesses run
// before cosigning and that clients and monitors replay to follow rotations.
package rotation

import (
	"encoding/binary"
	"errors"
)

// EntryType enumerates log entry types.
type EntryType uint8

const (
	KeyPublication   EntryType = 1
	PendingNormal    EntryType = 2 // ROTATION_PENDING, normal path
	PendingRecovery  EntryType = 3 // ROTATION_PENDING, recovery path
	CancelNormal     EntryType = 4
	CancelRecovery   EntryType = 5
	RotationNormal   EntryType = 6 // KEY_ROTATION, normal path
	RotationRecovery EntryType = 7 // KEY_ROTATION, recovery path
	EAKRevocation    EntryType = 8
)

func (t EntryType) String() string {
	return [...]string{"?", "KEY_PUBLICATION", "ROTATION_PENDING(normal)", "ROTATION_PENDING(recovery)",
		"CANCEL(normal)", "CANCEL(recovery)", "KEY_ROTATION(normal)", "KEY_ROTATION(recovery)",
		"EAK_REVOCATION"}[t]
}

// Entry is one log entry. Which fields are set depends on Type:
//
//	KeyPublication   Identity, SigA = IK signature (proof of possession)
//	PendingNormal    FromSeq, NewDigest, SigA = sigma_old by current IK
//	PendingRecovery  FromSeq, NewDigest, Identity, PeerPub (sponsor),
//	                 SigA = signature by IK_new (possession), SigB = sponsor signature
//	CancelNormal     FromSeq, NewDigest, SigA = signature by current IK
//	CancelRecovery   FromSeq, NewDigest, PeerPub, SigA = signature by that peer
//	RotationNormal   FromSeq, NewDigest, Identity, SigA = sigma_old, SigB = sigma_new
//	RotationRecovery FromSeq, NewDigest, Identity, SigA = sigma_rot (FROST, 64 B)
//	EAKRevocation    FromSeq, EAKDigest, SigA = signature by current IK
//
// Timestamp is assigned by the log and is not covered by the signatures.
type Entry struct {
	Type      EntryType
	Domain    string
	FromSeq   uint64
	NewDigest []byte
	Identity  []byte // TLV-encoded identity object
	PeerPub   []byte
	EAKDigest []byte
	Timestamp uint64
	SigA      []byte
	SigB      []byte
}

func put(b []byte, t byte, v []byte) []byte {
	b = append(b, t, byte(len(v)>>8), byte(len(v)))
	return append(b, v...)
}

// TBS returns the signed part of the entry (the "rotation record" for
// rotation entries). Absent fields are encoded as empty values.
func (e *Entry) TBS() []byte {
	var b []byte
	b = put(b, 1, []byte{byte(e.Type)})
	b = put(b, 2, []byte(e.Domain))
	b = put(b, 3, binary.BigEndian.AppendUint64(nil, e.FromSeq))
	b = put(b, 4, e.NewDigest)
	b = put(b, 5, e.Identity)
	b = put(b, 6, e.PeerPub)
	b = put(b, 7, e.EAKDigest)
	return b
}

// Marshal returns the full encoding stored in the log.
func (e *Entry) Marshal() []byte {
	b := e.TBS()
	b = put(b, 8, binary.BigEndian.AppendUint64(nil, e.Timestamp))
	b = put(b, 9, e.SigA)
	return put(b, 10, e.SigB)
}

var errEntry = errors.New("rotation: malformed entry")

// Unmarshal parses an encoded entry.
func Unmarshal(b []byte) (*Entry, error) {
	fields := make([][]byte, 11)
	for want := byte(1); want <= 10; want++ {
		if len(b) < 3 || b[0] != want {
			return nil, errEntry
		}
		n := int(b[1])<<8 | int(b[2])
		if len(b) < 3+n {
			return nil, errEntry
		}
		fields[want] = b[3 : 3+n]
		b = b[3+n:]
	}
	if len(b) != 0 || len(fields[1]) != 1 || len(fields[3]) != 8 || len(fields[8]) != 8 {
		return nil, errEntry
	}
	return &Entry{
		Type: EntryType(fields[1][0]), Domain: string(fields[2]),
		FromSeq: binary.BigEndian.Uint64(fields[3]), NewDigest: fields[4], Identity: fields[5],
		PeerPub: fields[6], EAKDigest: fields[7], Timestamp: binary.BigEndian.Uint64(fields[8]),
		SigA: fields[9], SigB: fields[10],
	}, nil
}

// FIPS 204 / FROST context strings, one per signature role.
const (
	CtxPublication   = "DIT-v3 key publication"
	CtxPendingNormal = "DIT-v3 normal rotation pending"
	CtxPendingRecov  = "DIT-v3 recovery rotation pending"
	CtxCancelNormal  = "DIT-v3 normal rotation cancel"
	CtxCancelRecov   = "DIT-v3 recovery rotation cancel"
	CtxRotationOld   = "DIT-v3 normal rotation old"
	CtxRotationNew   = "DIT-v3 normal rotation new"
	CtxRecovery      = "DIT-v3 recovery rotation" // prefixed to the FROST message
	CtxEAKRevocation = "DIT-v3 eak revocation"
)
