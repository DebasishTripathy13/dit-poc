// Package rotation implements DIT v2.2 normal and recovery rotation.
package rotation

import (
	"fmt"
	"time"

	"github.com/dit-protocol/poc/crypto"
	"github.com/dit-protocol/poc/identity"
)

// RotationRecord represents a key rotation record.
type RotationRecord struct {
	Version           string
	Domain            string
	SequenceNumber    uint64
	PrevIdentityHash  string
	OldIKPub          []byte
	NewIKPub          []byte
	Timestamp         time.Time
	Reason            string // "normal_rotation" or "recovery"
}

// NormalRotationResult holds the result of a normal rotation.
type NormalRotationResult struct {
	Record   *RotationRecord
	SigmaOld []byte // σ_old = ML-DSA-65.Sign(old_IK_priv, ...)
	SigmaNew []byte // σ_new = ML-DSA-65.Sign(new_IK_priv, ...)
}

// NormalRotation performs a PQ-secure normal rotation.
// Requires both old and new IK private keys.
func NormalRotation(oldIK, newIK *identity.IdentityKey, domain string, seq uint64, prevHash string) (*NormalRotationResult, error) {
	record := &RotationRecord{
		Version:          "DIT-v2.2",
		Domain:           domain,
		SequenceNumber:   seq,
		PrevIdentityHash: prevHash,
		OldIKPub:         oldIK.KeyPair.PublicKey,
		NewIKPub:         newIK.KeyPair.PublicKey,
		Timestamp:        time.Now(),
		Reason:           "normal_rotation",
	}

	recordHash := crypto.SHA3_384(serializeRecord(record))

	// σ_old = ML-DSA-65.Sign(old_IK_priv, "DIT-v2.2 normal rotation old" || H(record))
	oldMsg := append([]byte("DIT-v2.2 normal rotation old"), recordHash...)
	sigmaOld := oldIK.KeyPair.Sign(oldMsg)

	// σ_new = ML-DSA-65.Sign(new_IK_priv, "DIT-v2.2 normal rotation new" || H(record))
	newMsg := append([]byte("DIT-v2.2 normal rotation new"), recordHash...)
	sigmaNew := newIK.KeyPair.Sign(newMsg)

	return &NormalRotationResult{
		Record:   record,
		SigmaOld: sigmaOld,
		SigmaNew: sigmaNew,
	}, nil
}

// VerifyNormalRotation verifies a normal rotation.
func VerifyNormalRotation(result *NormalRotationResult) bool {
	recordHash := crypto.SHA3_384(serializeRecord(result.Record))

	oldMsg := append([]byte("DIT-v2.2 normal rotation old"), recordHash...)
	if !crypto.Verify(result.Record.OldIKPub, oldMsg, result.SigmaOld) {
		return false
	}

	newMsg := append([]byte("DIT-v2.2 normal rotation new"), recordHash...)
	return crypto.Verify(result.Record.NewIKPub, newMsg, result.SigmaNew)
}

func serializeRecord(r *RotationRecord) []byte {
	return []byte(fmt.Sprintf("%s|%s|%d|%s|%x|%x|%d|%s",
		r.Version, r.Domain, r.SequenceNumber, r.PrevIdentityHash,
		r.OldIKPub, r.NewIKPub, r.Timestamp.Unix(), r.Reason))
}
