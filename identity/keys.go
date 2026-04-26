// Package identity implements the DIT v2.2 three-layer key hierarchy.
package identity

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/dit-protocol/poc/crypto"
)

// IdentityKey represents a domain's long-term Identity Key (IK).
type IdentityKey struct {
	Domain    string
	KeyPair   *crypto.DSAKeyPair
	CreatedAt time.Time
}

// NewIdentityKey generates a fresh IK for a domain.
func NewIdentityKey(domain string) (*IdentityKey, error) {
	kp, err := crypto.GenerateDSAKeyPair()
	if err != nil {
		return nil, err
	}
	return &IdentityKey{
		Domain:    domain,
		KeyPair:   kp,
		CreatedAt: time.Now(),
	}, nil
}

// PublicKeyHash returns SHA3-384 hash of the IK public key.
func (ik *IdentityKey) PublicKeyHash() string {
	h := crypto.SHA3_384(ik.KeyPair.PublicKey)
	return hex.EncodeToString(h)
}

// EpochCredential represents the epoch authentication credential.
type EpochCredential struct {
	Domain    string
	EpochID   string
	EAKPub    []byte // EAK public key
	Validity  time.Time
	Sigma_IK  []byte // σ_IK over the credential
}

// EpochAuthKey represents a fresh-random Epoch Authentication Key (EAK).
// CRITICAL: EAK is NOT derived from IK. It is fresh random per epoch.
type EpochAuthKey struct {
	Domain     string
	EpochID    string
	KeyPair    *crypto.DSAKeyPair
	Credential *EpochCredential
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// NewEpochAuthKey generates a FRESH RANDOM EAK and certifies it with IK.
func NewEpochAuthKey(ik *IdentityKey, domain string) (*EpochAuthKey, error) {
	// Fresh random ML-DSA-65 key pair — NOT derived from IK
	eakKP, err := crypto.GenerateDSAKeyPair()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	epochID := fmt.Sprintf("%s-%s", domain, now.Format("2006-01-02"))

	// Build epoch credential
	credentialMsg := buildCredentialMessage(domain, epochID, eakKP.PublicKey, now)

	// σ_IK = ML-DSA-65.Sign(IK_priv, "DIT-v2.2 epoch credential" || credential)
	signMsg := append([]byte("DIT-v2.2 epoch credential"), credentialMsg...)
	sigma_IK := ik.KeyPair.Sign(signMsg)

	cred := &EpochCredential{
		Domain:   domain,
		EpochID:  epochID,
		EAKPub:   eakKP.PublicKey,
		Validity: now.Add(24 * time.Hour),
		Sigma_IK: sigma_IK,
	}

	return &EpochAuthKey{
		Domain:     domain,
		EpochID:    epochID,
		KeyPair:    eakKP,
		Credential: cred,
		CreatedAt:  now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}, nil
}

// VerifyCredential verifies the epoch credential against the IK.
func VerifyCredential(ikPub []byte, cred *EpochCredential) bool {
	credMsg := buildCredentialMessage(cred.Domain, cred.EpochID, cred.EAKPub, cred.Validity.Add(-24*time.Hour))
	signMsg := append([]byte("DIT-v2.2 epoch credential"), credMsg...)
	return crypto.Verify(ikPub, signMsg, cred.Sigma_IK)
}

func buildCredentialMessage(domain, epochID string, eakPub []byte, ts time.Time) []byte {
	msg := []byte(domain)
	msg = append(msg, []byte(epochID)...)
	msg = append(msg, eakPub...)
	msg = append(msg, []byte(ts.Format(time.RFC3339))...)
	return msg
}
