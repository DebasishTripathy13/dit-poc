package crypto

import "crypto/mlkem"

// ParseEncapsulationKey parses a serialized ML-KEM-768 encapsulation key.
func ParseEncapsulationKey(data []byte) (*KEMEncapsulationKey, error) {
	return mlkem.NewEncapsulationKey768(data)
}
