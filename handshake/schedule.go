package handshake

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha512"
	"hash"
)

// TLS 1.3 key schedule (RFC 8446 §7.1) for TLS_AES_256_GCM_SHA384.

var newHash = sha512.New384

const hashLen = 48

func transcriptHash(msgs ...[]byte) []byte {
	h := newHash()
	for _, m := range msgs {
		h.Write(m)
	}
	return h.Sum(nil)
}

func expandLabel(secret []byte, label string, context []byte, n int) []byte {
	w := &builder{}
	w.u16(uint16(n))
	w.vec8([]byte("tls13 " + label))
	w.vec8(context)
	out, err := hkdf.Expand(newHash, secret, string(w.b), n)
	if err != nil {
		panic(err)
	}
	return out
}

func deriveSecret(secret []byte, label string, th []byte) []byte {
	return expandLabel(secret, label, th, hashLen)
}

func extract(ikm, salt []byte) []byte {
	out, err := hkdf.Extract(newHash, ikm, salt)
	if err != nil {
		panic(err)
	}
	return out
}

type schedule struct {
	hs, master         []byte
	cHS, sHS, cAP, sAP []byte
	emptyHash, zeros   []byte
}

// newSchedule computes the handshake secret from the X25519MLKEM768 shared
// secret (ss_mlkem || ss_x25519, RFC 10024) and the CH..SH transcript hash.
func newSchedule(shared, thCHSH []byte) *schedule {
	s := &schedule{emptyHash: transcriptHash(), zeros: make([]byte, hashLen)}
	early := extract(s.zeros, s.zeros)
	s.hs = extract(shared, deriveSecret(early, "derived", s.emptyHash))
	s.cHS = deriveSecret(s.hs, "c hs traffic", thCHSH)
	s.sHS = deriveSecret(s.hs, "s hs traffic", thCHSH)
	s.master = extract(s.zeros, deriveSecret(s.hs, "derived", s.emptyHash))
	return s
}

func (s *schedule) application(thCHSF []byte) {
	s.cAP = deriveSecret(s.master, "c ap traffic", thCHSF)
	s.sAP = deriveSecret(s.master, "s ap traffic", thCHSF)
}

func trafficKeys(secret []byte) *aeadState {
	return newAEAD(expandLabel(secret, "key", nil, 32), expandLabel(secret, "iv", nil, 12))
}

func finishedMAC(base, th []byte) []byte {
	m := hmac.New(func() hash.Hash { return newHash() }, expandLabel(base, "finished", nil, hashLen))
	m.Write(th)
	return m.Sum(nil)
}

// certificateVerifyInput is the RFC 8446 §4.4.3 signed content.
func certificateVerifyInput(th []byte) []byte {
	b := make([]byte, 0, 64+34+len(th))
	for i := 0; i < 64; i++ {
		b = append(b, 0x20)
	}
	b = append(b, "TLS 1.3, server CertificateVerify"...)
	b = append(b, 0)
	return append(b, th...)
}

func erase(bs ...[]byte) {
	for _, b := range bs {
		clear(b)
	}
}
