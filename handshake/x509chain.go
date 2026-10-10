package handshake

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"time"
)

// Baseline (b'): the same TLS 1.3 implementation as DIT, with X25519MLKEM768
// key exchange and a classical ECDSA P-256 X.509 chain verified by
// crypto/x509. Comparing it with Go's crypto/tls running the same
// configuration (baseline b) isolates the cost of our implementation;
// comparing it with DIT isolates the cost of post-quantum authentication.

// X509Server serves an ECDSA certificate chain (leaf, intermediate).
type X509Server struct {
	Leaf, Intermediate []byte // DER
	Key                *ecdsa.PrivateKey
}

// Certificate implements ServerAuth.
func (s *X509Server) Certificate([]byte) (byte, []byte, error) {
	list := &builder{}
	for _, c := range [][]byte{s.Leaf, s.Intermediate} {
		list.vec24(c)
		list.vec16(nil)
	}
	body := &builder{}
	body.vec8(nil)
	body.vec24(list.b)
	return certTypeX509, body.b, nil
}

// SigScheme implements schemeSigner.
func (s *X509Server) SigScheme() uint16 { return sigECDSAP256SHA256 }

// SignCertificateVerify implements ServerAuth (ECDSA P-256 with SHA-256).
func (s *X509Server) SignCertificateVerify(content []byte) []byte {
	h := sha256.Sum256(content)
	sig, err := ecdsa.SignASN1(rand.Reader, s.Key, h[:])
	if err != nil {
		panic(err)
	}
	return sig
}

// X509Client verifies the chain against Roots with crypto/x509.
type X509Client struct {
	Roots      *x509.CertPool
	ServerName string
	Now        time.Time
	leafKey    *ecdsa.PublicKey
	Verifies   int
}

func (c *X509Client) CertType() byte    { return certTypeX509 }
func (c *X509Client) Extension() []byte { return nil }
func (c *X509Client) SigScheme() uint16 { return sigECDSAP256SHA256 }

// VerifyCertificate implements ClientAuth.
func (c *X509Client) VerifyCertificate(body []byte) ([]byte, error) {
	p := &parser{b: body}
	p.vec8()
	list := &parser{b: p.vec24()}
	leafDER := list.vec24()
	list.vec16()
	interDER := list.vec24()
	list.vec16()
	if p.err || list.err {
		return nil, errDecode
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, err
	}
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(inter)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: c.Roots, Intermediates: pool,
		DNSName: c.ServerName, CurrentTime: c.Now}); err != nil {
		return nil, err
	}
	k, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("x509chain: leaf key is not ECDSA")
	}
	c.leafKey = k
	c.Verifies = 3 // leaf by intermediate, intermediate by root, CertificateVerify
	return nil, nil
}

// VerifyCV implements cvVerifier.
func (c *X509Client) VerifyCV(content, sig []byte) bool {
	h := sha256.Sum256(content)
	return c.leafKey != nil && ecdsa.VerifyASN1(c.leafKey, h[:], sig)
}
