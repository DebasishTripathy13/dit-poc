// Package baseline provides the classical and hybrid-KEM TLS 1.3 baselines,
// run with the Go standard library crypto/tls:
//
//	(a) TLS 1.3, ECDSA P-256 chain, X25519
//	(b) TLS 1.3, ECDSA P-256 chain, X25519MLKEM768 (no PQ authentication)
//
// The chain is root -> intermediate -> leaf. The leaf carries the extensions
// of a typical WebPKI leaf, including an SCT list extension of realistic size
// (two ECDSA-signed SCTs), so that certificate sizes are representative.
package baseline

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// Chain is an ECDSA P-256 certificate chain.
type Chain struct {
	Leaf, Intermediate, Root *x509.Certificate
	LeafKey                  *ecdsa.PrivateKey
	Pool                     *x509.CertPool
}

var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// NewChain builds a root, intermediate and leaf for serverName.
func NewChain(serverName string, now time.Time) (*Chain, error) {
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		return k
	}
	rootKey, interKey, leafKey := key(), key(), key()
	serial := func() *big.Int { n, _ := rand.Int(rand.Reader, big.NewInt(1<<62)); return n }
	ca := func(cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: serial(), Subject: pkix.Name{CommonName: cn, Organization: []string{"DIT Benchmark CA"}, Country: []string{"US"}},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
		}
	}
	rootT := ca("DIT Benchmark Root")
	rootDER, err := x509.CreateCertificate(rand.Reader, rootT, rootT, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	root, _ := x509.ParseCertificate(rootDER)
	interT := ca("DIT Benchmark Intermediate E1")
	interT.MaxPathLenZero = true
	interT.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	interT.CRLDistributionPoints = []string{"http://crl.example-ca.test/root.crl"}
	interT.IssuingCertificateURL = []string{"http://ca.example-ca.test/root.cer"}
	interDER, err := x509.CreateCertificate(rand.Reader, interT, root, &interKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	inter, _ := x509.ParseCertificate(interDER)

	// Two SCTs of the size produced by ECDSA-signing CT logs (RFC 6962):
	// 1+32+8+2+2+2+72 = 119 bytes each, in a TLS-encoded list, wrapped in an
	// OCTET STRING.
	var sctList []byte
	for i := 0; i < 2; i++ {
		sct := make([]byte, 119)
		rand.Read(sct)
		sctList = append(sctList, byte(len(sct)>>8), byte(len(sct)))
		sctList = append(sctList, sct...)
	}
	sctList = append([]byte{byte(len(sctList) >> 8), byte(len(sctList))}, sctList...)
	sctExt, _ := asn1.Marshal(sctList)

	leafT := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: serverName},
		DNSNames:  []string{serverName, "www." + serverName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(47 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		OCSPServer:            []string{"http://ocsp.example-ca.test"},
		IssuingCertificateURL: []string{"http://ca.example-ca.test/e1.cer"},
		CRLDistributionPoints: []string{"http://crl.example-ca.test/e1.crl"},
		PolicyIdentifiers:     []asn1.ObjectIdentifier{{2, 23, 140, 1, 2, 1}},
		ExtraExtensions:       []pkix.Extension{{Id: oidSCTList, Value: sctExt}},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafT, inter, &leafKey.PublicKey, interKey)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &Chain{Leaf: leaf, Intermediate: inter, Root: root, LeafKey: leafKey, Pool: pool}, nil
}

// MetaBytes returns the bytes of a certificate that are neither the subject
// public key info nor the signature value; used to size the synthetic ML-DSA
// certificates of baseline (c). The SCT list is excluded for the leaf, since
// baseline (c) carries its own (ML-DSA-signed) SCTs.
func MetaBytes(c *x509.Certificate) int {
	n := len(c.Raw) - len(c.RawSubjectPublicKeyInfo) - len(c.Signature)
	for _, e := range c.Extensions {
		if e.Id.Equal(oidSCTList) {
			n -= len(e.Value)
		}
	}
	return n
}

// Variant selects the key-exchange group.
type Variant int

const (
	Classical Variant = iota // (a) X25519
	HybridKEM                // (b) X25519MLKEM768
)

func curves(v Variant) []tls.CurveID {
	if v == HybridKEM {
		return []tls.CurveID{tls.X25519MLKEM768}
	}
	return []tls.CurveID{tls.X25519}
}

// ServerConfig returns a TLS 1.3-only server configuration.
func (c *Chain) ServerConfig(v Variant) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, CurvePreferences: curves(v), SessionTicketsDisabled: true,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{c.Leaf.Raw, c.Intermediate.Raw}, PrivateKey: c.LeafKey, Leaf: c.Leaf,
		}},
	}
}

// ClientConfig returns a TLS 1.3-only client that validates the chain.
func (c *Chain) ClientConfig(v Variant, serverName string, now time.Time) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, CurvePreferences: curves(v), RootCAs: c.Pool,
		ServerName: serverName, SessionTicketsDisabled: true, Time: func() time.Time { return now },
	}
}
