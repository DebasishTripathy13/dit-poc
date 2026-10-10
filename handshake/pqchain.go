package handshake

import (
	"bytes"
	"crypto/rand"
	"errors"

	"github.com/DebasishTripathy13/dit-poc/pqc"
)

// Baseline (c): TLS 1.3 with X25519MLKEM768 and a fully post-quantum X.509
// chain (leaf + intermediate, ML-DSA-65 throughout) with two embedded SCTs
// signed with ML-DSA-65. Go's crypto/x509 cannot build ML-DSA certificates,
// so each certificate is a synthetic DER-sized blob:
//
//	cert = meta (CertMetaBytes, measured from the ECDSA chain of baseline a)
//	       || SPKI (1974 B) || [SCT list, leaf only] || signature (3309 B)
//
// The client performs the same signature checks a real chain requires
// (intermediate by root, leaf by intermediate, two SCTs, CertificateVerify),
// with real ML-DSA-65 keys, so both byte counts and CPU cost are realistic.

// SCTSize is an RFC 6962 SCT with an ML-DSA-65 signature:
// version 1 + log_id 32 + timestamp 8 + extensions 2 + algorithm 2 + sig 2+3309.
const SCTSize = 1 + 32 + 8 + 2 + 2 + 2 + pqc.MLDSA65SignatureSize

// PQChain is the server configuration of baseline (c).
type PQChain struct {
	Root, Inter, Leaf *pqc.SigningKey
	CTLogs            []*pqc.SigningKey
	leafCert, interCt []byte
	leafTBS, interTBS []byte
	scts              [][]byte
}

// NewPQChain builds a chain whose certificates carry metaBytes of non-key,
// non-signature DER content each.
func NewPQChain(metaBytes int) (*PQChain, error) {
	c := &PQChain{}
	var err error
	for _, k := range []**pqc.SigningKey{&c.Root, &c.Inter, &c.Leaf} {
		if *k, err = pqc.GenerateSigningKey(); err != nil {
			return nil, err
		}
	}
	for i := 0; i < 2; i++ {
		k, err := pqc.GenerateSigningKey()
		if err != nil {
			return nil, err
		}
		c.CTLogs = append(c.CTLogs, k)
	}
	meta := make([]byte, metaBytes)
	rand.Read(meta)
	c.interTBS = append(append([]byte(nil), meta...), SPKI(c.Inter.PublicKey())...)
	c.interCt = append(append([]byte(nil), c.interTBS...), c.Root.Sign("", c.interTBS)...)
	precert := append(append([]byte(nil), meta...), SPKI(c.Leaf.PublicKey())...)
	sctList := &builder{}
	var scts []byte
	for _, lk := range c.CTLogs {
		body := make([]byte, SCTSize-2-pqc.MLDSA65SignatureSize)
		copy(body[1:33], pqc.SHA3(lk.PublicKey())[:32])
		sct := append(append(body, byte(pqc.MLDSA65SignatureSize>>8), byte(pqc.MLDSA65SignatureSize&0xff)),
			lk.Sign("", precert)...)
		c.scts = append(c.scts, sct)
		w := &builder{}
		w.vec16(sct)
		scts = append(scts, w.b...)
	}
	sctList.vec16(scts)
	c.leafTBS = append(precert, sctList.b...)
	c.leafCert = append(append([]byte(nil), c.leafTBS...), c.Inter.Sign("", c.leafTBS)...)
	return c, nil
}

// LeafBytes and IntermediateBytes return the certificate sizes.
func (c *PQChain) LeafBytes() int         { return len(c.leafCert) }
func (c *PQChain) IntermediateBytes() int { return len(c.interCt) }

// Certificate implements ServerAuth: an X.509 certificate_list of two entries.
func (c *PQChain) Certificate([]byte) (byte, []byte, error) {
	list := &builder{}
	for _, cert := range [][]byte{c.leafCert, c.interCt} {
		list.vec24(cert)
		list.vec16(nil)
	}
	body := &builder{}
	body.vec8(nil)
	body.vec24(list.b)
	return certTypeX509, body.b, nil
}

// SignCertificateVerify implements ServerAuth with the leaf key.
func (c *PQChain) SignCertificateVerify(content []byte) []byte { return c.Leaf.Sign("", content) }

// Client returns the client side of baseline (c), which holds only the root
// and CT log public keys.
func (c *PQChain) Client() *PQChainClient {
	pc := &PQChainClient{RootPub: c.Root.PublicKey()}
	for _, l := range c.CTLogs {
		pc.LogPubs = append(pc.LogPubs, l.PublicKey())
	}
	return pc
}

// PQChainClient verifies baseline (c) certificate chains.
type PQChainClient struct {
	RootPub  []byte
	LogPubs  [][]byte
	Verifies int
}

func (c *PQChainClient) CertType() byte    { return certTypeX509 }
func (c *PQChainClient) Extension() []byte { return nil }

// VerifyCertificate implements ClientAuth with the root as trust anchor.
func (c *PQChainClient) VerifyCertificate(body []byte) ([]byte, error) {
	c.Verifies = 0
	p := &parser{b: body}
	p.vec8()
	list := &parser{b: p.vec24()}
	leaf := list.vec24()
	list.vec16()
	inter := list.vec24()
	list.vec16()
	if p.err || list.err {
		return nil, errDecode
	}
	sig := pqc.MLDSA65SignatureSize
	if len(inter) <= sig+1974 || len(leaf) <= sig+1974 {
		return nil, errDecode
	}
	interTBS, leafTBS := inter[:len(inter)-sig], leaf[:len(leaf)-sig]
	interKey, err := spkiKey(interTBS[len(interTBS)-1974:])
	if err != nil {
		return nil, err
	}
	if !pqc.Verify(c.RootPub, "", interTBS, inter[len(inter)-sig:]) {
		return nil, errors.New("pqchain: intermediate signature invalid")
	}
	if !pqc.Verify(interKey, "", leafTBS, leaf[len(leaf)-sig:]) {
		return nil, errors.New("pqchain: leaf signature invalid")
	}
	// Leaf TBS = precert || SCT list; the precert ends with the leaf SPKI.
	sctLen := 2 + len(c.LogPubs)*(2+SCTSize)
	if len(leafTBS) < sctLen+1974 {
		return nil, errDecode
	}
	precert := leafTBS[:len(leafTBS)-sctLen]
	leafKey, err := spkiKey(precert[len(precert)-1974:])
	if err != nil {
		return nil, err
	}
	sp := &parser{b: leafTBS[len(precert):]}
	scts := &parser{b: sp.vec16()}
	for _, lp := range c.LogPubs {
		s := scts.vec16()
		if scts.err || len(s) != SCTSize || !bytes.Equal(s[1:33], pqc.SHA3(lp)[:32]) ||
			!pqc.Verify(lp, "", precert, s[SCTSize-sig:]) {
			return nil, errors.New("pqchain: SCT invalid")
		}
	}
	c.Verifies = 2 + len(c.LogPubs) + 1
	return leafKey, nil
}
