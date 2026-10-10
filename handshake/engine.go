package handshake

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/DebasishTripathy13/dit-poc/pqc"
)

// ServerAuth supplies the server's authentication messages.
type ServerAuth interface {
	// Certificate returns the server_certificate_type (RFC 7250) and the body
	// of the Certificate message; clientExt is the client's DIT extension.
	Certificate(clientExt []byte) (certType byte, body []byte, err error)
	// SignCertificateVerify signs the RFC 8446 §4.4.3 content.
	SignCertificateVerify(content []byte) []byte
}

// ClientAuth verifies the server's authentication messages.
type ClientAuth interface {
	CertType() byte
	// Extension is the DIT ClientHello extension, or nil.
	Extension() []byte
	// VerifyCertificate checks the Certificate body and returns the ML-DSA-65
	// key that must have signed CertificateVerify.
	VerifyCertificate(body []byte) (cvKey []byte, err error)
}

// Optional interfaces for authenticators that do not use ML-DSA-65 for
// CertificateVerify (baseline b', an ECDSA P-256 X.509 chain). Authenticators
// that do not implement them use ML-DSA-65.
type schemeSigner interface{ SigScheme() uint16 }

type cvVerifier interface {
	SigScheme() uint16
	VerifyCV(content, sig []byte) bool
}

func serverScheme(a ServerAuth) uint16 {
	if s, ok := a.(schemeSigner); ok {
		return s.SigScheme()
	}
	return sigMLDSA65
}

// Session is an established connection after the handshake.
type Session struct {
	rc       *recordConn
	CAP, SAP []byte // application traffic secrets (exposed for tests)
}

// Send writes one application data record.
func (s *Session) Send(b []byte) error { return s.rc.writeAppData(b) }

// Recv reads one application data record.
func (s *Session) Recv() ([]byte, error) { return s.rc.readAppData() }

func random32() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// ─── Client ───────────────────────────────────────────────────────────────────

// Client runs the client side of the handshake.
func Client(conn io.ReadWriter, serverName string, auth ClientAuth) (*Session, error) {
	rc := &recordConn{rw: conn}
	kx, share, err := pqc.GenerateHybridClientKey()
	if err != nil {
		return nil, err
	}

	exts := &builder{}
	sn := &builder{}
	sn.u8(0)
	sn.vec16([]byte(serverName))
	snl := &builder{}
	snl.vec16(sn.b)
	exts.ext(extServerName, snl.b)
	exts.ext(extSupportedVersions, []byte{2, 0x03, 0x04})
	exts.ext(extSupportedGroups, []byte{0, 2, groupX25519MLKEM768 >> 8, groupX25519MLKEM768 & 0xff})
	scheme := uint16(sigMLDSA65)
	if v, ok := auth.(cvVerifier); ok {
		scheme = v.SigScheme()
	}
	exts.ext(extSigAlgs, []byte{0, 2, byte(scheme >> 8), byte(scheme)})
	ks := &builder{}
	ks.u16(groupX25519MLKEM768)
	ks.vec16(share)
	ksl := &builder{}
	ksl.vec16(ks.b)
	exts.ext(extKeyShare, ksl.b)
	if auth.CertType() == certTypeRawPublicKey {
		exts.ext(extServerCertType, []byte{1, certTypeRawPublicKey})
	}
	if e := auth.Extension(); e != nil {
		exts.ext(extDIT, e)
	}
	ch := &builder{}
	ch.u16(0x0303)
	ch.raw(random32())
	ch.vec8(random32()) // legacy_session_id
	ch.vec16([]byte{suiteAES256GCMSHA384 >> 8, suiteAES256GCMSHA384 & 0xff})
	ch.vec8([]byte{0})
	ch.vec16(exts.b)
	chMsg := handshakeMsg(typeClientHello, ch.b)
	if err := rc.writeHandshake(chMsg); err != nil {
		return nil, err
	}

	// ServerHello.
	typ, shMsg, err := rc.readHandshake()
	if err != nil || typ != typeServerHello {
		return nil, fmt.Errorf("handshake: expected ServerHello: %v", err)
	}
	p := &parser{b: shMsg[4:]}
	p.u16()
	p.take(32)
	p.vec8()
	if p.u16() != suiteAES256GCMSHA384 {
		return nil, errors.New("handshake: unexpected cipher suite")
	}
	p.u8()
	shExt, err := parseExtensions(p.vec16())
	if err != nil || p.err {
		return nil, errDecode
	}
	kp := &parser{b: shExt[extKeyShare]}
	if kp.u16() != groupX25519MLKEM768 {
		return nil, errors.New("handshake: unexpected group")
	}
	shared, err := kx.Decaps(kp.vec16())
	if err != nil {
		return nil, err
	}
	ksched := newSchedule(shared, transcriptHash(chMsg, shMsg))
	erase(shared)
	rc.read = trafficKeys(ksched.sHS)

	// EncryptedExtensions, Certificate, CertificateVerify, Finished.
	typ, eeMsg, err := rc.readHandshake()
	if err != nil || typ != typeEncryptedExts {
		return nil, fmt.Errorf("handshake: expected EncryptedExtensions: %v", err)
	}
	typ, certMsg, err := rc.readHandshake()
	if err != nil || typ != typeCertificate {
		return nil, fmt.Errorf("handshake: expected Certificate: %v", err)
	}
	cvKey, err := auth.VerifyCertificate(certMsg[4:])
	if err != nil {
		return nil, err
	}
	typ, cvMsg, err := rc.readHandshake()
	if err != nil || typ != typeCertificateVerify {
		return nil, fmt.Errorf("handshake: expected CertificateVerify: %v", err)
	}
	cp := &parser{b: cvMsg[4:]}
	alg, sig := cp.u16(), cp.vec16()
	if cp.err || alg != scheme {
		return nil, errDecode
	}
	th := transcriptHash(chMsg, shMsg, eeMsg, certMsg)
	cvOK := false
	if v, ok := auth.(cvVerifier); ok {
		cvOK = v.VerifyCV(certificateVerifyInput(th), sig)
	} else {
		cvOK = pqc.Verify(cvKey, "", certificateVerifyInput(th), sig)
	}
	if !cvOK {
		return nil, errors.New("handshake: CertificateVerify invalid")
	}
	typ, finMsg, err := rc.readHandshake()
	if err != nil || typ != typeFinished {
		return nil, fmt.Errorf("handshake: expected Finished: %v", err)
	}
	th = transcriptHash(chMsg, shMsg, eeMsg, certMsg, cvMsg)
	if !hmac.Equal(finMsg[4:], finishedMAC(ksched.sHS, th)) {
		return nil, errors.New("handshake: server Finished invalid")
	}
	thSF := transcriptHash(chMsg, shMsg, eeMsg, certMsg, cvMsg, finMsg)
	ksched.application(thSF)

	rc.write = trafficKeys(ksched.cHS)
	if err := rc.writeHandshake(handshakeMsg(typeFinished, finishedMAC(ksched.cHS, thSF))); err != nil {
		return nil, err
	}
	rc.write, rc.read = trafficKeys(ksched.cAP), trafficKeys(ksched.sAP)
	erase(ksched.hs, ksched.master, ksched.cHS, ksched.sHS)
	return &Session{rc: rc, CAP: ksched.cAP, SAP: ksched.sAP}, nil
}

// ─── Server ───────────────────────────────────────────────────────────────────

// Server runs the server side of the handshake.
func Server(conn io.ReadWriter, auth ServerAuth) (*Session, error) {
	rc := &recordConn{rw: conn}
	typ, chMsg, err := rc.readHandshake()
	if err != nil || typ != typeClientHello {
		return nil, fmt.Errorf("handshake: expected ClientHello: %v", err)
	}
	p := &parser{b: chMsg[4:]}
	p.u16()
	p.take(32)
	sid := p.vec8()
	suites := p.vec16()
	p.vec8()
	chExt, err := parseExtensions(p.vec16())
	if err != nil || p.err {
		return nil, errDecode
	}
	if !bytes.Contains(suites, []byte{suiteAES256GCMSHA384 >> 8, suiteAES256GCMSHA384 & 0xff}) {
		return nil, errors.New("handshake: no common cipher suite")
	}
	var clientShare []byte
	kl := &parser{b: chExt[extKeyShare]}
	entries := &parser{b: kl.vec16()}
	for len(entries.b) > 0 && !entries.err {
		g, ks := entries.u16(), entries.vec16()
		if g == groupX25519MLKEM768 {
			clientShare = ks
		}
	}
	if clientShare == nil {
		return nil, errors.New("handshake: no X25519MLKEM768 key share")
	}
	serverShare, shared, err := pqc.HybridServerEncaps(clientShare)
	if err != nil {
		return nil, err
	}

	ext := &builder{}
	ext.ext(extSupportedVersions, []byte{0x03, 0x04})
	ks := &builder{}
	ks.u16(groupX25519MLKEM768)
	ks.vec16(serverShare)
	ext.ext(extKeyShare, ks.b)
	sh := &builder{}
	sh.u16(0x0303)
	sh.raw(random32())
	sh.vec8(sid)
	sh.u16(suiteAES256GCMSHA384)
	sh.u8(0)
	sh.vec16(ext.b)
	shMsg := handshakeMsg(typeServerHello, sh.b)
	if err := rc.writeHandshake(shMsg); err != nil {
		return nil, err
	}
	ksched := newSchedule(shared, transcriptHash(chMsg, shMsg))
	erase(shared)
	rc.write = trafficKeys(ksched.sHS)

	certType, certBody, err := auth.Certificate(chExt[extDIT])
	if err != nil {
		return nil, err
	}
	ee := &builder{}
	if certType == certTypeRawPublicKey {
		e := &builder{}
		e.ext(extServerCertType, []byte{certTypeRawPublicKey})
		ee.vec16(e.b)
	} else {
		ee.vec16(nil)
	}
	eeMsg := handshakeMsg(typeEncryptedExts, ee.b)
	certMsg := handshakeMsg(typeCertificate, certBody)
	th := transcriptHash(chMsg, shMsg, eeMsg, certMsg)
	cv := &builder{}
	cv.u16(serverScheme(auth))
	cv.vec16(auth.SignCertificateVerify(certificateVerifyInput(th)))
	cvMsg := handshakeMsg(typeCertificateVerify, cv.b)
	th = transcriptHash(chMsg, shMsg, eeMsg, certMsg, cvMsg)
	finMsg := handshakeMsg(typeFinished, finishedMAC(ksched.sHS, th))
	flight := bytes.Join([][]byte{eeMsg, certMsg, cvMsg, finMsg}, nil)
	if err := rc.writeHandshake(flight); err != nil {
		return nil, err
	}
	thSF := transcriptHash(chMsg, shMsg, eeMsg, certMsg, cvMsg, finMsg)
	ksched.application(thSF)

	rc.read = trafficKeys(ksched.cHS)
	typ, cfMsg, err := rc.readHandshake()
	if err != nil || typ != typeFinished {
		return nil, fmt.Errorf("handshake: expected client Finished: %v", err)
	}
	if !hmac.Equal(cfMsg[4:], finishedMAC(ksched.cHS, thSF)) {
		return nil, errors.New("handshake: client Finished invalid")
	}
	rc.write, rc.read = trafficKeys(ksched.sAP), trafficKeys(ksched.cAP)
	erase(ksched.hs, ksched.master, ksched.cHS, ksched.sHS)
	return &Session{rc: rc, CAP: ksched.cAP, SAP: ksched.sAP}, nil
}
