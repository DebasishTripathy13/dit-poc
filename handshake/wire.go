// Package handshake implements the DIT authentication layer over a TLS 1.3
// handshake (design Option A of the revised paper):
//
//   - key exchange: X25519MLKEM768 (RFC 10024), TLS 1.3 key schedule (RFC 8446
//     §7.1) with TLS_AES_256_GCM_SHA384;
//   - server authentication: the EAK as an RFC 7250 raw public key, an ML-DSA-65
//     CertificateVerify, and the DIT objects (epoch credential and, on first
//     contact, the log entry, inclusion proof and cosigned STH) in an
//     extension of the CertificateEntry, i.e. inside the encrypted flight.
//
// This is a message-level implementation written for measurement. It follows
// the RFC 8446 encodings and record layer, but omits HelloRetryRequest,
// resumption, client authentication, alerts and middlebox-compatibility mode,
// and it does not interoperate with unmodified TLS stacks.
package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// Code points.
const (
	versionTLS13          = 0x0304
	suiteAES256GCMSHA384  = 0x1302
	groupX25519MLKEM768   = 0x11EC // RFC 10024
	sigMLDSA65            = 0x0905 // draft-ietf-tls-mldsa
	sigECDSAP256SHA256    = 0x0403
	extServerName         = 0x0000
	extSupportedGroups    = 0x000a
	extSigAlgs            = 0x000d
	extServerCertType     = 0x0014 // RFC 7250
	extSupportedVersions  = 0x002b
	extKeyShare           = 0x0033
	extDIT                = 0xff5d // private use; DIT identity extension
	certTypeRawPublicKey  = 2
	certTypeX509          = 0
	typeClientHello       = 1
	typeServerHello       = 2
	typeEncryptedExts     = 8
	typeCertificate       = 11
	typeCertificateVerify = 15
	typeFinished          = 20
	recHandshake          = 22
	recAppData            = 23
	maxFragment           = 1 << 14
)

// ─── Byte builders ────────────────────────────────────────────────────────────

type builder struct{ b []byte }

func (w *builder) u8(v byte)    { w.b = append(w.b, v) }
func (w *builder) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *builder) u24(v int)    { w.b = append(w.b, byte(v>>16), byte(v>>8), byte(v)) }
func (w *builder) raw(v []byte) { w.b = append(w.b, v...) }
func (w *builder) vec8(v []byte) {
	w.u8(byte(len(v)))
	w.raw(v)
}
func (w *builder) vec16(v []byte) {
	w.u16(uint16(len(v)))
	w.raw(v)
}
func (w *builder) vec24(v []byte) {
	w.u24(len(v))
	w.raw(v)
}
func (w *builder) ext(t uint16, body []byte) {
	w.u16(t)
	w.vec16(body)
}

type parser struct {
	b   []byte
	err bool
}

func (p *parser) take(n int) []byte {
	if p.err || len(p.b) < n {
		p.err = true
		return nil
	}
	v := p.b[:n]
	p.b = p.b[n:]
	return v
}
func (p *parser) u8() byte {
	v := p.take(1)
	if v == nil {
		return 0
	}
	return v[0]
}
func (p *parser) u16() uint16 {
	v := p.take(2)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint16(v)
}
func (p *parser) u24() int {
	v := p.take(3)
	if v == nil {
		return 0
	}
	return int(v[0])<<16 | int(v[1])<<8 | int(v[2])
}
func (p *parser) u64() uint64 {
	v := p.take(8)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}
func (p *parser) vec8() []byte  { return p.take(int(p.u8())) }
func (p *parser) vec16() []byte { return p.take(int(p.u16())) }
func (p *parser) vec24() []byte { return p.take(p.u24()) }

var errDecode = errors.New("handshake: decode error")

func parseExtensions(b []byte) (map[uint16][]byte, error) {
	p := &parser{b: b}
	m := map[uint16][]byte{}
	for len(p.b) > 0 && !p.err {
		t := p.u16()
		m[t] = p.vec16()
	}
	if p.err {
		return nil, errDecode
	}
	return m, nil
}

func handshakeMsg(t byte, body []byte) []byte {
	w := &builder{}
	w.u8(t)
	w.vec24(body)
	return w.b
}

// ─── Record layer ─────────────────────────────────────────────────────────────

// CountingConn records the bytes written and read on a connection.
type CountingConn struct {
	net.Conn
	BytesWritten, BytesRead int
}

func (c *CountingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.BytesWritten += n
	return n, err
}

func (c *CountingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.BytesRead += n
	return n, err
}

type aeadState struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

func newAEAD(key, iv []byte) *aeadState {
	blk, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		panic(err)
	}
	return &aeadState{aead: g, iv: iv}
}

func (a *aeadState) nonce() []byte {
	n := append([]byte(nil), a.iv...)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], a.seq)
	for i := 0; i < 8; i++ {
		n[4+i] ^= s[i]
	}
	a.seq++
	return n
}

type recordConn struct {
	rw    io.ReadWriter
	write *aeadState
	read  *aeadState
	hsBuf []byte // reassembly buffer for handshake messages
}

func header(typ byte, n int) []byte {
	return []byte{typ, 0x03, 0x03, byte(n >> 8), byte(n)}
}

// writeHandshake sends handshake bytes, fragmented into records of at most
// 2^14 bytes, encrypted if write keys are installed.
func (r *recordConn) writeHandshake(data []byte) error {
	var out []byte
	for len(data) > 0 {
		n := min(len(data), maxFragment)
		frag := data[:n]
		data = data[n:]
		if r.write == nil {
			out = append(out, header(recHandshake, n)...)
			out = append(out, frag...)
			continue
		}
		out = append(out, r.seal(recHandshake, frag)...)
	}
	_, err := r.rw.Write(out)
	return err
}

func (r *recordConn) seal(inner byte, frag []byte) []byte {
	pt := append(append([]byte(nil), frag...), inner)
	n := len(pt) + r.write.aead.Overhead()
	hdr := header(recAppData, n)
	return append(hdr, r.write.aead.Seal(nil, r.write.nonce(), pt, hdr)...)
}

func (r *recordConn) writeAppData(data []byte) error {
	_, err := r.rw.Write(r.seal(recAppData, data))
	return err
}

// readRecord returns the content type and plaintext of the next record.
func (r *recordConn) readRecord() (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r.rw, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[3:]))
	if n > maxFragment+256 {
		return 0, nil, errDecode
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r.rw, body); err != nil {
		return 0, nil, err
	}
	if r.read == nil {
		return hdr[0], body, nil
	}
	if hdr[0] != recAppData {
		return 0, nil, errDecode
	}
	pt, err := r.read.aead.Open(nil, r.read.nonce(), body, hdr[:])
	if err != nil {
		return 0, nil, errors.New("handshake: bad record MAC")
	}
	i := len(pt) - 1
	for i >= 0 && pt[i] == 0 {
		i--
	}
	if i < 0 {
		return 0, nil, errDecode
	}
	return pt[i], pt[:i], nil
}

// readHandshake returns the next complete handshake message (with header).
func (r *recordConn) readHandshake() (byte, []byte, error) {
	for {
		if len(r.hsBuf) >= 4 {
			n := int(r.hsBuf[1])<<16 | int(r.hsBuf[2])<<8 | int(r.hsBuf[3])
			if len(r.hsBuf) >= 4+n {
				msg := r.hsBuf[:4+n]
				r.hsBuf = r.hsBuf[4+n:]
				return msg[0], msg, nil
			}
		}
		typ, body, err := r.readRecord()
		if err != nil {
			return 0, nil, err
		}
		if typ != recHandshake {
			return 0, nil, errDecode
		}
		r.hsBuf = append(r.hsBuf, body...)
	}
}

func (r *recordConn) readAppData() ([]byte, error) {
	typ, body, err := r.readRecord()
	if err != nil {
		return nil, err
	}
	if typ != recAppData {
		return nil, errDecode
	}
	return body, nil
}
