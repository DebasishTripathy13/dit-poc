package identity

import (
	"encoding/binary"
	"errors"
)

// TLV is the canonical binary encoding used for every signed or hashed DIT
// object: 1-byte type, 2-byte big-endian length, value. Fields are emitted in
// ascending type order, so the encoding of a given object is unique.

type tlvWriter struct{ b []byte }

func (w *tlvWriter) bytes(t byte, v []byte) {
	w.b = append(w.b, t, byte(len(v)>>8), byte(len(v)))
	w.b = append(w.b, v...)
}

func (w *tlvWriter) u64(t byte, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	w.bytes(t, b[:])
}

func (w *tlvWriter) str(t byte, s string) { w.bytes(t, []byte(s)) }

type tlvReader struct {
	b    []byte
	last int
}

var errTLV = errors.New("identity: malformed TLV")

func (r *tlvReader) next(want byte) ([]byte, error) {
	if len(r.b) < 3 || int(r.b[0]) != int(want) || int(want) <= r.last {
		return nil, errTLV
	}
	n := int(r.b[1])<<8 | int(r.b[2])
	if len(r.b) < 3+n {
		return nil, errTLV
	}
	v := r.b[3 : 3+n]
	r.b = r.b[3+n:]
	r.last = int(want)
	return v, nil
}

func (r *tlvReader) u64(want byte) (uint64, error) {
	v, err := r.next(want)
	if err != nil || len(v) != 8 {
		return 0, errTLV
	}
	return binary.BigEndian.Uint64(v), nil
}

func (r *tlvReader) done() error {
	if len(r.b) != 0 {
		return errTLV
	}
	return nil
}
