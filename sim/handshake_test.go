package sim

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/dit-protocol/poc/handshake"
	"github.com/dit-protocol/poc/tlog"
)

type result struct {
	s   *handshake.Session
	err error
}

// run executes one handshake over net.Pipe and exchanges one application
// record in each direction.
func run(t *testing.T, srv handshake.ServerAuth, cli handshake.ClientAuth, mitm func(io.ReadWriter) io.ReadWriter) (*handshake.Session, *handshake.Session, error) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ch := make(chan result, 1)
	go func() {
		s, err := handshake.Server(b, srv)
		if err == nil {
			if msg, e := s.Recv(); e != nil || string(msg) != "ping" {
				err = errors.New("server: bad application data")
			} else {
				err = s.Send([]byte("pong"))
			}
		}
		if err != nil {
			b.Close()
		}
		ch <- result{s, err}
	}()
	var conn io.ReadWriter = a
	if mitm != nil {
		conn = mitm(a)
	}
	c, err := handshake.Client(conn, Domain, cli)
	if err == nil {
		err = c.Send([]byte("ping"))
		if err == nil {
			var msg []byte
			msg, err = c.Recv()
			if err == nil && string(msg) != "pong" {
				err = errors.New("client: bad application data")
			}
		}
	}
	if err != nil {
		a.Close()
		<-ch
		return nil, nil, err
	}
	r := <-ch
	return c, r.s, r.err
}

func TestColdWarmAndCachedPaths(t *testing.T) {
	for _, enc := range []handshake.Encoding{handshake.TLV, handshake.JSON} {
		w, err := NewWorld(1000, enc)
		if err != nil {
			t.Fatal(err)
		}
		cold := w.ColdClient()
		c, s, err := run(t, w.Server, cold, nil)
		if err != nil {
			t.Fatalf("enc=%d cold: %v", enc, err)
		}
		if !bytes.Equal(c.CAP, s.CAP) || !bytes.Equal(c.SAP, s.SAP) {
			t.Fatal("traffic secrets differ")
		}
		if cold.Verifies != 2+1+Quorum || cold.Presented == nil {
			t.Fatalf("cold path: %d verifications", cold.Verifies)
		}
		warm := w.WarmClient(false)
		if _, _, err := run(t, w.Server, warm, nil); err != nil || warm.Verifies != 2 {
			t.Fatalf("warm (credential not cached): %v, %d verifications", err, warm.Verifies)
		}
		cached := w.WarmClient(true)
		if _, _, err := run(t, w.Server, cached, nil); err != nil || cached.Verifies != 1 {
			t.Fatalf("warm (credential cached): %v, %d verifications", err, cached.Verifies)
		}
	}
}

func TestPQChainBaseline(t *testing.T) {
	c, err := handshake.NewPQChain(400)
	if err != nil {
		t.Fatal(err)
	}
	cl := c.Client()
	if _, _, err := run(t, c, cl, nil); err != nil {
		t.Fatal(err)
	}
	if cl.Verifies != 5 {
		t.Fatalf("pq chain: %d verifications", cl.Verifies)
	}
	other, _ := handshake.NewPQChain(400)
	if _, _, err := run(t, other, cl, nil); err == nil {
		t.Fatal("chain under a different root accepted")
	}
}

func TestFirstContactRejections(t *testing.T) {
	w, err := NewWorld(100, handshake.TLV)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong DNSSEC commitment (adversary controls the server, not DNS).
	cl := w.ColdClient()
	cl.DNSCommitment = make([]byte, 48)
	if _, _, err := run(t, w.Server, cl, nil); !errors.Is(err, handshake.ErrCommitment) {
		t.Fatalf("wrong commitment: %v", err)
	}
	// Stale STH.
	cl = w.ColdClient()
	cl.Now = func() time.Time { return w.Now.Add(48 * time.Hour) }
	if _, _, err := run(t, w.Server, cl, nil); err == nil {
		t.Fatal("stale STH accepted")
	}
	// Only q-1 cosignatures.
	saved := w.Server.STH
	w.Server.STH = &tlog.CosignedSTH{STH: saved.STH, Cosigns: saved.Cosigns[:Quorum-1]}
	if _, _, err := run(t, w.Server, w.ColdClient(), nil); err == nil {
		t.Fatal("q-1 cosignatures accepted")
	}
	w.Server.STH = saved
	// Wrong inclusion index.
	w.Server.Index--
	if _, _, err := run(t, w.Server, w.ColdClient(), nil); !errors.Is(err, handshake.ErrInclusion) {
		t.Fatalf("bad inclusion: %v", err)
	}
	w.Server.Index++
}

// An EAK whose credential was issued by a different IK is rejected, and a
// server presenting another identity triggers pin resolution.
func TestImpersonationRejected(t *testing.T) {
	w, _ := NewWorld(100, handshake.TLV)
	other, _ := NewWorld(100, handshake.TLV)
	// other's server presents its own (validly logged) identity to a client
	// that pinned w's identity.
	if _, _, err := run(t, other.Server, w.WarmClient(false), nil); err == nil {
		t.Fatal("foreign credential accepted on warm path")
	}
	cl := w.WarmClient(false)
	cl.DNSCommitment = nil
	other.Server.Entry, other.Server.Index, other.Server.Proof, other.Server.STH = w.Server.Entry, w.Server.Index, w.Server.Proof, w.Server.STH
	if _, _, err := run(t, other.Server, cl, nil); err == nil {
		t.Fatal("credential from a different IK accepted")
	}
	// Raw public key that differs from the certified EAK.
	srv := *w.Server
	_ = w.NewEAK()
	srv.Credential = w.Server.Credential // credential for the new EAK, old key signs
	if _, _, err := run(t, &srv, w.WarmClient(false), nil); !errors.Is(err, handshake.ErrEAKMatch) {
		t.Fatalf("EAK mismatch: %v", err)
	}
}

// flipper corrupts one byte of the server's encrypted flight.
type flipper struct {
	io.ReadWriter
	n, at int
}

func (f *flipper) Read(b []byte) (int, error) {
	n, err := f.ReadWriter.Read(b)
	for i := 0; i < n; i++ {
		if f.n == f.at {
			b[i] ^= 0x01
		}
		f.n++
	}
	return n, err
}

// Any modification of handshake bytes is detected (record MAC, signature or
// Finished), including in the ServerHello key share.
func TestTamperingDetected(t *testing.T) {
	w, _ := NewWorld(100, handshake.TLV)
	for _, pos := range []int{20, 200, 1500, 3000, 6000} {
		_, _, err := run(t, w.Server, w.WarmClient(true), func(c io.ReadWriter) io.ReadWriter {
			return &flipper{ReadWriter: c, at: pos}
		})
		if err == nil {
			t.Fatalf("tampering at byte %d not detected", pos)
		}
	}
}

// After a normal rotation, a server still using an epoch credential from the
// previous IK is accepted only within the grace period.
func TestGracePeriod(t *testing.T) {
	w, _ := NewWorld(100, handshake.TLV)
	prev := w.Owner.Identity
	next := *prev
	next.Seq++
	next.IKPub = make([]byte, 1952) // stand-in successor; only Seq matters here
	cl := w.WarmClient(false)
	cl.Pin = &next
	if _, _, err := run(t, w.Server, cl, nil); err == nil {
		t.Fatal("credential from previous IK accepted without grace")
	}
	cl = w.WarmClient(false)
	cl.Pin, cl.GracePrev, cl.GraceUntil = &next, prev, w.Now.Add(time.Hour)
	if _, _, err := run(t, w.Server, cl, nil); err != nil {
		t.Fatalf("within grace: %v", err)
	}
	cl = w.WarmClient(false)
	cl.Pin, cl.GracePrev, cl.GraceUntil = &next, prev, w.Now.Add(-time.Hour)
	if _, _, err := run(t, w.Server, cl, nil); err == nil {
		t.Fatal("credential from previous IK accepted after grace")
	}
}
