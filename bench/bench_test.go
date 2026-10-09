// Package bench holds Go benchmarks for the main DIT operations. They run on
// in-memory pipes and are meant for quick regression checks:
//
//	go test -run=^$ -bench=. -benchmem ./bench/
//
// The numbers reported in the paper come from cmd/ditbench, which measures
// over TCP with a pinned single-core server (see README).
package bench

import (
	"net"
	"testing"

	"github.com/dit-protocol/poc/handshake"
	"github.com/dit-protocol/poc/pqc"
	"github.com/dit-protocol/poc/sim"
	"github.com/dit-protocol/poc/tlog"
)

func BenchmarkMLDSA65Sign(b *testing.B) {
	k, _ := pqc.GenerateSigningKey()
	msg := make([]byte, 64)
	for i := 0; i < b.N; i++ {
		k.Sign("", msg)
	}
}

func BenchmarkMLDSA65Verify(b *testing.B) {
	k, _ := pqc.GenerateSigningKey()
	msg := make([]byte, 64)
	sig := k.Sign("", msg)
	for i := 0; i < b.N; i++ {
		if !pqc.Verify(k.PublicKey(), "", msg, sig) {
			b.Fatal("verify")
		}
	}
}

func BenchmarkX25519MLKEM768(b *testing.B) {
	for i := 0; i < b.N; i++ {
		c, share, _ := pqc.GenerateHybridClientKey()
		s, _, _ := pqc.HybridServerEncaps(share)
		if _, err := c.Decaps(s); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMerkleInclusionVerify(b *testing.B) {
	tr := &tlog.Tree{}
	for i := 0; i < 1<<16; i++ {
		tr.Append([]byte{byte(i), byte(i >> 8)})
	}
	p, _ := tr.InclusionProof(12345, tr.Size())
	root, lh := tr.Root(), tlog.LeafHash([]byte{byte(12345 & 0xff), byte(12345 >> 8)})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !tlog.VerifyInclusion(lh, 12345, tr.Size(), p, root) {
			b.Fatal("proof")
		}
	}
}

func handshakeBench(b *testing.B, srv handshake.ServerAuth, mk func() handshake.ClientAuth) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c1, c2 := net.Pipe()
		done := make(chan error, 1)
		go func() { _, err := handshake.Server(c2, srv); done <- err }()
		if _, err := handshake.Client(c1, sim.Domain, mk()); err != nil {
			b.Fatal(err)
		}
		if err := <-done; err != nil {
			b.Fatal(err)
		}
		c1.Close()
		c2.Close()
	}
}

func BenchmarkHandshakeDITWarm(b *testing.B) {
	w, _ := sim.NewWorld(1<<12, handshake.TLV)
	handshakeBench(b, w.Server, func() handshake.ClientAuth { return w.WarmClient(true) })
}

func BenchmarkHandshakeDITCold(b *testing.B) {
	w, _ := sim.NewWorld(1<<12, handshake.TLV)
	handshakeBench(b, w.Server, func() handshake.ClientAuth { return w.ColdClient() })
}

func BenchmarkHandshakeFullPQChain(b *testing.B) {
	c, _ := handshake.NewPQChain(450)
	handshakeBench(b, c, func() handshake.ClientAuth { return c.Client() })
}
