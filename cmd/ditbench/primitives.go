package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"filippo.io/edwards25519"

	"github.com/DebasishTripathy13/dit-poc/frost"
	"github.com/DebasishTripathy13/dit-poc/identity"
	"github.com/DebasishTripathy13/dit-poc/pqc"
	"github.com/DebasishTripathy13/dit-poc/rotation"
	"github.com/DebasishTripathy13/dit-poc/tlog"
)

type prim struct {
	name, group string
	fn          func(b *testing.B)
}

func primitives() []prim {
	msg := make([]byte, 64)
	kb := make([]byte, 1024)
	rand.Read(kb)
	sk, _ := pqc.GenerateSigningKey()
	sig := sk.Sign("", msg)
	pub := sk.PublicKey()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h := sha256.Sum256(msg)
	ecSig, _ := ecdsa.SignASN1(rand.Reader, ec, h[:])
	dk, _ := mlkem.GenerateKey768()
	ek := dk.EncapsulationKey()
	_, ct := ek.Encapsulate()
	hk, share, _ := pqc.GenerateHybridClientKey()
	srvShare, _, _ := pqc.HybridServerEncaps(share)
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	xp := x.PublicKey()

	// Merkle inclusion proof at depth 20 (log of 2^20 entries).
	tr := &tlog.Tree{}
	for i := 0; i < 1<<20; i++ {
		tr.AppendLeafHash(pqc.SHA3([]byte(strconv.Itoa(i))))
	}
	idx := uint64(777_777)
	proof, _ := tr.InclusionProof(idx, tr.Size())
	root := tr.Root()
	lh := pqc.SHA3([]byte(strconv.Itoa(int(idx))))

	ik, _ := pqc.GenerateSigningKey()
	now := time.Unix(1_800_000_000, 0)
	_, cred, _ := identity.IssueEpochCredential(ik, "bank.example", 0, now)
	idObj := &identity.IdentityObject{Domain: "bank.example", IKPub: ik.PublicKey(), PrevDigest: make([]byte, 48)}

	shares, gpk, _ := frost.TrustedDealerKeygen(3, 5)
	frostMsg := []byte("recovery rotation record")
	frostSign := func() []byte {
		var ns []*frost.Nonces
		var cs []*frost.Commitment
		for _, s := range shares[:3] {
			n, c := frost.Commit(s)
			ns, cs = append(ns, n), append(cs, c)
		}
		var zs []*edwards25519.Scalar
		for i, s := range shares[:3] {
			z, _ := frost.SignShare(s, ns[i], frostMsg, cs)
			zs = append(zs, z)
		}
		return frost.Aggregate(shares[0].GroupPublic, frostMsg, cs, zs)
	}
	frostSig := frostSign()

	// One normal rotation (pending + rotation) applied by a witness/client.
	o, _, pubEntry, _ := rotation.NewDomain("bank.example", 3, 5, []byte("c"))
	pubEntry.Timestamp = uint64(now.Unix())
	ik2, _ := pqc.GenerateSigningKey()
	next := rotation.Successor(o.Identity, ik2.PublicKey())
	pend := rotation.PendingNormalEntry(o.IK, o.Identity, next, now.Add(time.Hour))
	rot := rotation.RotationNormalEntry(o.IK, ik2, o.Identity, next, now.Add(26*time.Hour))

	return []prim{
		{"mldsa65_keygen", "ML-DSA-65", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pqc.GenerateSigningKey()
			}
		}},
		{"mldsa65_sign", "ML-DSA-65", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				sk.Sign("", msg)
			}
		}},
		{"mldsa65_verify", "ML-DSA-65", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if !pqc.Verify(pub, "", msg, sig) {
					b.Fatal("verify")
				}
			}
		}},
		{"mlkem768_keygen", "ML-KEM-768", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				mlkem.GenerateKey768()
			}
		}},
		{"mlkem768_encaps", "ML-KEM-768", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ek.Encapsulate()
			}
		}},
		{"mlkem768_decaps", "ML-KEM-768", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				dk.Decapsulate(ct)
			}
		}},
		{"x25519mlkem768_client_keygen", "X25519MLKEM768", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pqc.GenerateHybridClientKey()
			}
		}},
		{"x25519mlkem768_server_encaps", "X25519MLKEM768", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pqc.HybridServerEncaps(share)
			}
		}},
		{"x25519mlkem768_client_decaps", "X25519MLKEM768", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				hk.Decaps(srvShare)
			}
		}},
		{"x25519_keygen_and_ecdh", "classical", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				k, _ := ecdh.X25519().GenerateKey(rand.Reader)
				k.ECDH(xp)
			}
		}},
		{"ecdsa_p256_sign", "classical", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ecdsa.SignASN1(rand.Reader, ec, h[:])
			}
		}},
		{"ecdsa_p256_verify", "classical", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ecdsa.VerifyASN1(&ec.PublicKey, h[:], ecSig)
			}
		}},
		{"sha3_384_1KiB", "hash", func(b *testing.B) {
			b.SetBytes(1024)
			for i := 0; i < b.N; i++ {
				pqc.SHA3(kb)
			}
		}},
		{"sha256_1KiB", "hash", func(b *testing.B) {
			b.SetBytes(1024)
			for i := 0; i < b.N; i++ {
				sha256.Sum256(kb)
			}
		}},
		{"sha3_384_64B", "hash", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pqc.SHA3(msg)
			}
		}},
		{"sha256_64B", "hash", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				sha256.Sum256(msg)
			}
		}},
		{"merkle_inclusion_verify_depth20", "DIT", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if !tlog.VerifyInclusion(lh, idx, tr.Size(), proof, root) {
					b.Fatal("proof")
				}
			}
		}},
		{"eak_issue_keygen_and_ik_sign", "DIT", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				identity.IssueEpochCredential(ik, "bank.example", 0, now)
			}
		}},
		{"epoch_credential_verify", "DIT", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if err := identity.VerifyCredential(idObj, cred, now.Add(time.Minute)); err != nil {
					b.Fatal(err)
				}
			}
		}},
		{"frost_3of5_sign_total", "DIT recovery", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				frostSign()
			}
		}},
		{"frost_signature_verify_ed25519", "DIT recovery", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if !ed25519.Verify(gpk, frostMsg, frostSig) {
					b.Fatal("frost")
				}
			}
		}},
		{"normal_rotation_apply", "DIT", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				s := rotation.NewState()
				if s.Apply(pubEntry) != nil || s.Apply(pend) != nil || s.Apply(rot) != nil {
					b.Fatal("apply")
				}
			}
		}},
	}
}

func runPrimitives(path string) {
	var rows [][]string
	for _, p := range primitives() {
		r := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			p.fn(b)
		})
		// testing.Benchmark targets ~1 s; repeat until -benchtime is reached.
		for r.T < *flagBenchTime && r.N < 1<<30 {
			n := r.N * 2
			r = testing.Benchmark(func(b *testing.B) {
				b.ReportAllocs()
				if b.N < n {
					b.N = n
				}
				p.fn(b)
			})
		}
		ns := float64(r.T.Nanoseconds()) / float64(r.N)
		rows = append(rows, []string{p.name, p.group, strconv.Itoa(r.N), strconv.FormatFloat(ns, 'f', 1, 64),
			strconv.FormatFloat(1e9/ns, 'f', 0, 64), strconv.FormatInt(r.AllocsPerOp(), 10),
			strconv.FormatInt(r.AllocedBytesPerOp(), 10)})
		fmt.Fprintf(os.Stderr, "%-34s %12.1f ns/op\n", p.name, ns)
	}
	writeCSV(path, []string{"primitive", "group", "iterations", "ns_per_op", "ops_per_s", "allocs_per_op", "bytes_per_op"}, rows)
}
