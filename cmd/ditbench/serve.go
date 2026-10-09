package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/dit-protocol/poc/baseline"
	"github.com/dit-protocol/poc/handshake"
	"github.com/dit-protocol/poc/sim"
)

// trust is what the server process hands to the load generator: listening
// ports and the public trust material a client needs (CA roots, the DIT DNS
// commitment, witness keys, and the pinned identity / cached credential).
type trust struct {
	Ports       map[string]int `json:"ports"`
	ECDSARoot   []byte         `json:"ecdsa_root"`
	PQRoot      []byte         `json:"pq_root"`
	PQLogs      [][]byte       `json:"pq_logs"`
	PQMetaBytes int            `json:"pq_meta_bytes"`
	Commitment  []byte         `json:"dit_commitment"`
	LogPub      []byte         `json:"dit_log_pub"`
	Witnesses   map[int][]byte `json:"dit_witnesses"`
	Identity    []byte         `json:"dit_identity"`
	Credential  []byte         `json:"dit_credential"`
	LogSize     uint64         `json:"dit_log_size"`
	Now         int64          `json:"now"`
}

// fixedNow is the evaluation time used by every component, so that runs are
// reproducible regardless of the wall clock.
var fixedNow = time.Unix(1_800_000_000, 0)

func serve(logSize int) error {
	chain, err := baseline.NewChain(sim.Domain, fixedNow)
	if err != nil {
		return err
	}
	meta := (baseline.MetaBytes(chain.Leaf) + baseline.MetaBytes(chain.Intermediate)) / 2
	pq, err := handshake.NewPQChain(meta)
	if err != nil {
		return err
	}
	world, err := sim.NewWorld(logSize, handshake.TLV)
	if err != nil {
		return err
	}
	jsonServer := *world.Server
	jsonServer.Encoding = handshake.JSON

	type handler func(net.Conn) error
	handlers := map[string]handler{
		"a": func(c net.Conn) error { return tls.Server(c, chain.ServerConfig(baseline.Classical)).Handshake() },
		"b": func(c net.Conn) error { return tls.Server(c, chain.ServerConfig(baseline.HybridKEM)).Handshake() },
		"c": func(c net.Conn) error { _, err := handshake.Server(c, pq); return err },
		"dit": func(c net.Conn) error {
			_, err := handshake.Server(c, world.Server)
			return err
		},
		"dit-json": func(c net.Conn) error { _, err := handshake.Server(c, &jsonServer); return err },
	}
	t := trust{Ports: map[string]int{}, ECDSARoot: chain.Root.Raw, PQRoot: pq.Root.PublicKey(),
		PQMetaBytes: meta, Commitment: world.Commitment, LogPub: world.Policy.LogPub,
		Witnesses: map[int][]byte{}, Identity: world.Owner.Identity.MarshalTLV(),
		Credential: world.Server.Credential.MarshalTLV(), LogSize: world.Log.Tree.Size(), Now: fixedNow.Unix()}
	for _, l := range pq.CTLogs {
		t.PQLogs = append(t.PQLogs, l.PublicKey())
	}
	for id, pub := range world.Policy.Witnesses {
		t.Witnesses[int(id)] = pub
	}
	for name, h := range handlers {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		t.Ports[name] = ln.Addr().(*net.TCPAddr).Port
		go func(ln net.Listener, h handler) {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					_ = h(c)
				}()
			}
		}(ln, h)
	}
	out, _ := json.Marshal(t)
	fmt.Println(string(out))
	// Serve until the parent closes stdin.
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	return nil
}
