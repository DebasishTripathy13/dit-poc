package main

import (
	"strconv"

	"github.com/dit-protocol/poc/handshake"
	"github.com/dit-protocol/poc/pqc"
	"github.com/dit-protocol/poc/sim"
)

// runSizes records the encoded size of every DIT object, in TLV and JSON, as
// produced by the code (Appendix: byte-count derivation).
func runSizes(path string) {
	w, err := sim.NewWorld(*flagLogSize, handshake.TLV)
	check(err)
	id := w.Owner.Identity
	idJSON, _ := id.MarshalJSON()
	cred := w.Server.Credential
	credJSON, _ := cred.MarshalJSON()
	cold := &handshake.Bundle{Credential: cred, Entry: w.Server.Entry, Index: w.Server.Index,
		Proof: w.Server.Proof, STH: w.Server.STH}
	coldTLV, coldJSON := handshake.BundleSizes(cold)
	newEpoch := &handshake.Bundle{Credential: cred}
	neTLV, neJSON := handshake.BundleSizes(newEpoch)
	proofBytes := 0
	for _, p := range w.Server.Proof {
		proofBytes += len(p)
	}
	row := func(name string, tlv, json int, note string) []string {
		return []string{name, strconv.Itoa(tlv), strconv.Itoa(json), note}
	}
	rows := [][]string{
		row("mldsa65_public_key", pqc.MLDSA65PublicKeySize, 0, "FIPS 204"),
		row("mldsa65_signature", pqc.MLDSA65SignatureSize, 0, "FIPS 204"),
		row("mldsa65_spki_der", len(handshake.SPKI(cred.EAKPub)), 0, "RFC 9881 SubjectPublicKeyInfo"),
		row("x25519mlkem768_client_share", pqc.HybridClientShareSize, 0, "1184 + 32 (RFC 10024)"),
		row("x25519mlkem768_server_share", pqc.HybridServerShareSize, 0, "1088 + 32 (RFC 10024)"),
		row("dns_commitment", len(id.Digest()), 0, "SHA3-384 of identity object"),
		row("identity_object", len(id.MarshalTLV()), len(idJSON), "5 recovery peers"),
		row("epoch_credential", len(cred.MarshalTLV()), len(credJSON), ""),
		row("log_entry_key_publication", len(w.PubEntry), 0, "includes identity object and IK signature"),
		row("inclusion_proof", proofBytes, 0, "depth "+strconv.Itoa(len(w.Server.Proof))+", 48 B per level"),
		row("cosigned_sth", w.Server.STH.WireSize(), 0, "log signature + q=5 cosignatures"),
		row("dit_bundle_new_epoch", neTLV, neJSON, "credential only"),
		row("dit_bundle_cold", coldTLV, coldJSON, "credential + entry + proof + cosigned STH"),
		row("log_size", int(w.Log.Tree.Size()), 0, "entries in simulated log"),
	}
	writeCSV(path, []string{"object", "bytes_tlv", "bytes_json", "note"}, rows)
}
