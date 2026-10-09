#!/usr/bin/env python3
"""Generate the paper's tables and number macros from the benchmark CSVs.

    python3 scripts/make_table1.py --results results --out results/generated

Writes:
  table1.tex        Table 1: bytes, signature checks, properties per variant
  table_cpu.tex     Table 2: latency (loopback), client and server CPU, throughput
  table_sizes.tex   Appendix: measured size of every DIT object
  table_prims.tex   Appendix: primitive microbenchmarks
  numbers.tex       \\newcommand macros for every number quoted in the text

Every value is read from the CSVs or computed here by the formula shown next
to it; nothing is typed by hand. Standard library only.
"""
import argparse
import csv
import math
import os

VARIANTS = [
    # key, label, PQ auth, PQ key exchange, CA-issued certificates
    ("a_tls13_classical", "(a) TLS 1.3 classical", "no", "no", "yes"),
    ("b_tls13_hybrid_kem", "(b) TLS 1.3 hybrid KEM", "no", "yes", "yes"),
    ("c_tls13_full_pq", "(c) TLS 1.3 fully PQ", "yes", "yes", "yes"),
    ("dit_warm", "DIT warm", "yes", "yes", "no"),
    ("dit_warm_new_epoch", "DIT warm, new epoch", "yes", "yes", "no"),
    ("dit_cold", "DIT cold (first contact)", "yes$^\\dagger$", "yes", "no"),
]

# TCP model for extra round trips caused by the server flight (Appendix B):
# initial congestion window of 10 segments (RFC 6928), MSS 1460 bytes, window
# doubling per round trip (slow start, no loss).
INITCWND_SEGMENTS = 10
MSS = 1460


def extra_rtts(server_bytes):
    """Round trips beyond the first needed to deliver server_bytes."""
    cwnd, sent, rtts = INITCWND_SEGMENTS * MSS, 0, 0
    while True:
        sent += cwnd
        if sent >= server_bytes:
            return rtts
        cwnd *= 2
        rtts += 1


def read(path, key):
    with open(path, newline="") as f:
        return {r[key]: r for r in csv.DictReader(f)}


def kb(n):
    return f"{int(n) / 1000:.1f}"


def num(n):
    return f"{int(round(float(n))):,}".replace(",", "{,}")


def macro_name(s):
    out, up = "", True
    for ch in s:
        if ch.isalnum():
            out += ch.upper() if up else ch
            up = False
        else:
            up = True
    digits = {"0": "Zero", "1": "One", "2": "Two", "3": "Three", "4": "Four",
              "5": "Five", "6": "Six", "7": "Seven", "8": "Eight", "9": "Nine"}
    return "".join(digits.get(c, c) for c in out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--out", default="results/generated")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    hs = read(os.path.join(a.results, "handshakes.csv"), "variant")
    sizes = read(os.path.join(a.results, "sizes.csv"), "object")
    prims = read(os.path.join(a.results, "primitives.csv"), "primitive")
    env = {r["key"]: r["value"] for r in csv.DictReader(open(os.path.join(a.results, "env.csv")))}

    # ── Table 1 ──
    rows = []
    for key, label, pqa, pqk, ca in VARIANTS:
        r = hs[key]
        rows.append(" & ".join([
            label, num(r["client_to_server_bytes"]), num(r["server_to_client_bytes"]),
            num(r["total_bytes"]), r["client_sig_verifications"],
            str(extra_rtts(int(r["server_to_client_bytes"]))), pqa, pqk, ca]) + r" \\")
    t1 = "\n".join([
        r"\begin{tabular}{lrrrccccc}",
        r"\toprule",
        r"Variant & C$\to$S (B) & S$\to$C (B) & Total (B) & Sig.\ checks & Extra RTTs & PQ auth. & PQ KEX & CA certs \\",
        r"\midrule",
        *rows,
        r"\bottomrule",
        r"\end{tabular}",
    ])
    open(os.path.join(a.out, "table1.tex"), "w").write(t1 + "\n")

    # ── Table 2: CPU and latency ──
    rows = []
    for key, label, *_ in VARIANTS:
        r = hs[key]
        rows.append(" & ".join([
            label, r["latency_p50_us"], r["latency_p95_us"], r["latency_p99_us"],
            r["client_cpu_us_per_hs"], r["server_cpu_us_per_hs"],
            num(r["server_hs_per_s_single_core"])]) + r" \\")
    t2 = "\n".join([
        r"\begin{tabular}{lrrrrrr}",
        r"\toprule",
        r" & \multicolumn{3}{c}{Latency, loopback ($\mu$s)} & Client CPU & Server CPU & Server hs/s \\",
        r"\cmidrule(lr){2-4}",
        r"Variant & P50 & P95 & P99 & ($\mu$s/hs) & ($\mu$s/hs) & (1 core) \\",
        r"\midrule",
        *rows,
        r"\bottomrule",
        r"\end{tabular}",
    ])
    open(os.path.join(a.out, "table_cpu.tex"), "w").write(t2 + "\n")

    # ── Appendix: sizes ──
    labels = {
        "mldsa65_public_key": "ML-DSA-65 public key", "mldsa65_signature": "ML-DSA-65 signature",
        "mldsa65_spki_der": "ML-DSA-65 SubjectPublicKeyInfo (DER)",
        "x25519mlkem768_client_share": "X25519MLKEM768 client key share",
        "x25519mlkem768_server_share": "X25519MLKEM768 server key share",
        "dns_commitment": "DNS commitment (SHA3-384)", "identity_object": "Identity object",
        "epoch_credential": "Epoch credential", "log_entry_key_publication": "Log entry (KEY\\_PUBLICATION)",
        "log_entry_pending_normal": "Log entry (ROTATION\\_PENDING, normal)",
        "log_entry_rotation_normal": "Log entry (KEY\\_ROTATION, normal)",
        "log_entry_pending_recovery": "Log entry (ROTATION\\_PENDING, recovery)",
        "log_entry_rotation_recovery": "Log entry (KEY\\_ROTATION, recovery)",
        "log_entry_cancel_recovery": "Log entry (CANCEL, recovery)",
        "inclusion_proof": "Inclusion proof", "cosigned_sth": "Cosigned STH ($q=5$)",
        "dit_bundle_new_epoch": "DIT extension, new epoch", "dit_bundle_cold": "DIT extension, first contact",
    }
    rows = []
    for k, lab in labels.items():
        r = sizes[k]
        js = num(r["bytes_json"]) if int(r["bytes_json"]) else "--"
        note = r["note"].replace("_", "\\_")
        rows.append(f"{lab} & {num(r['bytes_tlv'])} & {js} & {note} \\\\")
    t3 = "\n".join([r"\begin{tabular}{lrrl}", r"\toprule",
                    r"Object & TLV (B) & JSON (B) & Note \\", r"\midrule", *rows,
                    r"\bottomrule", r"\end{tabular}"])
    open(os.path.join(a.out, "table_sizes.tex"), "w").write(t3 + "\n")

    # ── Appendix: primitives ──
    plabels = [
        ("mldsa65_keygen", "ML-DSA-65 key generation"), ("mldsa65_sign", "ML-DSA-65 sign"),
        ("mldsa65_verify", "ML-DSA-65 verify"), ("mlkem768_keygen", "ML-KEM-768 key generation"),
        ("mlkem768_encaps", "ML-KEM-768 encapsulation"), ("mlkem768_decaps", "ML-KEM-768 decapsulation"),
        ("x25519mlkem768_client_keygen", "X25519MLKEM768 client key share"),
        ("x25519mlkem768_server_encaps", "X25519MLKEM768 server share + secret"),
        ("x25519mlkem768_client_decaps", "X25519MLKEM768 client secret"),
        ("x25519_keygen_and_ecdh", "X25519 key generation + ECDH"),
        ("ecdsa_p256_sign", "ECDSA P-256 sign"), ("ecdsa_p256_verify", "ECDSA P-256 verify"),
        ("sha3_384_1KiB", "SHA3-384, 1 KiB"), ("sha256_1KiB", "SHA-256, 1 KiB"),
        ("sha3_384_64B", "SHA3-384, 64 B"), ("sha256_64B", "SHA-256, 64 B"),
        ("merkle_inclusion_verify_depth20", "Merkle inclusion proof verify (depth 20)"),
        ("eak_issue_keygen_and_ik_sign", "EAK issuance (key generation + IK signature)"),
        ("epoch_credential_verify", "Epoch credential verification"),
        ("frost_3of5_sign_total", "FROST 3-of-5 signing (all rounds, all signers)"),
        ("frost_signature_verify_ed25519", "FROST signature verification (Ed25519)"),
        ("normal_rotation_apply", "Normal rotation validation (publication + pending + rotation)"),
    ]
    rows = [f"{lab} & {float(prims[k]['ns_per_op']) / 1000:.1f} & {num(prims[k]['ops_per_s'])} \\\\"
            for k, lab in plabels]
    t4 = "\n".join([r"\begin{tabular}{lrr}", r"\toprule",
                    r"Operation & $\mu$s/op & ops/s \\", r"\midrule", *rows,
                    r"\bottomrule", r"\end{tabular}"])
    open(os.path.join(a.out, "table_prims.tex"), "w").write(t4 + "\n")

    # ── Macros ──
    m = {}
    for key, *_ in VARIANTS + [("dit_warm_new_epoch_json",), ("dit_cold_json",)]:
        r = hs[key]
        n = macro_name(key)
        m[n + "Total"] = num(r["total_bytes"])
        m[n + "TotalKB"] = kb(r["total_bytes"])
        m[n + "Down"] = num(r["server_to_client_bytes"])
        m[n + "Up"] = num(r["client_to_server_bytes"])
        m[n + "Sigs"] = r["client_sig_verifications"]
        m[n + "SrvCPU"] = r["server_cpu_us_per_hs"]
        m[n + "CliCPU"] = r["client_cpu_us_per_hs"]
        m[n + "HSs"] = num(r["server_hs_per_s_single_core"])
        m[n + "Pfifty"] = r["latency_p50_us"]
        m[n + "Pninetynine"] = r["latency_p99_us"]
        m[n + "ExtraRTT"] = str(extra_rtts(int(r["server_to_client_bytes"])))
    for k in labels:
        m["Size" + macro_name(k)] = num(sizes[k]["bytes_tlv"])
        if int(sizes[k]["bytes_json"]):
            m["Size" + macro_name(k) + "Json"] = num(sizes[k]["bytes_json"])
    for k, _ in plabels:
        m["Prim" + macro_name(k)] = f"{float(prims[k]['ns_per_op']) / 1000:.1f}"
    t = lambda k: int(hs[k]["total_bytes"])
    m["RatioFullPQOverDITWarm"] = f"{t('c_tls13_full_pq') / t('dit_warm'):.1f}"
    m["RatioDITWarmOverClassical"] = f"{t('dit_warm') / t('a_tls13_classical'):.1f}"
    m["RatioDITWarmOverHybrid"] = f"{t('dit_warm') / t('b_tls13_hybrid_kem'):.1f}"
    m["JsonOverheadColdPct"] = f"{100 * (t('dit_cold_json') / t('dit_cold') - 1):.0f}"
    m["JsonOverheadNewEpochPct"] = f"{100 * (t('dit_warm_new_epoch_json') / t('dit_warm_new_epoch') - 1):.0f}"
    s = lambda k: float(hs[k]["server_cpu_us_per_hs"])
    m["CPURatioDITWarmOverFullPQ"] = f"{s('dit_warm') / s('c_tls13_full_pq'):.2f}"
    # Third-party certificate issuance for 1,000 domains with 47-day
    # certificates: at least ceil(365/47) issuances per domain per year.
    m["IssuancePerDomainYear"] = str(math.ceil(365 / 47))
    m["IssuanceThousandDomains"] = num(1000 * math.ceil(365 / 47))
    m["InitCwndBytes"] = num(INITCWND_SEGMENTS * MSS)
    m["LogSize"] = num(sizes["log_size"]["bytes_tlv"])
    for k in ["handshakes_measured", "handshakes_warmup", "throughput_concurrency", "server_cpu",
              "go_version", "cpu_model", "git_commit", "kernel", "throughput_seconds"]:
        m["Env" + macro_name(k)] = env[k].replace("_", "\\_")
    with open(os.path.join(a.out, "numbers.tex"), "w") as f:
        f.write("% Generated by scripts/make_table1.py from results/*.csv. Do not edit.\n")
        for k in sorted(m):
            f.write(f"\\newcommand{{\\{k}}}{{{m[k]}}}\n")
    print(f"wrote tables and {len(m)} macros to {a.out}")


if __name__ == "__main__":
    main()
