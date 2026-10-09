#!/usr/bin/env python3
"""Generate Figure 8 from results/handshakes.csv (the same file as Table 1).

    python3 scripts/make_fig8.py --results results --out results/generated

Writes fig8.pdf and fig8.png: (left) bytes on the wire per handshake split
by direction; (right) server CPU time per handshake on one core (median of
the throughput windows; whiskers show minimum and maximum).
Requires matplotlib.
"""
import argparse
import csv
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

VARIANTS = [
    ("a_tls13_classical", "(a) classical"),
    ("b_tls13_hybrid_kem", "(b) hybrid KEM"),
    ("c_tls13_full_pq", "(c) fully PQ"),
    ("dit_warm", "DIT warm"),
    ("dit_warm_new_epoch", "DIT new epoch"),
    ("dit_cold", "DIT cold"),
]
UP, DOWN, CPU = "#6b7a8f", "#1f4e79", "#2e7d5b"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--out", default="results/generated")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.results, "handshakes.csv"), newline="") as f:
        hs = {r["variant"]: r for r in csv.DictReader(f)}
    labels = [lab for _, lab in VARIANTS]
    up = [int(hs[k]["client_to_server_bytes"]) / 1000 for k, _ in VARIANTS]
    down = [int(hs[k]["server_to_client_bytes"]) / 1000 for k, _ in VARIANTS]
    cpu = [float(hs[k]["server_cpu_us_per_hs"]) for k, _ in VARIANTS]
    lo = [c - float(hs[k]["server_cpu_us_per_hs_min"]) for c, (k, _) in zip(cpu, VARIANTS)]
    hi = [float(hs[k]["server_cpu_us_per_hs_max"]) - c for c, (k, _) in zip(cpu, VARIANTS)]

    plt.rcParams.update({"font.size": 8, "font.family": "serif"})
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.0, 2.6))
    y = range(len(labels))
    ax1.barh(y, up, color=UP, label="client $\\to$ server")
    ax1.barh(y, down, left=up, color=DOWN, label="server $\\to$ client")
    for i, (u, d) in enumerate(zip(up, down)):
        ax1.text(u + d + 0.4, i, f"{u + d:.1f}", va="center")
    ax1.set_yticks(list(y), labels)
    ax1.invert_yaxis()
    ax1.set_xlabel("Handshake bytes (kB)")
    ax1.set_xlim(0, max(u + d for u, d in zip(up, down)) * 1.15)
    ax1.legend(frameon=False, loc="upper right")
    ax1.spines[["top", "right"]].set_visible(False)

    ax2.barh(y, cpu, color=CPU, xerr=[lo, hi], error_kw={"elinewidth": 0.8, "capsize": 2})
    for i, c in enumerate(cpu):
        ax2.text(c + hi[i] + 10, i, f"{c:.0f}", va="center")
    ax2.set_yticks(list(y), [""] * len(labels))
    ax2.invert_yaxis()
    ax2.set_xlabel("Server CPU per handshake ($\\mu$s, one core)")
    ax2.set_xlim(0, max(cpu) * 1.18)
    ax2.spines[["top", "right"]].set_visible(False)

    fig.tight_layout()
    for ext in ("pdf", "png"):
        meta = {"CreationDate": None} if ext == "pdf" else {"Software": None}
        fig.savefig(os.path.join(a.out, f"fig8.{ext}"), dpi=200, metadata=meta)
    print(f"wrote {a.out}/fig8.pdf")


if __name__ == "__main__":
    main()
