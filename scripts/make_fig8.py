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
    ("bp_ours_hybrid_ecdsa", "(b') hybrid, ours"),
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

    plt.rcParams.update({"font.size": 8, "font.family": "sans-serif",
                         "font.sans-serif": ["Helvetica", "Arial", "Liberation Sans", "DejaVu Sans"],
                         "mathtext.fontset": "dejavusans"})
    netem_path = os.path.join(a.results, "netem.csv")
    has_netem = os.path.exists(netem_path)
    if has_netem:
        fig = plt.figure(figsize=(7.0, 4.8))
        gs = fig.add_gridspec(2, 2, height_ratios=[1.0, 1.0])
        ax1, ax2 = fig.add_subplot(gs[0, 0]), fig.add_subplot(gs[0, 1])
        ax3 = fig.add_subplot(gs[1, :])
    else:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.0, 2.6))
    y = range(len(labels))
    ax1.barh(y, up, color=UP, label="client $\\to$ server")
    ax1.barh(y, down, left=up, color=DOWN, label="server $\\to$ client")
    for i, (u, d) in enumerate(zip(up, down)):
        ax1.text(u + d + 0.4, i, f"{u + d:.1f}", va="center")
    ax1.set_yticks(list(y), labels)
    ax1.invert_yaxis()
    ax1.set_xlabel("Handshake size (kB)")
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

    ax1.set_title("a", loc="left", fontsize=10, fontweight="bold")
    ax2.set_title("b", loc="left", fontsize=10, fontweight="bold")
    if has_netem:
        with open(netem_path, newline="") as f:
            rows = list(csv.DictReader(f))
        with open(os.path.join(a.results, "netem_env.csv"), newline="") as f:
            loss = {r["key"]: r["value"] for r in csv.DictReader(f)}["loss_pct_per_direction"]
        lines = [("a_tls13_classical", "(a) classical", "-", "o"), ("b_tls13_hybrid_kem", "(b) hybrid KEM", "-", "s"),
                 ("c_tls13_full_pq", "(c) fully PQ", "--", "^"), ("dit_warm", "DIT warm", "-", "D"),
                 ("dit_cold", "DIT cold", "--", "v")]
        rtts = sorted({float(r["rtt_ms"]) for r in rows})
        xs = list(range(len(rtts)))
        off = {k: (i - (len(lines) - 1) / 2) * 0.035 for i, (k, *_) in enumerate(lines)}
        for key, lab, ls, mk in lines:
            ys = [float(next(r for r in rows if r["variant"] == key and float(r["rtt_ms"]) == rt)["p50_in_rtts"])
                  for rt in rtts]
            ax3.plot([x + off[key] for x in xs], ys, ls, marker=mk, ms=4, lw=1.1, label=lab)
        for level in (2, 3):
            ax3.axhline(level, color="0.6", lw=0.6, ls=":", zorder=0)
        ax3.set_xticks(xs, [f"{r:g} ms" for r in rtts])
        ax3.set_xlim(-0.4, len(rtts) - 0.6)
        ax3.set_ylim(1.5, 4.0)
        ax3.set_yticks([2, 2.5, 3, 3.5])
        ax3.set_xlabel(f"Round-trip time (emulated, {float(loss):g}% loss per direction)")
        ax3.set_ylabel("Median handshake time (RTTs)")
        ax3.legend(frameon=False, ncol=5, loc="upper center", bbox_to_anchor=(0.5, 1.0))
        ax3.set_title("c", loc="left", fontsize=10, fontweight="bold")
        ax3.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    for ext in ("pdf", "png"):
        meta = {"CreationDate": None} if ext == "pdf" else {"Software": None}
        fig.savefig(os.path.join(a.out, f"fig8.{ext}"), dpi=200, metadata=meta)
    print(f"wrote {a.out}/fig8.pdf")


if __name__ == "__main__":
    main()
