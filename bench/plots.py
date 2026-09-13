"""Figures for Phase 2, in the shape of the paper's Figs. 4 and 5.

    python -m bench.plots     (after python -m bench.report)

Reads ``bench/out/phase2.json`` so that plotting never re-runs the benchmark.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "out"

PAPER_TE, PAPER_TA, PAPER_TH = 0.112, 0.005, 0.004


def main(backend: str = "ristretto255") -> int:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    src = OUT / f"phase2_{backend}.json"
    if not src.exists():
        print(f"no results at {src}; run `python -m bench.report --backend {backend}` first")
        return 1
    d = json.loads(src.read_text())
    ns = d["sweep"]["n"]

    # -- Fig A: aggregate verification vs n (cf. the paper's Fig. 5) --------
    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    ax.plot(ns, d["sweep"]["cbas_ms"], "o-", label="Qiao et al. CBAS (measured)", lw=1.8)
    ax.plot(ns, d["sweep"]["verma_ms"], "s-", label="Verma et al. CB-CAS (measured)", lw=1.8)
    ax.plot(ns, d["sweep"]["ed25519_ms"], "^--", label="n x Ed25519 (no aggregation)",
            lw=1.4, alpha=0.75)

    sv = d["fits"]["verma"]["slope_ms_per_signer"]
    ax.plot(ns, [sv * n for n in ns], ":", color="crimson", lw=2.0,
            label="CBAS as Table III claims (= Verma)")

    ax.set_xlabel("number of signers, n")
    ax.set_ylabel("aggregate verification time (ms)")
    ax.set_title(f"Aggregate verification cost\n{d.get('backend', backend)}, steady clock")
    ax.legend(fontsize=8.5)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUT / f"fig_aggverify_vs_n_{backend}.png", dpi=150)
    plt.close(fig)

    # -- Fig B: the n=100 comparison (cf. the paper's Fig. 4) ---------------
    claimed = 102 * PAPER_TE + 101 * PAPER_TA + 200 * PAPER_TH
    actual = 202 * PAPER_TE + 300 * PAPER_TA + 300 * PAPER_TH

    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    labels = ["Table III\nas published", "Same Table IV costs,\nmeasured counts"]
    vals = [claimed, actual]
    bars = ax.bar(labels, vals, color=["#c9c9c9", "#2f6f9f"], width=0.55)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.4, f"{v:.3f} ms",
                ha="center", fontsize=10)
    ax.set_ylabel("aggregate verification time (ms)")
    ax.set_title(f"Aggregate verification at n = 100\n"
                 f"under the paper's own Table IV costs  (factor {actual / claimed:.2f})")
    ax.set_ylim(0, actual * 1.2)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUT / f"fig_n100_comparison_{backend}.png", dpi=150)
    plt.close(fig)

    # -- Fig C: measured vs predicted per-signer slope ----------------------
    fig, ax = plt.subplots(figsize=(6.8, 4.2))
    names = ["Verma\n(published =\nmeasured)", "CBAS\nas Table III\nclaims",
             "CBAS\npredicted from\nmeasured counts", "CBAS\nmeasured"]
    sc = d["fits"]["cbas"]["slope_ms_per_signer"] * 1000
    svv = d["fits"]["verma"]["slope_ms_per_signer"] * 1000
    prim = d["primitives_ms"]
    pred_claim = (prim["Te"] + prim["Ta"] + 2 * prim["Th"]) * 1000
    pred_true = (2 * prim["Te"] + 3 * prim["Ta"] + 3 * prim["Th"]) * 1000
    vals = [svv, pred_claim, pred_true, sc]
    colors = ["#7f7f7f", "#c9c9c9", "#8fb8d8", "#2f6f9f"]
    bars = ax.bar(names, vals, color=colors, width=0.6)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 3, f"{v:.0f}", ha="center", fontsize=10)
    ax.set_ylabel("per-signer slope (us)")
    ax.set_title("Per-signer cost: what the tables claim, what the counts\n"
                 "predict, and what the clock says")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUT / f"fig_slope_comparison_{backend}.png", dpi=150)
    plt.close(fig)

    for stem in ("fig_aggverify_vs_n", "fig_n100_comparison", "fig_slope_comparison"):
        print(f"  wrote {(OUT / f'{stem}_{backend}.png').relative_to(Path.cwd())}")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="ristretto255")
    raise SystemExit(main(ap.parse_args().backend))
