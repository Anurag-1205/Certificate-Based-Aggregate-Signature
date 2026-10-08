"""Quantitative figures for the deck, drawn only from verified data.

    .venv/bin/python presentation/build/make_figures.py

Inputs : presentation/data/claims.json  (written by audit/verify_claims.py)
Outputs: presentation/figures/*.png     (300 dpi; every figure carries its own source line)
"""
import json
import pathlib
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import theme as T  # noqa: E402

ROOT = HERE.parents[1]
FIG = ROOT / "presentation" / "figures"
FIG.mkdir(exist_ok=True)
C = json.loads((ROOT / "presentation" / "data" / "claims.json").read_text())
AUD = json.loads((ROOT / "presentation" / "data" / "audit_checks.json").read_text())

plt.rcParams.update({
    "font.family": "Carlito", "font.size": 15, "axes.edgecolor": T.MUTED, "axes.labelcolor": T.INK,
    "xtick.color": T.INK, "ytick.color": T.INK, "text.color": T.INK, "axes.spines.top": False,
    "axes.spines.right": False, "mathtext.fontset": "stix", "figure.dpi": 100, "savefig.dpi": 300,
    "axes.titlesize": 16, "axes.titleweight": "bold", "axes.titlelocation": "left",
})
GRAY = "#8A94A3"


def source(fig, text):
    import textwrap
    width = int(fig.get_figwidth() * 15.5)
    fig.text(0.012, 0.01, textwrap.fill(text, width), fontsize=10.5, color=T.MUTED, ha="left", va="bottom", linespacing=1.15)


def save(fig, name):
    fig.savefig(FIG / name, facecolor="white")
    plt.close(fig)
    print("wrote", (FIG / name).relative_to(ROOT))


# ------------------------------------------------------------------ 1. n = 100 bars (slide 24)
n100 = C["n100"]
fig, ax = plt.subplots(figsize=(5.7, 3.95))
fig.subplots_adjust(left=0.15, right=0.97, top=0.90, bottom=0.335)
labels = ["Paper's printed row\n(the bar in its Fig. 4)", "Recount of the paper's\nown equation"]
vals = [n100["printed_ms"], n100["recount_ms"]]
bars = ax.bar(labels, vals, color=[GRAY, T.INK], width=0.5)
for b, v in zip(bars, vals):
    ax.text(b.get_x() + b.get_width() / 2, v + 0.6, f"{v:.3f} ms", ha="center", fontsize=17, fontweight="bold")
ax.text(bars[1].get_x() + bars[1].get_width() / 2, vals[1] / 2, f"×{n100['factor']:.2f}", ha="center", color="white", fontsize=24, fontweight="bold")
ax.set_ylim(0, 31)
ax.set_ylabel("Aggregate verification (ms)")
ax.set_title("n = 100 signers, paper's Table IV unit costs")
ax.tick_params(axis="x", labelsize=12.5)
ax.grid(axis="y", alpha=0.25)
source(fig, "Source: paper Tables III–IV; recount from the implementation (audit/verify_claims.py). Model values, not measurements.")
save(fig, "fig_n100_bars.png")

# ------------------------------------------------------------------ 2. per-signer composition
fig, ax = plt.subplots(figsize=(5.6, 4.4))
fig.subplots_adjust(left=0.19, right=0.97, top=0.90, bottom=0.27)
te, ta, th = 112, 5, 4  # µs, Table IV
rows = {"Paper\n(1Te + 1Ta + 2Th)": (1, 1, 2), "Recount\n(2Te + 3Ta + 3Th)": (2, 3, 3)}
cols = {"Te": T.INK, "Ta": "#7F8A99", "Th": "#C3CAD4"}
x = np.arange(2)
bottom = np.zeros(2)
for key, unit in (("Te", te), ("Ta", ta), ("Th", th)):
    h = np.array([r[("Te", "Ta", "Th").index(key)] * unit for r in rows.values()], dtype=float)
    ax.bar(x, h, 0.5, bottom=bottom, color=cols[key], label=f"{key} = {unit} µs")
    bottom += h
tot = bottom
for i, t_ in enumerate(tot):
    ax.text(i, t_ + 6, f"{t_:.0f} µs", ha="center", fontsize=18, fontweight="bold")
ax.text(1, tot[1] / 2 - 10, "Te: 224 µs\nof 251", ha="center", color="white", fontsize=14.5)
ax.text(0, tot[0] / 2 - 10, "Te: 112 µs\nof 125", ha="center", color="white", fontsize=14.5)
ax.set_xticks(x, list(rows))
ax.set_ylim(0, 300)
ax.set_ylabel("Cost per signer (µs)")
ax.set_title("Per-signer verification cost")
ax.legend(frameon=False, fontsize=13.5, loc="upper left")
ax.grid(axis="y", alpha=0.25)
source(fig, "Source: paper Table IV unit costs × operation counts per signer (ratio 2.008). Model values.")
save(fig, "fig_per_signer.png")

# ------------------------------------------------------------------ 3. Fig. 5 recomputed
f5 = C["fig5_ms"]
fig, ax = plt.subplots(figsize=(7.0, 4.75))
fig.subplots_adjust(left=0.115, right=0.97, top=0.91, bottom=0.25)
ax.plot(f5["n"], f5["ours_printed"], "-o", color=GRAY, lw=2.4, ms=5, label="Qiao as printed (paper Fig. 5, \"Our CBAS scheme\")")
ax.plot(f5["n"], f5["ref6"], "-", color=T.VER, lw=5.5, alpha=0.35, label="Scheme [6] as printed (paper's row, not verified by us)")
ax.plot(f5["n"], f5["ours_recount"], "--", color=T.INK, lw=2.4, label="Qiao recounted from its algorithm")
ax.set_xlabel("Number of signers, n")
ax.set_ylabel("Aggregate verification (ms)")
ax.set_title("Paper's Fig. 5, recomputed from its own formulas")
ax.legend(frameon=False, fontsize=12.5, loc="upper left")
ax.grid(alpha=0.25)
source(fig, "Source: paper Tables III–IV formulas, n = 50 … 500 (step 30); recount from the implementation. Model values.")
save(fig, "fig_fig5_recomputed.png")

# ------------------------------------------------------------------ 4. measured vs n (Kaggle Xeon)
k = C["timing"]["kaggle_sweep"]
n = np.array(k["n"])
cb, vm = np.array(k["cbas_ms"]), np.array(k["verma_ms"])
fig, ax = plt.subplots(figsize=(6.0, 4.3))
fig.subplots_adjust(left=0.15, right=0.96, top=0.89, bottom=0.30)
ax.plot(n, cb, "o", color=T.INK, ms=8, label="Qiao CBAS (measured)")
ax.plot(n, vm, "s", color=GRAY, ms=8, label="Verma CB-CAS (measured)")
sc, sv = k["fits"]["cbas"]["slope_ms_per_signer"], k["fits"]["verma"]["slope_ms_per_signer"]
ic, iv = k["fits"]["cbas"]["intercept_ms"], k["fits"]["verma"]["intercept_ms"]
ax.plot(n, sc * n + ic, "-", color=T.INK, lw=1.6)
ax.plot(n, sv * n + iv, "-", color=GRAY, lw=1.6)
ax.plot(n, sv * n + ic, ":", color=T.BAD, lw=3, label="Qiao if its row equalled Verma's (Table III)")
ax.text(500, cb[-1] + 5, f"{sc*1000:.0f} µs / signer", ha="right", fontsize=13, fontweight="bold")
ax.text(500, vm[-1] + 5, f"{sv*1000:.0f} µs / signer", ha="right", fontsize=13.5, color="#5B6675", fontweight="bold")
ax.set_xlabel("Number of signers, n")
ax.set_ylabel("Aggregate verification time (ms)")
ax.set_title("Measured on one machine: ratio 2.12")
ax.set_xlim(40, 510)
ax.legend(frameon=False, fontsize=11.5, loc="upper left")
ax.grid(alpha=0.25)
source(fig, "Source: bench/results/sweep_kaggle-xeon.json — Xeon 2.2 GHz, Ristretto255/libsodium, n = 50 … 500 (10 points), median of 7 interleaved rounds.")
save(fig, "fig_measured_vs_n.png")

# ------------------------------------------------------------------ 5. ratio of all 11 runs
runs = C["timing"]["runs"]
groups = [("Ryzen 5 7520U\nRistretto255 (5 runs)", "Ryzen 5 7520U", "ristretto255"),
          ("Ryzen 5 7520U\nP-256 (5 runs)", "Ryzen 5 7520U", "p256"),
          ("Xeon 2.2 GHz (Kaggle)\nRistretto255 (1 run)", "Xeon 2.2 GHz (Kaggle)", "ristretto255")]
fig, ax = plt.subplots(figsize=(6.0, 4.3))
fig.subplots_adjust(left=0.15, right=0.96, top=0.89, bottom=0.33)
rng = np.random.default_rng(3)
bare = {0: C["timing"]["summary"]["ryzen_ristretto255"]["pred"], 1: C["timing"]["summary"]["ryzen_p256"]["pred"],
        2: C["timing"]["summary"]["kaggle_ristretto255"]["pred"]}
real_p256 = float(np.mean([r["real_hash"] for r in AUD["timing_model"]["p256"]]))
for i, (lab, mach, be) in enumerate(groups):
    ys = [r["ratio"] for r in runs if r["machine"] == mach and r["backend"] == be]
    ax.plot(i + rng.uniform(-0.08, 0.08, len(ys)), ys, "o", color=T.INK, ms=10, alpha=0.9, zorder=3,
            label="measured run" if i == 0 else None)
    ax.plot([i], [bare[i]], "D", color=T.AGG, ms=11, zorder=4, label="predicted from operation counts" if i == 0 else None)
ax.plot([1], [real_p256], "D", mfc="white", mec=T.AGG, mew=2.4, ms=11, zorder=4, label="… with real hash calls priced (audit)")
ax.axhline(1.0, color=T.BAD, lw=2.4)
ax.text(2.45, 1.05, "printed rows imply 1.00", color=T.BAD, ha="right", fontsize=13, fontweight="bold")
ax.set_xticks(range(3), [g[0] for g in groups], fontsize=11.5)
ax.set_xlim(-0.5, 2.5)
ax.set_ylim(0.8, 3.35)
ax.set_ylabel("Per-signer ratio, Qiao ÷ Verma")
ax.set_title("All 11 recorded runs: 1.99 – 2.48")
ax.legend(frameon=False, fontsize=11, loc="upper left", ncols=1)
ax.grid(axis="y", alpha=0.25)
source(fig, "Source: bench/results/sweep_ryzen5-7520u.json (10 runs), sweep_kaggle-xeon.json (1 run); real-hash prediction: audit/dagger_checks.py.")
save(fig, "fig_ratio_runs.png")
print("done")
