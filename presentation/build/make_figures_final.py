"""Figures for the final deck, drawn only from verified data.

    .venv/bin/python presentation/build/make_figures_final.py

Input : presentation/data/claims_final.json  (written by audit/verify_claims_final.py)
Output: presentation/figures/final_*.png      (300 dpi, each with its own source line)

Series colours are the first two slots of the dataviz reference categorical palette,
validated on the white slide surface (lightness, chroma, CVD and contrast all pass).
"""
import json
import pathlib
import sys
import textwrap

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
C = json.loads((ROOT / "presentation" / "data" / "claims_final.json").read_text())
QIAO, VERMA = "#2a78d6", "#eb6834"

plt.rcParams.update({
    "font.family": "Carlito", "font.size": 15, "axes.edgecolor": T.MUTED, "axes.labelcolor": T.INK,
    "xtick.color": T.INK, "ytick.color": T.INK, "text.color": T.INK, "axes.spines.top": False,
    "axes.spines.right": False, "figure.dpi": 100, "savefig.dpi": 300,
    "axes.titlesize": 16, "axes.titleweight": "bold", "axes.titlelocation": "left",
})


def source(fig, text):
    fig.text(0.012, 0.01, textwrap.fill(text, int(fig.get_figwidth() * 15.5)), fontsize=10.5, color=T.MUTED,
             ha="left", va="bottom", linespacing=1.15)


# ------------------------------------------------------------------ optimisation, P-256
o = C["optimisation"]["p256"]["slopes"]
stages = [("naive", "As specified\n(one call per term)"), ("msm", "+ multi-scalar\nmultiplication"),
          ("prepared", "+ prepared\nsensor roster")]
q = np.array([o["cbas"][k] for k, _ in stages])
v = np.array([o["verma"][k] for k, _ in stages])
fig, ax = plt.subplots(figsize=(7.2, 4.6))
fig.subplots_adjust(left=0.12, right=0.98, top=0.86, bottom=0.27)
x = np.arange(3)
w = 0.34
bq = ax.bar(x - w / 2 - 0.01, q, w, color=QIAO, label="Qiao et al. (repaired CBAS)", edgecolor="white", linewidth=1.5)
bv = ax.bar(x + w / 2 + 0.01, v, w, color=VERMA, label="Verma et al. (CB-CAS)", edgecolor="white", linewidth=1.5)
for b, val in list(zip(bq, q)) + list(zip(bv, v)):
    ax.text(b.get_x() + b.get_width() / 2, val + 3, f"{val:.0f}", ha="center", fontsize=13.5, color=T.INK)
for i in range(3):
    ax.text(x[i], max(q[i], v[i]) + 24, f"ratio ×{q[i] / v[i]:.2f}", ha="center", fontsize=15, fontweight="bold",
            color=T.INK)
ax.set_xticks(x, [lab for _, lab in stages], fontsize=13)
ax.set_ylim(0, 215)
ax.set_ylabel("Aggregate verification, µs per signer")
ax.set_title("Same optimisations for both schemes, P-256 / OpenSSL")
ax.legend(frameon=False, fontsize=12.5, loc="upper right")
ax.grid(axis="y", alpha=0.25)
ax.set_axisbelow(True)
source(fig, f"Source: bench/results/optimization_p256.json (run {C['optimisation']['p256']['timestamp'][:10]}), "
            "slope of a linear fit over n = 50 … 500. Four runs: ratio 2.37–2.46 as specified, 2.95–3.07 fully optimised.")
fig.savefig(FIG / "final_optimisation.png", facecolor="white")
plt.close(fig)
print("wrote presentation/figures/final_optimisation.png")
