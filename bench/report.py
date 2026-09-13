"""Phase 2 analysis: measured timings against the published cost expressions.

The operation counter established that aggregate verification costs
``(2n+2)Te + 3nTa + 3nTh`` where Tables II and III report
``(n+2)Te + (n+1)Ta + 2nTh``.  That result depends on one instrument and one
counting model.  This module supplies a second, independent line of evidence:
direct wall-clock timing.

The decisive quantity is the **slope ratio** between the two schemes.  If the
published rows were right, both schemes would have identical per-signer costs
and the ratio would be 1.  If the measured counts are right, the ratio should
sit near 2.  Slopes are used rather than absolute times because they are
insensitive to the fixed per-call overhead of Python and ctypes, and because
absolute times are not comparable with the paper's in any case: its curve is a
PBC Type-A curve at roughly 80-bit security, ours is Ristretto255 at 128-bit.

    python -m bench.report
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from .harness import Environment, cpu_policy, linfit
from .ops import costs_ms, measure_primitives
from .sweep import DEFAULT_NS, run_sweep

OUT = Path(__file__).resolve().parent / "out"

# The paper's Table IV costs, for reference only.
PAPER_TE, PAPER_TA, PAPER_TH = 0.112, 0.005, 0.004

RULE = "=" * 74


def _slope_from_counts(per_signer_te, per_signer_ta, per_signer_th, te, ta, th) -> float:
    return per_signer_te * te + per_signer_ta * ta + per_signer_th * th


def main(backend: str = "ristretto255") -> int:
    from cbas.backend import BACKENDS

    env = Environment()
    print(RULE)
    print(f"  PHASE 2  aggregate verification cost, measured  [{BACKENDS[backend]().name}]")
    print(RULE)
    print(env.render())
    print(f"  CPU policy : {cpu_policy()}")
    print()

    print("  measuring primitive operations at a steady clock ...")
    prims = measure_primitives(backend=backend)
    te, ta, th = costs_ms(prims)
    print()
    for key in ("Te", "Te_base", "Ta", "Th", "Ts"):
        m = prims[key]
        print(f"    {m.label:<32} {m.median_ms:8.5f} ms   (IQR {m.iqr_ms:.5f})")
    print()
    print(f"    ratio Ta/Te = {ta / te:.3f}   (paper's Table IV: {PAPER_TA / PAPER_TE:.3f})")
    print( "    point addition is relatively dearer here because each call")
    print( "    marshals buffers through ctypes; this inflates Ta and Th")
    print( "    equally for both schemes and cancels in the ratio below.")
    print()

    print("  running interleaved sweep ...")
    sweep = run_sweep(DEFAULT_NS, backend=backend)
    s = sweep.stabilisation
    print(f"    stabilisation: converged={s['converged']} in {s['seconds']:.1f}s, "
          f"steady reference {s['reference_ms']:.5f} ms")
    first, last = s["history"][0], s["reference_ms"]
    print(f"    clock ramped {first / last:.2f}x during warm-up "
          f"({first:.4f} -> {last:.4f} ms per scalar multiplication)")
    print()

    ns = [p.n for p in sweep.cbas]
    cbas_ms = [p.agg_verify_ms for p in sweep.cbas]
    verma_ms = [p.agg_verify_ms for p in sweep.verma]
    ed_ms = [t for _, t in sweep.ed25519]

    print(f"  {'n':>5}  {'CBAS ms':>10}  {'Verma ms':>10}  {'Ed25519 ms':>11}  {'CBAS/Verma':>11}")
    for i, n in enumerate(ns):
        print(f"  {n:>5}  {cbas_ms[i]:>10.3f}  {verma_ms[i]:>10.3f}  {ed_ms[i]:>11.3f}  "
              f"{cbas_ms[i] / verma_ms[i]:>11.3f}")
    print()

    sc, ic, r2c = linfit(ns, cbas_ms)
    sv, iv, r2v = linfit(ns, verma_ms)
    se, ie, r2e = linfit(ns, ed_ms)

    print(RULE)
    print("  LINEAR FIT  (per-signer slope is the robust quantity)")
    print(RULE)
    print(f"    CBAS    {sc * 1000:8.3f} us/signer   intercept {ic:7.3f} ms   r2 = {r2c:.6f}")
    print(f"    Verma   {sv * 1000:8.3f} us/signer   intercept {iv:7.3f} ms   r2 = {r2v:.6f}")
    print(f"    Ed25519 {se * 1000:8.3f} us/signature intercept {ie:7.3f} ms   r2 = {r2e:.6f}")
    print()
    print(f"    measured slope ratio CBAS/Verma = {sc / sv:.3f}")
    print()

    # -- cross-check: counts x measured primitive costs vs measured timing --
    print(RULE)
    print("  CROSS-CHECK  operation counts against wall-clock")
    print(RULE)
    pred_true = _slope_from_counts(2, 3, 3, te, ta, th)       # measured counts
    pred_claim = _slope_from_counts(1, 1, 2, te, ta, th)      # the published row
    pred_verma = _slope_from_counts(1, 1, 2, te, ta, th)      # Verma, published = measured

    print("    predicted per-signer slope, from counts x measured primitive costs:")
    print(f"      CBAS, measured counts   2Te + 3Ta + 3Th = {pred_true * 1000:7.3f} us")
    print(f"      CBAS, published row      Te +  Ta + 2Th = {pred_claim * 1000:7.3f} us")
    print(f"      Verma, published row     Te +  Ta + 2Th = {pred_verma * 1000:7.3f} us")
    print()
    r_pred = pred_true / pred_verma
    r_meas = sc / sv
    print(f"    predicted ratio from measured counts  : {r_pred:.3f}")
    print( "    predicted ratio from published rows   : 1.000")
    print(f"    measured ratio                        : {r_meas:.3f}")
    print()

    overhead_cbas = sc - pred_true
    overhead_verma = sv - pred_verma
    print(f"    per-signer cost not covered by the Te/Ta/Th model:")
    print(f"      CBAS  {overhead_cbas * 1000:7.3f} us  ({overhead_cbas / sc * 100:.0f}% of measured)")
    print(f"      Verma {overhead_verma * 1000:7.3f} us  ({overhead_verma / sv * 100:.0f}% of measured)")
    print( "    This is Python loop, TLV encoding and attribute access. It is not")
    print( "    equal between the schemes: CBAS hashes three times per signer to")
    print( "    Verma's two, and multiplies two points to Verma's one, so the")
    print( "    interpreter does more work per signer for CBAS. Where the group")
    print( "    operations themselves are cheap, this pushes the measured ratio")
    print( "    above the ratio the operation counts alone predict.")
    print()

    # Which hypothesis does the measurement support?
    d_counts = abs(r_meas - r_pred)
    d_rows = abs(r_meas - 1.0)
    print( "    competing hypotheses for the per-signer ratio:")
    print(f"      published rows say 1.000  -> off by {d_rows:.3f}")
    print(f"      measured counts say {r_pred:.3f}  -> off by {d_counts:.3f}")
    if d_counts < d_rows:
        print(f"    the measurement favours the measured counts by {d_rows / max(d_counts, 1e-9):.1f}x")
    else:  # pragma: no cover
        print( "    the measurement favours the published rows")
    print()
    print(f"    measured ratio is >= 1.5   : {r_meas >= 1.5}   (published rows require 1.000)")
    print()

    # -- what the paper's own Table IV costs would give ---------------------
    print(RULE)
    print("  UNDER THE PAPER'S OWN TABLE IV COSTS, n = 100")
    print(RULE)
    claimed = 102 * PAPER_TE + 101 * PAPER_TA + 200 * PAPER_TH
    actual = 202 * PAPER_TE + 300 * PAPER_TA + 300 * PAPER_TH
    print(f"    published expression  (n+2)Te + (n+1)Ta + 2nTh = {claimed:7.3f} ms")
    print(f"    measured counts      (2n+2)Te + 3nTa  + 3nTh   = {actual:7.3f} ms")
    print(f"    factor                                          {actual / claimed:7.3f}")
    print(f"    Fig. 4 of the paper plots {claimed:.3f} ms, so it was derived")
    print( "    from Table III and carries the same discrepancy.")
    print(RULE)

    OUT.mkdir(exist_ok=True)
    payload = {
        "backend": BACKENDS[backend]().name,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "environment": env.as_dict(),
        "cpu_policy": cpu_policy(),
        "stabilisation": {k: v for k, v in sweep.stabilisation.items() if k != "history"},
        "primitives_ms": {k: m.median_ms for k, m in prims.items()},
        "sweep": {
            "n": ns,
            "cbas_ms": cbas_ms,
            "verma_ms": verma_ms,
            "ed25519_ms": ed_ms,
            "cbas_ops": [[p.ops_Te, p.ops_Ta, p.ops_Th] for p in sweep.cbas],
            "verma_ops": [[p.ops_Te, p.ops_Ta, p.ops_Th] for p in sweep.verma],
        },
        "fits": {
            "cbas": {"slope_ms_per_signer": sc, "intercept_ms": ic, "r2": r2c},
            "verma": {"slope_ms_per_signer": sv, "intercept_ms": iv, "r2": r2v},
            "ed25519": {"slope_ms_per_signature": se, "intercept_ms": ie, "r2": r2e},
        },
        "slope_ratio_measured": sc / sv,
        "overhead_per_signer_ms": {"cbas": sc - pred_true, "verma": sv - pred_verma},
        "predicted_slope_ms": {"cbas_counts": pred_true, "published_row": pred_claim},
        "slope_ratio_predicted_from_counts": pred_true / pred_verma,
        "slope_ratio_predicted_from_published_rows": 1.0,
    }
    path = OUT / f"phase2_{backend}.json"
    path.write_text(json.dumps(payload, indent=2))
    print(f"\n  raw results written to {path.relative_to(Path.cwd())}")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="ristretto255",
                    help="group backend: ristretto255 (libsodium) or p256 (openssl)")
    raise SystemExit(main(ap.parse_args().backend))
