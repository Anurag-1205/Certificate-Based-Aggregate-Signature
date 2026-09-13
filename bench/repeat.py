"""Repeat the sweep several times per backend and report the spread.

A single sweep gives a point estimate; run-to-run variation on a laptop is not
negligible, so the claim should rest on a distribution rather than one number.
Writes a machine-readable summary to ``bench/results/`` for the record.

    python -m bench.repeat --repeats 3
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import time
from pathlib import Path

from cbas.backend import BACKENDS

from .harness import Environment, cpu_policy, linfit
from .ops import costs_ms, measure_primitives
from .sweep import DEFAULT_NS, run_sweep

RESULTS = Path(__file__).resolve().parent / "results"


def one_run(backend: str, ns) -> dict:
    prims = measure_primitives(backend=backend)
    te, ta, th = costs_ms(prims)
    sweep = run_sweep(ns, backend=backend)

    xs = [p.n for p in sweep.cbas]
    sc, _, r2c = linfit(xs, [p.agg_verify_ms for p in sweep.cbas])
    sv, _, r2v = linfit(xs, [p.agg_verify_ms for p in sweep.verma])

    pred_cbas = 2 * te + 3 * ta + 3 * th
    pred_verma = te + ta + 2 * th
    return {
        "slope_cbas_ms": sc, "slope_verma_ms": sv,
        "r2_cbas": r2c, "r2_verma": r2v,
        "ratio_measured": sc / sv,
        "ratio_predicted": pred_cbas / pred_verma,
        "primitives_ms": {"Te": te, "Ta": ta, "Th": th},
        "counts_checked": {
            "cbas": [sweep.cbas[-1].ops_Te, sweep.cbas[-1].ops_Ta, sweep.cbas[-1].ops_Th],
            "verma": [sweep.verma[-1].ops_Te, sweep.verma[-1].ops_Ta, sweep.verma[-1].ops_Th],
            "n": xs[-1],
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--backends", default="ristretto255,p256")
    ap.add_argument("--ns", default="", help="comma-separated n values")
    ap.add_argument("--tag", default="", help="label for the output file")
    args = ap.parse_args()

    ns = [int(x) for x in args.ns.split(",")] if args.ns else DEFAULT_NS
    backends = [b.strip() for b in args.backends.split(",")]
    env = Environment()

    print("=" * 74)
    print("  REPEATED SWEEPS")
    print("=" * 74)
    print(env.render())
    print(f"  CPU policy : {cpu_policy()}")
    print(f"  n values   : {ns}")
    print(f"  repeats    : {args.repeats} per backend")
    print()

    summary = {}
    for backend in backends:
        name = BACKENDS[backend]().name
        print(f"  {name}")
        runs = []
        for i in range(args.repeats):
            r = one_run(backend, ns)
            runs.append(r)
            print(f"    run {i + 1}: ratio {r['ratio_measured']:.3f}  "
                  f"(predicted {r['ratio_predicted']:.3f})  "
                  f"slopes {r['slope_cbas_ms'] * 1000:.1f} / {r['slope_verma_ms'] * 1000:.1f} us  "
                  f"r2 {min(r['r2_cbas'], r['r2_verma']):.5f}")

        # A poor linear fit means the run was perturbed (competing load, clock
        # movement). Such runs are reported but excluded from the headline
        # figure, rather than silently averaged in.
        MIN_R2 = 0.99
        clean = [r for r in runs if min(r["r2_cbas"], r["r2_verma"]) >= MIN_R2]
        dropped = len(runs) - len(clean)
        if dropped:
            print(f"    {dropped} run(s) excluded: linear fit r2 < {MIN_R2}")
        usable = clean or runs
        ratios = [r["ratio_measured"] for r in usable]
        preds = [r["ratio_predicted"] for r in usable]
        counts = runs[0]["counts_checked"]
        n = counts["n"]
        assert counts["cbas"] == [2 * n + 2, 3 * n, 3 * n], counts["cbas"]
        assert counts["verma"] == [n + 2, n + 1, 2 * n], counts["verma"]

        summary[backend] = {
            "backend_name": name,
            "runs": runs,
            "runs_used": len(usable),
            "runs_excluded_low_r2": dropped,
            "ratio_median": statistics.median(ratios),
            "ratio_min": min(ratios), "ratio_max": max(ratios),
            "ratio_predicted_median": statistics.median(preds),
            "counts_verified": True,
        }
        print(f"    median {statistics.median(ratios):.3f}  "
              f"range [{min(ratios):.3f}, {max(ratios):.3f}]  "
              f"predicted {statistics.median(preds):.3f}")
        print(f"    operation counts at n={n} verified: "
              f"CBAS (2n+2, 3n, 3n), Verma (n+2, n+1, 2n)")
        print()

    RESULTS.mkdir(exist_ok=True)
    tag = args.tag or platform.node().replace(".", "-")
    payload = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "environment": env.as_dict(),
        "cpu_policy": cpu_policy(),
        "n_values": ns,
        "repeats": args.repeats,
        "backends": summary,
    }
    path = RESULTS / f"sweep_{tag}.json"
    path.write_text(json.dumps(payload, indent=2))

    print("=" * 74)
    print("  VERDICT")
    print("=" * 74)
    for backend, d in summary.items():
        lo, hi = d["ratio_min"], d["ratio_max"]
        print(f"  {d['backend_name']:<24} ratio in [{lo:.3f}, {hi:.3f}], "
              f"published rows require 1.000 -> {'excluded' if lo > 1.3 else 'NOT excluded'}")
    print()
    print(f"  written to {path.relative_to(Path.cwd())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
