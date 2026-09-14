"""Phase 3: what aggregate verification costs when implemented well.

The paper's Tables II and III describe the naive algorithm, evaluating each term
of the verification equation separately. That is the right baseline for checking
the tables, and ``scheme.agg_verify`` keeps it. But it is not what a deployment
would run, and the interesting question is whether optimising changes the
conclusion.

Two optimisations are applied:

1. **Multi-scalar multiplication.** The verification equation is one fixed-base
   term plus a weighted sum of points, which OpenSSL evaluates in a single
   native call rather than one crossing of the ctypes boundary per term.
2. **A prepared roster.** An industrial deployment verifies repeated batches
   from a fixed set of sensors, so each signer's public key encoding,
   certificate-nonce encoding and ``h0`` hash are invariant and computed once.

Both schemes receive both optimisations. Optimising one and not the other would
produce a ratio that describes the implementations rather than the schemes.

    python -m bench.optimization
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from cbas import scheme as fixed
from cbas import verma
from cbas.backend import BACKENDS
from cbas.optimized import (
    MSM_TERMS,
    agg_verify_msm,
    agg_verify_prepared,
    prepare,
    verma_agg_verify_msm,
    verma_agg_verify_prepared,
    verma_prepare,
)

from .harness import Environment, cpu_policy, linfit, measure_many, stabilize
from .sweep import _build_fixed, _build_verma

RESULTS = Path(__file__).resolve().parent / "results"
NS = [50, 100, 200, 300, 400, 500]
RULE = "=" * 74


def main(backend: str = "p256", ns=None, rounds: int = 5) -> int:
    ns = ns or NS
    be = BACKENDS[backend]()
    env = Environment()

    print(RULE)
    print(f"  PHASE 3  optimised aggregate verification  [{be.name}]")
    print(RULE)
    print(env.render())
    print(f"  CPU policy   : {cpu_policy()}")
    print(f"  native MSM   : {be.has_native_msm}")
    print()

    if not be.has_native_msm:
        print("  This backend has no native multi-scalar routine, so the MSM path")
        print("  falls back to naive evaluation and will not be faster. The")
        print("  optimisation is a property of the library, not of the scheme.")
        print()

    stabilize(be)
    max_n = max(ns)
    fp, fsigners, fmessages, fsigs = _build_fixed(be, max_n)
    vp, vsigners, vmessages, vsigs = _build_verma(be, max_n)
    fprep_all = prepare(fp, fsigners)
    vprep_all = verma_prepare(vp, vsigners)

    tasks = {}
    for n in ns:
        fa = fixed.agg_sign(fp, fsigs[:n])
        va = verma.agg_sign(vp, vsigs[:n])
        S, M, PR = fsigners[:n], fmessages[:n], fprep_all[:n]
        VS, VM, VPR = vsigners[:n], vmessages[:n], vprep_all[:n]

        # Correctness before timing: a fast path that rejects valid signatures
        # is not worth measuring.
        assert fixed.agg_verify(fp, S, M, fa)
        assert agg_verify_msm(fp, S, M, fa)
        assert agg_verify_prepared(fp, PR, M, fa)
        assert verma.agg_verify(vp, VS, VM, va)
        assert verma_agg_verify_prepared(vp, VPR, VM, va)

        tasks[f"cbas_naive:{n}"] = lambda p=fp, s=S, m=M, a=fa: fixed.agg_verify(p, s, m, a)
        tasks[f"cbas_msm:{n}"] = lambda p=fp, s=S, m=M, a=fa: agg_verify_msm(p, s, m, a)
        tasks[f"cbas_prep:{n}"] = lambda p=fp, r=PR, m=M, a=fa: agg_verify_prepared(p, r, m, a)
        tasks[f"verma_naive:{n}"] = lambda p=vp, s=VS, m=VM, a=va: verma.agg_verify(p, s, m, a)
        tasks[f"verma_msm:{n}"] = lambda p=vp, s=VS, m=VM, a=va: verma_agg_verify_msm(p, s, m, a)
        tasks[f"verma_prep:{n}"] = lambda p=vp, r=VPR, m=VM, a=va: verma_agg_verify_prepared(p, r, m, a)

    r = measure_many(tasks, rounds=rounds)
    ms = lambda key, n: r[f"{key}:{n}"].median_ms
    slope = lambda key: linfit(ns, [ms(key, n) for n in ns])[0] * 1000

    print(f"  aggregate verification, ms      [{be.name}]")
    print()
    print(f"  {'n':>5} | {'CBAS naive':>10} {'+MSM':>8} {'+prepared':>10} | "
          f"{'Verma naive':>11} {'+MSM':>8} {'+prepared':>10}")
    for n in ns:
        print(f"  {n:>5} | {ms('cbas_naive', n):>10.3f} {ms('cbas_msm', n):>8.3f} "
              f"{ms('cbas_prep', n):>10.3f} | {ms('verma_naive', n):>11.3f} "
              f"{ms('verma_msm', n):>8.3f} {ms('verma_prep', n):>10.3f}")
    print()

    sc_n, sc_m, sc_p = slope("cbas_naive"), slope("cbas_msm"), slope("cbas_prep")
    sv_n, sv_m, sv_p = slope("verma_naive"), slope("verma_msm"), slope("verma_prep")

    print(RULE)
    print("  PER-SIGNER SLOPE (us)")
    print(RULE)
    print(f"  {'':<8} {'naive':>9} {'+MSM':>9} {'+prepared':>10} {'speedup':>9}")
    print(f"  {'CBAS':<8} {sc_n:>9.1f} {sc_m:>9.1f} {sc_p:>10.1f} {sc_n / sc_p:>8.2f}x")
    print(f"  {'Verma':<8} {sv_n:>9.1f} {sv_m:>9.1f} {sv_p:>10.1f} {sv_n / sv_p:>8.2f}x")
    print()

    print(RULE)
    print("  DOES OPTIMISING RESCUE THE PUBLISHED PARITY CLAIM?")
    print(RULE)
    print(f"    CBAS/Verma ratio, both naive      : {sc_n / sv_n:.3f}")
    print(f"    CBAS/Verma ratio, both optimised  : {sc_p / sv_p:.3f}")
    print( "    Tables II and III require         : 1.000")
    print()
    print( "    No. Verma's scheme optimises further, because its verification")
    print(f"    is a multi-scalar multiplication over n+2 terms against this")
    print( "    scheme's 3n+1, so the disparity grows rather than closing:")
    print(f"      MSM terms at n=500: CBAS {MSM_TERMS['cbas'](500)}, "
          f"Verma {MSM_TERMS['verma'](500)}  (ratio {MSM_TERMS['cbas'](500) / MSM_TERMS['verma'](500):.2f})")
    print(RULE)

    RESULTS.mkdir(exist_ok=True)
    payload = {
        "phase": 3,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "backend": be.name,
        "native_msm": be.has_native_msm,
        "environment": env.as_dict(),
        "n_values": ns,
        "timings_ms": {k: [ms(k, n) for n in ns]
                       for k in ("cbas_naive", "cbas_msm", "cbas_prep",
                                 "verma_naive", "verma_msm", "verma_prep")},
        "slopes_us_per_signer": {
            "cbas": {"naive": sc_n, "msm": sc_m, "prepared": sc_p},
            "verma": {"naive": sv_n, "msm": sv_m, "prepared": sv_p},
        },
        "ratio_naive": sc_n / sv_n,
        "ratio_optimised": sc_p / sv_p,
        "ratio_published_rows_require": 1.0,
        "msm_terms": {"cbas": MSM_TERMS["cbas"](max(ns)), "verma": MSM_TERMS["verma"](max(ns))},
    }
    path = RESULTS / f"optimization_{backend}.json"
    path.write_text(json.dumps(payload, indent=2))
    print(f"\n  written to {path.relative_to(Path.cwd())}")
    return 0


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="p256")
    ap.add_argument("--rounds", type=int, default=5)
    raise SystemExit(main(ap.parse_args().backend, rounds=ap.parse_args().rounds))
