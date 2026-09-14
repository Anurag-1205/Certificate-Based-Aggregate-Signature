"""Phase 4: the cost of surviving a bad signature.

Aggregation destroys the information needed to attribute a failure. The three
policies in ``cbas.aggregator`` trade aggregator work against exposure, and this
measures that trade so the choice can be made on numbers rather than taste.

Reported as **cost per delivered signature**: total aggregator plus cloud work,
divided by the number of signatures that actually reach the cloud verified.
A policy that is cheap but delivers nothing under load scores badly, which is
the point.

    python -m bench.dos
"""

from __future__ import annotations

import json
import random
import time
from pathlib import Path

from cbas import scheme as fixed
from cbas.aggregator import Aggregator, Policy, best_subbatch_size, locate_faults
from cbas.backend import BACKENDS
from cbas.optimized import agg_verify_prepared, prepare

from .harness import Environment, measure_many, stabilize
from .sweep import _build_fixed

RESULTS = Path(__file__).resolve().parent / "results"
RULE = "=" * 74
FAULT_RATES = [0.0, 0.001, 0.005, 0.02, 0.05, 0.10]


def _corrupt(be, sig):
    return fixed.Signature(T=sig.T, z=be.scalar_add(sig.z, be.scalar_from_int(1)))


def main(backend: str = "p256", n: int = 200, trials: int = 5, seed: int = 7) -> int:
    be = BACKENDS[backend]()
    env = Environment()
    rng = random.Random(seed)

    print(RULE)
    print(f"  PHASE 4  aggregator policy under faults  [{be.name}]")
    print(RULE)
    print(env.render())
    print(f"  batch size n : {n}")
    print()

    stabilize(be)
    params, signers, messages, sigs = _build_fixed(be, n)
    prepared = prepare(params, signers)
    agg_all = fixed.agg_sign(params, sigs)

    # Unit costs, measured rather than assumed.
    one = fixed.AggregateSignature(T=(sigs[0].T,), z=sigs[0].z)
    units = measure_many({
        "single": lambda: agg_verify_prepared(params, prepared[:1], messages[:1], one),
        "aggregate": lambda: agg_verify_prepared(params, prepared, messages, agg_all),
    }, rounds=7)
    c_single = units["single"].median_ms
    c_agg = units["aggregate"].median_ms

    print("  unit costs")
    print(f"    one signature, verified individually : {c_single:8.4f} ms")
    print(f"    {n} signatures, verified as an aggregate: {c_agg:8.4f} ms "
          f"({c_agg / n:.4f} ms per signature)")
    print(f"    individual verification is {c_single / (c_agg / n):.1f}x dearer per signature")
    print()
    print("    This gap is why locating faults by divide and conquer beats")
    print("    checking every signature: a clean range of any size costs one")
    print("    aggregate verification.")
    print()

    print(RULE)
    print("  COST PER DELIVERED SIGNATURE (ms), by policy and fault rate")
    print(RULE)
    print(f"  {'fault rate':>11} {'faults':>7} | {'BLIND':>18} {'PREVERIFY':>12} {'RETAIN':>12}")

    rows = []
    for rate in FAULT_RATES:
        totals = {p_: 0.0 for p_ in Policy}
        delivered = {p_: 0 for p_ in Policy}
        faults_seen = 0

        for _ in range(trials):
            bad = {i for i in range(n) if rng.random() < rate}
            faults_seen += len(bad)
            batch = [_corrupt(be, s_) if i in bad else s_ for i, s_ in enumerate(sigs)]
            good = n - len(bad)

            # BLIND: the aggregator does nothing; the cloud pays one aggregate
            # verification and receives nothing at all if any signature is bad.
            totals[Policy.BLIND] += c_agg
            delivered[Policy.BLIND] += good if not bad else 0

            # PREVERIFY and RETAIN: measure the aggregator directly rather than
            # modelling it, then add the cloud's aggregate verification.
            for policy in (Policy.PREVERIFY, Policy.RETAIN):
                a = Aggregator(params, signers, policy=policy)
                for sg, m, g in zip(signers, messages, batch):
                    a.submit(sg, m, g)
                t0 = time.perf_counter()
                r = a.aggregate()
                totals[policy] += (time.perf_counter() - t0) * 1000
                if r.aggregate is not None:
                    totals[policy] += c_agg
                delivered[policy] += r.n

        def per(policy):
            d = delivered[policy]
            return totals[policy] / d if d else float("inf")

        b, pre, ret = per(Policy.BLIND), per(Policy.PREVERIFY), per(Policy.RETAIN)
        rows.append({"fault_rate": rate, "mean_faults": faults_seen / trials,
                     "blind": b, "preverify": pre, "retain": ret})
        bs = "inf (batch lost)" if b == float("inf") else f"{b:.4f}"
        best = min(("PREVERIFY", pre), ("RETAIN", ret), key=lambda t: t[1])[0]
        print(f"  {rate:>11.3f} {faults_seen / trials:>7.1f} | {bs:>18} "
              f"{pre:>12.4f} {ret:>12.4f}   {best}")

    print()
    print(RULE)
    print("  SUB-BATCHING UNDER BLIND AGGREGATION")
    print(RULE)
    print("  If the aggregator cannot verify at all, splitting bounds the blast")
    print("  radius, at the cost of more aggregates to check. Costs below use")
    print("  this backend's measured fixed and per-signature verification cost,")
    print("  so the optimum is an interior one rather than 'abandon aggregation'.")
    print()
    from cbas.aggregator import subbatch_plan

    # Split the measured aggregate cost into a fixed part and a per-signature
    # part, so the model reflects this implementation rather than a guess.
    per_sig = (c_agg - c_single) / max(n - 1, 1)
    fixed_part = max(c_agg - n * per_sig, 0.0)
    print(f"  cost model: verify(k) = {fixed_part:.4f} + k x {per_sig:.4f} ms")
    print()
    ks = (10, 25, 50, 100, 500)
    print(f"  {'fault rate':>11} | " + " ".join(f"k={k:<7}" for k in ks) + "  best k")
    sub_rows = []
    for rate in (0.001, 0.005, 0.02, 0.05, 0.10):
        cells = [f"{subbatch_plan(500, rate, k, fixed_part, per_sig)['cost_per_delivered']:.4f}"
                 for k in ks]
        best = best_subbatch_size(500, rate, cost_fixed=fixed_part,
                                  cost_per_signature=per_sig)
        sub_rows.append({"rate": rate, "best_k": best["k"],
                         "cost_per_delivered": best["cost_per_delivered"],
                         "fraction_delivered": best["expected_fraction_delivered"]})
        print(f"  {rate:>11.3f} | " + " ".join(f"{c:<9}" for c in cells) +
              f"  {best['k']:>3} ({best['cost_per_delivered']:.4f} ms, "
              f"{best['expected_fraction_delivered']:.1%} delivered)")

    print()
    print(RULE)
    print("  CONCLUSION")
    print(RULE)
    print("  BLIND is the paper's model and is untenable at any nonzero fault")
    print("  rate: one bad signature costs the whole batch, and the culprit")
    print("  cannot be identified from the aggregate.")
    print()
    print("  RETAIN dominates PREVERIFY whenever faults are rare, because a")
    print("  clean batch costs one aggregate verification instead of n")
    print(f"  individual ones ({c_single / (c_agg / n):.0f}x dearer per signature).")
    print()
    print("  PREVERIFY is preferable when faults are common enough that")
    print("  localisation runs often, and when the aggregator must guarantee")
    print("  the cloud never sees a failing aggregate.")
    print(RULE)

    RESULTS.mkdir(exist_ok=True)
    payload = {
        "phase": 4, "backend": be.name, "n": n, "trials": trials,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "environment": env.as_dict(),
        "unit_cost_ms": {"single_verify": c_single, "aggregate_verify": c_agg,
                         "per_signature_in_aggregate": c_agg / n},
        "policy_rows": rows,
        "subbatch": sub_rows,
    }
    path = RESULTS / f"dos_{backend}.json"
    path.write_text(json.dumps(payload, indent=2))
    print(f"\n  written to {path.relative_to(Path.cwd())}")
    return 0


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="p256")
    ap.add_argument("-n", type=int, default=200)
    a = ap.parse_args()
    raise SystemExit(main(a.backend, a.n))
