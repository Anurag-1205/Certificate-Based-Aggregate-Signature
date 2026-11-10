"""Price the real hash calls, not a bare hash, in the per-signer timing model.

The Te/Ta/Th model in ``bench.report`` charges every hash as one SHA-512 plus a
wide reduction. A real ``H1`` call also serialises its point arguments: CBAS
encodes 8 points per signer during verification, Verma 2
(``test_hash_inputs_encode_8_points_per_signer_against_vermas_2``). On P-256
via OpenSSL an encoding costs a modular inversion, so the bare model
undercounts CBAS more than Verma. On Ristretto255 encoding is nearly free.

    python -m bench.hashcost [--repeats 3]

Prints the predicted CBAS/Verma per-signer slope ratio under both models.
"""

from __future__ import annotations

import argparse
import hashlib

from cbas import verma
from cbas.backend import BACKENDS
from cbas.hashing import H0, H1

from .harness import measure_many, stabilize

RULE = "=" * 74


def predict(be) -> dict:
    k, j = be.scalar_random(), be.scalar_random()
    P, Q, T = be.point_mul_base(k), be.point_mul_base(j), be.point_mul_base(be.scalar_random())
    wide = bytes(range(64))
    m, ident, d = b"temp=21.5C;seq=7", b"sensor-0007", b"epoch-0"
    r = measure_many({
        "Te": lambda: be.point_mul(k, Q),
        "Ta": lambda: be.point_add(P, Q),
        "Th_bare": lambda: be.scalar_from_wide(hashlib.sha512(wide).digest()),
        "cbas_H0": lambda: H0(be, ident, P, Q),
        "cbas_H1": lambda: H1(be, m, P, Q, ident, T, d),
        "verma_H0": lambda: verma.H0(be, ident, P),
        "verma_H1": lambda: verma.H1(be, m, P, ident, d),
    }, rounds=9)
    te, ta, th = r["Te"].median_ms, r["Ta"].median_ms, r["Th_bare"].median_ms
    # Per signer: CBAS 2Te + 3Ta + H0 + H1 + H2 (H2 costs as H1); Verma Te + Ta + H0 + H1.
    cbas_hash = r["cbas_H0"].median_ms + 2 * r["cbas_H1"].median_ms
    verma_hash = r["verma_H0"].median_ms + r["verma_H1"].median_ms
    return {
        "bare": (2 * te + 3 * ta + 3 * th) / (te + ta + 2 * th),
        "real_hash": (2 * te + 3 * ta + cbas_hash) / (te + ta + verma_hash),
    }


def main(repeats: int = 3) -> int:
    print(RULE)
    print("  predicted per-signer slope ratio CBAS/Verma")
    print(RULE)
    for name in ("p256", "ristretto255"):
        be = BACKENDS[name]()
        runs = []
        for _ in range(repeats):
            stabilize(be, max_seconds=12, min_seconds=3)
            runs.append(predict(be))
        bare = ", ".join(f"{x['bare']:.3f}" for x in runs)
        real = ", ".join(f"{x['real_hash']:.3f}" for x in runs)
        print(f"  {name:<12} bare-hash model : {bare}")
        print(f"  {'':<12} real-hash model : {real}")
    print(RULE)
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repeats", type=int, default=3)
    raise SystemExit(main(ap.parse_args().repeats))
