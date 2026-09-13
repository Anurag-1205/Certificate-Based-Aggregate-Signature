"""Per-operation costs on this machine: the local equivalent of Table IV.

Qiao et al. report Te = 0.112, Ta = 0.005, Th = 0.004 ms on an Intel i5-4200H
using PBC-0.5.14.  Those figures are not directly comparable to ours: their
curve is a supersingular PBC Type-A curve at roughly 80-bit security over a
512-bit base field, while ours is Ristretto255 at 128-bit security.  Absolute
timings will differ; the point of measuring locally is to enable the
cross-check in ``report.py``, where operation counts are converted to predicted
times and compared against directly measured ones.
"""

from __future__ import annotations

from cbas.backend import BACKENDS, SodiumBackend

from .harness import Measurement, measure, measure_many, stabilize


def measure_primitives(be=None, stabilise: bool = True,
                       backend: str = "ristretto255") -> dict[str, Measurement]:
    """Measure Te, Ta, Th and Ts at a steady clock.

    Stabilisation is not optional in practice: on the test machine the
    per-operation cost falls by a factor of two once the core has ramped, so
    primitives measured cold are not comparable with sweep figures measured
    warm.
    """
    be = be or BACKENDS[backend]()
    if stabilise:
        stabilize(be)

    k = be.scalar_random()
    j = be.scalar_random()
    P = be.point_mul_base(k)
    Q = be.point_mul_base(j)
    wide = bytes(range(64))

    import hashlib

    def hash_to_scalar():
        be.scalar_from_wide(hashlib.sha512(wide).digest())

    return measure_many({
        "Te_base": lambda: be.point_mul_base(k),
        "Te": lambda: be.point_mul(k, Q),
        "Ta": lambda: be.point_add(P, Q),
        "Th": hash_to_scalar,
        "Ts": lambda: be.scalar_mul(k, j),
    }, rounds=9)


def costs_ms(prims: dict[str, Measurement]) -> tuple[float, float, float]:
    """The ``(Te, Ta, Th)`` triple used to convert operation counts to times."""
    return prims["Te"].median_ms, prims["Ta"].median_ms, prims["Th"].median_ms
