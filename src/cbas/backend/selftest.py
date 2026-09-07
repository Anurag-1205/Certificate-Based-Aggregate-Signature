"""Standalone algebraic self-test for the group backend.

Run with ``python -m cbas.backend.selftest`` (or ``make selftest``).

This deliberately depends on nothing but the backend itself.  If these checks
do not pass, no result produced anywhere else in the project means anything --
so this is the first thing to run on a new machine, a new libsodium, or a new
backend.

The checks that matter most:

  * ``(l-1)*P + P == identity`` confirms the group really has the prime order we
    believe it has.  The scheme's algebra (and the Section IV forgery, which
    inverts a hash scalar) is only valid in a prime-order group.
  * the identity-handling checks pin down the libsodium ``-1`` return-code
    hazard documented in ``sodium.py``.
"""

from __future__ import annotations

import os
import sys
import traceback

from .base import InvalidPoint, InvalidScalar
from .counter import CountingBackend
from .sodium import RISTRETTO255_ORDER, SodiumBackend

_PASS, _FAIL = 0, 0
_FAILURES: list[str] = []


def check(name: str):
    def decorator(fn):
        global _PASS, _FAIL
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            _FAIL += 1
            _FAILURES.append(f"{name}: {exc}")
            print(f"  FAIL  {name}")
            print("        " + "\n        ".join(traceback.format_exc().splitlines()[-3:]))
        else:
            _PASS += 1
            print(f"  ok    {name}")
        return fn

    return decorator


def main() -> int:
    be = SodiumBackend()
    P = be.generator
    O = be.identity

    print(f"backend        : {be.name}")
    print(f"libsodium      : {be.libsodium_version}")
    print(f"group order    : {be.order}")
    print(f"order == 2^252 + 27742317777372353535851937790883648493: "
          f"{be.order == RISTRETTO255_ORDER}")
    print()
    print("group axioms")

    @check("generator is not the identity")
    def _():
        assert not be.point_is_identity(P)

    @check("P + O == P  (identity is neutral)")
    def _():
        assert be.point_eq(be.point_add(P, O), P)

    @check("P - P == O")
    def _():
        assert be.point_is_identity(be.point_sub(P, P))

    @check("addition is commutative")
    def _():
        a, b = be.scalar_random(), be.scalar_random()
        A, B = be.point_mul_base(a), be.point_mul_base(b)
        assert be.point_eq(be.point_add(A, B), be.point_add(B, A))

    @check("addition is associative")
    def _():
        a, b, c = (be.scalar_random() for _ in range(3))
        A, B, C = (be.point_mul_base(s) for s in (a, b, c))
        assert be.point_eq(
            be.point_add(be.point_add(A, B), C),
            be.point_add(A, be.point_add(B, C)),
        )

    print()
    print("scalar multiplication")

    @check("5*P == P+P+P+P+P  (scalar mult agrees with repeated addition)")
    def _():
        five = be.point_mul_base(be.scalar_from_int(5))
        acc = P
        for _ in range(4):
            acc = be.point_add(acc, P)
        assert be.point_eq(five, acc)

    @check("(a+b)*P == a*P + b*P  (distributive over scalar addition)")
    def _():
        a, b = be.scalar_random(), be.scalar_random()
        lhs = be.point_mul_base(be.scalar_add(a, b))
        rhs = be.point_add(be.point_mul_base(a), be.point_mul_base(b))
        assert be.point_eq(lhs, rhs)

    @check("(a*b)*P == a*(b*P)  (compatible with scalar multiplication)")
    def _():
        a, b = be.scalar_random(), be.scalar_random()
        lhs = be.point_mul_base(be.scalar_mul(a, b))
        rhs = be.point_mul(a, be.point_mul_base(b))
        assert be.point_eq(lhs, rhs)

    @check("point_mul(k, P) == point_mul_base(k)")
    def _():
        k = be.scalar_random()
        assert be.point_eq(be.point_mul(k, P), be.point_mul_base(k))

    @check("(-a)*P == -(a*P)")
    def _():
        a = be.scalar_random()
        lhs = be.point_mul_base(be.scalar_negate(a))
        rhs = be.point_sub(O, be.point_mul_base(a))
        assert be.point_eq(lhs, rhs)
        assert be.point_is_identity(be.point_add(lhs, be.point_mul_base(a)))

    print()
    print("prime order")

    @check("(l-1)*P + P == O  (the group order really is l)")
    def _():
        lm1 = be.scalar_from_int(RISTRETTO255_ORDER - 1)
        assert be.point_is_identity(be.point_add(be.point_mul_base(lm1), P))

    @check("(l-1)*P == -P")
    def _():
        lm1 = be.scalar_from_int(RISTRETTO255_ORDER - 1)
        assert be.point_eq(be.point_mul_base(lm1), be.point_sub(O, P))

    print()
    print("scalar field")

    @check("a * a^-1 == 1")
    def _():
        a = be.scalar_random()
        prod = be.scalar_mul(a, be.scalar_invert(a))
        assert be.scalar_to_int(prod) == 1, be.scalar_to_int(prod)

    @check("a^-1 * (a*P) == P")
    def _():
        a = be.scalar_random()
        assert be.point_eq(be.point_mul(be.scalar_invert(a), be.point_mul_base(a)), P)

    @check("inverting zero is rejected")
    def _():
        try:
            be.scalar_invert(be.scalar_from_int(0))
        except InvalidScalar:
            return
        raise AssertionError("expected InvalidScalar")

    @check("scalar_from_int / scalar_to_int round-trip")
    def _():
        for v in (0, 1, 2, 12345, RISTRETTO255_ORDER - 1):
            assert be.scalar_to_int(be.scalar_from_int(v)) == v

    @check("scalar_from_int reduces mod l")
    def _():
        assert be.scalar_to_int(be.scalar_from_int(RISTRETTO255_ORDER)) == 0
        assert be.scalar_to_int(be.scalar_from_int(RISTRETTO255_ORDER + 7)) == 7

    @check("wide reduction is deterministic and in range")
    def _():
        w = os.urandom(64)
        s1, s2 = be.scalar_from_wide(w), be.scalar_from_wide(w)
        assert s1 == s2
        assert 0 <= be.scalar_to_int(s1) < RISTRETTO255_ORDER

    print()
    print("identity handling (the libsodium -1 hazard)")

    @check("0*P == O  (libsodium returns -1 here; must not be an error)")
    def _():
        assert be.point_is_identity(be.point_mul_base(be.scalar_from_int(0)))

    @check("k*O == O  (libsodium returns -1 here too)")
    def _():
        assert be.point_is_identity(be.point_mul(be.scalar_random(), O))

    @check("a*P + (-a)*P == O via point_mul")
    def _():
        a = be.scalar_random()
        A = be.point_mul_base(a)
        negA = be.point_mul_base(be.scalar_negate(a))
        assert be.point_is_identity(be.point_add(A, negA))

    print()
    print("encoding and validation")

    @check("point encode/decode round-trip")
    def _():
        A = be.point_mul_base(be.scalar_random())
        assert be.point_eq(be.point_from_bytes(be.point_to_bytes(A)), A)

    @check("identity encodes and decodes")
    def _():
        assert be.point_is_identity(be.point_from_bytes(be.point_to_bytes(O)))

    @check("invalid point encoding is rejected")
    def _():
        try:
            be.point_from_bytes(b"\xff" * 32)
        except InvalidPoint:
            return
        raise AssertionError("expected InvalidPoint")

    @check("wrong-length point is rejected")
    def _():
        try:
            be.point_from_bytes(b"\x00" * 31)
        except InvalidPoint:
            return
        raise AssertionError("expected InvalidPoint")

    @check("non-canonical scalar (>= l) is rejected")
    def _():
        try:
            be.scalar_from_bytes((RISTRETTO255_ORDER).to_bytes(32, "little"))
        except InvalidScalar:
            return
        raise AssertionError("expected InvalidScalar")

    @check("scalar encode/decode round-trip")
    def _():
        s = be.scalar_random()
        assert be.scalar_from_bytes(be.scalar_to_bytes(s)) == s

    print()
    print("operation counter")

    @check("counter tallies Te / Ta / Th correctly")
    def _():
        cb = CountingBackend(SodiumBackend())
        with cb.count() as c:
            A = cb.point_mul_base(cb.scalar_random())   # 1 Te
            B = cb.point_mul(cb.scalar_random(), A)     # 1 Te
            cb.point_add(A, B)                          # 1 Ta
            cb.point_sub(A, B)                          # 1 Ta
            cb.note_hash(3)                             # 3 Th
        assert (c.Te, c.Ta, c.Th) == (2, 2, 3), (c.Te, c.Ta, c.Th)

    @check("counter blocks are independent")
    def _():
        cb = CountingBackend(SodiumBackend())
        with cb.count() as c1:
            cb.point_mul_base(cb.scalar_from_int(3))
        with cb.count() as c2:
            cb.point_add(cb.generator, cb.generator)
        assert (c1.Te, c1.Ta) == (1, 0)
        assert (c2.Te, c2.Ta) == (0, 1)

    @check("sum_points costs exactly n-1 Ta")
    def _():
        cb = CountingBackend(SodiumBackend())
        pts = [cb.point_mul_base(cb.scalar_from_int(i + 1)) for i in range(6)]
        with cb.count() as c:
            total = cb.sum_points(pts)
        assert c.Ta == 5, c.Ta
        assert c.Te == 0
        assert cb.point_eq(total, cb.point_mul_base(cb.scalar_from_int(21)))

    @check("OpCount.formula renders Table III-style expressions")
    def _():
        from .base import OpCount

        assert OpCount(Te=202, Ta=300, Th=300).formula(100) == "(2n+2)Te + 3nTa + 3nTh"
        assert OpCount(Te=102, Ta=101, Th=200).formula(100) == "(n+2)Te + (n+1)Ta + 2nTh"

    print()
    print("=" * 60)
    print(f"  {_PASS} passed, {_FAIL} failed")
    if _FAILURES:
        print()
        for f in _FAILURES:
            print(f"  - {f}")
    print("=" * 60)
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
