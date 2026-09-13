"""Property-based checks on the group backend.

The standalone ``python -m cbas.backend.selftest`` covers the same ground
without needing pytest (run it first on a new machine).  This file adds
randomised property testing on top.
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cbas.backend import (
    P256_ORDER,
    RISTRETTO255_ORDER,
    InvalidPoint,
    InvalidScalar,
    OpenSSLBackend,
    SodiumBackend,
)

# Scalars are generated in a range valid for every backend, then reduced.
scalars = st.integers(min_value=0, max_value=2**250)


def test_group_order_is_the_documented_prime(raw_backend):
    expected = {
        "ristretto255/libsodium": RISTRETTO255_ORDER,
        "p256/openssl": P256_ORDER,
    }[raw_backend.name]
    assert raw_backend.order == expected


def test_order_is_prime(raw_backend):
    """A cheap Miller-Rabin: the scheme's algebra requires prime order."""
    n = raw_backend.order
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            pytest.fail(f"composite witness {a}")


@given(a=scalars, b=scalars)
@settings(max_examples=50, deadline=None)
def test_distributive_over_scalar_addition(raw_backend, a, b):
    be = raw_backend
    sa, sb = be.scalar_from_int(a), be.scalar_from_int(b)
    lhs = be.point_mul_base(be.scalar_add(sa, sb))
    rhs = be.point_add(be.point_mul_base(sa), be.point_mul_base(sb))
    assert be.point_eq(lhs, rhs)


@given(a=scalars, b=scalars)
@settings(max_examples=50, deadline=None)
def test_scalar_mul_compatibility(raw_backend, a, b):
    be = raw_backend
    sa, sb = be.scalar_from_int(a), be.scalar_from_int(b)
    lhs = be.point_mul_base(be.scalar_mul(sa, sb))
    rhs = be.point_mul(sa, be.point_mul_base(sb))
    assert be.point_eq(lhs, rhs)


@given(a=st.integers(min_value=1, max_value=2**250))
@settings(max_examples=50, deadline=None)
def test_inverse_roundtrip(raw_backend, a):
    be = raw_backend
    sa = be.scalar_from_int(a % be.order or 1)
    assert be.point_eq(be.point_mul(be.scalar_invert(sa), be.point_mul_base(sa)), be.generator)


@given(v=scalars)
@settings(max_examples=50, deadline=None)
def test_scalar_int_roundtrip(raw_backend, v):
    v %= raw_backend.order
    assert raw_backend.scalar_to_int(raw_backend.scalar_from_int(v)) == v


@given(v=scalars)
@settings(max_examples=50, deadline=None)
def test_point_encoding_roundtrip(raw_backend, v):
    be = raw_backend
    P = be.point_mul_base(be.scalar_from_int(v))
    assert be.point_eq(be.point_from_bytes(be.point_to_bytes(P)), P)


def test_identity_results_are_not_errors(raw_backend):
    """libsodium returns -1 for these; they are legitimate group elements."""
    be = raw_backend
    assert be.point_is_identity(be.point_mul_base(be.scalar_from_int(0)))
    assert be.point_is_identity(be.point_mul(be.scalar_random(), be.identity))
    a = be.scalar_random()
    assert be.point_is_identity(
        be.point_add(be.point_mul_base(a), be.point_mul_base(be.scalar_negate(a)))
    )


def test_prime_order_via_scalar_wraparound(raw_backend):
    be = raw_backend
    lm1 = be.scalar_from_int(be.order - 1)
    assert be.point_is_identity(be.point_add(be.point_mul_base(lm1), be.generator))


@pytest.mark.parametrize("bad", [b"\xff" * 32, b"\x01" * 32, b"\x02" * 31, b"\x09" * 40])
def test_invalid_points_rejected(raw_backend, bad):
    with pytest.raises(InvalidPoint):
        raw_backend.point_from_bytes(bad)


def test_non_canonical_scalar_rejected(raw_backend):
    endian = "little" if isinstance(raw_backend, SodiumBackend) else "big"
    with pytest.raises(InvalidScalar):
        raw_backend.scalar_from_bytes(raw_backend.order.to_bytes(32, endian))


def test_inverting_zero_rejected(raw_backend):
    with pytest.raises(InvalidScalar):
        raw_backend.scalar_invert(raw_backend.scalar_from_int(0))


def test_sum_points_costs_n_minus_1_additions(be):
    pts = [be.point_mul_base(be.scalar_from_int(i + 1)) for i in range(7)]
    with be.count() as c:
        total = be.sum_points(pts)
    assert (c.Te, c.Ta) == (0, 6)
    assert be.point_eq(total, be.point_mul_base(be.scalar_from_int(28)))


def test_counting_backend_matches_raw_backend(raw_backend):
    """Counting must not change results."""
    from cbas.backend import CountingBackend

    cb = CountingBackend(raw_backend)
    k = cb.scalar_from_int(123456789)
    assert cb.point_to_bytes(cb.point_mul_base(k)) == raw_backend.point_to_bytes(
        raw_backend.point_mul_base(raw_backend.scalar_from_int(123456789))
    )


def test_backends_are_structurally_independent(raw_backend):
    """The two backends are genuinely different groups, not aliases."""
    assert raw_backend.name in {"ristretto255/libsodium", "p256/openssl"}
    if raw_backend.name == "p256/openssl":
        assert raw_backend.point_bytes == 33
        assert raw_backend.order != RISTRETTO255_ORDER
    else:
        assert raw_backend.point_bytes == 32
        assert raw_backend.order != P256_ORDER
