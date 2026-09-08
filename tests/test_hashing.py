"""H1 and H2 must be independent, or the scheme's third fix collapses."""

import pytest

from cbas.hashing import ALL_DSTS, DST_H0, DST_H1, DST_H2, H0, H1, H2


@pytest.fixture
def inputs(be):
    pk = be.point_mul_base(be.scalar_random())
    R = be.point_mul_base(be.scalar_random())
    T = be.point_mul_base(be.scalar_random())
    return dict(message=b"m", pk=pk, R=R, identity=b"sensor-1", T=T, delta=b"epoch-0")


def test_h1_and_h2_differ_on_identical_input(be, inputs):
    """The load-bearing test.

    The paper applies H1 and H2 to the *same* string.  If both were plain
    SHA-256 of that string, u == v and the certificate term and secret-key term
    would share a coefficient -- collapsing Fix #3 and invalidating the
    two-sided security reduction.  Domain separation is what prevents this.
    """
    v = H1(be, **inputs)
    u = H2(be, **inputs)
    assert u != v


def test_all_domain_tags_are_distinct():
    assert len(set(ALL_DSTS)) == len(ALL_DSTS)
    for dst in ALL_DSTS:
        assert dst.startswith(b"CBAS-")


def test_h0_differs_from_h1_and_h2(be, inputs):
    h0 = H0(be, inputs["identity"], inputs["pk"], inputs["R"])
    assert h0 != H1(be, **inputs)
    assert h0 != H2(be, **inputs)


def test_deterministic(be, inputs):
    assert H1(be, **inputs) == H1(be, **inputs)
    assert H2(be, **inputs) == H2(be, **inputs)
    assert H0(be, inputs["identity"], inputs["pk"], inputs["R"]) == H0(
        be, inputs["identity"], inputs["pk"], inputs["R"]
    )


@pytest.mark.parametrize("field", ["message", "identity", "delta"])
def test_sensitive_to_each_byte_field(be, inputs, field):
    base = H1(be, **inputs)
    altered = dict(inputs)
    altered[field] = inputs[field] + b"!"
    assert H1(be, **altered) != base


@pytest.mark.parametrize("field", ["pk", "R", "T"])
def test_sensitive_to_each_group_field(be, inputs, field):
    base = H1(be, **inputs)
    altered = dict(inputs)
    altered[field] = be.point_mul_base(be.scalar_random())
    assert H1(be, **altered) != base


def test_t_is_bound_into_both_hashes(be, inputs):
    """Fix #2: T must affect both v and u, or the Verma forgery survives."""
    v0, u0 = H1(be, **inputs), H2(be, **inputs)
    altered = dict(inputs)
    altered["T"] = be.point_mul_base(be.scalar_random())
    assert H1(be, **altered) != v0
    assert H2(be, **altered) != u0


def test_field_reordering_changes_the_hash(be, inputs):
    """TLV means swapping two fields of equal type is detectable."""
    swapped = dict(inputs)
    swapped["message"], swapped["identity"] = inputs["identity"], inputs["message"]
    assert H1(be, **swapped) != H1(be, **inputs)


def test_each_hash_counts_as_one_th(be, inputs):
    with be.count() as c:
        H1(be, **inputs)
    assert c.Th == 1
    with be.count() as c:
        H0(be, inputs["identity"], inputs["pk"], inputs["R"])
        H1(be, **inputs)
        H2(be, **inputs)
    assert c.Th == 3


def test_output_is_in_range(be, inputs):
    v = H1(be, **inputs)
    assert 0 < be.scalar_to_int(v) < be.order
