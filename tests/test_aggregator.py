"""Aggregator policy, pre-verification and fault localisation."""

import pytest

from cbas import scheme as fixed
from cbas.aggregator import (
    Aggregator,
    Policy,
    best_subbatch_size,
    locate_faults,
    subbatch_plan,
)
from cbas.optimized import prepare
from tests.test_scheme_roundtrip import enrol, sign_all


def _fleet(be, n):
    params, _, signers, secrets, messages = enrol(be, n)
    sigs = sign_all(params, signers, secrets, messages)
    return params, signers, messages, sigs


def _corrupt(be, sig):
    return fixed.Signature(T=sig.T, z=be.scalar_add(sig.z, be.scalar_from_int(1)))


def _run(params, signers, messages, sigs, policy):
    agg = Aggregator(params, signers, policy=policy)
    for s, m, g in zip(signers, messages, sigs):
        agg.submit(s, m, g)
    return agg.aggregate()


# -- the vulnerability -------------------------------------------------------

def test_blind_aggregation_lets_one_bad_signature_kill_the_batch(be):
    """The behaviour this module exists to address.

    Nothing is cryptographically wrong: the aggregate faithfully sums what it
    was given. But every honest sensor is denied service by one bad member.
    """
    params, signers, messages, sigs = _fleet(be, 10)
    sigs[4] = _corrupt(be, sigs[4])
    r = _run(params, signers, messages, sigs, Policy.BLIND)
    assert r.n == 10 and not r.rejected
    assert not fixed.agg_verify(params, r.signers, r.messages, r.aggregate)


def test_culprit_is_unrecoverable_from_the_aggregate_alone(be):
    """Why localisation needs the retained signatures.

    After summing, the individual z_i are gone; the aggregate carries no
    information about which contribution was wrong.
    """
    params, signers, messages, sigs = _fleet(be, 6)
    sigs[2] = _corrupt(be, sigs[2])
    r = _run(params, signers, messages, sigs, Policy.BLIND)
    assert set(vars(r.aggregate)) == {"T", "z"}
    assert len(r.aggregate.T) == 6      # only the commitments survive
    assert not isinstance(r.aggregate.z, (list, tuple))


# -- the mitigations ---------------------------------------------------------

@pytest.mark.parametrize("policy", [Policy.PREVERIFY, Policy.RETAIN])
@pytest.mark.parametrize("bad", [[], [0], [3], [0, 7], [1, 4, 8]])
def test_policies_isolate_exactly_the_bad_signatures(be, policy, bad):
    params, signers, messages, sigs = _fleet(be, 10)
    for i in bad:
        sigs[i] = _corrupt(be, sigs[i])
    r = _run(params, signers, messages, sigs, policy)
    assert sorted(r.rejected) == sorted(bad)
    assert r.n == 10 - len(bad)
    if r.aggregate is not None:
        assert fixed.agg_verify(params, r.signers, r.messages, r.aggregate)


@pytest.mark.parametrize("policy", [Policy.PREVERIFY, Policy.RETAIN])
def test_all_bad_yields_no_aggregate(be, policy):
    params, signers, messages, sigs = _fleet(be, 4)
    sigs = [_corrupt(be, s) for s in sigs]
    r = _run(params, signers, messages, sigs, policy)
    assert r.aggregate is None
    assert sorted(r.rejected) == [0, 1, 2, 3]


def test_clean_batch_is_untouched(be):
    params, signers, messages, sigs = _fleet(be, 8)
    for policy in Policy:
        r = _run(params, signers, messages, sigs, policy)
        assert r.ok and r.n == 8
        assert fixed.agg_verify(params, r.signers, r.messages, r.aggregate)


def test_retain_pays_nothing_extra_on_a_clean_batch(be):
    """The point of RETAIN: one aggregate verification when nothing is wrong."""
    params, signers, messages, sigs = _fleet(be, 16)
    r = _run(params, signers, messages, sigs, Policy.RETAIN)
    assert r.ok
    assert r.aggregate_verifications == 1
    assert r.single_verifications == 0


def test_preverify_costs_one_verification_per_submission(be):
    params, signers, messages, sigs = _fleet(be, 12)
    r = _run(params, signers, messages, sigs, Policy.PREVERIFY)
    assert r.single_verifications == 12


# -- localisation ------------------------------------------------------------

@pytest.mark.parametrize("bad", [[], [0], [5], [0, 5], [1, 2, 3], [0, 3, 6, 7]])
def test_locate_faults_finds_exactly_the_bad_indices(be, bad):
    params, signers, messages, sigs = _fleet(be, 8)
    for i in bad:
        sigs[i] = _corrupt(be, sigs[i])
    found = locate_faults(params, prepare(params, signers), messages, sigs)
    assert sorted(found) == sorted(bad)


def test_localisation_is_sublinear_for_a_single_fault(be):
    """One fault in 32 must cost far fewer than 32 verifications."""
    params, signers, messages, sigs = _fleet(be, 32)
    sigs[19] = _corrupt(be, sigs[19])
    counter = [0]
    found = locate_faults(params, prepare(params, signers), messages, sigs, counter)
    assert found == [19]
    assert counter[0] < 32, f"used {counter[0]} verifications for one fault in 32"


# -- roster discipline -------------------------------------------------------

def test_unknown_signer_is_refused(be):
    params, signers, messages, sigs = _fleet(be, 3)
    agg = Aggregator(params, signers)
    stranger = fixed.Signer(identity=b"not-enrolled", pk=signers[0].pk, R=signers[0].R)
    with pytest.raises(ValueError):
        agg.submit(stranger, b"m", sigs[0])


def test_empty_aggregation_is_benign(be):
    params, signers, _, _ = _fleet(be, 2)
    assert Aggregator(params, signers).aggregate().aggregate is None


def test_aggregator_uses_no_secret_material(be):
    """The security argument depends on this; policy must not change it."""
    import inspect

    src = inspect.getsource(Aggregator)
    for forbidden in ("msk", ".sk", "MasterSecretKey", "cert.c"):
        assert forbidden not in src, f"aggregator references {forbidden}"


# -- sub-batch model ---------------------------------------------------------

def test_subbatch_survival_matches_the_closed_form():
    p, k = 0.01, 50
    plan = subbatch_plan(500, p, k)
    assert plan["batch_survival_probability"] == pytest.approx((1 - p) ** k)
    assert plan["batches"] == 10


def test_smaller_batches_deliver_more_under_failures():
    big = subbatch_plan(500, 0.02, 500)
    small = subbatch_plan(500, 0.02, 25)
    assert small["expected_fraction_delivered"] > big["expected_fraction_delivered"]


def test_no_failures_means_batching_is_pointless():
    for k in (1, 50, 500):
        assert subbatch_plan(500, 0.0, k)["expected_fraction_delivered"] == pytest.approx(1.0)


def test_best_subbatch_size_shrinks_as_failures_rise():
    low = best_subbatch_size(500, 0.001)["k"]
    high = best_subbatch_size(500, 0.05)["k"]
    assert high <= low


@pytest.mark.parametrize("bad_rate", [-0.1, 1.0, 2.0])
def test_invalid_failure_rate_rejected(bad_rate):
    with pytest.raises(ValueError):
        subbatch_plan(100, bad_rate, 10)
