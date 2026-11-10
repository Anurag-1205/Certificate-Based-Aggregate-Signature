"""Optimised aggregate verification must agree with the reference exactly.

An optimisation that changes which signatures are accepted is not an
optimisation, so every fast path here is checked against the transliterated
reference in ``scheme.py`` -- on both backends, for valid signatures and for
each kind of tampering.
"""

import pytest

from cbas import scheme as fixed
from cbas import verma
from cbas.optimized import (
    MSM_TERMS,
    PreparedSigner,
    agg_verify_msm,
    agg_verify_prepared,
    prepare,
    verify_single_msm,
    verma_agg_verify_msm,
    verma_agg_verify_prepared,
    verma_prepare,
)
from tests.test_scheme_roundtrip import enrol, sign_all
from tests.test_verma import enrol as verma_enrol
from tests.test_verma import sign_all as verma_sign_all


def _cbas(be, n):
    params, _, signers, secrets, messages = enrol(be, n)
    agg = fixed.agg_sign(params, sign_all(params, signers, secrets, messages))
    return params, signers, messages, agg


def _verma(be, n):
    params, _, signers, secrets, messages = verma_enrol(be, n)
    agg = verma.agg_sign(params, verma_sign_all(params, signers, secrets, messages))
    return params, signers, messages, agg


# -- agreement with the reference -------------------------------------------

@pytest.mark.parametrize("n", [1, 2, 3, 9, 31])
def test_msm_agrees_with_naive(be, n):
    params, signers, messages, agg = _cbas(be, n)
    assert fixed.agg_verify(params, signers, messages, agg)
    assert agg_verify_msm(params, signers, messages, agg)


@pytest.mark.parametrize("n", [1, 2, 3, 9, 31])
def test_prepared_agrees_with_naive(be, n):
    params, signers, messages, agg = _cbas(be, n)
    assert agg_verify_prepared(params, prepare(params, signers), messages, agg)


@pytest.mark.parametrize("n", [1, 4, 17])
def test_verma_optimised_agrees_with_naive(be, n):
    params, signers, messages, agg = _verma(be, n)
    assert verma.agg_verify(params, signers, messages, agg)
    assert verma_agg_verify_msm(params, signers, messages, agg)
    assert verma_agg_verify_prepared(params, verma_prepare(params, signers), messages, agg)


def test_verify_single_msm(be):
    params, signers, messages, agg = _cbas(be, 1)
    sig = fixed.Signature(T=agg.T[0], z=agg.z)
    assert verify_single_msm(params, signers[0], messages[0], sig)


# -- tampering must still be rejected ---------------------------------------

@pytest.mark.parametrize("path", ["msm", "prepared"])
def test_tampered_message_rejected(be, path):
    params, signers, messages, agg = _cbas(be, 6)
    bad = list(messages)
    bad[3] = b"tampered"
    if path == "msm":
        assert not agg_verify_msm(params, signers, bad, agg)
    else:
        assert not agg_verify_prepared(params, prepare(params, signers), bad, agg)


def test_tampered_z_rejected(be):
    params, signers, messages, agg = _cbas(be, 5)
    bad = fixed.AggregateSignature(T=agg.T, z=be.scalar_add(agg.z, be.scalar_from_int(1)))
    assert not agg_verify_msm(params, signers, messages, bad)
    assert not agg_verify_prepared(params, prepare(params, signers), messages, bad)


def test_tampered_commitment_rejected(be):
    params, signers, messages, agg = _cbas(be, 5)
    T = list(agg.T)
    T[2] = be.point_mul_base(be.scalar_random())
    bad = fixed.AggregateSignature(T=tuple(T), z=agg.z)
    assert not agg_verify_msm(params, signers, messages, bad)
    assert not agg_verify_prepared(params, prepare(params, signers), messages, bad)


def test_substituted_public_key_rejected(be):
    params, signers, messages, agg = _cbas(be, 4)
    impostor = fixed.keygen(params)
    bad = list(signers)
    bad[0] = fixed.Signer(identity=signers[0].identity, pk=impostor.pk, R=signers[0].R)
    assert not agg_verify_msm(params, bad, messages, agg)
    assert not agg_verify_prepared(params, prepare(params, bad), messages, agg)


def test_length_mismatch_rejected(be):
    params, signers, messages, agg = _cbas(be, 4)
    with pytest.raises(ValueError):
        agg_verify_msm(params, signers[:2], messages, agg)
    with pytest.raises(ValueError):
        agg_verify_prepared(params, prepare(params, signers)[:2], messages, agg)


# -- structure ---------------------------------------------------------------

def test_prepared_roster_caches_invariants(be):
    """h0 and the point encodings must match what the reference computes."""
    from cbas.hashing import H0

    params, signers, messages, agg = _cbas(be, 3)
    for ps, signer in zip(prepare(params, signers), signers):
        assert isinstance(ps, PreparedSigner)
        assert ps.pk_bytes == be.point_to_bytes(signer.pk)
        assert ps.R_bytes == be.point_to_bytes(signer.R)
        assert ps.h0 == H0(be, signer.identity, signer.pk, signer.R)


def test_prepared_roster_is_reusable_across_batches(be):
    """The point of preparing: one roster, many batches of messages."""
    params, _, signers, secrets, _ = enrol(be, 4)
    prepared = prepare(params, signers)
    for batch in range(3):
        messages = [f"batch-{batch}-reading-{i}".encode() for i in range(4)]
        sigs = sign_all(params, signers, secrets, messages)
        agg = fixed.agg_sign(params, sigs)
        assert agg_verify_prepared(params, prepared, messages, agg)


@pytest.mark.parametrize("n", [1, 10, 100])
def test_msm_term_counts(be, n):
    """CBAS needs 3n+1 MSM terms to Verma's n+2 -- the source of the gap."""
    assert MSM_TERMS["cbas"](n) == 3 * n + 1
    assert MSM_TERMS["verma"](n) == n + 2


def test_native_msm_is_counted_separately_from_te(be):
    """A native multi-scalar call is not expressible as a number of Te."""
    n = 8
    params, signers, messages, agg = _cbas(be, n)
    with be.count() as c:
        assert agg_verify_prepared(params, prepare(params, signers), messages, agg)
    if be.has_native_msm:
        assert c.Tm == 1
        assert c.Tm_terms == 3 * n + 1
        assert c.Te == 1          # only the z*P comparison
    else:
        # Fallback path: no native call, so the work shows up as Te/Ta.
        assert c.Tm == 0
        assert c.Te > n


def test_prepared_path_does_fewer_hashes(be):
    """H0 leaves the hot path entirely once the roster is prepared."""
    n = 10
    params, signers, messages, agg = _cbas(be, n)
    prepared = prepare(params, signers)
    with be.count() as c_naive:
        fixed.agg_verify(params, signers, messages, agg)
    with be.count() as c_prep:
        agg_verify_prepared(params, prepared, messages, agg)
    assert c_naive.Th == 3 * n
    assert c_prep.Th == 2 * n


# -- signer side -------------------------------------------------------------

def test_prepared_signing_verifies_under_the_reference(be):
    """Prepared signatures must be accepted by the unmodified verifier."""
    from cbas.optimized import prepare_signing, sign_prepared

    params, _, signers, secrets, _ = enrol(be, 1)
    keys, cert = secrets[0]
    ctx = prepare_signing(params, signers[0], keys.sk, cert)
    for i in range(8):
        msg = f"reading-{i}".encode()
        sig = sign_prepared(params, ctx, msg)
        assert fixed.verify_single(params, signers[0], msg, sig)
        assert not fixed.verify_single(params, signers[0], msg + b"!", sig)


def test_prepared_signing_keeps_the_nonce_fresh(be):
    """Caching must not make signing deterministic.

    The scheme's replay resistance rests on a fresh nonce per signature; an
    optimisation that cached T would silently destroy it.
    """
    from cbas.optimized import prepare_signing, sign_prepared

    params, _, signers, secrets, _ = enrol(be, 1)
    keys, cert = secrets[0]
    ctx = prepare_signing(params, signers[0], keys.sk, cert)
    sigs = [sign_prepared(params, ctx, b"same message") for _ in range(6)]
    assert len({s.T for s in sigs}) == 6
    assert len({s.z for s in sigs}) == 6


def test_prepared_signing_aggregates_normally(be):
    """Prepared and plain signatures must aggregate together."""
    from cbas.optimized import prepare_signing, sign_prepared

    params, _, signers, secrets, messages = enrol(be, 4)
    sigs = []
    for i, (signer, (keys, cert), m) in enumerate(zip(signers, secrets, messages)):
        if i % 2:
            sigs.append(fixed.sign(params, signer, keys.sk, cert, m))
        else:
            ctx = prepare_signing(params, signer, keys.sk, cert)
            sigs.append(sign_prepared(params, ctx, m))
    agg = fixed.agg_sign(params, sigs)
    assert fixed.agg_verify(params, signers, messages, agg)
    assert agg_verify_prepared(params, prepare(params, signers), messages, agg)


def test_prepared_signing_costs_the_same_group_operations(be):
    """Caching saves encoding work, not cryptographic work."""
    from cbas.optimized import prepare_signing, sign_prepared

    params, _, signers, secrets, messages = enrol(be, 1)
    keys, cert = secrets[0]
    ctx = prepare_signing(params, signers[0], keys.sk, cert)
    with be.count() as c_plain:
        fixed.sign(params, signers[0], keys.sk, cert, messages[0])
    with be.count() as c_prep:
        sign_prepared(params, ctx, messages[0])
    assert (c_plain.Te, c_plain.Th) == (1, 2)
    assert (c_prep.Te, c_prep.Th) == (1, 2)
