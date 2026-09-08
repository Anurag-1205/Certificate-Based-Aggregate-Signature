"""End-to-end correctness of the six algorithms."""

import pytest

from cbas.scheme import (
    AggregateSignature,
    Signer,
    agg_sign,
    agg_verify,
    cert_gen,
    cert_verify,
    keygen,
    setup,
    sign,
    verify_single,
)


def enrol(be, n, delta=b"epoch-0"):
    params, msk = setup(be, delta)
    signers, secrets, messages = [], [], []
    for i in range(n):
        identity = f"sensor-{i:03d}".encode()
        keys = keygen(params)
        cert = cert_gen(params, msk, identity, keys.pk)
        signers.append(Signer(identity=identity, pk=keys.pk, R=cert.R))
        secrets.append((keys, cert))
        messages.append(f"reading-{i}".encode())
    return params, msk, signers, secrets, messages


def sign_all(params, signers, secrets, messages):
    return [
        sign(params, s, k.sk, c, m)
        for s, (k, c), m in zip(signers, secrets, messages)
    ]


def test_certificate_verifies(be):
    params, msk, signers, secrets, _ = enrol(be, 3)
    for s, (_, cert) in zip(signers, secrets):
        assert cert_verify(params, s.identity, s.pk, cert)


def test_certificate_rejects_wrong_identity(be):
    params, msk, signers, secrets, _ = enrol(be, 1)
    _, cert = secrets[0]
    assert not cert_verify(params, b"someone-else", signers[0].pk, cert)


def test_single_signature_verifies(be):
    params, _, signers, secrets, messages = enrol(be, 1)
    sig = sign(params, signers[0], secrets[0][0].sk, secrets[0][1], messages[0])
    assert verify_single(params, signers[0], messages[0], sig)


@pytest.mark.parametrize("n", [1, 2, 3, 8, 17])
def test_aggregate_verifies_for_various_n(be, n):
    params, _, signers, secrets, messages = enrol(be, n)
    sigs = sign_all(params, signers, secrets, messages)
    agg = agg_sign(params, sigs)
    assert agg.n == n
    assert agg_verify(params, signers, messages, agg)


def test_signing_is_probabilistic(be):
    """Same message twice must give different signatures (replay resistance)."""
    params, _, signers, secrets, messages = enrol(be, 1)
    a = sign(params, signers[0], secrets[0][0].sk, secrets[0][1], messages[0])
    b = sign(params, signers[0], secrets[0][0].sk, secrets[0][1], messages[0])
    assert a.T != b.T and a.z != b.z
    assert verify_single(params, signers[0], messages[0], a)
    assert verify_single(params, signers[0], messages[0], b)


def test_tampered_message_is_rejected(be):
    params, _, signers, secrets, messages = enrol(be, 5)
    agg = agg_sign(params, sign_all(params, signers, secrets, messages))
    bad = list(messages)
    bad[2] = b"tampered"
    assert not agg_verify(params, signers, bad, agg)


def test_tampered_z_is_rejected(be):
    params, _, signers, secrets, messages = enrol(be, 4)
    agg = agg_sign(params, sign_all(params, signers, secrets, messages))
    bad = AggregateSignature(T=agg.T, z=be.scalar_add(agg.z, be.scalar_from_int(1)))
    assert not agg_verify(params, signers, messages, bad)


def test_tampered_commitment_is_rejected(be):
    params, _, signers, secrets, messages = enrol(be, 4)
    agg = agg_sign(params, sign_all(params, signers, secrets, messages))
    T = list(agg.T)
    T[1] = be.point_mul_base(be.scalar_random())
    assert not agg_verify(params, signers, messages, AggregateSignature(T=tuple(T), z=agg.z))


def test_substituted_public_key_is_rejected(be):
    """Fix #1: R is bound into H0, so swapping a public key must fail."""
    params, _, signers, secrets, messages = enrol(be, 3)
    agg = agg_sign(params, sign_all(params, signers, secrets, messages))
    impostor = keygen(params)
    bad = list(signers)
    bad[0] = Signer(identity=signers[0].identity, pk=impostor.pk, R=signers[0].R)
    assert not agg_verify(params, bad, messages, agg)


def test_substituted_R_is_rejected(be):
    params, _, signers, secrets, messages = enrol(be, 3)
    agg = agg_sign(params, sign_all(params, signers, secrets, messages))
    bad = list(signers)
    bad[1] = Signer(
        identity=signers[1].identity,
        pk=signers[1].pk,
        R=be.point_mul_base(be.scalar_random()),
    )
    assert not agg_verify(params, bad, messages, agg)


def test_message_order_matters(be):
    """Messages must stay paired with their signers."""
    params, _, signers, secrets, messages = enrol(be, 4)
    agg = agg_sign(params, sign_all(params, signers, secrets, messages))
    swapped = list(messages)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    assert not agg_verify(params, signers, swapped, agg)


def test_same_signer_twice_in_one_aggregate(be):
    """A signer legitimately contributing two readings must verify."""
    params, msk, signers, secrets, _ = enrol(be, 1)
    signer, (keys, cert) = signers[0], secrets[0]
    m1, m2 = b"reading-A", b"reading-B"
    sigs = [
        sign(params, signer, keys.sk, cert, m1),
        sign(params, signer, keys.sk, cert, m2),
    ]
    agg = agg_sign(params, sigs)
    assert agg_verify(params, [signer, signer], [m1, m2], agg)


def test_cross_epoch_signature_is_rejected(be):
    """Delta separates epochs, so a signature must not replay into another."""
    params, msk, signers, secrets, messages = enrol(be, 1, delta=b"epoch-0")
    sig = sign(params, signers[0], secrets[0][0].sk, secrets[0][1], messages[0])
    other = type(params)(backend=params.backend, pk_ta=params.pk_ta, delta=b"epoch-1")
    assert not verify_single(other, signers[0], messages[0], sig)


def test_signature_from_another_system_is_rejected(be):
    """A signature under a different KGC must not verify."""
    p1, _, s1, sec1, m1 = enrol(be, 1)
    p2, _, _, _, _ = enrol(be, 1)
    sig = sign(p1, s1[0], sec1[0][0].sk, sec1[0][1], m1[0])
    assert not verify_single(p2, s1[0], m1[0], sig)


def test_empty_aggregate_is_rejected(be):
    params, _, _, _, _ = enrol(be, 1)
    with pytest.raises(ValueError):
        agg_sign(params, [])


def test_length_mismatch_is_rejected(be):
    params, _, signers, secrets, messages = enrol(be, 3)
    agg = agg_sign(params, sign_all(params, signers, secrets, messages))
    with pytest.raises(ValueError):
        agg_verify(params, signers[:2], messages, agg)


def test_aggregation_is_order_independent(be):
    """z is a plain sum, so reordering signers consistently still verifies.

    This is also why hierarchical (multi-tier) aggregation works with no
    protocol change: the operation is associative and commutative.
    """
    params, _, signers, secrets, messages = enrol(be, 5)
    sigs = sign_all(params, signers, secrets, messages)
    order = [3, 0, 4, 1, 2]
    agg = agg_sign(params, [sigs[i] for i in order])
    assert agg_verify(params, [signers[i] for i in order], [messages[i] for i in order], agg)


def test_two_tier_aggregation(be):
    """Aggregating aggregates gives the same result as one flat aggregate."""
    params, _, signers, secrets, messages = enrol(be, 6)
    sigs = sign_all(params, signers, secrets, messages)
    flat = agg_sign(params, sigs)
    left = agg_sign(params, sigs[:3])
    right = agg_sign(params, sigs[3:])
    merged = AggregateSignature(T=left.T + right.T, z=be.scalar_add(left.z, right.z))
    assert merged.T == flat.T
    assert merged.z == flat.z
    assert agg_verify(params, signers, messages, merged)
