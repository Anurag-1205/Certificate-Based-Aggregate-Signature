"""Key recovery from a reused signing nonce, and the hedged-nonce defence.

The attacker in every test sees only public data and signatures, except the
KGC tests, where it also holds the certificate it issued. No test reads the
victim's secret key except to check the attacker's answer.
"""

import pytest

from cbas import scheme as fixed, verma
from cbas.nonce_reuse import (
    NonceReuseError,
    forge_verma_with_keys,
    forge_with_keys,
    recover_keys_outsider,
    recover_sk_kgc,
    recover_verma,
    sign_hedged,
    stuck_rng,
    two_signature_solutions,
)

READINGS = [b"temp=21.4C;seq=1", b"temp=21.5C;seq=2", b"temp=21.3C;seq=3"]


def _victim(be, ident=b"sensor-042"):
    params, msk = fixed.setup(be, b"epoch-0")
    keys = fixed.keygen(params)
    cert = fixed.cert_gen(params, msk, ident, keys.pk)
    return params, keys, cert, fixed.Signer(identity=ident, pk=keys.pk, R=cert.R)


def _stuck_signatures(be, params, signer, sk, cert, messages, sign=fixed.sign):
    with stuck_rng(be, be.scalar_random()):
        return [sign(params, signer, sk, cert, m) for m in messages]


# -- the simulated fault ----------------------------------------------------

def test_stuck_rng_repeats_the_commitment_and_signatures_still_verify(be):
    params, keys, cert, signer = _victim(be)
    sigs = _stuck_signatures(be, params, signer, keys.sk, cert, READINGS)
    assert all(be.point_eq(s.T, sigs[0].T) for s in sigs)
    assert all(fixed.verify_single(params, signer, m, s) for m, s in zip(READINGS, sigs))


def test_stuck_rng_is_restored_after_the_block(be):
    nonce = be.scalar_random()
    with stuck_rng(be, nonce):
        assert be.scalar_to_int(be.scalar_random()) == be.scalar_to_int(nonce)
    assert be.scalar_to_int(be.scalar_random()) != be.scalar_to_int(be.scalar_random())


# -- outsider: three signatures give every secret ---------------------------

def test_outsider_recovers_both_secrets_from_three_signatures(be):
    params, keys, cert, signer = _victim(be)
    sigs = _stuck_signatures(be, params, signer, keys.sk, cert, READINGS)
    rec = recover_keys_outsider(params, signer, READINGS, sigs)
    assert be.scalar_to_int(rec.sk) == be.scalar_to_int(keys.sk)
    assert be.scalar_to_int(rec.c) == be.scalar_to_int(cert.c)


def test_recovered_keys_sign_new_messages_that_verify_and_aggregate(be):
    params, keys, cert, signer = _victim(be)
    sigs = _stuck_signatures(be, params, signer, keys.sk, cert, READINGS)
    rec = recover_keys_outsider(params, signer, READINGS, sigs)

    target = b"valve=OPEN;line=A"
    forged = forge_with_keys(params, signer, rec, target)
    assert fixed.verify_single(params, signer, target, forged)

    honest = fixed.sign(params, signer, keys.sk, cert, b"temp=21.6C;seq=4")
    agg = fixed.agg_sign(params, [honest, forged])
    assert fixed.agg_verify(params, [signer, signer], [b"temp=21.6C;seq=4", target], agg)


def test_two_signatures_leave_an_outsider_a_discrete_log(be):
    """Every guess of sk fits both signatures; only a discrete log picks the right one."""
    params, keys, cert, signer = _victim(be)
    msgs = READINGS[:2]
    sigs = _stuck_signatures(be, params, signer, keys.sk, cert, msgs)
    T = sigs[0].T
    for _ in range(3):
        cand = two_signature_solutions(params, signer, msgs, sigs, be.scalar_random())
        for m, s in zip(msgs, sigs):
            u = fixed.H2(be, m, signer.pk, signer.R, signer.identity, T, params.delta)
            v = fixed.H1(be, m, signer.pk, signer.R, signer.identity, T, params.delta)
            z = be.scalar_add(cand.t, be.scalar_add(be.scalar_mul(cand.c, u),
                                                    be.scalar_mul(cand.sk, v)))
            assert be.scalar_to_int(z) == be.scalar_to_int(s.z)
        assert not be.point_eq(be.point_mul_base(cand.sk), signer.pk)


def test_outsider_needs_three_signatures(be):
    params, keys, cert, signer = _victim(be)
    sigs = _stuck_signatures(be, params, signer, keys.sk, cert, READINGS[:2])
    with pytest.raises(NonceReuseError, match="need 3"):
        recover_keys_outsider(params, signer, READINGS[:2], sigs)


def test_repeated_message_adds_no_equation(be):
    params, keys, cert, signer = _victim(be)
    msgs = [READINGS[0], READINGS[0], READINGS[1]]
    sigs = _stuck_signatures(be, params, signer, keys.sk, cert, msgs)
    with pytest.raises(NonceReuseError, match="distinct"):
        recover_keys_outsider(params, signer, msgs, sigs)


def test_healthy_rng_gives_the_attack_nothing(be):
    params, keys, cert, signer = _victim(be)
    sigs = [fixed.sign(params, signer, keys.sk, cert, m) for m in READINGS]
    with pytest.raises(NonceReuseError, match="different nonces"):
        recover_keys_outsider(params, signer, READINGS, sigs)


# -- the KGC: two signatures give the key it is never meant to learn -------

def test_kgc_recovers_sk_from_two_signatures(be):
    params, keys, cert, signer = _victim(be)
    sigs = _stuck_signatures(be, params, signer, keys.sk, cert, READINGS[:2])
    sk = recover_sk_kgc(params, signer, cert, READINGS[:2], sigs)
    assert be.scalar_to_int(sk) == be.scalar_to_int(keys.sk)


# -- Verma: two signatures, any attacker ------------------------------------

def test_verma_outsider_forges_after_two_reused_nonces(be):
    params, msk = verma.setup(be, b"epoch-0")
    keys = verma.keygen(params)
    cert = verma.cert_gen(params, msk, b"sensor-042", keys.pk)
    signer = verma.Signer(identity=b"sensor-042", pk=keys.pk)
    msgs = READINGS[:2]
    with stuck_rng(be, be.scalar_random()):
        sigs = [verma.sign(params, signer, keys.sk, cert, m) for m in msgs]

    rec = recover_verma(params, signer, msgs, sigs)
    assert be.scalar_to_int(rec.sk) == be.scalar_to_int(keys.sk)
    forged = forge_verma_with_keys(params, signer, rec, b"valve=OPEN")
    assert verma.verify_single(params, signer, b"valve=OPEN", forged)


# -- the defence ------------------------------------------------------------

def test_hedged_signatures_verify_with_the_unchanged_verifier(be):
    params, keys, cert, signer = _victim(be)
    for m in READINGS:
        assert fixed.verify_single(params, signer, m, sign_hedged(params, signer, keys.sk, cert, m))


def test_hedged_nonces_differ_per_message_even_with_a_stuck_rng(be):
    params, keys, cert, signer = _victim(be)
    sigs = _stuck_signatures(be, params, signer, keys.sk, cert, READINGS, sign=sign_hedged)
    encodings = {be.point_to_bytes(s.T) for s in sigs}
    assert len(encodings) == len(READINGS)
    with pytest.raises(NonceReuseError, match="different nonces"):
        recover_keys_outsider(params, signer, READINGS, sigs)


def test_hedged_signatures_aggregate_with_ordinary_ones(be):
    params, keys, cert, signer = _victim(be)
    a = sign_hedged(params, signer, keys.sk, cert, READINGS[0])
    b = fixed.sign(params, signer, keys.sk, cert, READINGS[1])
    agg = fixed.agg_sign(params, [a, b])
    assert fixed.agg_verify(params, [signer, signer], READINGS[:2], agg)
