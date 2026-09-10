"""The malicious-KGC forgery: succeeds on Verma, fails on the repaired scheme.

This is the project's central experiment.
"""

import pytest

from cbas import ablation, scheme as fixed, verma
from cbas.attack import attempt_forge_fixed, forge_verma
from tests.test_verma import enrol as verma_enrol


TARGETS = [
    b"temp=-40.0C;line=A;seq=17;SHUTDOWN",
    b"pressure=0;valve=OPEN",
    b"",
    b"\x00\xff" * 40,
]


def _verma_victim(be):
    params, msk = verma.setup(be, b"epoch-0")
    ident = b"sensor-042"
    keys = verma.keygen(params)
    cert = verma.cert_gen(params, msk, ident, keys.pk)
    signer = verma.Signer(identity=ident, pk=keys.pk)
    msg = b"temp=21.4C;line=A;seq=17"
    sig = verma.sign(params, signer, keys.sk, cert, msg)
    assert verma.verify_single(params, signer, msg, sig)
    return params, msk, signer, keys, cert, msg, sig


def _fixed_victim(be):
    params, msk = fixed.setup(be, b"epoch-0")
    ident = b"sensor-042"
    keys = fixed.keygen(params)
    cert = fixed.cert_gen(params, msk, ident, keys.pk)
    signer = fixed.Signer(identity=ident, pk=keys.pk, R=cert.R)
    msg = b"temp=21.4C;line=A;seq=17"
    sig = fixed.sign(params, signer, keys.sk, cert, msg)
    assert fixed.verify_single(params, signer, msg, sig)
    return params, msk, signer, keys, cert, msg, sig


# -- the break ---------------------------------------------------------------

@pytest.mark.parametrize("target", TARGETS)
def test_malicious_kgc_forges_verma(be, target):
    """A universal forgery on arbitrary messages, from one observed signature."""
    params, _, signer, _, cert, msg, sig = _verma_victim(be)
    forged = forge_verma(params, signer, cert, msg, sig, target)
    assert verma.verify_single(params, signer, target, forged)


def test_forgery_never_touches_the_secret_key(be):
    """The attacker has no sk_i -- structurally, it is not passed in.

    This is what makes the break fatal: certificate-based cryptography exists
    precisely so that the KGC alone cannot sign.
    """
    import inspect

    sig = inspect.signature(forge_verma)
    assert "sk" not in sig.parameters
    assert set(sig.parameters) == {
        "params", "signer", "cert", "observed_message", "observed_sig", "target_message"
    }


def test_forged_signature_is_indistinguishable_in_shape(be):
    params, _, signer, _, cert, msg, sig = _verma_victim(be)
    forged = forge_verma(params, signer, cert, msg, sig, b"anything")
    assert len(be.point_to_bytes(forged.R)) == len(be.point_to_bytes(sig.R))
    assert len(be.scalar_to_bytes(forged.z)) == len(be.scalar_to_bytes(sig.z))


def test_forgery_survives_aggregation(be):
    """A forged signature aggregates alongside honest ones and is not detected."""
    params, _, signer, _, cert, msg, sig = _verma_victim(be)
    target = b"SHUTDOWN"
    forged = forge_verma(params, signer, cert, msg, sig, target)
    agg = verma.agg_sign(params, [sig, forged])
    assert verma.agg_verify(params, [signer, signer], [msg, target], agg)


def test_many_forgeries_from_one_signature(be):
    """One observed signature yields unlimited forgeries."""
    params, _, signer, _, cert, msg, sig = _verma_victim(be)
    for i in range(25):
        target = f"forged-message-{i}".encode()
        forged = forge_verma(params, signer, cert, msg, sig, target)
        assert verma.verify_single(params, signer, target, forged)


# -- the repaired scheme holds ----------------------------------------------

@pytest.mark.parametrize("target", TARGETS)
def test_same_attack_fails_on_repaired_scheme(be, target):
    params, _, signer, _, cert, msg, sig = _fixed_victim(be)
    attempt = attempt_forge_fixed(params, signer, cert, msg, sig, target)
    assert not attempt.succeeded
    assert "fixed point" in attempt.reason


def test_attack_iteration_never_settles(be):
    """Every candidate T' differs: the fixed-point search does not converge."""
    params, _, signer, _, cert, msg, sig = _fixed_victim(be)
    attempt = attempt_forge_fixed(params, signer, cert, msg, sig, b"SHUTDOWN",
                                  max_iterations=24)
    assert len(attempt.trace) == 24
    assert len(set(attempt.trace)) == 24, "candidates should all be distinct"


# -- isolating the cause -----------------------------------------------------

@pytest.mark.parametrize("target", TARGETS)
def test_ablating_fix2_restores_the_forgery(be, target):
    """The controlled experiment.

    Remove Fix #2 alone -- T dropped from H1 and H2 -- and leave Fixes #1 and #3
    intact. The forgery succeeds again. So binding the nonce commitment into
    the hashes is the change that carries the security, not the R-in-H0 binding
    and not the two-independent-oracle split.
    """
    params, msk = ablation.setup(be, b"epoch-0")
    ident = b"sensor-042"
    keys = ablation.keygen(params)
    cert = ablation.cert_gen(params, msk, ident, keys.pk)
    signer = ablation.Signer(identity=ident, pk=keys.pk, R=cert.R)
    msg = b"temp=21.4C;line=A;seq=17"
    sig = ablation.sign(params, signer, keys.sk, cert, msg)

    # The ablated variant is a self-consistent scheme, not a broken build.
    assert ablation.verify_single(params, signer, msg, sig)
    assert not ablation.verify_single(params, signer, b"different", sig)

    forged = ablation.forge_ablated(params, signer, cert, msg, sig, target)
    assert ablation.verify_single(params, signer, target, forged)


def test_ablated_variant_still_has_fixes_1_and_3(be):
    """Confirms the ablation changed only Fix #2."""
    from cbas import hashing
    from cbas.ablation import H1_ablated, H2_ablated

    # Fix #1 intact: the ablation imports the real H0, which binds R.
    assert ablation.H0 is hashing.H0

    # Fix #3 intact: u and v remain independent oracles.
    params, msk = ablation.setup(be)
    keys = ablation.keygen(params)
    cert = ablation.cert_gen(params, msk, b"id", keys.pk)
    args = (b"m", keys.pk, cert.R, b"id", params.delta)
    assert H1_ablated(be, *args) != H2_ablated(be, *args)
