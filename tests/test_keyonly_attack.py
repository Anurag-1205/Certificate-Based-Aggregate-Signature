"""The key-only universal forgery, and the 2x2 that explains it.

In the Goldwasser-Micali-Rivest taxonomy this is a key-only attack (the
adversary is given nothing but the target's public key) producing a universal
forgery (a valid signature on an arbitrary, verifier-chosen message) -- the
strongest possible combination. No secret key, no certificate, no observed
signature and no interaction is required anywhere in this file.
"""

import pytest

from cbas import ablation, ablation_r, scheme as fixed, verma
from cbas.keyonly_attack import attempt_keyonly_forge_fixed, forge_verma_keyonly
from cbas.scheme import Signer, Signature


def _victim(mod, be, ident=b"victim-007"):
    """Enrol one real, honestly-certified signer under ``mod``."""
    params, msk = mod.setup(be, b"epoch-0")
    keys = mod.keygen(params)
    cert = mod.cert_gen(params, msk, ident, keys.pk)
    return params, keys, cert


# -- the break: Verma has no unbound commitment protection at all -----------

def test_keyonly_forge_breaks_verma_with_only_id_and_pk(be):
    params, keys, cert = _victim(verma, be)
    signer = verma.Signer(identity=b"victim-007", pk=keys.pk)
    forged = forge_verma_keyonly(params, signer.identity, signer.pk, b"attacker chosen")
    assert verma.verify_single(params, signer, b"attacker chosen", forged)


def test_keyonly_forge_needs_no_secret_material(be):
    import inspect

    sig = inspect.signature(forge_verma_keyonly)
    assert set(sig.parameters) == {"params", "identity", "pk", "target_message", "z"}


def test_keyonly_forge_works_on_a_real_enrolled_victims_key(be):
    """The forged signature is attributed to a real, uncompromised identity."""
    params, keys, cert = _victim(verma, be)
    signer = verma.Signer(identity=b"victim-007", pk=keys.pk)
    honest_sig = verma.sign(params, signer, keys.sk, cert, b"real reading")
    forged = forge_verma_keyonly(params, signer.identity, signer.pk, b"forged reading")
    assert verma.verify_single(params, signer, b"forged reading", forged)
    assert verma.verify_single(params, signer, b"real reading", honest_sig)  # unaffected


def test_keyonly_forge_needs_no_observed_signature(be):
    """Unlike attack.py's forgery, no prior signature is ever touched."""
    params, keys, cert = _victim(verma, be)
    signer = verma.Signer(identity=b"victim-007", pk=keys.pk)
    forged = forge_verma_keyonly(params, signer.identity, signer.pk, b"never observed anything")
    assert verma.verify_single(params, signer, b"never observed anything", forged)


def test_keyonly_forgery_produces_unlimited_messages(be):
    params, keys, cert = _victim(verma, be)
    signer = verma.Signer(identity=b"victim-007", pk=keys.pk)
    for i in range(10):
        m = f"message-{i}".encode()
        forged = forge_verma_keyonly(params, signer.identity, signer.pk, m)
        assert verma.verify_single(params, signer, m, forged)


def test_keyonly_forgery_survives_aggregation(be):
    params, keys, cert = _victim(verma, be)
    signer = verma.Signer(identity=b"victim-007", pk=keys.pk)
    forged = forge_verma_keyonly(params, signer.identity, signer.pk, b"forged")
    honest_sig = verma.sign(params, signer, keys.sk, cert, b"real")
    agg = verma.agg_sign(params, [honest_sig, forged])
    assert verma.agg_verify(params, [signer, signer], [b"real", b"forged"], agg)


def test_keyonly_forge_works_even_on_an_arbitrary_unregistered_key(be):
    """pk need not belong to anyone; the forge never uses its discrete log."""
    params, _ = verma.setup(be, b"e")
    unknown_pk = be.point_mul_base(be.scalar_random())
    signer = verma.Signer(identity=b"nobody", pk=unknown_pk)
    forged = forge_verma_keyonly(params, b"nobody", unknown_pk, b"m")
    assert verma.verify_single(params, signer, b"m", forged)


# -- the real scheme resists both directions ---------------------------------

@pytest.mark.parametrize("target", [b"m1", b"", b"\x00\xff" * 10])
def test_keyonly_attack_fails_on_the_real_scheme(be, target):
    params, keys, cert = _victim(fixed, be)
    seed = be.point_mul_base(be.scalar_random())
    attempt = attempt_keyonly_forge_fixed(params, b"victim-007", keys.pk,
                                          R_seed=seed, T_seed=seed, target_message=target)
    assert not attempt.succeeded
    assert "fixed point" in attempt.reason


def test_keyonly_attempt_candidates_are_all_distinct(be):
    params, keys, cert = _victim(fixed, be)
    seed = be.point_mul_base(be.scalar_random())
    attempt = attempt_keyonly_forge_fixed(params, b"victim-007", keys.pk,
                                          R_seed=seed, T_seed=seed,
                                          target_message=b"x", max_iterations=20)
    assert len(attempt.trace) == 20
    assert len(set(attempt.trace)) == 20


# -- the 2x2: each ablation is broken via its own open door, and only its own --

def test_ablation_fix2_removed_is_broken_via_t_not_r(be):
    """Fix #1 (R) intact, Fix #2 (T) removed: T is the exploitable free variable."""
    params, keys, cert = _victim(ablation, be)
    forged = ablation.forge_keyonly_via_t(params, b"victim-007", keys.pk, cert.R, b"m")
    victim = Signer(identity=b"victim-007", pk=keys.pk, R=cert.R)
    assert ablation.verify_single(params, victim, b"m", forged)


def test_ablation_fix2_removed_still_resists_solving_for_r(be):
    """The door Fix #1 closes stays closed even with Fix #2 gone."""
    params, keys, cert = _victim(ablation, be)
    seed = be.point_mul_base(be.scalar_random())
    attempt = ablation.attempt_solve_for_r_ablated(params, b"victim-007", keys.pk,
                                                   seed, b"m")
    assert not attempt["succeeded"]


def test_ablation_fix1_removed_is_broken_via_r_not_t(be):
    """Fix #2 (T) intact, Fix #1 (R) removed: R is the exploitable free variable."""
    params, keys, cert = _victim(ablation_r, be)
    forged, forged_R = ablation_r.forge_keyonly(params, b"victim-007", keys.pk, b"m")
    victim = Signer(identity=b"victim-007", pk=keys.pk, R=forged_R)
    assert ablation_r.verify_single(params, victim, b"m", forged)


def test_ablation_fix1_removed_still_resists_solving_for_t(be):
    """The door Fix #2 closes stays closed even with Fix #1 gone."""
    params, keys, cert = _victim(ablation_r, be)
    attempt = ablation_r.attempt_solve_for_t_ablation_r(params, b"victim-007", keys.pk,
                                                        cert.R, b"m")
    assert not attempt["succeeded"]


def test_ablation_r_is_a_self_consistent_scheme(be):
    """Confirms ablation_r.py is a real scheme, not a broken build."""
    params, keys, cert = _victim(ablation_r, be)
    signer = Signer(identity=b"victim-007", pk=keys.pk, R=cert.R)
    sig = ablation_r.sign(params, signer, keys.sk, cert, b"honest")
    assert ablation_r.verify_single(params, signer, b"honest", sig)
    assert not ablation_r.verify_single(params, signer, b"different", sig)


def test_ablation_r_changed_only_fix1(be):
    """Confirms the ablation isolates Fix #1: T is still bound (Fix #2 intact)."""
    params, keys, cert = _victim(ablation_r, be)
    v1 = ablation_r.H1_no_r(be, b"m", keys.pk, b"victim-007", cert.R, b"e")
    v2 = ablation_r.H1_no_r(be, b"m", keys.pk, b"victim-007", be.point_mul_base(be.scalar_random()), b"e")
    assert v1 != v2, "H1_no_r must still depend on T"
