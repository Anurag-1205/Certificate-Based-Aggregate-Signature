"""Section V-C of the paper lists four security properties. Two are checked here.

Property 2, "resist replay attacks": the paper argues that signing is
probabilistic, so signing the same message twice gives different signatures.
That is true, but it does not stop replay: an old (message, signature) pair
still verifies, and nothing in the scheme marks it as old.

Property 4, "perfect forward security": the paper argues that no one can
obtain the nonce. Forward security for signatures (Bellare and Miner, 1999)
means that stealing today's key does not allow signing for an earlier time
period. Here the keys never change, so a stolen key signs for any period.
"""

from dataclasses import replace

from cbas import scheme as fixed
from cbas.nonce_reuse import forge_with_keys, recover_keys_outsider, stuck_rng

READINGS = [b"temp=21.4C;seq=1", b"temp=21.5C;seq=2", b"temp=21.3C;seq=3"]


def _victim(be, delta=b"epoch-0"):
    params, msk = fixed.setup(be, delta)
    keys = fixed.keygen(params)
    cert = fixed.cert_gen(params, msk, b"sensor-042", keys.pk)
    return params, keys, cert, fixed.Signer(identity=b"sensor-042", pk=keys.pk, R=cert.R)


# -- property 2: replay -----------------------------------------------------

def test_signing_is_probabilistic_as_the_paper_says(be):
    params, keys, cert, signer = _victim(be)
    a = fixed.sign(params, signer, keys.sk, cert, READINGS[0])
    b = fixed.sign(params, signer, keys.sk, cert, READINGS[0])
    assert not be.point_eq(a.T, b.T)


def test_a_replayed_signature_still_verifies(be):
    params, keys, cert, signer = _victim(be)
    sig = fixed.sign(params, signer, keys.sk, cert, b"valve=OPEN")
    assert fixed.verify_single(params, signer, b"valve=OPEN", sig)
    assert fixed.verify_single(params, signer, b"valve=OPEN", sig)  # replayed later


def test_a_replayed_signature_aggregates_into_a_new_batch(be):
    params, keys, cert, signer = _victim(be)
    old = fixed.sign(params, signer, keys.sk, cert, b"valve=OPEN")
    fresh = fixed.sign(params, signer, keys.sk, cert, READINGS[0])
    agg = fixed.agg_sign(params, [fresh, old])
    assert fixed.agg_verify(params, [signer, signer], [READINGS[0], b"valve=OPEN"], agg)


def test_the_same_signature_twice_in_one_batch_verifies(be):
    params, keys, cert, signer = _victim(be)
    sig = fixed.sign(params, signer, keys.sk, cert, b"valve=OPEN")
    agg = fixed.agg_sign(params, [sig, sig])
    assert fixed.agg_verify(params, [signer, signer], [b"valve=OPEN", b"valve=OPEN"], agg)


# -- property 4: forward security ---------------------------------------------

def test_the_nonce_can_be_obtained_when_the_rng_repeats(be):
    """The paper's premise, "no one can obtain the random value", fails here."""
    params, keys, cert, signer = _victim(be)
    with stuck_rng(be, be.scalar_random()):
        sigs = [fixed.sign(params, signer, keys.sk, cert, m) for m in READINGS]
    rec = recover_keys_outsider(params, signer, READINGS, sigs)
    assert be.point_eq(be.point_mul_base(rec.t), sigs[0].T)


def test_a_key_stolen_later_signs_for_an_earlier_period(be):
    """Keys are fixed for life, so a later theft reaches back to epoch 0."""
    epoch0, keys, cert, signer = _victim(be, b"epoch-0")
    genuine = fixed.sign(epoch0, signer, keys.sk, cert, READINGS[0])

    epoch1 = replace(epoch0, delta=b"epoch-1")
    with stuck_rng(be, be.scalar_random()):
        sigs = [fixed.sign(epoch1, signer, keys.sk, cert, m) for m in READINGS]
    stolen = recover_keys_outsider(epoch1, signer, READINGS, sigs)

    backdated = forge_with_keys(epoch0, signer, stolen, b"temp=99.0C;seq=0")
    assert fixed.verify_single(epoch0, signer, b"temp=99.0C;seq=0", backdated)
    agg = fixed.agg_sign(epoch0, [genuine, backdated])
    assert fixed.agg_verify(epoch0, [signer, signer], [READINGS[0], b"temp=99.0C;seq=0"], agg)


def test_nothing_in_the_scheme_updates_a_key(be):
    """Every algorithm's output for a signer is the same in every period."""
    epoch0, keys, cert, signer = _victim(be, b"epoch-0")
    epoch1 = replace(epoch0, delta=b"epoch-1")
    assert fixed.cert_verify(epoch1, signer.identity, signer.pk, cert)
    sig = fixed.sign(epoch1, signer, keys.sk, cert, READINGS[0])
    assert fixed.verify_single(epoch1, signer, READINGS[0], sig)
