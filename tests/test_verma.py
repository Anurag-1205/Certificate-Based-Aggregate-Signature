"""Verma et al.'s CB-CAS must be implemented *correctly*.

If it were not, the forgery in test_forgery.py would prove nothing -- an attack
on a broken implementation is not an attack on the scheme.
"""

import pytest

from cbas import verma


def enrol(be, n, delta=b"epoch-0"):
    params, msk = verma.setup(be, delta)
    signers, secrets, messages = [], [], []
    for i in range(n):
        ident = f"sensor-{i:03d}".encode()
        keys = verma.keygen(params)
        cert = verma.cert_gen(params, msk, ident, keys.pk)
        signers.append(verma.Signer(identity=ident, pk=keys.pk))
        secrets.append((keys, cert))
        messages.append(f"reading-{i}".encode())
    return params, msk, signers, secrets, messages


def sign_all(params, signers, secrets, messages):
    return [verma.sign(params, s, k.sk, c, m)
            for s, (k, c), m in zip(signers, secrets, messages)]


def test_single_signature_verifies(be):
    params, _, signers, secrets, messages = enrol(be, 1)
    sig = verma.sign(params, signers[0], secrets[0][0].sk, secrets[0][1], messages[0])
    assert verma.verify_single(params, signers[0], messages[0], sig)


@pytest.mark.parametrize("n", [1, 2, 5, 11])
def test_aggregate_verifies(be, n):
    params, _, signers, secrets, messages = enrol(be, n)
    agg = verma.agg_sign(params, sign_all(params, signers, secrets, messages))
    assert verma.agg_verify(params, signers, messages, agg)


def test_tampered_message_rejected(be):
    params, _, signers, secrets, messages = enrol(be, 4)
    agg = verma.agg_sign(params, sign_all(params, signers, secrets, messages))
    bad = list(messages)
    bad[1] = b"tampered"
    assert not verma.agg_verify(params, signers, bad, agg)


def test_signing_is_probabilistic(be):
    params, _, signers, secrets, messages = enrol(be, 1)
    a = verma.sign(params, signers[0], secrets[0][0].sk, secrets[0][1], messages[0])
    b = verma.sign(params, signers[0], secrets[0][0].sk, secrets[0][1], messages[0])
    assert a.R != b.R and a.z != b.z


@pytest.mark.parametrize("n", [1, 5, 20, 50])
def test_aggregate_is_constant_size(be, n):
    """Verma's selling point: the aggregate does not grow with n.

    This is the property that the omission of R from the hash buys, and the
    property that costs them the scheme.
    """
    params, _, signers, secrets, messages = enrol(be, n)
    agg = verma.agg_sign(params, sign_all(params, signers, secrets, messages))
    size = len(be.point_to_bytes(agg.R)) + len(be.scalar_to_bytes(agg.z))
    assert size == be.point_bytes + be.scalar_bytes  # independent of n


def test_verma_aggverify_cost_matches_its_published_row(be):
    """Sanity check on the counting method used in VERIFICATION.md.

    Table III of Qiao et al. gives Verma's aggregate verification as
    (n+2)Te + (n+1)Ta + 2nTh. Our instrument reproduces that exactly -- which
    is what licenses the claim that the same instrument, applied to Qiao's own
    scheme, gives the right answer there too.
    """
    for n in (1, 3, 10, 25):
        params, _, signers, secrets, messages = enrol(be, n)
        agg = verma.agg_sign(params, sign_all(params, signers, secrets, messages))
        with be.count() as c:
            assert verma.agg_verify(params, signers, messages, agg)
        assert c.Te == n + 2, f"n={n}: expected {n + 2} Te, got {c.Te}"
        assert c.Ta == n + 1, f"n={n}: expected {n + 1} Ta, got {c.Ta}"
        assert c.Th == 2 * n, f"n={n}: expected {2 * n} Th, got {c.Th}"


def test_verma_aggsign_cost_matches_its_published_row(be):
    """Table III gives Verma AggSign (n-1)Ta. It genuinely sums R_i in the group."""
    n = 9
    params, _, signers, secrets, messages = enrol(be, n)
    sigs = sign_all(params, signers, secrets, messages)
    with be.count() as c:
        verma.agg_sign(params, sigs)
    assert c.Ta == n - 1
    assert c.Te == 0
