"""Operation-count regression tests.

These encode the project's central empirical claim: the cost rows Qiao et al.
give for **their own** scheme in Tables II and III are identical to the rows
they give for Verma et al.'s scheme, and are too low.  Their scheme's
verification equation carries an extra per-signer term ``u_i R_i`` and an extra
hash ``H2``, so the two cannot cost the same.

If any of these assertions ever changes, either the implementation drifted from
Section V-A or the counting model changed -- both worth a hard look.
"""

import pytest

from cbas.scheme import agg_sign, agg_verify, cert_gen, keygen, setup, sign, verify_single
from tests.test_scheme_roundtrip import enrol, sign_all

# The paper's own per-operation costs, Table IV (ms).
TE, TA, TH = 0.112, 0.005, 0.004


def test_setup_and_keygen_cost_one_te(be):
    with be.count() as c:
        params, msk = setup(be)
    assert (c.Te, c.Ta, c.Th) == (1, 0, 0)
    with be.count() as c:
        keygen(params)
    assert (c.Te, c.Ta, c.Th) == (1, 0, 0)


def test_cert_gen_costs_one_te_one_th(be):
    params, msk = setup(be)
    keys = keygen(params)
    with be.count() as c:
        cert_gen(params, msk, b"sensor-000", keys.pk)
    assert (c.Te, c.Ta, c.Th) == (1, 0, 1)


def test_sign_costs_1te_2th_not_1te_1th(be):
    """Table II claims Sign = 1Te + 1Th.  It is 1Te + 2Th.

    Signing computes v_i = H1(...) *and* u_i = H2(...): two hashes, not one.
    Verma et al. genuinely compute only one, which is where the row came from.
    """
    params, _, signers, secrets, messages = enrol(be, 1)
    with be.count() as c:
        sign(params, signers[0], secrets[0][0].sk, secrets[0][1], messages[0])
    assert (c.Te, c.Ta, c.Th) == (1, 0, 2), "Table II claims 1Te + 1Th"


def test_single_verify_costs_4te_3ta_3th_not_3te_2ta_2th(be):
    """Table II claims Verify = 3Te + 2Ta + 2Th.  It is 4Te + 3Ta + 3Th."""
    params, _, signers, secrets, messages = enrol(be, 1)
    sig = sign(params, signers[0], secrets[0][0].sk, secrets[0][1], messages[0])
    with be.count() as c:
        assert verify_single(params, signers[0], messages[0], sig)
    assert (c.Te, c.Ta, c.Th) == (4, 3, 3), "Table II claims 3Te + 2Ta + 2Th"


@pytest.mark.parametrize("n", [1, 2, 5, 10, 25, 50])
def test_agg_verify_is_2n_plus_2_te(be, n):
    """Table III claims (n+2)Te + (n+1)Ta + 2nTh.  It is (2n+2)Te + 3nTa + 3nTh."""
    params, _, signers, secrets, messages = enrol(be, n)
    agg = agg_sign(params, sign_all(params, signers, secrets, messages))
    with be.count() as c:
        assert agg_verify(params, signers, messages, agg)
    assert c.Te == 2 * n + 2, f"claimed n+2 = {n + 2}, measured {c.Te}"
    assert c.Ta == 3 * n, f"claimed n+1 = {n + 1}, measured {c.Ta}"
    assert c.Th == 3 * n, f"claimed 2n = {2 * n}, measured {c.Th}"


def test_agg_verify_formula_rendering(be):
    n = 12
    params, _, signers, secrets, messages = enrol(be, n)
    agg = agg_sign(params, sign_all(params, signers, secrets, messages))
    with be.count() as c:
        agg_verify(params, signers, messages, agg)
    assert c.formula(n) == "(2n+2)Te + 3nTa + 3nTh"


def test_agg_sign_uses_no_group_operations(be):
    """Table III charges AggSign (n-1)Ta.  This scheme performs zero group ops.

    Aggregation here is n-1 *scalar* additions plus concatenating the T_i.
    Verma et al. genuinely compute R = sum R_i in the group, which is where the
    row came from -- so this column overstates our cost, in the paper's favour.
    """
    n = 8
    params, _, signers, secrets, messages = enrol(be, n)
    sigs = sign_all(params, signers, secrets, messages)
    with be.count() as c:
        agg_sign(params, sigs)
    assert (c.Te, c.Ta, c.Th) == (0, 0, 0)
    assert c.Ts == n - 1


@pytest.mark.parametrize("n", [10, 100])
def test_cost_understatement_factor(be, n):
    """Under the paper's own Table IV costs, verification is ~2x the claim."""
    params, _, signers, secrets, messages = enrol(be, n)
    agg = agg_sign(params, sign_all(params, signers, secrets, messages))
    with be.count() as c:
        agg_verify(params, signers, messages, agg)
    claimed = (n + 2) * TE + (n + 1) * TA + (2 * n) * TH
    measured = c.cost_ms(TE, TA, TH)
    assert measured > claimed
    factor = measured / claimed
    assert 1.8 < factor < 2.0, f"n={n}: factor {factor:.3f}"


def test_n100_matches_the_published_figure4_bar(be):
    """Fig. 4's 12.729 ms bar for n=100 is exactly Table III evaluated.

    Reproducing it from the claimed formula confirms Fig. 4 inherits the same
    error, and lets us state what the bar should have been.
    """
    n = 100
    claimed_ms = (n + 2) * TE + (n + 1) * TA + (2 * n) * TH
    assert round(claimed_ms, 3) == 12.729

    params, _, signers, secrets, messages = enrol(be, n)
    agg = agg_sign(params, sign_all(params, signers, secrets, messages))
    with be.count() as c:
        agg_verify(params, signers, messages, agg)
    assert round(c.cost_ms(TE, TA, TH), 3) == 25.324


# ---------------------------------------------------------------------------
# Robustness of the claim against the strongest counter-argument
# ---------------------------------------------------------------------------

def test_hash_claim_survives_the_caching_objection(be):
    """The best objection to the 3nTh claim, and why it does not rescue the row.

    ``h_i0 = H0(id_i || pk_i || R_i)`` depends only on static per-signer data,
    so a verifier serving a fixed sensor fleet could cache it and pay only
    ``v_i`` and ``u_i`` per message -- giving 2nTh and matching the published
    row.  But the same optimisation applies to Verma et al., whose ``h_i0`` is
    likewise message-independent; caching there leaves only ``v_i``, i.e. nTh.

    So under *either* model the two schemes differ by exactly n hashes:

        no caching : ours 3n vs Verma 2n
        caching    : ours 2n vs Verma  n

    The paper assigns 2nTh to *both*.  Since it gives Verma 2nTh, it is using
    the no-caching model -- under which this scheme costs 3nTh.  The rows
    cannot be equal under any consistent choice.
    """
    n = 6
    params, _, signers, secrets, messages = enrol(be, n)
    agg = agg_sign(params, sign_all(params, signers, secrets, messages))

    with be.count() as c:
        agg_verify(params, signers, messages, agg)
    assert c.Th == 3 * n                       # no caching: three hashes per signer

    cacheable = n                              # one H0 per signer is message-independent
    assert c.Th - cacheable == 2 * n           # caching: still 2n, not Verma's 2n... equal
    # ...but Verma under the same caching assumption would drop to n, not 2n:
    verma_no_cache, verma_cached = 2 * n, n
    assert verma_no_cache != c.Th              # published row says both are 2n
    assert verma_cached != c.Th - cacheable    # and caching does not equalise them either


def test_te_claim_cannot_be_rescued_by_algebraic_rewriting(be):
    """The sum(u_i R_i) term genuinely requires n scalar multiplications.

    One might hope to fold it away using c_i*P = R_i + h_i0*P_TA, which gives
    sum(u_i R_i) + (sum u_i h_i0)*P_TA == (sum u_i c_i)*P -- a single scalar
    multiplication.  But c_i is the signer's *secret* certificate, which the
    verifier does not have, so this rewriting is unavailable to a verifier.

    This test confirms the identity holds (so the algebra is right) while the
    verifier-side cost stands.
    """
    n = 4
    params, msk, signers, secrets, messages = enrol(be, n)
    sigs = sign_all(params, signers, secrets, messages)
    agg = agg_sign(params, sigs)

    from cbas.hashing import H0, H1, H2

    lhs_terms, uh_acc, uc_acc = [], None, None
    for signer, (_, cert), m, T in zip(signers, secrets, messages, agg.T):
        h0 = H0(be, signer.identity, signer.pk, signer.R)
        u = H2(be, m, signer.pk, signer.R, signer.identity, T, params.delta)
        lhs_terms.append(be.point_mul(u, signer.R))
        uh = be.scalar_mul(u, h0)
        uc = be.scalar_mul(u, cert.c)          # needs the SECRET c_i
        uh_acc = uh if uh_acc is None else be.scalar_add(uh_acc, uh)
        uc_acc = uc if uc_acc is None else be.scalar_add(uc_acc, uc)

    verifier_side = be.point_add(be.sum_points(lhs_terms), be.point_mul(uh_acc, params.pk_ta))
    secret_side = be.point_mul_base(uc_acc)
    assert be.point_eq(verifier_side, secret_side), "the identity should hold"
    # It holds -- but only the secret_side is cheap, and it needs c_i.
