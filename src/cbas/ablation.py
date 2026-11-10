"""Deliberately weakened variants of the repaired scheme, for controlled experiments.

**Not a real scheme. Never use this for anything.**

The repaired scheme makes three changes to Verma et al.'s CB-CAS at once:

    Fix #1  R_i is hashed into H0 at certificate generation
    Fix #2  the nonce commitment T_i is hashed into both H1 and H2
    Fix #3  the certificate term is scaled by u, the secret-key term by v,
            using two independent random oracles

Showing that the forgery works on Verma and fails on the repaired scheme does
not by itself say *which* change is responsible.  This module supplies the
control: the repaired scheme with **Fix #2 alone removed** -- ``T_i`` dropped
from ``H1`` and ``H2``, everything else untouched.

If the forgery succeeds here and nowhere else, Fix #2 is the load-bearing
change.  See ``tests/test_forgery.py::test_ablating_fix2_restores_the_forgery``.
"""

from __future__ import annotations

import hashlib
from typing import Sequence

from .backend.base import Backend
from .encoding import as_bytes, tlv_encode
from .hashing import H0  # Fix #1 left intact
from .scheme import (  # noqa: F401  (re-exported so the ablation is a drop-in)
    AggregateSignature,
    Certificate,
    MasterSecretKey,
    PublicParams,
    Signature,
    Signer,
    UserKeyPair,
    agg_sign,
    cert_gen,
    keygen,
    setup,
)

DST_H1_ABLATED = b"ABLATION-noT-v1-H1-signature-v"
DST_H2_ABLATED = b"ABLATION-noT-v1-H2-signature-u"


def _hash_to_scalar(backend: Backend, dst: bytes, *fields):
    preimage = tlv_encode(dst, *(as_bytes(f) for f in fields))
    backend.note_hash(1)
    return backend.scalar_from_wide(hashlib.sha512(preimage).digest())


def H1_ablated(backend: Backend, message, pk, R, identity, delta):
    """``H1`` with ``T`` removed -- Fix #2 ablated."""
    return _hash_to_scalar(
        backend, DST_H1_ABLATED, message,
        backend.point_to_bytes(pk), backend.point_to_bytes(R), identity, delta,
    )


def H2_ablated(backend: Backend, message, pk, R, identity, delta):
    """``H2`` with ``T`` removed -- Fix #2 ablated."""
    return _hash_to_scalar(
        backend, DST_H2_ABLATED, message,
        backend.point_to_bytes(pk), backend.point_to_bytes(R), identity, delta,
    )


def sign(params: PublicParams, signer: Signer, sk, cert: Certificate, message: bytes) -> Signature:
    """Identical to the real Sign except that ``T`` is not hashed in."""
    be = params.be
    t = be.scalar_random()
    T = be.point_mul_base(t)
    v = H1_ablated(be, message, signer.pk, signer.R, signer.identity, params.delta)
    u = H2_ablated(be, message, signer.pk, signer.R, signer.identity, params.delta)
    z = be.scalar_add(t, be.scalar_add(be.scalar_mul(cert.c, u), be.scalar_mul(sk, v)))
    return Signature(T=T, z=z)


def agg_verify(
    params: PublicParams,
    signers: Sequence[Signer],
    messages: Sequence[bytes],
    aggsig: AggregateSignature,
) -> bool:
    """The real verification equation, with the ablated hashes."""
    be = params.be
    n = len(signers)
    if not (n == len(messages) == len(aggsig.T)) or n == 0:
        raise ValueError("length mismatch or empty aggregate")

    lhs = be.point_mul_base(aggsig.z)
    uR, vpk, uh_acc = [], [], None
    for signer, message, T in zip(signers, messages, aggsig.T):
        h0 = H0(be, signer.identity, signer.pk, signer.R)
        v = H1_ablated(be, message, signer.pk, signer.R, signer.identity, params.delta)
        u = H2_ablated(be, message, signer.pk, signer.R, signer.identity, params.delta)
        uR.append(be.point_mul(u, signer.R))
        vpk.append(be.point_mul(v, signer.pk))
        uh = be.scalar_mul(u, h0)
        uh_acc = uh if uh_acc is None else be.scalar_add(uh_acc, uh)

    rhs = be.point_add(be.sum_points(aggsig.T), be.sum_points(uR))
    rhs = be.point_add(rhs, be.point_mul(uh_acc, params.pk_ta))
    rhs = be.point_add(rhs, be.sum_points(vpk))
    return be.point_eq(lhs, rhs)


def verify_single(params: PublicParams, signer: Signer, message: bytes, sig: Signature) -> bool:
    return agg_verify(params, [signer], [message], AggregateSignature(T=(sig.T,), z=sig.z))


def forge_keyonly_via_t(
    params: PublicParams,
    identity: bytes,
    pk,
    R,
    target_message: bytes,
    z=None,
):
    """A key-only forgery against THIS ablation, solving for T instead of R.

    Fix #1 (R bound into every hash) is intact here, so ``keyonly_attack.py``'s
    R-solving technique is blocked -- confirmed below by
    ``attempt_solve_for_r_ablated``, which does not converge. But Fix #2 is
    removed: T is *not* an input to ``H1_ablated``/``H2_ablated``. That leaves
    T, not R, as the free variable -- h0, u and v are all computable once
    (id, pk, R, m) are fixed, none of them needing T, so the verify equation is
    a plain linear statement in T:

        T := z*P - u*R - u*h0*P_TA - v*pk

    No observed signature is needed (contrast ``forge_ablated`` above, which
    needs one), and no secret key. ``R`` can be any point at all, including a
    real, honestly-published victim's -- the certificate is never checked
    against it. This is a *stronger* break of this ablation than the
    rescaling attack it was built to demonstrate: fewer capabilities are
    needed to mount it.
    """
    be = params.be
    z = z if z is not None else be.scalar_from_int(0)
    h0 = H0(be, identity, pk, R)
    v = H1_ablated(be, target_message, pk, R, identity, params.delta)
    u = H2_ablated(be, target_message, pk, R, identity, params.delta)
    T = be.point_sub(
        be.point_mul_base(z),
        be.point_add(be.point_mul(u, R),
                     be.point_add(be.point_mul(u, be.point_mul(h0, params.pk_ta)),
                                  be.point_mul(v, pk))),
    )
    return Signature(T=T, z=z)


def attempt_solve_for_r_ablated(
    params: PublicParams,
    identity: bytes,
    pk,
    T_seed,
    target_message: bytes,
    z=None,
    max_iterations: int = 16,
) -> dict:
    """The complementary check: Fix #1 is intact, so solving for R should fail.

    Attempted for completeness, so the claim that "R is still protected here"
    rests on a failed attempt rather than an assertion. h0 and v (H1_ablated
    includes R) both depend on R, so this is the same fixed-point circularity
    as the real scheme -- just checked against this specific variant.
    """
    be = params.be
    z = z if z is not None else be.scalar_from_int(0)
    T = T_seed
    R = T_seed  # arbitrary seed; any starting point is as good as another
    trace = []

    for k in range(1, max_iterations + 1):
        h0 = H0(be, identity, pk, R)
        v = H1_ablated(be, target_message, pk, R, identity, params.delta)
        u = H2_ablated(be, target_message, pk, R, identity, params.delta)
        if be.scalar_is_zero(u):  # pragma: no cover
            break
        rhs = be.point_sub(
            be.point_mul_base(z),
            be.point_add(T, be.point_add(be.point_mul(u, be.point_mul(h0, params.pk_ta)),
                                         be.point_mul(v, pk))),
        )
        R_required = be.point_mul(be.scalar_invert(u), rhs)
        trace.append(be.point_to_bytes(R_required)[:8].hex())
        if be.point_eq(R_required, R):
            sig = Signature(T=T, z=z)
            fake = Signer(identity=identity, pk=pk, R=R)
            if verify_single(params, fake, target_message, sig):
                return {"succeeded": True, "iterations": k, "trace": trace}
        R = R_required

    return {"succeeded": False, "iterations": max_iterations, "trace": trace,
           "reason": "R is bound into H0 and H1_ablated here (Fix #1 intact); "
                     "the iteration does not settle."}


def forge_ablated(
    params: PublicParams,
    signer: Signer,
    cert: Certificate,
    observed_message: bytes,
    observed_sig: Signature,
    target_message: bytes,
) -> Signature:
    """The rescaling forgery, which succeeds once Fix #2 is removed.

    With ``T`` out of the hashes, ``v'`` and ``u'`` for the target message are
    computable immediately, so the circularity that defeats the attack against
    the real scheme is gone and the Verma rescaling goes through unchanged.
    """
    be = params.be
    v = H1_ablated(be, observed_message, signer.pk, signer.R, signer.identity, params.delta)
    u = H2_ablated(be, observed_message, signer.pk, signer.R, signer.identity, params.delta)

    # w = t + sk*v, after stripping the certificate term.
    w = be.scalar_sub(observed_sig.z, be.scalar_mul(cert.c, u))

    v2 = H1_ablated(be, target_message, signer.pk, signer.R, signer.identity, params.delta)
    u2 = H2_ablated(be, target_message, signer.pk, signer.R, signer.identity, params.delta)

    ratio = be.scalar_mul(v2, be.scalar_invert(v))
    T_forged = be.point_mul(ratio, observed_sig.T)
    z_forged = be.scalar_add(be.scalar_mul(ratio, w), be.scalar_mul(cert.c, u2))
    return Signature(T=T_forged, z=z_forged)
