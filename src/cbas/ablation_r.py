"""A second controlled ablation: the R-binding removed, the T-binding kept.

**Not a real scheme. Never use this for anything.**

``ablation.py`` isolates Fix #2 (the nonce commitment ``T`` bound into ``H1``
and ``H2``) by removing it alone, and shows the *rescaling* forgery of
``attack.py`` succeeds against the result. That leaves open whether Fix #1
(``R`` bound into every hash) does any independent work, or whether Fix #2
alone would have sufficed.

This module is the complementary control: **Fix #1 removed, Fix #2 kept**.
``R`` is dropped as an input to ``H0``, ``H1`` and ``H2`` -- so the certificate
nonce is no longer bound to the certificate *or* the signature -- while ``T``
remains bound into ``H1``/``H2`` exactly as in the real scheme.

``tests/test_keyonly_attack.py`` shows the *key-only* forgery of
``keyonly_attack.py`` succeeds against this variant, while it fails against
both the real scheme and ``ablation.py``'s variant. Read together with
``ablation.py``, the two experiments show the corrections are independently
necessary, each closing a different attack:

               | R bound (Fix #1) | R not bound
    -----------|------------------|-------------
    T bound    | real scheme:     | this module:
    (Fix #2)   |   both closed    |   key-only forgery open
    -----------|------------------|-------------
    T not bound| ablation.py:     | Verma (real):
                |   rescaling open |   both open
"""

from __future__ import annotations

import hashlib
from typing import Sequence

from .backend.base import Backend
from .encoding import as_bytes, tlv_encode
from .scheme import (  # noqa: F401  (re-exported so the ablation is a drop-in)
    AggregateSignature,
    Certificate,
    MasterSecretKey,
    PublicParams,
    Signature,
    Signer,
    UserKeyPair,
    agg_sign,
    keygen,
    setup,
)

DST_H0_NO_R = b"ABLATION-noR-v1-H0-certificate"
DST_H1_NO_R = b"ABLATION-noR-v1-H1-signature-v"
DST_H2_NO_R = b"ABLATION-noR-v1-H2-signature-u"


def _hash_to_scalar(backend: Backend, dst: bytes, *fields):
    preimage = tlv_encode(dst, *(as_bytes(f) for f in fields))
    backend.note_hash(1)
    return backend.scalar_from_wide(hashlib.sha512(preimage).digest())


def H0_no_r(backend: Backend, identity, pk):
    """``H0`` with ``R`` removed -- Fix #1 ablated at certificate generation."""
    return _hash_to_scalar(backend, DST_H0_NO_R, identity, backend.point_to_bytes(pk))


def H1_no_r(backend: Backend, message, pk, identity, T, delta):
    """``H1`` with ``R`` removed, ``T`` kept -- Fix #1 ablated, Fix #2 intact."""
    return _hash_to_scalar(
        backend, DST_H1_NO_R, message, backend.point_to_bytes(pk),
        identity, backend.point_to_bytes(T), delta,
    )


def H2_no_r(backend: Backend, message, pk, identity, T, delta):
    """``H2`` with ``R`` removed, ``T`` kept -- Fix #1 ablated, Fix #2 intact."""
    return _hash_to_scalar(
        backend, DST_H2_NO_R, message, backend.point_to_bytes(pk),
        identity, backend.point_to_bytes(T), delta,
    )


def cert_gen(params: PublicParams, msk: MasterSecretKey, identity: bytes, pk) -> Certificate:
    """Identical to the real CertGen, except ``H0`` does not see ``R``."""
    be = params.be
    r = be.scalar_random()
    R = be.point_mul_base(r)
    h0 = H0_no_r(be, identity, pk)              # Fix #1 ablated: R not bound
    c = be.scalar_add(r, be.scalar_mul(msk.s, h0))
    return Certificate(c=c, R=R)


def sign(params: PublicParams, signer: Signer, sk, cert: Certificate, message: bytes) -> Signature:
    """Identical to the real Sign, except ``H1``/``H2`` do not see ``R``."""
    be = params.be
    t = be.scalar_random()
    T = be.point_mul_base(t)
    v = H1_no_r(be, message, signer.pk, signer.identity, T, params.delta)
    u = H2_no_r(be, message, signer.pk, signer.identity, T, params.delta)
    z = be.scalar_add(t, be.scalar_add(be.scalar_mul(cert.c, u), be.scalar_mul(sk, v)))
    return Signature(T=T, z=z)


def agg_verify(
    params: PublicParams,
    signers: Sequence[Signer],
    messages: Sequence[bytes],
    aggsig: AggregateSignature,
) -> bool:
    """The real verification equation, with the R-less ablated hashes."""
    be = params.be
    n = len(signers)
    if not (n == len(messages) == len(aggsig.T)) or n == 0:
        raise ValueError("length mismatch or empty aggregate")

    lhs = be.point_mul_base(aggsig.z)
    uR, vpk, uh_acc = [], [], None
    for signer, message, T in zip(signers, messages, aggsig.T):
        h0 = H0_no_r(be, signer.identity, signer.pk)
        v = H1_no_r(be, message, signer.pk, signer.identity, T, params.delta)
        u = H2_no_r(be, message, signer.pk, signer.identity, T, params.delta)
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


def attempt_solve_for_t_ablation_r(
    params: PublicParams,
    identity: bytes,
    pk,
    R_seed,
    target_message: bytes,
    z=None,
    max_iterations: int = 16,
) -> dict:
    """Complementary check: Fix #2 is intact here, so solving for T should fail.

    H1_no_r and H2_no_r both take T as an input, so holding R fixed and trying
    to solve for T hits the same fixed-point circularity as the real scheme.
    Attempted rather than assumed.
    """
    be = params.be
    z = z if z is not None else be.scalar_from_int(0)
    R = R_seed
    T = R_seed
    trace = []

    for k in range(1, max_iterations + 1):
        h0 = H0_no_r(be, identity, pk)
        v = H1_no_r(be, target_message, pk, identity, T, params.delta)
        u = H2_no_r(be, target_message, pk, identity, T, params.delta)
        T_required = be.point_sub(
            be.point_mul_base(z),
            be.point_add(be.point_mul(u, R),
                         be.point_add(be.point_mul(u, be.point_mul(h0, params.pk_ta)),
                                      be.point_mul(v, pk))),
        )
        trace.append(be.point_to_bytes(T_required)[:8].hex())
        if be.point_eq(T_required, T):
            sig = Signature(T=T, z=z)
            fake = Signer(identity=identity, pk=pk, R=R)
            if verify_single(params, fake, target_message, sig):
                return {"succeeded": True, "iterations": k, "trace": trace}
        T = T_required

    return {"succeeded": False, "iterations": max_iterations, "trace": trace,
           "reason": "T is bound into H1_no_r and H2_no_r here (Fix #2 intact); "
                     "the iteration does not settle."}


def forge_keyonly(
    params: PublicParams,
    identity: bytes,
    pk,
    target_message: bytes,
    z=None,
) -> Signature:
    """The key-only forgery, adapted to this ablation's verify equation.

    ``z*P = T + u*R + u*h0*P_TA + v*pk``. With ``R`` removed from every hash,
    ``h0``, ``u`` and ``v`` are all computable from public data before ``R`` is
    chosen -- exactly the property that made Verma's scheme breakable this way.
    Unlike Verma, ``R`` here has coefficient ``u`` rather than 1, so recovering
    it needs one scalar inversion, not just point subtraction; the attack is no
    harder for that.
    """
    be = params.be
    z = z if z is not None else be.scalar_from_int(0)
    t = be.scalar_random()
    T = be.point_mul_base(t)

    h0 = H0_no_r(be, identity, pk)
    v = H1_no_r(be, target_message, pk, identity, T, params.delta)
    u = H2_no_r(be, target_message, pk, identity, T, params.delta)

    rhs = be.point_sub(
        be.point_mul_base(z),
        be.point_add(T, be.point_add(be.point_mul(u, be.point_mul(h0, params.pk_ta)),
                                     be.point_mul(v, pk))),
    )
    R_forged = be.point_mul(be.scalar_invert(u), rhs)
    return Signature(T=T, z=z), R_forged
