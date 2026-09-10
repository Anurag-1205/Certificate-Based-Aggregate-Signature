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
