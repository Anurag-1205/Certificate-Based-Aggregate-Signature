"""Aggregate verification via multi-scalar multiplication.

``scheme.agg_verify`` is a direct transliteration of the paper: it evaluates
each term separately, costing ``2n+2`` scalar multiplications. That is the
algorithm the paper's Tables II and III describe, and it stays untouched so the
cost analysis has a faithful reference to measure.

This module implements the same check as a single multi-scalar multiplication.
The verification equation

    z*P == sum(T_i) + sum(u_i R_i) + (sum u_i h_i0) P_TA + sum(v_i pk_i)

is rearranged so that everything is on one side:

    z*P - sum(u_i R_i) - (sum u_i h_i0) P_TA - sum(v_i pk_i) - sum(T_i) == O

which is exactly the form ``multi_scalar_mul`` evaluates: a fixed-base term plus
a weighted sum of points, tested against the identity. A backend with a native
multi-scalar routine computes the whole sum in one call.

Verma's scheme is given the same treatment. A comparison between an optimised
implementation of one scheme and a naive implementation of the other would be
worthless, so both are optimised the same way.

Correctness is not assumed: ``tests/test_optimized.py`` checks the optimised
path against the naive one on every backend, for valid signatures and for each
kind of tampering.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from . import verma as _verma
from .hashing import H0, H0_bytes, H1, H1_bytes, H2, H2_bytes
from .scheme import (
    AggregateSignature,
    Certificate,
    PublicParams,
    Signature,
    Signer,
)


def agg_verify_msm(
    params: PublicParams,
    signers: Sequence[Signer],
    messages: Sequence[bytes],
    aggsig: AggregateSignature,
) -> bool:
    """Verify an aggregate signature using one multi-scalar multiplication."""
    be = params.be
    n = len(signers)
    if not (n == len(messages) == len(aggsig.T)):
        raise ValueError(
            f"length mismatch: {n} signers, {len(messages)} messages, {len(aggsig.T)} commitments"
        )
    if n == 0:
        raise ValueError("cannot verify an empty aggregate")

    one = be.scalar_from_int(1)
    points, scalars = [], []
    uh_acc = None

    for signer, message, T in zip(signers, messages, aggsig.T):
        h0 = H0(be, signer.identity, signer.pk, signer.R)
        v = H1(be, message, signer.pk, signer.R, signer.identity, T, params.delta)
        u = H2(be, message, signer.pk, signer.R, signer.identity, T, params.delta)

        points += [signer.R, signer.pk, T]
        scalars += [u, v, one]

        uh = be.scalar_mul(u, h0)
        uh_acc = uh if uh_acc is None else be.scalar_add(uh_acc, uh)

    points.append(params.pk_ta)
    scalars.append(uh_acc)

    # Scalars are kept positive and the sum compared against z*P, rather than
    # negating all 3n+1 of them to test for the identity: one extra scalar
    # multiplication is cheaper than 3n+1 field negations.
    rhs = be.multi_scalar_mul(None, points, scalars)
    return be.point_eq(be.point_mul_base(aggsig.z), rhs)


@dataclass(frozen=True)
class PreparedSigner:
    """A signer with its invariant work done once.

    ``pk`` and ``R`` never change for an enrolled sensor, so their encodings and
    the hash ``h0 = H0(id || pk || R)`` are fixed for the lifetime of the
    certificate. An industrial deployment verifies repeated batches from a
    fixed roster of sensors, so this work is pure repetition -- and point
    encoding dominated a profile of the unprepared path.
    """

    signer: Signer
    pk_bytes: bytes
    R_bytes: bytes
    h0: object


def prepare(params: PublicParams, signers: Sequence[Signer]) -> list[PreparedSigner]:
    """Precompute the per-signer invariants. Do this once per roster."""
    be = params.be
    out = []
    for signer in signers:
        pk_b = be.point_to_bytes(signer.pk)
        R_b = be.point_to_bytes(signer.R)
        out.append(PreparedSigner(
            signer=signer, pk_bytes=pk_b, R_bytes=R_b,
            h0=H0_bytes(be, signer.identity, pk_b, R_b),
        ))
    return out


def agg_verify_prepared(
    params: PublicParams,
    prepared: Sequence[PreparedSigner],
    messages: Sequence[bytes],
    aggsig: AggregateSignature,
) -> bool:
    """Aggregate verification against a precomputed roster.

    Identical in result to :func:`agg_verify_msm`; it differs only in reusing
    the invariants rather than recomputing them. ``H0`` disappears from the hot
    path entirely, and point encoding drops from eight calls per signer to one.
    """
    be = params.be
    n = len(prepared)
    if not (n == len(messages) == len(aggsig.T)):
        raise ValueError(
            f"length mismatch: {n} signers, {len(messages)} messages, {len(aggsig.T)} commitments"
        )
    if n == 0:
        raise ValueError("cannot verify an empty aggregate")

    one = be.scalar_from_int(1)
    delta = params.delta
    points, scalars = [], []
    uh_acc = None

    for ps, message, T in zip(prepared, messages, aggsig.T):
        T_b = be.point_to_bytes(T)
        pk_b, R_b, ident = ps.pk_bytes, ps.R_bytes, ps.signer.identity
        v = H1_bytes(be, message, pk_b, R_b, ident, T_b, delta)
        u = H2_bytes(be, message, pk_b, R_b, ident, T_b, delta)

        points += [ps.signer.R, ps.signer.pk, T]
        scalars += [u, v, one]

        uh = be.scalar_mul(u, ps.h0)
        uh_acc = uh if uh_acc is None else be.scalar_add(uh_acc, uh)

    points.append(params.pk_ta)
    scalars.append(uh_acc)

    rhs = be.multi_scalar_mul(None, points, scalars)
    return be.point_eq(be.point_mul_base(aggsig.z), rhs)


def verify_single_msm(params: PublicParams, signer: Signer,
                      message: bytes, sig: Signature) -> bool:
    return agg_verify_msm(params, [signer], [message],
                          AggregateSignature(T=(sig.T,), z=sig.z))


def verma_agg_verify_msm(
    params: "_verma.PublicParams",
    signers: Sequence["_verma.Signer"],
    messages: Sequence[bytes],
    aggsig: "_verma.AggregateSignature",
) -> bool:
    """The same optimisation applied to Verma et al.'s scheme.

    Its equation ``z*P == R + (sum h_i0) P_TA + sum(v_i pk_i)`` rearranges to
    ``z*P - sum(v_i pk_i) - (sum h_i0) P_TA - R == O``, an MSM over ``n+2``
    points against this scheme's ``3n+1``. Optimising only one of the two would
    make any comparison between them meaningless.
    """
    be = params.be
    n = len(signers)
    if n != len(messages):
        raise ValueError(f"{n} signers but {len(messages)} messages")
    if n == 0:
        raise ValueError("cannot verify an empty aggregate")

    one = be.scalar_from_int(1)
    points, scalars = [], []
    h_acc = None

    for signer, message in zip(signers, messages):
        h0 = _verma.H0(be, signer.identity, signer.pk)
        v = _verma.H1(be, message, signer.pk, signer.identity, params.delta)
        points.append(signer.pk)
        scalars.append(v)
        h_acc = h0 if h_acc is None else be.scalar_add(h_acc, h0)

    points.append(params.pk_ta)
    scalars.append(h_acc)
    points.append(aggsig.R)
    scalars.append(one)

    rhs = be.multi_scalar_mul(None, points, scalars)
    return be.point_eq(be.point_mul_base(aggsig.z), rhs)


@dataclass(frozen=True)
class PreparedVermaSigner:
    """Verma's per-signer invariants, cached on the same terms.

    Its ``h0 = H0(id || pk)`` is static for exactly the same reason, so the
    optimisation applies equally. Comparing an optimised implementation of one
    scheme against an unoptimised implementation of the other would produce a
    ratio that says more about the implementations than about the schemes, so
    both get the same treatment.
    """

    signer: "_verma.Signer"
    pk_bytes: bytes
    h0: object


def verma_prepare(params: "_verma.PublicParams",
                  signers: Sequence["_verma.Signer"]) -> list[PreparedVermaSigner]:
    be = params.be
    out = []
    for signer in signers:
        pk_b = be.point_to_bytes(signer.pk)
        out.append(PreparedVermaSigner(
            signer=signer, pk_bytes=pk_b,
            h0=_verma.H0_bytes(be, signer.identity, pk_b),
        ))
    return out


def verma_agg_verify_prepared(
    params: "_verma.PublicParams",
    prepared: Sequence[PreparedVermaSigner],
    messages: Sequence[bytes],
    aggsig: "_verma.AggregateSignature",
) -> bool:
    """Verma's aggregate verification against a precomputed roster."""
    be = params.be
    n = len(prepared)
    if n != len(messages):
        raise ValueError(f"{n} signers but {len(messages)} messages")
    if n == 0:
        raise ValueError("cannot verify an empty aggregate")

    one = be.scalar_from_int(1)
    delta = params.delta
    points, scalars = [], []
    h_acc = None

    for ps, message in zip(prepared, messages):
        v = _verma.H1_bytes(be, message, ps.pk_bytes, ps.signer.identity, delta)
        points.append(ps.signer.pk)
        scalars.append(v)
        h_acc = ps.h0 if h_acc is None else be.scalar_add(h_acc, ps.h0)

    points.append(params.pk_ta)
    scalars.append(h_acc)
    points.append(aggsig.R)
    scalars.append(one)

    rhs = be.multi_scalar_mul(None, points, scalars)
    return be.point_eq(be.point_mul_base(aggsig.z), rhs)


# ---------------------------------------------------------------------------
# Signer side
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SigningContext:
    """A sensor's invariant signing state.

    In this setting the sensors are the constrained devices, so the signer side
    is where saved work matters most. ``Sign`` hashes ``pk``, ``R`` and ``T``
    into each of ``H1`` and ``H2``, which means six point encodings per
    signature -- and four of them re-encode values that never change for the
    lifetime of the certificate.

    Holding the encodings leaves one encoding per signature, for the fresh
    nonce commitment ``T``, which is the only part that genuinely varies.
    """

    signer: Signer
    sk: object
    cert: "Certificate"
    pk_bytes: bytes
    R_bytes: bytes


def prepare_signing(params: PublicParams, signer: Signer, sk,
                    cert: "Certificate") -> SigningContext:
    """Compute a sensor's invariant signing state once, at enrolment."""
    be = params.be
    return SigningContext(
        signer=signer, sk=sk, cert=cert,
        pk_bytes=be.point_to_bytes(signer.pk),
        R_bytes=be.point_to_bytes(cert.R),
    )


def sign_prepared(params: PublicParams, ctx: SigningContext, message: bytes) -> Signature:
    """Sign using precomputed encodings.

    Identical in output distribution to :func:`cbas.scheme.sign`; the nonce is
    still drawn fresh for every signature, so the scheme's replay resistance is
    unaffected.
    """
    be = params.be
    t = be.scalar_random()
    T = be.point_mul_base(t)
    T_bytes = be.point_to_bytes(T)
    ident, delta = ctx.signer.identity, params.delta

    v = H1_bytes(be, message, ctx.pk_bytes, ctx.R_bytes, ident, T_bytes, delta)
    u = H2_bytes(be, message, ctx.pk_bytes, ctx.R_bytes, ident, T_bytes, delta)
    z = be.scalar_add(t, be.scalar_add(be.scalar_mul(ctx.cert.c, u),
                                       be.scalar_mul(ctx.sk, v)))
    return Signature(T=T, z=z)


#: How many MSM terms each scheme's aggregate verification requires.
MSM_TERMS = {"cbas": lambda n: 3 * n + 1, "verma": lambda n: n + 2}
