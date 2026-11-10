"""Key recovery from a reused signing nonce, and a hedged-nonce defence.

The repaired scheme signs with ``z = t + c*u + sk*v``, where ``t`` is a fresh
random nonce, ``c`` the certificate secret and ``sk`` the user's secret key.
If a sensor's random-number generator repeats ``t`` (a stuck or re-seeded
RNG, a cloned VM or firmware image), every signature it makes under that
nonce is one more linear equation in the same unknowns.

How many signatures are needed differs by scheme and by attacker:

* Verma et al.: ``z = r2 + c + sk*v``.  The certificate term has coefficient 1,
  so ``r2 + c`` behaves as one unknown and **two** signatures give ``sk``.
* Qiao et al., outsider: ``c`` is scaled by the per-message hash ``u``, so it
  is a separate unknown.  Three unknowns (``t``, ``c``, ``sk``) need **three**
  signatures.  Two give one equation in ``c`` and ``sk``: every guess of
  ``sk`` fits some ``c``, and picking the right one is a discrete logarithm.
* Qiao et al., the KGC: it issued the certificate, so it already knows ``c``.
  **Two** signatures give it ``sk``, which is the key the scheme promises
  the KGC never learns.

This is the standard nonce-reuse attack on Schnorr-type signatures, applied
to this scheme.  ``sign_hedged`` is the usual defence (as in EdDSA and
RFC 6979): derive the nonce from the secret keys and the message, mixed with
the RNG output, so a broken RNG can no longer repeat a nonce across different
messages.  Verifiers need no change.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Sequence

from . import scheme as fixed
from . import verma
from .backend.base import Backend
from .hashing import H1, H2, _hash_to_scalar

DST_NONCE = b"CBAS-Qiao2023-v1-hedged-nonce"


class NonceReuseError(ValueError):
    """The signatures do not share a nonce, or are too few for this attacker."""


@contextmanager
def stuck_rng(backend: Backend, nonce):
    """Make ``backend.scalar_random()`` return ``nonce`` inside the block.

    Simulates a sensor whose RNG output repeats.  Only the instance is
    patched, so other backends are unaffected.
    """
    backend.scalar_random = lambda: nonce
    try:
        yield
    finally:
        del backend.scalar_random


@dataclass(frozen=True)
class RecoveredKeys:
    """Everything a signer holds: the reused nonce, ``c`` and ``sk``."""

    t: object
    c: object
    sk: object


def _coefficients(params: fixed.PublicParams, signer: fixed.Signer, message: bytes, T):
    be = params.be
    u = H2(be, message, signer.pk, signer.R, signer.identity, T, params.delta)
    v = H1(be, message, signer.pk, signer.R, signer.identity, T, params.delta)
    return u, v


def _check_shared_nonce(be: Backend, messages: Sequence[bytes], sigs, commitment, need: int):
    if len(messages) != len(sigs) or len(sigs) < need:
        raise NonceReuseError(f"need {need} signatures with their messages, got {len(sigs)}")
    if len(set(messages[:need])) < need:
        raise NonceReuseError("messages must be distinct; a repeated message adds no equation")
    first = commitment(sigs[0])
    if not all(be.point_eq(commitment(s), first) for s in sigs[:need]):
        raise NonceReuseError("the signatures use different nonces")


def recover_keys_outsider(
    params: fixed.PublicParams,
    signer: fixed.Signer,
    messages: Sequence[bytes],
    sigs: Sequence[fixed.Signature],
) -> RecoveredKeys:
    """Recover ``t``, ``c`` and ``sk`` from three signatures sharing one nonce.

    Uses only public data: the signer's identity, ``pk``, ``R`` and the
    signatures.  Solves the 3x3 system ``z_j = t + c*u_j + sk*v_j`` by
    Cramer's rule on the pairwise differences, then checks the answer against
    ``pk`` and the certificate equation, so a wrong answer is never returned.
    """
    be = params.be
    _check_shared_nonce(be, messages, sigs, lambda s: s.T, need=3)
    T = sigs[0].T
    (u1, v1), (u2, v2), (u3, v3) = (_coefficients(params, signer, m, T) for m in messages[:3])
    z1, z2, z3 = (s.z for s in sigs[:3])

    sub, mul = be.scalar_sub, be.scalar_mul
    a1, b1, d1 = sub(u1, u2), sub(v1, v2), sub(z1, z2)
    a2, b2, d2 = sub(u1, u3), sub(v1, v3), sub(z1, z3)
    det = sub(mul(a1, b2), mul(a2, b1))
    if be.scalar_is_zero(det):  # pragma: no cover - probability ~2^-252
        raise NonceReuseError("degenerate system")
    det_inv = be.scalar_invert(det)
    c = mul(sub(mul(d1, b2), mul(d2, b1)), det_inv)
    sk = mul(sub(mul(a1, d2), mul(a2, d1)), det_inv)
    t = sub(sub(z1, mul(c, u1)), mul(sk, v1))

    if not be.point_eq(be.point_mul_base(sk), signer.pk):  # pragma: no cover
        raise NonceReuseError("recovered sk does not match pk")
    if not fixed.cert_verify(params, signer.identity, signer.pk, fixed.Certificate(c=c, R=signer.R)):
        raise NonceReuseError("recovered c is not a valid certificate")  # pragma: no cover
    return RecoveredKeys(t=t, c=c, sk=sk)


def two_signature_solutions(
    params: fixed.PublicParams,
    signer: fixed.Signer,
    messages: Sequence[bytes],
    sigs: Sequence[fixed.Signature],
    sk_guess,
) -> RecoveredKeys:
    """For any guess of ``sk``, the ``(t, c)`` that make two signatures consistent.

    Every guess yields a solution consistent with both signatures.  Only one
    also satisfies ``sk*P == pk``, and testing guesses against that is
    exhaustive search: finding it is as hard as a discrete logarithm.
    """
    be = params.be
    _check_shared_nonce(be, messages, sigs, lambda s: s.T, need=2)
    T = sigs[0].T
    (u1, v1), (u2, v2) = (_coefficients(params, signer, m, T) for m in messages[:2])
    sub, mul = be.scalar_sub, be.scalar_mul
    # z1 - z2 = c*(u1 - u2) + sk*(v1 - v2), solved for c.
    c = mul(sub(sub(sigs[0].z, sigs[1].z), mul(sk_guess, sub(v1, v2))),
            be.scalar_invert(sub(u1, u2)))
    t = sub(sub(sigs[0].z, mul(c, u1)), mul(sk_guess, v1))
    return RecoveredKeys(t=t, c=c, sk=sk_guess)


def recover_sk_kgc(
    params: fixed.PublicParams,
    signer: fixed.Signer,
    cert: fixed.Certificate,
    messages: Sequence[bytes],
    sigs: Sequence[fixed.Signature],
):
    """The KGC recovers ``sk`` from two signatures sharing one nonce.

    The KGC issued ``cert`` and so knows ``c``; that removes one unknown.
    """
    be = params.be
    _check_shared_nonce(be, messages, sigs, lambda s: s.T, need=2)
    T = sigs[0].T
    (u1, v1), (u2, v2) = (_coefficients(params, signer, m, T) for m in messages[:2])
    sub, mul = be.scalar_sub, be.scalar_mul
    # z1 - z2 = c*(u1 - u2) + sk*(v1 - v2), solved for sk.
    sk = mul(sub(sub(sigs[0].z, sigs[1].z), mul(cert.c, sub(u1, u2))),
             be.scalar_invert(sub(v1, v2)))
    if not be.point_eq(be.point_mul_base(sk), signer.pk):  # pragma: no cover
        raise NonceReuseError("recovered sk does not match pk")
    return sk


def forge_with_keys(params: fixed.PublicParams, signer: fixed.Signer,
                    keys: RecoveredKeys, message: bytes) -> fixed.Signature:
    """Sign any message as the victim, using the recovered keys and a fresh nonce."""
    return fixed.sign(params, signer, keys.sk, fixed.Certificate(c=keys.c, R=signer.R), message)


@dataclass(frozen=True)
class VermaRecovery:
    """For Verma, ``r2 + c`` acts as one unknown, so ``sk`` and that sum suffice."""

    sk: object
    nonce_plus_c: object
    R: object


def recover_verma(
    params: verma.PublicParams,
    signer: verma.Signer,
    messages: Sequence[bytes],
    sigs: Sequence[verma.Signature],
) -> VermaRecovery:
    """Recover Verma's ``sk`` (and ``r2 + c``) from two signatures sharing a nonce."""
    be = params.be
    _check_shared_nonce(be, messages, sigs, lambda s: s.R, need=2)
    v1, v2 = (verma.H1(be, m, signer.pk, signer.identity, params.delta) for m in messages[:2])
    sub, mul = be.scalar_sub, be.scalar_mul
    sk = mul(sub(sigs[0].z, sigs[1].z), be.scalar_invert(sub(v1, v2)))
    if not be.point_eq(be.point_mul_base(sk), signer.pk):  # pragma: no cover
        raise NonceReuseError("recovered sk does not match pk")
    return VermaRecovery(sk=sk, nonce_plus_c=sub(sigs[0].z, mul(sk, v1)), R=sigs[0].R)


def forge_verma_with_keys(params: verma.PublicParams, signer: verma.Signer,
                          rec: VermaRecovery, message: bytes) -> verma.Signature:
    be = params.be
    v = verma.H1(be, message, signer.pk, signer.identity, params.delta)
    return verma.Signature(R=rec.R, z=be.scalar_add(rec.nonce_plus_c, be.scalar_mul(rec.sk, v)))


def sign_hedged(params: fixed.PublicParams, signer: fixed.Signer, sk,
                cert: fixed.Certificate, message: bytes) -> fixed.Signature:
    """``Sign`` with ``t = H(sk, c, m, ..., rng)`` instead of ``t = rng``.

    Same signing equation and the same signature format, so every verifier
    accepts it unchanged.  If the RNG repeats, ``t`` still differs for
    different messages, because the message is an input to the derivation.
    """
    be = params.be
    t = _hash_to_scalar(be, DST_NONCE, be.scalar_to_bytes(sk), be.scalar_to_bytes(cert.c),
                        message, be.point_to_bytes(signer.pk), be.point_to_bytes(signer.R),
                        signer.identity, params.delta, be.scalar_to_bytes(be.scalar_random()))
    T = be.point_mul_base(t)
    v = H1(be, message, signer.pk, signer.R, signer.identity, T, params.delta)
    u = H2(be, message, signer.pk, signer.R, signer.identity, T, params.delta)
    z = be.scalar_add(t, be.scalar_add(be.scalar_mul(cert.c, u), be.scalar_mul(sk, v)))
    return fixed.Signature(T=T, z=z)

