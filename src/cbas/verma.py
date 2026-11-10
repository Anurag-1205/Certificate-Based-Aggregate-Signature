"""Verma et al.'s CB-CAS scheme (IEEE Internet of Things Journal, 2020).

    G. K. Verma, B. B. Singh, N. Kumar, V. Chamola, "CB-CAS: Certificate-Based
    Efficient Signature Scheme With Compact Aggregation for Industrial Internet
    of Things Environment," IEEE IoT-J 7(4):2563-2572, 2020.

This scheme is **insecure** and is implemented here only so that the attack in
``attack.py`` can be run against it.  Do not use it.

Reviewed as Section IV-A of Qiao et al.  The flaw is on one line::

    v_i = H1(m_i || pk_i || id_i || D)

The per-signature randomness ``r_2i`` -- and its commitment ``R_i`` -- is *not*
hashed in.  That omission is deliberate: leaving ``R_i`` out of the hash is what
lets every ``R_i`` be summed into a single point, giving a **constant-size**
aggregate signature (``1|G| + 1|Z_q*|`` regardless of ``n``).  It is also
precisely what breaks the scheme.  Because ``v_i`` does not depend on the nonce,
the signing equation is affine in a coefficient the attacker knows, and an
affine relation with a known coefficient can be rescaled to any other
coefficient.  See ``attack.py``.

The independent analysis of Xiong et al. (IACR ePrint 2020/1027) reaches the
same conclusion about this scheme by a different route.

Encoding note: this implementation uses the same length-prefixed TLV and
domain-separated hashing discipline as the secure scheme.  That is deliberate --
it ensures the forgery demonstrates a genuine *scheme-level* break rather than
an artefact of sloppy encoding.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence

from .backend.base import Backend
from .encoding import as_bytes, tlv_encode

DST_H0 = b"VERMA-CBCAS2020-v1-H0-certificate"
DST_H1 = b"VERMA-CBCAS2020-v1-H1-signature-v"


def _hash_to_scalar(backend: Backend, dst: bytes, *fields):
    preimage = tlv_encode(dst, *(as_bytes(f) for f in fields))
    backend.note_hash(1)
    return backend.scalar_from_wide(hashlib.sha512(preimage).digest())


def H0_bytes(backend: Backend, identity, pk_bytes: bytes):
    return _hash_to_scalar(backend, DST_H0, identity, pk_bytes)


def H1_bytes(backend: Backend, message, pk_bytes: bytes, identity, delta):
    return _hash_to_scalar(backend, DST_H1, message, pk_bytes, identity, delta)


def H0(backend: Backend, identity, pk):
    """``H0(id || pk)``.  Note: no R, unlike the repaired scheme."""
    return H0_bytes(backend, identity, backend.point_to_bytes(pk))


def H1(backend: Backend, message, pk, identity, delta):
    """``H1(m || pk || id || D)``.  Note: **no T, no R** -- this is the flaw."""
    return H1_bytes(backend, message, backend.point_to_bytes(pk), identity, delta)


# --------------------------------------------------------------------------

@dataclass(frozen=True)
class PublicParams:
    backend: Backend
    pk_ta: object
    delta: bytes = b""

    @property
    def be(self) -> Backend:
        return self.backend


@dataclass(frozen=True)
class MasterSecretKey:
    s: object


@dataclass(frozen=True)
class UserKeyPair:
    sk: object
    pk: object


@dataclass(frozen=True)
class Certificate:
    """``Cert_i = (R1_i, c_i)``.  Known to the KGC, which issued it."""

    R1: object
    c: object


@dataclass(frozen=True)
class Signer:
    identity: bytes
    pk: object


@dataclass(frozen=True)
class Signature:
    R: object
    z: object


@dataclass(frozen=True)
class AggregateSignature:
    """Constant size: one group element and one scalar, for any ``n``."""

    R: object
    z: object


# --------------------------------------------------------------------------

def setup(backend: Backend, delta: bytes = b"epoch-0"):
    s = backend.scalar_random()
    return PublicParams(backend, backend.point_mul_base(s), delta), MasterSecretKey(s)


def keygen(params: PublicParams) -> UserKeyPair:
    be = params.be
    sk = be.scalar_random()
    return UserKeyPair(sk=sk, pk=be.point_mul_base(sk))


def cert_gen(params: PublicParams, msk: MasterSecretKey, identity: bytes, pk) -> Certificate:
    """``c_i = r1_i + s*H0(id||pk)``; note H0 does not bind R1_i."""
    be = params.be
    r1 = be.scalar_random()
    R1 = be.point_mul_base(r1)
    h0 = H0(be, identity, pk)
    return Certificate(R1=R1, c=be.scalar_add(r1, be.scalar_mul(msk.s, h0)))


def sign(params: PublicParams, signer: Signer, sk, cert: Certificate, message: bytes) -> Signature:
    """``R_i = R1_i + r2_i*P``;  ``z_i = r2_i + c_i + sk_i*v_i``."""
    be = params.be
    r2 = be.scalar_random()
    R = be.point_add(cert.R1, be.point_mul_base(r2))
    v = H1(be, message, signer.pk, signer.identity, params.delta)
    z = be.scalar_add(r2, be.scalar_add(cert.c, be.scalar_mul(sk, v)))
    return Signature(R=R, z=z)


def agg_sign(params: PublicParams, signatures: Sequence[Signature]) -> AggregateSignature:
    """``R = sum R_i``, ``z = sum z_i`` -- a genuinely constant-size aggregate."""
    be = params.be
    if not signatures:
        raise ValueError("cannot aggregate an empty signature list")
    return AggregateSignature(
        R=be.sum_points([s.R for s in signatures]),
        z=be.sum_scalars([s.z for s in signatures]),
    )


def agg_verify(
    params: PublicParams,
    signers: Sequence[Signer],
    messages: Sequence[bytes],
    aggsig: AggregateSignature,
) -> bool:
    """``zP == R + (sum h_i0)*P_TA + sum(v_i * pk_i)``."""
    be = params.be
    n = len(signers)
    if n != len(messages):
        raise ValueError(f"{n} signers but {len(messages)} messages")
    if n == 0:
        raise ValueError("cannot verify an empty aggregate")

    lhs = be.point_mul_base(aggsig.z)                                  # 1 Te

    h_acc, vpk_terms = None, []
    for signer, message in zip(signers, messages):
        h0 = H0(be, signer.identity, signer.pk)                        # Th
        v = H1(be, message, signer.pk, signer.identity, params.delta)  # Th
        vpk_terms.append(be.point_mul(v, signer.pk))                   # Te
        h_acc = h0 if h_acc is None else be.scalar_add(h_acc, h0)

    rhs = be.point_add(aggsig.R, be.point_mul(h_acc, params.pk_ta))    # Te, Ta
    rhs = be.point_add(rhs, be.sum_points(vpk_terms))                  # (n-1)+1 Ta

    return be.point_eq(lhs, rhs)


def verify_single(params: PublicParams, signer: Signer, message: bytes, sig: Signature) -> bool:
    return agg_verify(
        params, [signer], [message], AggregateSignature(R=sig.R, z=sig.z)
    )
