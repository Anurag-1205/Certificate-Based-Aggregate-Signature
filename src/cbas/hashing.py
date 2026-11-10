"""Domain-separated hash-to-scalar functions H0, H1, H2.

Why the domain separation is load-bearing
-----------------------------------------
The security proof models ``H0``, ``H1`` and ``H2`` as three **independent**
random oracles.  In the paper, ``H1`` and ``H2`` are given *identical* domains
and are applied to *identical* inputs::

    v_i = H1(m_i || pk_i || R_i || id_i || T_i || D)
    u_i = H2(m_i || pk_i || R_i || id_i || T_i || D)

So an implementation that instantiates both as, say, plain SHA-256 of that
string gets ``u_i == v_i``.  That is not a small inefficiency -- it collapses
the scheme's third fix.  The construction's whole improvement over Verma et
al. is that the certificate term is carried by ``u_i`` and the secret-key term
by ``v_i``, two *independent* random-oracle coefficients; that separation is
what lets the proof fork ``H0`` to extract the master key and fork ``H1`` to
extract the user's secret key.  Collapse ``u`` and ``v`` into one value and the
two-sided reduction no longer applies.

We therefore give each oracle a distinct domain separation tag, and
``tests/test_hashing.py`` asserts ``u != v`` on identical input.

Unbiased reduction
------------------
Each oracle is SHA-512 over the DST-tagged TLV encoding, giving exactly the 64
bytes that ``crypto_core_ristretto255_scalar_reduce`` consumes.  Wide reduction
of 64 bytes into a 253-bit field leaves bias below 2^-250, so there is no
modular bias and no variable-time rejection sampling.
"""

from __future__ import annotations

import hashlib

from .backend.base import Backend
from .encoding import as_bytes, tlv_encode

#: Versioned domain separation tags.  Changing these changes every signature,
#: so they are part of the scheme's wire format and must not drift.
DST_H0 = b"CBAS-Qiao2023-v1-H0-certificate"
DST_H1 = b"CBAS-Qiao2023-v1-H1-signature-v"
DST_H2 = b"CBAS-Qiao2023-v1-H2-signature-u"

ALL_DSTS = (DST_H0, DST_H1, DST_H2)


class HashError(Exception):
    """A hash output fell outside Z_p* (astronomically unlikely)."""


def _hash_to_scalar(backend: Backend, dst: bytes, *fields):
    """SHA-512 over ``tlv(dst, *fields)``, wide-reduced into Z_p*."""
    preimage = tlv_encode(dst, *(as_bytes(f) for f in fields))
    digest = hashlib.sha512(preimage).digest()
    backend.note_hash(1)
    s = backend.scalar_from_wide(digest)
    if backend.scalar_is_zero(s):
        # Probability ~2^-252.  The scheme requires Z_p*, so refuse rather than
        # silently producing a degenerate signature.
        raise HashError(f"hash to zero for dst={dst!r}")
    return s


# The ``*_bytes`` variants take points already encoded, so a caller holding a
# static signer roster can encode each public key and certificate nonce once
# rather than on every verification. Point encoding is not free -- it dominated
# a profile of aggregate verification -- and the encodings never change. The
# convenience wrappers below call straight through, so the two paths cannot
# drift apart and produce different hashes.

def H0_bytes(backend: Backend, identity, pk_bytes: bytes, R_bytes: bytes):
    return _hash_to_scalar(backend, DST_H0, identity, pk_bytes, R_bytes)


def H1_bytes(backend: Backend, message, pk_bytes: bytes, R_bytes: bytes,
             identity, T_bytes: bytes, delta):
    return _hash_to_scalar(backend, DST_H1, message, pk_bytes, R_bytes,
                           identity, T_bytes, delta)


def H2_bytes(backend: Backend, message, pk_bytes: bytes, R_bytes: bytes,
             identity, T_bytes: bytes, delta):
    return _hash_to_scalar(backend, DST_H2, message, pk_bytes, R_bytes,
                           identity, T_bytes, delta)


def H0(backend: Backend, identity, pk, R):
    """``H0(id || pk || R) -> Z_p*`` -- binds the certificate to R (Fix #1)."""
    return H0_bytes(backend, identity,
                    backend.point_to_bytes(pk), backend.point_to_bytes(R))


def H1(backend: Backend, message, pk, R, identity, T, delta):
    """``H1(m || pk || R || id || T || D) -> Z_p*`` -- the secret-key coefficient ``v``."""
    return H1_bytes(backend, message, backend.point_to_bytes(pk),
                    backend.point_to_bytes(R), identity,
                    backend.point_to_bytes(T), delta)


def H2(backend: Backend, message, pk, R, identity, T, delta):
    """``H2(m || pk || R || id || T || D) -> Z_p*`` -- the certificate coefficient ``u``."""
    return H2_bytes(backend, message, backend.point_to_bytes(pk),
                    backend.point_to_bytes(R), identity,
                    backend.point_to_bytes(T), delta)
