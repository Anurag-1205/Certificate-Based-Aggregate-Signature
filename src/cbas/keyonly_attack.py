"""A key-only universal forgery against Verma et al.'s CB-CAS, and why it fails
on the repaired scheme.

This is a different, strictly weaker-requirement attack than the one in
``attack.py``. In the Goldwasser-Micali-Rivest taxonomy (Goldwasser, Micali and
Rivest, "A Digital Signature Scheme Secure Against Adaptive Chosen-Message
Attacks," SIAM J. Computing 17(2), 1988), attacks are classified by what the
adversary is given (a **key-only attack** sees nothing but the public key; a
**chosen-message attack** may additionally obtain signatures on messages of its
choice) and forgeries by what is produced (a **universal forgery** is a valid
signature on an *arbitrary*, verifier-chosen message).

``attack.py``'s forgery is a chosen-message-attack-style break: the adversary
needs to have observed one valid signature (or, in the paper's own telling, be
a malicious KGC who captured one via a signature query). The forgery below
needs neither. It needs only the target's public key -- a key-only attack -- and
succeeds for an arbitrary message chosen after the fact, which is a universal
forgery. Key-only attack plus universal forgery is the strongest possible
combination in the GMR hierarchy: nothing about the attacker's access is
weaker, and nothing about what it produces is more damaging.

The mechanism
-------------
Verma's single-signer verification is

    z*P == R + h0*P_TA + v*pk,    h0 = H0(id, pk),  v = H1(m, pk, id, Delta)

Crucially, **R appears with coefficient 1, and neither h0 nor v depends on R**.
Given any target identity and public key -- the adversary need not know its
discrete log -- both h0 and v are computable from public information alone.
Fixing an arbitrary z (say, z = 0) turns the equation into a single linear
statement in the one remaining unknown, R, solved by ordinary point
arithmetic:

    R := z*P - h0*P_TA - v*pk

No discrete logarithm, no observed signature, no interaction with the KGC or
the victim. This is the same principle by which a Schnorr-style signature
breaks completely if the challenge is computed as ``H(m)`` instead of
``H(R, m)``: omitting the commitment from the hash leaves it as a free variable
that a linear equation can be solved for. Every standard treatment of Schnorr
signatures computes the challenge as a hash of the commitment together with the
message for exactly this reason.

Why it fails against the repaired scheme
-----------------------------------------
The repaired scheme's equation is

    z*P == T + u*R + u*h0*P_TA + v*pk

with h0 = H0(id, pk, R), u = H2(m, pk, R, id, T, Delta), v = H1(...). Now **R is
an argument to all three hash functions**, so h0, u and v cannot be computed
until R is fixed -- but solving the linear equation for R requires knowing u, h0
and v first. This is circular in exactly the sense the Forking-Lemma-style
attacks in ``attack.py`` are circular: a fixed point of a random oracle, not an
algebraic manipulation.

``ablation_r.py`` isolates which of the scheme's two corrections is
responsible: removing only the R-binding (independent of the T-binding that
``ablation.py`` removes) reopens exactly this attack, while removing only the
T-binding does not. See ``KEYONLY_FORGERY.md`` for the full 2x2 result.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import scheme as fixed
from . import verma
from .backend.base import Backend


def forge_verma_keyonly(
    params: verma.PublicParams,
    identity: bytes,
    pk,
    target_message: bytes,
    z=None,
) -> verma.Signature:
    """Forge a Verma CB-CAS signature given only a target identity and public key.

    No secret key, no certificate, no observed signature, and no interaction
    with the KGC or the target is required. ``pk`` may be a real, enrolled
    user's public key -- the forgery does not need to know its discrete log --
    or any point at all.
    """
    be = params.be
    z = z if z is not None else be.scalar_from_int(0)
    h0 = verma.H0(be, identity, pk)
    v = verma.H1(be, target_message, pk, identity, params.delta)
    R = be.point_sub(
        be.point_mul_base(z),
        be.point_add(be.point_mul(h0, params.pk_ta), be.point_mul(v, pk)),
    )
    return verma.Signature(R=R, z=z)


@dataclass
class KeyOnlyAttempt:
    """Outcome of attempting the same technique against the repaired scheme."""

    succeeded: bool
    iterations: int
    reason: str
    trace: list


def attempt_keyonly_forge_fixed(
    params: fixed.PublicParams,
    identity: bytes,
    pk,
    R_seed,
    T_seed,
    target_message: bytes,
    z=None,
    max_iterations: int = 16,
) -> KeyOnlyAttempt:
    """Attempt the key-only forgery against the repaired scheme.

    Solving the verify equation for ``R`` requires knowing ``h0``, ``u`` and
    ``v`` -- but those are hashes *of* ``R`` (and of ``T``, itself unconstrained
    here too). The natural attempt is therefore a fixed point search: guess
    ``R``, compute the hashes, solve for the ``R`` the equation would then
    require, and check whether it matches the guess. Each round below produces
    a different value, which is what "circular" means in practice: there is no
    algebraic shortcut, only exhaustive search over a 2^256 space.
    """
    be = params.be
    z = z if z is not None else be.scalar_from_int(0)
    T = T_seed
    R = R_seed
    trace = []

    for k in range(1, max_iterations + 1):
        h0 = fixed.H0(be, identity, pk, R)
        v = fixed.H1(be, target_message, pk, R, identity, T, params.delta)
        u = fixed.H2(be, target_message, pk, R, identity, T, params.delta)

        # Solve z*P = T + u*R_required + u*h0*P_TA + v*pk for R_required,
        # using the hash values computed from the *current guess* of R.
        u_inv = be.scalar_invert(u) if not be.scalar_is_zero(u) else None
        if u_inv is None:  # pragma: no cover - probability ~2^-252
            R_required = R
        else:
            rhs = be.point_sub(
                be.point_mul_base(z),
                be.point_add(T, be.point_add(
                    be.point_mul(u, be.point_mul(h0, params.pk_ta)),
                    be.point_mul(v, pk),
                )),
            )
            R_required = be.point_mul(u_inv, rhs)

        trace.append(be.point_to_bytes(R_required)[:8].hex())

        if be.point_eq(R_required, R):
            sig = fixed.Signature(T=T, z=z)
            fake_signer = fixed.Signer(identity=identity, pk=pk, R=R)
            if fixed.verify_single(params, fake_signer, target_message, sig):
                return KeyOnlyAttempt(True, k, "found a fixed point of H0/H1/H2", trace)

        R = R_required

    return KeyOnlyAttempt(
        False,
        max_iterations,
        "h0, u and v are all hashes of R (and of T), so solving the linear "
        "equation for R requires already knowing them, and computing them "
        "requires already knowing R. The iteration does not settle: this "
        "reduces to finding a fixed point of a random oracle over a 2^256 "
        "space, which is exhaustive search, not an algebraic attack.",
        trace,
    )
