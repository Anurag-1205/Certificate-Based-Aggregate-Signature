"""The malicious-KGC forgery against Verma et al.'s CB-CAS, and why it fails
against the repaired scheme.

Running this is the point of the project: it turns "the paper says scheme X is
broken" into "here is the forgery, executing".

Threat model
------------
The adversary is ``F2``, a malicious or compromised KGC.  It holds the master
secret key ``s`` and therefore the certificate ``Cert_i = (R1_i, c_i)`` of every
user -- it issued them.  It does **not** know any user's secret key ``sk_i``.
It observes one honest signature and forges signatures on messages of its
choosing, for that user.

This is the threat certificate-based cryptography exists to prevent: the whole
point of splitting the signing secret between the user (``sk_i``) and the KGC
(``Cert_i``) is that neither party alone can sign.  A scheme in which the KGC
alone can forge has degenerated to identity-based cryptography with full key
escrow.

The forgery (Section IV-B of Qiao et al.)
-----------------------------------------
Verma's signature is ``z_i = r2_i + c_i + sk_i*v_i`` with
``v_i = H1(m_i || pk_i || id_i || D)`` -- crucially, ``v_i`` does not depend on
the nonce ``r2_i``.  So the equation is affine in a coefficient ``v_i`` that the
attacker knows, and an affine relation with a known coefficient can be rescaled
to any other coefficient::

    strip the certificate:   r2_i*P      = R_i - R1_i
                             r2_i + sk_i*v_i = z_i - c_i

    normalise by v_i:        alpha = (z_i - c_i) / v_i   = r2_i/v_i + sk_i
                             A     = (R_i - R1_i) / v_i  = (r2_i/v_i)*P

    rescale to m':           v_i'  = H1(m' || pk_i || id_i || D)
                             R_i'  = R1_i + v_i'*A
                             z_i'  = v_i'*alpha + c_i

The result is a correctly distributed signature with effective nonce
``r~ = v_i'*r2_i/v_i``.  The attacker never learns ``sk_i`` or ``r2_i``
individually -- it does not need to.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import scheme as fixed
from . import verma
from .backend.base import Backend


# --------------------------------------------------------------------------
# The forgery against Verma et al.
# --------------------------------------------------------------------------

def forge_verma(
    params: verma.PublicParams,
    signer: verma.Signer,
    cert: verma.Certificate,
    observed_message: bytes,
    observed_sig: verma.Signature,
    target_message: bytes,
) -> verma.Signature:
    """Forge a Verma CB-CAS signature on ``target_message``.

    Requires only the victim's certificate (which the KGC issued) and one
    observed signature.  Never touches ``sk_i``.
    """
    be = params.be

    # Step 1 -- strip the certificate, isolating the nonce contribution.
    v = verma.H1(be, observed_message, signer.pk, signer.identity, params.delta)
    v_inv = be.scalar_invert(v)

    # Step 2 -- normalise by v.  Possible only because v is independent of r2.
    alpha = be.scalar_mul(be.scalar_sub(observed_sig.z, cert.c), v_inv)
    A = be.point_mul(v_inv, be.point_sub(observed_sig.R, cert.R1))

    # Step 3 -- rescale to the target message.
    v_target = verma.H1(be, target_message, signer.pk, signer.identity, params.delta)
    R_forged = be.point_add(cert.R1, be.point_mul(v_target, A))
    z_forged = be.scalar_add(be.scalar_mul(v_target, alpha), cert.c)

    return verma.Signature(R=R_forged, z=z_forged)


# --------------------------------------------------------------------------
# The same attack, attempted against the repaired scheme
# --------------------------------------------------------------------------

@dataclass
class ForgeryAttempt:
    """Outcome of attempting the rescaling attack on the repaired scheme."""

    succeeded: bool
    iterations: int
    reason: str
    #: Each candidate T' tried, to show the iteration does not settle.
    trace: list


def attempt_forge_fixed(
    params: fixed.PublicParams,
    signer: fixed.Signer,
    cert: fixed.Certificate,
    observed_message: bytes,
    observed_sig: fixed.Signature,
    target_message: bytes,
    max_iterations: int = 16,
) -> ForgeryAttempt:
    """Attempt the rescaling attack against the repaired scheme.

    The algebra still works.  Writing ``w = z_i - c_i*u_i = t_i + sk_i*v_i``, the
    forgery ``T' = (v'/v_i)*T_i``, ``z' = (v'/v_i)*w + c_i*u'`` would verify --
    *if* the attacker could compute ``v'`` before choosing ``T'``.

    But Fix #2 puts ``T`` inside both hashes, so ``v' = H1(m' || ... || T' || D)``
    and ``T' = (v'/v_i)*T_i``: each requires the other.  The attack therefore
    reduces to finding a fixed point of a random oracle, which this function
    demonstrates by iterating.  Each round produces a different ``T'``, and every
    candidate fails verification.
    """
    be = params.be

    v_i = fixed.H1(be, observed_message, signer.pk, signer.R,
                   signer.identity, observed_sig.T, params.delta)
    u_i = fixed.H2(be, observed_message, signer.pk, signer.R,
                   signer.identity, observed_sig.T, params.delta)
    v_i_inv = be.scalar_invert(v_i)

    # w = t_i + sk_i*v_i, obtained by stripping the certificate term.
    w = be.scalar_sub(observed_sig.z, be.scalar_mul(cert.c, u_i))

    # Seed the iteration with the only T the attacker has.
    T_candidate = observed_sig.T
    trace = []

    for k in range(1, max_iterations + 1):
        # Guess the coefficients that T_candidate would induce...
        v_guess = fixed.H1(be, target_message, signer.pk, signer.R,
                           signer.identity, T_candidate, params.delta)
        u_guess = fixed.H2(be, target_message, signer.pk, signer.R,
                           signer.identity, T_candidate, params.delta)

        # ...and the T the attack actually requires for that coefficient.
        ratio = be.scalar_mul(v_guess, v_i_inv)
        T_required = be.point_mul(ratio, observed_sig.T)
        trace.append(be.point_to_bytes(T_required)[:8].hex())

        if be.point_eq(T_required, T_candidate):
            # A fixed point: the forgery would go through.  Probability ~2^-252.
            z_forged = be.scalar_add(be.scalar_mul(ratio, w),
                                     be.scalar_mul(cert.c, u_guess))
            forged = fixed.Signature(T=T_candidate, z=z_forged)
            if fixed.verify_single(params, signer, target_message, forged):
                return ForgeryAttempt(True, k, "found a fixed point of H1", trace)

        # Also check the candidate outright, in case the algebra closes anyway.
        z_try = be.scalar_add(be.scalar_mul(ratio, w), be.scalar_mul(cert.c, u_guess))
        if fixed.verify_single(params, signer, target_message,
                               fixed.Signature(T=T_required, z=z_try)):
            return ForgeryAttempt(True, k, "candidate verified", trace)

        T_candidate = T_required

    return ForgeryAttempt(
        False,
        max_iterations,
        "T' must be fixed before v' = H1(...||T'||...) can be computed, but the "
        "attack defines T' = (v'/v_i)*T_i in terms of v'. The iteration never "
        "settles: forging reduces to finding a fixed point of a random oracle.",
        trace,
    )
