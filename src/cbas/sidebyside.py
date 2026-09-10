"""Side-by-side: the same attack code against the broken and the repaired scheme.

    python -m cbas.sidebyside
"""

from __future__ import annotations

from . import scheme as fixed
from . import verma
from .attack import attempt_forge_fixed, forge_verma
from .backend import SodiumBackend

RULE = "=" * 74


def run_verma(be) -> bool:
    print(RULE)
    print("  TARGET 1  Verma et al., CB-CAS (IEEE IoT-J 2020)")
    print(RULE)

    params, msk = verma.setup(be, b"epoch-0")
    ident = b"sensor-042"
    keys = verma.keygen(params)
    cert = verma.cert_gen(params, msk, ident, keys.pk)
    signer = verma.Signer(identity=ident, pk=keys.pk)

    honest_msg = b"temp=21.4C;line=A;seq=17"
    honest_sig = verma.sign(params, signer, keys.sk, cert, honest_msg)
    print(f"  honest message      : {honest_msg.decode()}")
    print(f"  honest sig verifies : {verma.verify_single(params, signer, honest_msg, honest_sig)}")

    target = b"temp=-40.0C;line=A;seq=17;SHUTDOWN"
    print(f"\n  attacker is the KGC. It holds the master key and the issued")
    print(f"  certificate, and has seen exactly one signature.")
    print(f"  It does NOT know sk_i.\n")
    print(f"  target message      : {target.decode()}")

    forged = forge_verma(params, signer, cert, honest_msg, honest_sig, target)
    ok = verma.verify_single(params, signer, target, forged)
    print(f"  forged sig verifies : {ok}    <-- {'FORGERY SUCCEEDED' if ok else 'failed'}")

    # And the forgery aggregates cleanly alongside honest signatures.
    agg = verma.agg_sign(params, [honest_sig, forged])
    agg_ok = verma.agg_verify(params, [signer, signer], [honest_msg, target], agg)
    print(f"  forgery survives aggregation : {agg_ok}")
    return ok


def run_fixed(be) -> bool:
    print()
    print(RULE)
    print("  TARGET 2  Qiao et al., repaired CBAS (IEEE Systems Journal 2023)")
    print(RULE)

    params, msk = fixed.setup(be, b"epoch-0")
    ident = b"sensor-042"
    keys = fixed.keygen(params)
    cert = fixed.cert_gen(params, msk, ident, keys.pk)
    signer = fixed.Signer(identity=ident, pk=keys.pk, R=cert.R)

    honest_msg = b"temp=21.4C;line=A;seq=17"
    honest_sig = fixed.sign(params, signer, keys.sk, cert, honest_msg)
    print(f"  honest sig verifies : {fixed.verify_single(params, signer, honest_msg, honest_sig)}")

    target = b"temp=-40.0C;line=A;seq=17;SHUTDOWN"
    print(f"  target message      : {target.decode()}")
    print(f"\n  same attacker, same capabilities, same attack.\n")

    attempt = attempt_forge_fixed(params, signer, cert, honest_msg, honest_sig, target)
    print(f"  forgery succeeded   : {attempt.succeeded}")
    print(f"  iterations tried    : {attempt.iterations}")
    print(f"\n  candidate T' per iteration (first 8 bytes):")
    for i, t in enumerate(attempt.trace[:6], 1):
        print(f"    {i:>2}. {t}...")
    if len(attempt.trace) > 6:
        print(f"    ... {len(attempt.trace) - 6} more, all distinct")

    print(f"\n  why it fails:")
    for line in _wrap(attempt.reason, 68):
        print(f"    {line}")
    return not attempt.succeeded


def _wrap(text: str, width: int):
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        out.append(line)
    return out


def main() -> int:
    be = SodiumBackend()
    broke_verma = run_verma(be)
    held_fixed = run_fixed(be)

    print()
    print(RULE)
    print("  SUMMARY")
    print(RULE)
    print(f"  Verma et al. CB-CAS  : {'BROKEN  - universal forgery by the KGC' if broke_verma else 'held'}")
    print(f"  Qiao et al. CBAS     : {'held    - attack does not apply' if held_fixed else 'BROKEN'}")
    print()
    print("  The difference is one line. Verma hashes")
    print("      v_i = H1(m_i || pk_i || id_i || D)")
    print("  and Qiao hashes")
    print("      v_i = H1(m_i || pk_i || R_i || id_i || T_i || D)")
    print()
    print("  Binding the nonce commitment T_i into the hash is what makes the")
    print("  rescaling step circular. Verma omitted it to obtain a constant-size")
    print("  aggregate; that compactness is exactly what cost them the scheme.")
    print(RULE)

    return 0 if (broke_verma and held_fixed) else 1


if __name__ == "__main__":
    raise SystemExit(main())
