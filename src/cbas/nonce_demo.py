"""A sensor with a stuck RNG gives away its keys; hedged nonces stop it.

    python -m cbas.nonce_demo [--backend ristretto255|p256]
"""

from __future__ import annotations

import argparse

from . import scheme as fixed
from .backend import BACKENDS
from .nonce_reuse import (
    NonceReuseError,
    forge_with_keys,
    recover_keys_outsider,
    recover_sk_kgc,
    sign_hedged,
    stuck_rng,
)

RULE = "=" * 74
READINGS = [b"temp=21.4C;line=A;seq=17", b"temp=21.5C;line=A;seq=18",
            b"temp=21.3C;line=A;seq=19"]
TARGET = b"valve=OPEN;line=A;seq=20"


def _short(be, x) -> str:
    return be.point_to_bytes(x)[:8].hex() + "..."


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", choices=sorted(BACKENDS), default="ristretto255")
    be = BACKENDS[ap.parse_args(argv).backend]()

    params, msk = fixed.setup(be, b"epoch-0")
    keys = fixed.keygen(params)
    cert = fixed.cert_gen(params, msk, b"sensor-042", keys.pk)
    signer = fixed.Signer(identity=b"sensor-042", pk=keys.pk, R=cert.R)

    print(RULE)
    print(f"  STEP 1  stuck RNG: sensor-042 signs three readings  [{be.name}]")
    print(RULE)
    with stuck_rng(be, be.scalar_random()):
        sigs = [fixed.sign(params, signer, keys.sk, cert, m) for m in READINGS]
    for m, s in zip(READINGS, sigs):
        ok = fixed.verify_single(params, signer, m, s)
        print(f"  {m.decode():<28} T = {_short(be, s.T)}  verifies: {ok}")
    print("  every signature is valid, so nothing looks wrong to the server.")

    print()
    print(RULE)
    print("  STEP 2  an outsider who only saw those three signatures")
    print(RULE)
    print("  z_j = t + c*u_j + sk*v_j    three equations, three unknowns (t, c, sk)")
    rec = recover_keys_outsider(params, signer, READINGS, sigs)
    sk_ok = be.point_eq(be.point_mul_base(rec.sk), signer.pk)
    c_ok = fixed.cert_verify(params, signer.identity, signer.pk, fixed.Certificate(c=rec.c, R=signer.R))
    print(f"  recovered sk matches pk           : {sk_ok}")
    print(f"  recovered c passes the cert check : {c_ok}")

    forged = forge_with_keys(params, signer, rec, TARGET)
    ok = fixed.verify_single(params, signer, TARGET, forged)
    print(f"\n  attacker signs  {TARGET.decode()}")
    print(f"  forged signature verifies         : {ok}    <-- {'KEYS STOLEN' if ok else 'failed'}")
    honest_msg = b"temp=21.6C;line=A;seq=21"
    honest = fixed.sign(params, signer, keys.sk, cert, honest_msg)
    agg = fixed.agg_sign(params, [honest, forged])
    agg_ok = fixed.agg_verify(params, [signer, signer], [honest_msg, TARGET], agg)
    print(f"  forgery passes aggregate verify   : {agg_ok}")

    print()
    print(RULE)
    print("  STEP 3  the KGC already knows c, so it needs only two")
    print(RULE)
    sk_kgc = recover_sk_kgc(params, signer, cert, READINGS[:2], sigs[:2])
    kgc_ok = be.point_eq(be.point_mul_base(sk_kgc), signer.pk)
    print(f"  KGC recovers sk from 2 signatures : {kgc_ok}")
    print("  (the scheme's promise is that the KGC never learns sk)")

    print()
    print(RULE)
    print("  STEP 4  same stuck RNG, hedged nonce t = H(sk, c, m, ..., rng)")
    print(RULE)
    with stuck_rng(be, be.scalar_random()):
        hsigs = [sign_hedged(params, signer, keys.sk, cert, m) for m in READINGS]
    for m, s in zip(READINGS, hsigs):
        ok_h = fixed.verify_single(params, signer, m, s)
        print(f"  {m.decode():<28} T = {_short(be, s.T)}  verifies: {ok_h}")
    try:
        recover_keys_outsider(params, signer, READINGS, hsigs)
        defended = False
        print("  attack result : keys recovered")
    except NonceReuseError as e:
        defended = True
        print(f"  attack result : refused -- {e}")
    print("  the verifier is unchanged; only the signer's nonce derivation differs.")

    print()
    print(RULE)
    print("  SUMMARY  signatures sharing one nonce, needed to recover the keys")
    print(RULE)
    print("  Verma et al., anyone          : 2")
    print("  Qiao et al., outsider         : 3   (c is scaled by u, so it is a third unknown)")
    print("  Qiao et al., the KGC          : 2   (it already knows c)")
    print("  Qiao et al., hedged nonces    : no shared nonce, attack does not start")
    print(RULE)

    return 0 if (sk_ok and c_ok and ok and agg_ok and kgc_ok and defended) else 1


if __name__ == "__main__":
    raise SystemExit(main())
