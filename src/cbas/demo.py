"""End-to-end walking skeleton: enrol n sensors, sign, aggregate, verify.

Also prints measured operation counts next to the paper's claimed costs, which
is the Phase 0 smoke test for the instrument that the Table III experiment
depends on.  Run with ``python -m cbas.demo`` or ``make verify``.
"""

from __future__ import annotations

from .backend import CountingBackend, SodiumBackend
from .scheme import (
    Signer,
    agg_sign,
    agg_verify,
    cert_gen,
    cert_verify,
    keygen,
    setup,
    sign,
    verify_single,
)

# Per-operation costs from the paper's Table IV (ms), measured on their PC.
PAPER_TE, PAPER_TA, PAPER_TH = 0.112, 0.005, 0.004


def build(be, n: int, delta: bytes = b"epoch-0"):
    params, msk = setup(be, delta)
    signers, secrets, messages = [], [], []
    for i in range(n):
        identity = f"sensor-{i:03d}".encode()
        keys = keygen(params)
        cert = cert_gen(params, msk, identity, keys.pk)
        signers.append(Signer(identity=identity, pk=keys.pk, R=cert.R))
        secrets.append((keys, cert))
        messages.append(f"temp={20 + i}.5C;line=A;seq={i}".encode())
    return params, msk, signers, secrets, messages


def main() -> int:
    n = 10
    be = CountingBackend(SodiumBackend())
    print(f"backend: {be.name}\n")

    params, msk, signers, secrets, messages = build(be, n)
    print(f"enrolled {n} sensors (Setup + KeyGen + CertGen)")

    ok = all(
        cert_verify(params, s.identity, s.pk, c)
        for s, (_, c) in zip(signers, secrets)
    )
    print(f"all certificates verify            : {ok}")

    # -- Sign -------------------------------------------------------------
    sigs = []
    with be.count() as c_sign_all:
        for signer, (keys, cert), m in zip(signers, secrets, messages):
            sigs.append(sign(params, signer, keys.sk, cert, m))
    per_sign = (c_sign_all.Te // n, c_sign_all.Ta // n, c_sign_all.Th // n)

    # -- single verify ----------------------------------------------------
    with be.count() as c_vrfy1:
        one = verify_single(params, signers[0], messages[0], sigs[0])
    print(f"single signature verifies          : {one}")

    # -- AggSign ----------------------------------------------------------
    with be.count() as c_agg:
        aggsig = agg_sign(params, sigs)

    # -- AggVerify --------------------------------------------------------
    with be.count() as c_aggv:
        valid = agg_verify(params, signers, messages, aggsig)
    print(f"aggregate of {n} verifies            : {valid}")

    # -- tamper detection -------------------------------------------------
    bad = list(messages)
    bad[3] = b"temp=999.9C;line=A;seq=3"
    rejected = not agg_verify(params, signers, bad, aggsig)
    print(f"tampered message rejected          : {rejected}\n")

    # -- measured vs. claimed --------------------------------------------
    print("=" * 72)
    print("measured operation counts vs. the paper's claims")
    print("=" * 72)
    rows = [
        ("Sign (per signature)", per_sign, "1Te + 1Th", "Table II"),
        ("Verify (single)", (c_vrfy1.Te, c_vrfy1.Ta, c_vrfy1.Th), "3Te + 2Ta + 2Th", "Table II"),
        ("AggVerify (n signers)", (c_aggv.Te, c_aggv.Ta, c_aggv.Th),
         "(n+2)Te + (n+1)Ta + 2nTh", "Table III"),
    ]
    for label, (te, ta, th), claimed, table in rows:
        meas = " + ".join(
            f"{v}{s}" for v, s in ((te, "Te"), (ta, "Ta"), (th, "Th")) if v
        )
        print(f"\n  {label}   [{table}, n={n}]")
        print(f"    claimed  : {claimed}")
        print(f"    measured : {meas}")
    print(f"\n  AggVerify as a formula in n : {c_aggv.formula(n)}")
    print(f"  AggSign                      : {c_agg.Te}Te + {c_agg.Ta}Ta"
          f"  ({c_agg.Ts} scalar additions, charged as (n-1)Ta by Table III)")

    claimed_ms = (n + 2) * PAPER_TE + (n + 1) * PAPER_TA + (2 * n) * PAPER_TH
    measured_ms = c_aggv.cost_ms(PAPER_TE, PAPER_TA, PAPER_TH)
    print(f"\n  AggVerify under Table IV costs, n={n}:")
    print(f"    paper's claim : {claimed_ms:7.3f} ms")
    print(f"    actual count  : {measured_ms:7.3f} ms   "
          f"(factor {measured_ms / claimed_ms:.2f}x)")
    print("=" * 72)

    return 0 if (ok and one and valid and rejected) else 1


if __name__ == "__main__":
    raise SystemExit(main())
