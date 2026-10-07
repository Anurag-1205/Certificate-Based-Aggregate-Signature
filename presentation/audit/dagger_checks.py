"""Audit checks that go beyond the repository's tests (the "audit" findings in the deck).

    .venv/bin/python presentation/audit/dagger_checks.py

These support backup slides B6 (why T_i appears in both hashes), B8/B9 and one remark on
slide 29. None of them is part of the repository's test-suite; each is a standalone,
read-only experiment. Writes presentation/data/audit_checks.json.
"""
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from bench.harness import measure_many, stabilize  # noqa: E402
from cbas import scheme as fixed, verma  # noqa: E402
from cbas.backend import BACKENDS  # noqa: E402
from cbas.encoding import as_bytes, tlv_encode  # noqa: E402
from cbas.hashing import H0, H1, H2  # noqa: E402

OUT = ROOT / "presentation" / "data" / "audit_checks.json"
res: dict = {}


def hs(be, dst, *f):
    return be.scalar_from_wide(hashlib.sha512(tlv_encode(dst, *(as_bytes(x) for x in f))).digest())


# ----------------------------------------------------------------------------------------
# A. Which hash must contain T_i?  Two rescaling attacks, two hash placements.
#    KGC attack  : knows c_i, rescales the sk_i*v_i part   (needs v' computable before T').
#    mirror attack: a malicious USER knows sk_i, rescales the c_i*u_i part (needs u' before T').
# ----------------------------------------------------------------------------------------
print("A. T_i placement vs the two rescaling attacks")
res["t_binding"] = {}
for name in sorted(BACKENDS):
    be = BACKENDS[name]()
    enc = be.point_to_bytes
    p, msk = fixed.setup(be, b"epoch-0")
    k = fixed.keygen(p)
    c = fixed.cert_gen(p, msk, b"id", k.pk)
    s = fixed.Signer(b"id", k.pk, c.R)
    h0 = H0(be, s.identity, s.pk, s.R)
    rows = {}
    for label, t1, t2 in (("T in H1 only", True, False), ("T in H2 only", False, True), ("T in both (Qiao)", True, True),
                          ("T in neither (ablation)", False, False)):
        def v_of(m, T):
            return hs(be, b"X-H1", m, enc(s.pk), enc(s.R), s.identity, *([enc(T)] if t1 else []), p.delta)

        def u_of(m, T):
            return hs(be, b"X-H2", m, enc(s.pk), enc(s.R), s.identity, *([enc(T)] if t2 else []), p.delta)

        def verify(m, T, z):
            u, v = u_of(m, T), v_of(m, T)
            rhs = be.point_add(be.point_add(be.point_add(T, be.point_mul(u, s.R)),
                                            be.point_mul(be.scalar_mul(u, h0), p.pk_ta)), be.point_mul(v, s.pk))
            return be.point_eq(be.point_mul_base(z), rhs)

        t = be.scalar_random()
        T = be.point_mul_base(t)
        m, m2 = b"m", b"SHUTDOWN"
        u, v = u_of(m, T), v_of(m, T)
        z = be.scalar_add(t, be.scalar_add(be.scalar_mul(c.c, u), be.scalar_mul(k.sk, v)))
        assert verify(m, T, z)
        # KGC: one-shot rescaling using the coefficient it can compute only if T is not an input
        w = be.scalar_sub(z, be.scalar_mul(c.c, u))
        lam = be.scalar_mul(v_of(m2, T), be.scalar_invert(v))
        T2 = be.point_mul(lam, T)
        z2 = be.scalar_add(be.scalar_mul(lam, w), be.scalar_mul(c.c, u_of(m2, T2)))
        kgc = bool(verify(m2, T2, z2))
        # malicious user: mirror image, rescale the certificate term
        y = be.scalar_sub(z, be.scalar_mul(k.sk, v))
        mu = be.scalar_mul(u_of(m2, T), be.scalar_invert(u))
        T3 = be.point_mul(mu, T)
        z3 = be.scalar_add(be.scalar_mul(mu, y), be.scalar_mul(k.sk, v_of(m2, T3)))
        usr = bool(verify(m2, T3, z3))
        rows[label] = {"kgc_rescaling_forges": kgc, "user_mirror_rescaling_forges": usr}
        print(f"  {name:<12} {label:<24} KGC attack forges={kgc!s:<5}  mirror (user) attack forges={usr}")
    res["t_binding"][name] = rows
    # the single-hash variant: u == v (no separation of H1 and H2), T bound
    def verify_uv(m, T, z):
        v = H1(be, m, s.pk, s.R, s.identity, T, p.delta)
        rhs = be.point_add(be.point_add(be.point_add(T, be.point_mul(v, s.R)),
                                        be.point_mul(be.scalar_mul(v, h0), p.pk_ta)), be.point_mul(v, s.pk))
        return be.point_eq(be.point_mul_base(z), rhs)

    t = be.scalar_random()
    T = be.point_mul_base(t)
    v = H1(be, b"m", s.pk, s.R, s.identity, T, p.delta)
    z = be.scalar_add(t, be.scalar_mul(be.scalar_add(c.c, k.sk), v))
    honest = bool(verify_uv(b"m", T, z))
    lam = be.scalar_mul(H1(be, b"SHUTDOWN", s.pk, s.R, s.identity, T, p.delta), be.scalar_invert(v))
    T2 = be.point_mul(lam, T)
    z2 = be.scalar_add(be.scalar_mul(lam, be.scalar_sub(z, be.scalar_mul(c.c, v))),
                       be.scalar_mul(c.c, H1(be, b"SHUTDOWN", s.pk, s.R, s.identity, T2, p.delta)))
    res["t_binding"][name]["u_equals_v_variant"] = {"honest_verifies": honest,
                                                     "kgc_rescaling_forges": bool(verify_uv(b"SHUTDOWN", T2, z2))}
    print(f"  {name:<12} u == v variant (one hash for both): honest={honest}, KGC rescaling forges="
          f"{res['t_binding'][name]['u_equals_v_variant']['kgc_rescaling_forges']}")

# ----------------------------------------------------------------------------------------
# B. Verma: forgery from public data only (R_i is in no hash, so it can be solved for).
# ----------------------------------------------------------------------------------------
print("B. Verma forged from public data alone (no certificate, no master key, no signature)")
res["verma_public_only"] = {}
for name in sorted(BACKENDS):
    be = BACKENDS[name]()
    params, _ = verma.setup(be, b"epoch-0")
    keys = verma.keygen(params)
    ident, target = b"sensor-042", b"SHUTDOWN"
    signer = verma.Signer(identity=ident, pk=keys.pk)
    z = be.scalar_random()
    h0 = verma.H0(be, ident, keys.pk)
    v = verma.H1(be, target, keys.pk, ident, params.delta)
    R = be.point_sub(be.point_sub(be.point_mul_base(z), be.point_mul(h0, params.pk_ta)), be.point_mul(v, keys.pk))
    okv = bool(verma.verify_single(params, signer, target, verma.Signature(R=R, z=z)))
    res["verma_public_only"][name] = okv
    print(f"  {name:<12} forged signature verifies: {okv}")

# ----------------------------------------------------------------------------------------
# C. Why does P-256 timing exceed the bare Te/Ta/Th prediction?  Price the real hash calls.
# ----------------------------------------------------------------------------------------
print("C. predicted slope ratio: bare hash model vs priced real hash calls (fresh timing, 3 repeats)")
res["timing_model"] = {}
for name in ("p256", "ristretto255"):
    be = BACKENDS[name]()
    reps = []
    for rep in range(3):
        stabilize(be, max_seconds=12, min_seconds=3)
        k, j = be.scalar_random(), be.scalar_random()
        P, Q, T = be.point_mul_base(k), be.point_mul_base(j), be.point_mul_base(be.scalar_random())
        wide = bytes(range(64))
        m, ident, d = b"temp=21.5C;seq=7", b"sensor-0007", b"epoch-0"
        r = measure_many({
            "Te": lambda: be.point_mul(k, Q), "Ta": lambda: be.point_add(P, Q),
            "Th_bare": lambda: be.scalar_from_wide(hashlib.sha512(wide).digest()),
            "q_H0": lambda: H0(be, ident, P, Q), "q_H1": lambda: H1(be, m, P, Q, ident, T, d),
            "v_H0": lambda: verma.H0(be, ident, P), "v_H1": lambda: verma.H1(be, m, P, ident, d),
        }, rounds=9)
        te, ta, thb = r["Te"].median_ms, r["Ta"].median_ms, r["Th_bare"].median_ms
        q_hash = r["q_H0"].median_ms + 2 * r["q_H1"].median_ms
        v_hash = r["v_H0"].median_ms + r["v_H1"].median_ms
        reps.append({"bare": (2 * te + 3 * ta + 3 * thb) / (te + ta + 2 * thb),
                     "real_hash": (2 * te + 3 * ta + q_hash) / (te + ta + v_hash),
                     "Te_us": te * 1e3, "Ta_us": ta * 1e3, "Th_bare_us": thb * 1e3})
    res["timing_model"][name] = reps
    print(f"  {name:<12} bare-hash model: {[round(x['bare'], 3) for x in reps]}   "
          f"real-hash model: {[round(x['real_hash'], 3) for x in reps]}")

OUT.write_text(json.dumps(res, indent=2))
print(f"\nwrote {OUT.relative_to(ROOT)}")
