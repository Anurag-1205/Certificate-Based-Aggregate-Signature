"""Recompute every number used in the final deck, from code and tracked data.

Run from the repository root:

    .venv/bin/python presentation/audit/verify_claims_final.py

Writes presentation/data/claims_final.json, which the final deck's slide and figure
builders read. Every claim is asserted; a mismatch stops the run. Read-only with
respect to src/, tests/ and bench/.
"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from cbas import ablation, ablation_r, scheme as fixed, verma  # noqa: E402
from cbas.aggregator import locate_faults  # noqa: E402
from cbas.attack import attempt_forge_fixed, forge_verma  # noqa: E402
from cbas.backend import BACKENDS, CountingBackend  # noqa: E402
from cbas.keyonly_attack import attempt_keyonly_forge_fixed, forge_verma_keyonly  # noqa: E402
from cbas.nonce_reuse import (NonceReuseError, forge_verma_with_keys, forge_with_keys,  # noqa: E402
                              recover_keys_outsider, recover_sk_kgc, recover_verma, sign_hedged,
                              stuck_rng)
from cbas.optimized import prepare  # noqa: E402
from tests.test_scheme_roundtrip import enrol as q_enrol, sign_all as q_sign_all  # noqa: E402

OUT = ROOT / "presentation" / "data" / "claims_final.json"
RESULTS = ROOT / "bench" / "results"
TE, TA, TH = 0.112, 0.005, 0.004          # paper Table IV (ms)
TARGETS = [b"temp=-40.0C;line=A;seq=17;SHUTDOWN", b"pressure=0;valve=OPEN", b"", b"\x00\xff" * 40]
READINGS = [b"temp=21.4C;line=A;seq=17", b"temp=21.5C;line=A;seq=18", b"temp=21.3C;line=A;seq=19"]
claims: dict = {}


def ok(cond, msg):
    if not cond:
        raise SystemExit(f"CLAIM FAILED: {msg}")
    print(f"  ok  {msg}")


def victim(mod, be, ident=b"sensor-042", delta=b"epoch-0"):
    params, msk = mod.setup(be, delta)
    keys = mod.keygen(params)
    cert = mod.cert_gen(params, msk, ident, keys.pk)
    return params, msk, keys, cert


# ---------------------------------------------------------------- 1. recap (interim results)
print("1. recap: the interim results, recomputed on the current code")
rc = {"verma_forged": 0, "qiao_forged": 0, "ablated_forged": 0, "trials": 0}
for name in sorted(BACKENDS):
    be = BACKENDS[name]()
    for tgt in TARGETS:
        rc["trials"] += 1
        m0 = READINGS[0]
        vp, _, vk, vc = victim(verma, be)
        vs = verma.Signer(identity=b"sensor-042", pk=vk.pk)
        vsig = verma.sign(vp, vs, vk.sk, vc, m0)
        rc["verma_forged"] += verma.verify_single(vp, vs, tgt, forge_verma(vp, vs, vc, m0, vsig, tgt))
        qp, _, qk, qc = victim(fixed, be)
        qs = fixed.Signer(identity=b"sensor-042", pk=qk.pk, R=qc.R)
        rc["qiao_forged"] += attempt_forge_fixed(qp, qs, qc, m0, fixed.sign(qp, qs, qk.sk, qc, m0), tgt).succeeded
        ap, _, ak, ac = victim(ablation, be)
        asg = ablation.Signer(identity=b"sensor-042", pk=ak.pk, R=ac.R)
        asig = ablation.sign(ap, asg, ak.sk, ac, m0)
        rc["ablated_forged"] += ablation.verify_single(ap, asg, tgt, ablation.forge_ablated(ap, asg, ac, m0, asig, tgt))
ok(rc["trials"] == 8 and rc["verma_forged"] == 8, "KGC forgery on Verma: 8/8")
ok(rc["qiao_forged"] == 0, "same attack on Qiao: 0/8")
ok(rc["ablated_forged"] == 8, "Qiao without the T binding: 8/8")

be = CountingBackend(BACKENDS["ristretto255"]())
params, _, signers, secrets, messages = q_enrol(be, 100)
agg = fixed.agg_sign(params, q_sign_all(params, signers, secrets, messages))
with be.count() as c:
    assert fixed.agg_verify(params, signers, messages, agg)
ok((c.Te, c.Ta, c.Th) == (202, 300, 300), "AggVerify at n=100 counts (2n+2)Te + 3nTa + 3nTh")
printed = round(102 * TE + 101 * TA + 200 * TH, 3)
recount = round(c.Te * TE + c.Ta * TA + c.Th * TH, 3)
ok((printed, recount) == (12.729, 25.324), "n=100 under Table IV: printed 12.729 ms, recount 25.324 ms")
interim = json.loads((ROOT / "presentation" / "data" / "claims.json").read_text())
ts = interim["timing"]["summary"]
lo = min(v["median"] for v in ts.values())
hi = max(v["median"] for v in ts.values())
ok(2.1 < lo < hi < 2.4, f"interim timing medians {lo:.2f} to {hi:.2f} (tracked sweep JSON)")
claims["recap"] = {**rc, "printed_ms": printed, "recount_ms": recount, "factor": round(recount / printed, 2),
                   "timing_median_lo": round(lo, 2), "timing_median_hi": round(hi, 2)}

# ---------------------------------------------------------------- 2. key-only forgery and the 2x2
print("2. key-only forgery and the 2x2")
ko = {"trials": 0, "verma_forged": 0, "verma_agg": 0, "qiao_forged": 0, "qiao_distinct_min": 99,
      "t_cell": 0, "t_cell_r_safe": 0, "r_cell": 0, "r_cell_needs_replaced_R": 0, "r_cell_t_safe": 0}
for name in sorted(BACKENDS):
    be = BACKENDS[name]()
    for tgt in TARGETS:
        ko["trials"] += 1
        vp, _, vk, vc = victim(verma, be)
        vs = verma.Signer(identity=b"sensor-042", pk=vk.pk)
        forged = forge_verma_keyonly(vp, b"sensor-042", vk.pk, tgt)
        ko["verma_forged"] += verma.verify_single(vp, vs, tgt, forged)
        honest = verma.sign(vp, vs, vk.sk, vc, READINGS[0])
        ko["verma_agg"] += verma.agg_verify(vp, [vs, vs], [READINGS[0], tgt], verma.agg_sign(vp, [honest, forged]))

        qp, _, qk, qc = victim(fixed, be)
        seed = be.point_mul_base(be.scalar_random())
        att = attempt_keyonly_forge_fixed(qp, b"sensor-042", qk.pk, R_seed=seed, T_seed=seed, target_message=tgt)
        ko["qiao_forged"] += att.succeeded
        ko["qiao_distinct_min"] = min(ko["qiao_distinct_min"], len(set(att.trace)))
        ko["sample_trace"] = {"backend": name, "rounds": att.trace[:3]}

        ap, _, ak, ac = victim(ablation, be)
        av = ablation.Signer(identity=b"sensor-042", pk=ak.pk, R=ac.R)
        ko["t_cell"] += ablation.verify_single(ap, av, tgt, ablation.forge_keyonly_via_t(ap, b"sensor-042", ak.pk, ac.R, tgt))
        ko["t_cell_r_safe"] += not ablation.attempt_solve_for_r_ablated(ap, b"sensor-042", ak.pk, seed, tgt)["succeeded"]

        rp, _, rk, rcert = victim(ablation_r, be)
        rsig, rR = ablation_r.forge_keyonly(rp, b"sensor-042", rk.pk, tgt)
        ko["r_cell"] += ablation_r.verify_single(rp, fixed.Signer(identity=b"sensor-042", pk=rk.pk, R=rR), tgt, rsig)
        ko["r_cell_needs_replaced_R"] += not ablation_r.verify_single(
            rp, fixed.Signer(identity=b"sensor-042", pk=rk.pk, R=rcert.R), tgt, rsig)
        ko["r_cell_t_safe"] += not ablation_r.attempt_solve_for_t_ablation_r(rp, b"sensor-042", rk.pk, rcert.R, tgt)["succeeded"]
k = ko["trials"]
ok(k == 8 and ko["verma_forged"] == 8 and ko["verma_agg"] == 8, "Verma: key-only forgery verifies and aggregates, 8/8")
ok(ko["qiao_forged"] == 0 and ko["qiao_distinct_min"] == 16, "Qiao: 0/8, 16 distinct candidates each")
ok(ko["t_cell"] == 8 and ko["t_cell_r_safe"] == 8, "T binding removed: solve for T forges 8/8 with the real R; solving for R still fails")
ok(ko["r_cell"] == 8 and ko["r_cell_t_safe"] == 8, "R binding removed: solve for R forges 8/8; solving for T still fails")
ok(ko["r_cell_needs_replaced_R"] == 8, "R-cell forgery fails under the real certificate R: it needs a replaced R")
claims["keyonly"] = ko

# ---------------------------------------------------------------- 3. nonce reuse
print("3. nonce reuse")
nr = {"trials": 0, "outsider3": 0, "forge_ok": 0, "forge_agg_ok": 0, "outsider2_refused": 0, "kgc2": 0,
      "verma2": 0, "hedged_distinct": 0, "hedged_refused": 0, "hedged_verify": 0}
for name in sorted(BACKENDS):
    be = BACKENDS[name]()
    for _ in range(4):
        nr["trials"] += 1
        qp, _, qk, qc = victim(fixed, be)
        qs = fixed.Signer(identity=b"sensor-042", pk=qk.pk, R=qc.R)
        with stuck_rng(be, be.scalar_random()):
            sigs = [fixed.sign(qp, qs, qk.sk, qc, m) for m in READINGS]
        rec = recover_keys_outsider(qp, qs, READINGS, sigs)
        nr["outsider3"] += (be.scalar_to_int(rec.sk) == be.scalar_to_int(qk.sk)
                            and be.scalar_to_int(rec.c) == be.scalar_to_int(qc.c))
        f = forge_with_keys(qp, qs, rec, b"valve=OPEN;line=A;seq=20")
        nr["forge_ok"] += fixed.verify_single(qp, qs, b"valve=OPEN;line=A;seq=20", f)
        h = fixed.sign(qp, qs, qk.sk, qc, b"temp=21.6C")
        nr["forge_agg_ok"] += fixed.agg_verify(qp, [qs, qs], [b"temp=21.6C", b"valve=OPEN;line=A;seq=20"], fixed.agg_sign(qp, [h, f]))
        try:
            recover_keys_outsider(qp, qs, READINGS[:2], sigs[:2])
        except NonceReuseError:
            nr["outsider2_refused"] += 1
        nr["kgc2"] += be.scalar_to_int(recover_sk_kgc(qp, qs, qc, READINGS[:2], sigs[:2])) == be.scalar_to_int(qk.sk)

        vp, _, vk, vc = victim(verma, be)
        vs = verma.Signer(identity=b"sensor-042", pk=vk.pk)
        with stuck_rng(be, be.scalar_random()):
            vsigs = [verma.sign(vp, vs, vk.sk, vc, m) for m in READINGS[:2]]
        vrec = recover_verma(vp, vs, READINGS[:2], vsigs)
        nr["verma2"] += verma.verify_single(vp, vs, b"valve=OPEN", forge_verma_with_keys(vp, vs, vrec, b"valve=OPEN"))

        with stuck_rng(be, be.scalar_random()):
            hs = [sign_hedged(qp, qs, qk.sk, qc, m) for m in READINGS]
        nr["hedged_distinct"] += len({be.point_to_bytes(s.T) for s in hs}) == 3
        nr["hedged_verify"] += all(fixed.verify_single(qp, qs, m, s) for m, s in zip(READINGS, hs))
        try:
            recover_keys_outsider(qp, qs, READINGS, hs)
        except NonceReuseError:
            nr["hedged_refused"] += 1
t = nr["trials"]
ok(t == 8 and nr["outsider3"] == 8 and nr["forge_ok"] == 8 and nr["forge_agg_ok"] == 8,
   "outsider, 3 signatures: sk and c recovered, forgery verifies and aggregates, 8/8")
ok(nr["outsider2_refused"] == 8, "outsider with 2 signatures: refused, 8/8")
ok(nr["kgc2"] == 8, "KGC, 2 signatures: sk recovered, 8/8")
ok(nr["verma2"] == 8, "Verma, 2 signatures: forgery verifies, 8/8")
ok(nr["hedged_distinct"] == 8 and nr["hedged_verify"] == 8 and nr["hedged_refused"] == 8,
   "hedged nonces under a stuck RNG: distinct T, verify unchanged, attack refused, 8/8")
claims["nonce"] = nr

# ---------------------------------------------------------------- 4. Section V-C claims
print("4. Section V-C properties 2 and 4")
vc_ = {"replay": 0, "replay_in_batch": 0, "backdated": 0, "trials": 0}
for name in sorted(BACKENDS):
    be = BACKENDS[name]()
    vc_["trials"] += 1
    p0, _, kk, cc = victim(fixed, be, delta=b"epoch-0")
    sg = fixed.Signer(identity=b"sensor-042", pk=kk.pk, R=cc.R)
    old = fixed.sign(p0, sg, kk.sk, cc, b"valve=OPEN")
    vc_["replay"] += fixed.verify_single(p0, sg, b"valve=OPEN", old)
    vc_["replay_in_batch"] += fixed.agg_verify(p0, [sg, sg], [b"valve=OPEN"] * 2, fixed.agg_sign(p0, [old, old]))
    p1 = fixed.PublicParams(backend=be, pk_ta=p0.pk_ta, delta=b"epoch-1")
    with stuck_rng(be, be.scalar_random()):
        later = [fixed.sign(p1, sg, kk.sk, cc, m) for m in READINGS]
    stolen = recover_keys_outsider(p1, sg, READINGS, later)
    vc_["backdated"] += fixed.verify_single(p0, sg, b"temp=99.0C;seq=0", forge_with_keys(p0, sg, stolen, b"temp=99.0C;seq=0"))
ok(vc_["replay"] == vc_["replay_in_batch"] == 2, "an old signature replays, also twice in one batch (both backends)")
ok(vc_["backdated"] == 2, "keys stolen in epoch 1 sign a back-dated epoch-0 reading that verifies (both backends)")
claims["vc"] = vc_

# ---------------------------------------------------------------- 5. aggregator
print("5. aggregator")
be = BACKENDS["p256"]()
params, _, signers, secrets, messages = q_enrol(be, 32)
sigs = q_sign_all(params, signers, secrets, messages)
good_agg = fixed.agg_sign(params, sigs)
sigs[19] = fixed.Signature(T=sigs[19].T, z=be.scalar_add(sigs[19].z, be.scalar_from_int(1)))
bad_agg = fixed.agg_sign(params, sigs)
ok(fixed.agg_verify(params, signers, messages, good_agg) and not fixed.agg_verify(params, signers, messages, bad_agg),
   "one bad signature in 32 makes the whole aggregate fail")
counter = [0]
found = locate_faults(params, prepare(params, signers), messages, sigs, counter)
ok(found == [19] and counter[0] < 32, f"RETAIN locates the one fault in 32 with {counter[0]} verifications")
dos = json.loads((RESULTS / "dos_p256.json").read_text())
u = dos["unit_cost_ms"]
rows = {r["fault_rate"]: r for r in dos["policy_rows"]}
gap = u["single_verify"] / u["per_signature_in_aggregate"]
ok(1.6 < gap < 1.9, f"individual verification is {gap:.2f}x dearer per signature (recorded)")
ok(rows[0.0]["retain"] < rows[0.0]["preverify"] and rows[0.005]["preverify"] < rows[0.005]["retain"],
   "RETAIN cheaper on clean batches, PREVERIFY cheaper from 0.5%")
ok(rows[0.02]["blind"] == float("inf") and rows[0.0]["blind"] < rows[0.0]["retain"],
   "BLIND cheapest on clean batches, delivers nothing from 2%")
claims["aggregator"] = {"n_locate": 32, "locate_verifications": counter[0], "gap": round(gap, 2),
                        "rows": [{k_: (None if v == float("inf") else round(v, 4)) for k_, v in r.items()}
                                 for r in dos["policy_rows"]],
                        "n": dos["n"], "trials": dos["trials"], "timestamp": dos["timestamp"]}

# ---------------------------------------------------------------- 6. optimisation
print("6. optimisation (tracked JSON)")
opt = {}
for b in ("p256", "ristretto255"):
    d = json.loads((RESULTS / f"optimization_{b}.json").read_text())
    opt[b] = {"ratio_naive": round(d["ratio_naive"], 4), "ratio_optimised": round(d["ratio_optimised"], 4),
              "slopes": {s: {k_: round(v, 1) for k_, v in d["slopes_us_per_signer"][s].items()} for s in ("cbas", "verma")},
              "msm_terms": d["msm_terms"], "native_msm": d["native_msm"], "timestamp": d["timestamp"]}
ok(opt["p256"]["ratio_optimised"] > opt["p256"]["ratio_naive"] > 2.3, "P-256: the ratio grows when both schemes are optimised")
ok(opt["ristretto255"]["ratio_optimised"] > opt["ristretto255"]["ratio_naive"], "Ristretto255: the ratio still grows")
ok(opt["p256"]["msm_terms"] == {"cbas": 1501, "verma": 502}, "MSM terms at n=500: 1501 vs 502 (3n+1 vs n+2)")
claims["optimisation"] = opt

# ---------------------------------------------------------------- 7. test and self-test counts
print("7. test counts")
out = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-o", "addopts="],
                     cwd=ROOT, capture_output=True, text=True).stdout
ids = [l for l in out.splitlines() if "::" in l]
indep = [i for i in ids if "p256" not in i and "ristretto255" not in i]
per = [i for i in ids if "[p256" in i or "-p256" in i or "p256]" in i or "p256-" in i]
st = subprocess.run([sys.executable, "-m", "cbas.backend.selftest"], cwd=ROOT, capture_output=True, text=True,
                    env={"PYTHONPATH": str(ROOT / "src")}).stdout
self_n = int(re.search(r"(\d+) passed, 0 failed", st).group(1))
ok(len(ids) == 2 * len(per) + len(indep), f"{len(ids)} tests = {len(per)} x 2 backends + {len(indep)} backend-independent")
ok(self_n == 62, "self-test: 62 algebra checks")
claims["tests"] = {"total": len(ids), "per_backend": len(per), "independent": len(indep), "selftest": self_n}

OUT.write_text(json.dumps(claims, indent=2))
print(f"\nwrote {OUT.relative_to(ROOT)}")
