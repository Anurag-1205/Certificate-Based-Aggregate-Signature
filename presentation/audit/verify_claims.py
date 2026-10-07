"""Recompute every number used in the interim deck, from code and tracked data.

Run from the repository root:

    .venv/bin/python presentation/audit/verify_claims.py

Writes presentation/data/claims.json, which the figure and slide builders read, so no
number in the deck is typed in by hand. Every claim is asserted; a mismatch stops the run.
Read-only with respect to src/, tests/ and bench/.
"""
import json
import pathlib
import re
import statistics
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from cbas import ablation, scheme as fixed, verma  # noqa: E402
from cbas.attack import attempt_forge_fixed, forge_verma  # noqa: E402
from cbas.backend import BACKENDS, CountingBackend  # noqa: E402
from tests.test_scheme_roundtrip import enrol as q_enrol, sign_all as q_sign_all  # noqa: E402
from tests.test_verma import enrol as v_enrol, sign_all as v_sign_all  # noqa: E402

OUT = ROOT / "presentation" / "data" / "claims.json"
TB, TE, TA, TH = 1.365, 0.112, 0.005, 0.004          # paper Table IV (ms)
claims: dict = {"table_iv_ms": {"Tb": TB, "Te": TE, "Ta": TA, "Th": TH}}


def cost(te=0, ta=0, th=0, tb=0):
    return round(tb * TB + te * TE + ta * TA + th * TH, 6)


def ok(cond, msg):
    if not cond:
        raise SystemExit(f"CLAIM FAILED: {msg}")
    print(f"  ok  {msg}")


# ---------------------------------------------------------------- 1. operation counts
print("1. operation counts (both backends)")
counts = {}
for name in sorted(BACKENDS):
    be = CountingBackend(BACKENDS[name]())
    row = {}
    # Qiao
    params, _, signers, secrets, messages = q_enrol(be, 1)
    with be.count() as c:
        sig = fixed.sign(params, signers[0], secrets[0][0].sk, secrets[0][1], messages[0])
    row["qiao_sign"] = [c.Te, c.Ta, c.Th]
    with be.count() as c:
        assert fixed.verify_single(params, signers[0], messages[0], sig)
    row["qiao_verify"] = [c.Te, c.Ta, c.Th]
    for n in (10, 100):
        params, _, signers, secrets, messages = q_enrol(be, n)
        sigs = q_sign_all(params, signers, secrets, messages)
        with be.count() as c:
            agg = fixed.agg_sign(params, sigs)
        row[f"qiao_aggsign_n{n}"] = [c.Te, c.Ta, c.Th, c.Ts]
        with be.count() as c:
            assert fixed.agg_verify(params, signers, messages, agg)
        row[f"qiao_aggverify_n{n}"] = [c.Te, c.Ta, c.Th]
    # Verma
    params, _, signers, secrets, messages = v_enrol(be, 1)
    with be.count() as c:
        vsig = verma.sign(params, signers[0], secrets[0][0].sk, secrets[0][1], messages[0])
    row["verma_sign"] = [c.Te, c.Ta, c.Th]
    with be.count() as c:
        assert verma.verify_single(params, signers[0], messages[0], vsig)
    row["verma_verify"] = [c.Te, c.Ta, c.Th]
    for n in (10, 100):
        params, _, signers, secrets, messages = v_enrol(be, n)
        sigs = v_sign_all(params, signers, secrets, messages)
        with be.count() as c:
            agg = verma.agg_sign(params, sigs)
        row[f"verma_aggsign_n{n}"] = [c.Te, c.Ta, c.Th, 0]
        with be.count() as c:
            assert verma.agg_verify(params, signers, messages, agg)
        row[f"verma_aggverify_n{n}"] = [c.Te, c.Ta, c.Th]
    counts[name] = row

for name, r in counts.items():
    ok(r["qiao_sign"] == [1, 0, 2], f"{name}: Qiao Sign = 1Te + 2Th")
    ok(r["qiao_verify"] == [4, 3, 3], f"{name}: Qiao single Verify = 4Te + 3Ta + 3Th")
    for n in (10, 100):
        ok(r[f"qiao_aggverify_n{n}"] == [2 * n + 2, 3 * n, 3 * n], f"{name}: Qiao AggVerify n={n} = (2n+2)Te + 3nTa + 3nTh")
        ok(r[f"verma_aggverify_n{n}"] == [n + 2, n + 1, 2 * n], f"{name}: Verma AggVerify n={n} = (n+2)Te + (n+1)Ta + 2nTh (= printed row)")
        ok(r[f"qiao_aggsign_n{n}"][:3] == [0, 0, 0] and r[f"qiao_aggsign_n{n}"][3] == n - 1,
           f"{name}: Qiao AggSign n={n} = 0 group operations, {n-1} scalar additions")
        ok(r[f"verma_aggsign_n{n}"][:3] == [0, n - 1, 0], f"{name}: Verma AggSign n={n} = (n-1)Ta (= printed row)")
    ok(r["verma_sign"] == [1, 1, 1], f"{name}: Verma Sign = 1Te + 1Ta + 1Th (printed: 1Te + 1Th)")
    ok(r["verma_verify"] == [3, 2, 2], f"{name}: Verma single Verify = 3Te + 2Ta + 2Th (= printed row)")
ok(counts["p256"] == counts["ristretto255"], "operation counts identical on both backends")
claims["op_counts"] = counts

# ---------------------------------------------------------------- 2. n = 100 arithmetic
print("2. n = 100 under the paper's Table IV")
n = 100
printed = cost(te=n + 2, ta=n + 1, th=2 * n)
recount = cost(te=2 * n + 2, ta=3 * n, th=3 * n)
cached = cost(te=2 * n + 1, ta=3 * n - 1, th=2 * n)
ok(round(printed, 3) == 12.729, f"printed row at n=100 = {printed:.3f} ms (= Fig. 4 bar 12.729)")
ok(round(recount, 3) == 25.324, f"recount at n=100 = {recount:.3f} ms")
ok(round(cached, 3) == 24.807, f"recount with per-signer caching at n=100 = {cached:.3f} ms")
claims["n100"] = {"printed_ms": printed, "recount_ms": recount, "cached_ms": cached,
                  "factor": recount / printed, "factor_cached": cached / printed,
                  "per_signer_printed_ms": cost(1, 1, 2), "per_signer_recount_ms": cost(2, 3, 3),
                  "per_signer_factor": cost(2, 3, 3) / cost(1, 1, 2)}
ok(abs(recount / printed - 1.9895) < 5e-4, f"factor = {recount / printed:.4f}")

# ---------------------------------------------------------------- 3. paper figures recomputed
print("3. Figs. 3-5 recomputed from Tables II-IV")
fig3 = {  # (Sign, Verify) rows exactly as printed in Table II; Tb counted
    "[6]": ((0, 1, 0, 2), (0, 4, 0, 3)), "[11]": ((0, 1, 0, 1), (0, 3, 2, 2)),
    "[21]": ((0, 3, 2, 2), (3, 1, 1, 3)), "[22]": ((0, 5, 3, 3), (3, 2, 2, 3)),
    "[23]": ((0, 2, 1, 1), (3, 1, 0, 2)), "[24]": ((0, 3, 2, 2), (4, 1, 0, 4)),
    "ours_printed": ((0, 1, 0, 1), (0, 3, 2, 2)), "ours_recount": ((0, 1, 0, 2), (0, 4, 3, 3)),
}
f3 = {}
for k, (s, v) in fig3.items():
    f3[k] = [cost(tb=s[0], te=s[1], ta=s[2], th=s[3]), cost(tb=v[0], te=v[1], ta=v[2], th=v[3])]
labels = {"[6]": (0.12, 0.46, 0.58), "[11]": (0.116, 0.354, 0.47), "[21]": (0.354, 4.224, 4.578),
          "[22]": (0.587, 4.341, 4.928), "[23]": (0.233, 4.215, 4.448), "[24]": (0.354, 5.588, 5.942)}
for k, (s_, v_, t_) in labels.items():   # values printed on the bars of the paper's Fig. 3
    ok(round(f3[k][0], 3) == round(s_, 3) and round(f3[k][1], 3) == round(v_, 3), f"Fig. 3 {k}: sign {s_}, verify {v_} reproduced")
claims["fig3_ms"] = f3
fig4 = {
    "[6]": [cost(ta=n - 1), cost(te=2 * n + 2, ta=3 * n - 1, th=3 * n)],
    "[11]": [cost(ta=n - 1), printed], "ours_printed": [cost(ta=n - 1), printed],
    "ours_recount": [cost(ta=n - 1), recount],
}
ok([round(x, 3) for x in fig4["[6]"]] == [0.495, 25.319], "Fig. 4 [6]: AggSign 0.495, AggVerify 25.319")
ok([round(x, 3) for x in fig4["ours_printed"]] == [0.495, 12.729], "Fig. 4 ours/[11]: 0.495, 12.729")
claims["fig4_ms"] = fig4
ns = list(range(50, 501, 30))
claims["fig5_ms"] = {
    "n": ns,
    "ours_printed": [cost(te=k + 2, ta=k + 1, th=2 * k) for k in ns],
    "ref6": [cost(te=2 * k + 2, ta=3 * k - 1, th=3 * k) for k in ns],
    "ours_recount": [cost(te=2 * k + 2, ta=3 * k, th=3 * k) for k in ns],
}
ok(round(claims["fig5_ms"]["ours_printed"][-1] - 0, 3) > 0, "Fig. 5 series computed")
claims["ours_recount_minus_ref6_n100_ms"] = fig4["ours_recount"][1] - fig4["[6]"][1]
ok(abs(claims["ours_recount_minus_ref6_n100_ms"] - 0.005) < 1e-9, "recount - [6] at n=100 = 0.005 ms (= one Ta)")

# ---------------------------------------------------------------- 4. caching convention
print("4. caching convention (per-signer C_i = R_i + h0_i * P_TA precomputed)")
from cbas.hashing import H0, H1, H2  # noqa: E402
cache = {}
for name in sorted(BACKENDS):
    be = CountingBackend(BACKENDS[name]())
    out = {}
    for nn in (1, 10, 100):
        params, _, signers, secrets, messages = q_enrol(be, nn)
        agg = fixed.agg_sign(params, q_sign_all(params, signers, secrets, messages))
        C = [be.point_add(s.R, be.point_mul(H0(be, s.identity, s.pk, s.R), params.pk_ta)) for s in signers]
        with be.count() as c:
            lhs = be.point_mul_base(agg.z)
            uC, vpk = [], []
            for s, m, T, Ci in zip(signers, messages, agg.T, C):
                v = H1(be, m, s.pk, s.R, s.identity, T, params.delta)
                u = H2(be, m, s.pk, s.R, s.identity, T, params.delta)
                uC.append(be.point_mul(u, Ci))
                vpk.append(be.point_mul(v, s.pk))
            rhs = be.point_add(be.point_add(be.sum_points(agg.T), be.sum_points(uC)), be.sum_points(vpk))
            valid = be.point_eq(lhs, rhs)
        assert valid
        out[f"n{nn}"] = [c.Te, c.Ta, c.Th]
    vparams, vmsk = verma.setup(be, b"epoch-0")
    k = verma.keygen(vparams)
    cert = verma.cert_gen(vparams, vmsk, b"id", k.pk)
    sg = verma.Signer(b"id", k.pk)
    sig = verma.sign(vparams, sg, k.sk, cert, b"m")
    hP = be.point_mul(verma.H0(be, b"id", k.pk), vparams.pk_ta)
    with be.count() as c:
        v = verma.H1(be, b"m", k.pk, b"id", vparams.delta)
        assert be.point_eq(be.point_mul_base(sig.z), be.point_add(be.point_add(sig.R, hP), be.point_mul(v, k.pk)))
    out["verma_single"] = [c.Te, c.Ta, c.Th]
    cache[name] = out
for name, r in cache.items():
    ok(r["n1"] == [3, 2, 2], f"{name}: Qiao single Verify with caching = 3Te + 2Ta + 2Th (= printed Table II row)")
    ok(r["n100"] == [201, 299, 200], f"{name}: Qiao AggVerify n=100 with caching = 201Te + 299Ta + 200Th (> printed 102Te)")
    ok(r["verma_single"] == [2, 2, 1], f"{name}: Verma single Verify under the same caching = 2Te + 2Ta + 1Th")
claims["caching"] = cache

# ---------------------------------------------------------------- 5. attack / ablation matrix
print("5. attack and ablation matrix")
TARGETS = [b"temp=-40.0C;line=A;seq=17;SHUTDOWN", b"pressure=0;valve=OPEN", b"", b"\x00\xff" * 40]
mat = {"verma_forged": 0, "qiao_forged": 0, "ablated_forged": 0, "trials": 0, "qiao_iterations": [],
       "qiao_distinct": [], "verma_aggregation_ok": 0, "controls_ok": 0}
for name in sorted(BACKENDS):
    be = BACKENDS[name]()
    for tgt in TARGETS:
        mat["trials"] += 1
        vp, vmsk = verma.setup(be, b"epoch-0")
        vk = verma.keygen(vp)
        vc = verma.cert_gen(vp, vmsk, b"sensor-042", vk.pk)
        vs = verma.Signer(identity=b"sensor-042", pk=vk.pk)
        m0 = b"temp=21.4C;line=A;seq=17"
        vsig = verma.sign(vp, vs, vk.sk, vc, m0)
        forged = forge_verma(vp, vs, vc, m0, vsig, tgt)
        mat["verma_forged"] += verma.verify_single(vp, vs, tgt, forged)
        agg = verma.agg_sign(vp, [vsig, forged])
        mat["verma_aggregation_ok"] += verma.agg_verify(vp, [vs, vs], [m0, tgt], agg)

        qp, qmsk = fixed.setup(be, b"epoch-0")
        qk = fixed.keygen(qp)
        qc = fixed.cert_gen(qp, qmsk, b"sensor-042", qk.pk)
        qs = fixed.Signer(identity=b"sensor-042", pk=qk.pk, R=qc.R)
        qsig = fixed.sign(qp, qs, qk.sk, qc, m0)
        att = attempt_forge_fixed(qp, qs, qc, m0, qsig, tgt)
        mat["qiao_forged"] += att.succeeded
        mat["qiao_iterations"].append(att.iterations)
        mat["qiao_distinct"].append(len(set(att.trace)))

        ap, amsk = ablation.setup(be, b"epoch-0")
        ak = ablation.keygen(ap)
        ac = ablation.cert_gen(ap, amsk, b"sensor-042", ak.pk)
        asg = ablation.Signer(identity=b"sensor-042", pk=ak.pk, R=ac.R)
        asig = ablation.sign(ap, asg, ak.sk, ac, m0)
        mat["controls_ok"] += (ablation.verify_single(ap, asg, m0, asig)
                               and not ablation.verify_single(ap, asg, b"different", asig))
        aforged = ablation.forge_ablated(ap, asg, ac, m0, asig, tgt)
        mat["ablated_forged"] += ablation.verify_single(ap, asg, tgt, aforged)
ok(mat["verma_forged"] == mat["trials"] == 8, "Verma forgery verifies in 8/8 trials (4 messages x 2 backends)")
ok(mat["verma_aggregation_ok"] == 8, "Verma forgery survives aggregation in 8/8 trials")
ok(mat["qiao_forged"] == 0 and all(i == 16 for i in mat["qiao_iterations"]), "Qiao rescaling attempt: 0/8 succeed, 16 iterations each")
ok(all(d == 16 for d in mat["qiao_distinct"]), "Qiao attempt: all 16 candidates distinct in every trial")
ok(mat["ablated_forged"] == 8, "ablated variant (T_i not hashed): forgery verifies in 8/8 trials")
ok(mat["controls_ok"] == 8, "ablated variant controls: honest verifies, other message rejected, 8/8")
claims["attack_matrix"] = mat

# ---------------------------------------------------------------- 6. test and self-test counts
print("6. test and self-test counts")
py = str(ROOT / ".venv" / "bin" / "python")
col = subprocess.run([py, "-m", "pytest", "-p", "no:cacheprovider", "-o", "addopts=", "--collect-only", "-q"],
                     capture_output=True, text=True, cwd=ROOT).stdout
ids = [l for l in col.splitlines() if "::" in l]
by_backend = {b: sum(1 for l in ids if re.search(rf"\[(?:[^\]]*-)?{b}(?:-[^\]]*)?\]", l)) for b in ("p256", "ristretto255")}
no_backend = sum(1 for l in ids if not re.search(r"p256|ristretto255", l))
ok(len(ids) == 221, f"pytest collects {len(ids)} tests")
ok(by_backend["p256"] == by_backend["ristretto255"] == 101 and no_backend == 19, "221 = 101 x 2 backends + 19 backend-independent")
run = subprocess.run([py, "-m", "pytest", "-p", "no:cacheprovider", "-o", "addopts=", "-q"],
                     capture_output=True, text=True, cwd=ROOT)
ok(run.returncode == 0 and "221 passed" in run.stdout, "pytest: 221 passed, exit code 0")
st = subprocess.run([py, "-m", "cbas.backend.selftest"], capture_output=True, text=True, cwd=ROOT).stdout
ok("62 passed, 0 failed" in st, "selftest: 62 passed, 0 failed (31 checks x 2 backends)")
per_file = {}
for l in ids:
    per_file[l.split("::")[0].replace("tests/", "")] = per_file.get(l.split("::")[0].replace("tests/", ""), 0) + 1
claims["tests"] = {"total": len(ids), "per_backend": by_backend["p256"], "backend_independent": no_backend,
                   "selftest_checks": 62, "per_file": per_file}

# ---------------------------------------------------------------- 7. recorded timing (tracked JSON)
print("7. recorded timing ratios (tracked bench/results)")
ry = json.loads((ROOT / "bench/results/sweep_ryzen5-7520u.json").read_text())
kg = json.loads((ROOT / "bench/results/sweep_kaggle-xeon.json").read_text())
runs = []
for b, d in ry["backends"].items():
    for i, r in enumerate(d["runs"], 1):
        runs.append({"machine": "Ryzen 5 7520U", "backend": b, "run": i, "ratio": r["ratio_measured"],
                     "pred": r["ratio_predicted"], "r2": min(r["r2_cbas"], r["r2_verma"])})
runs.append({"machine": "Xeon 2.2 GHz (Kaggle)", "backend": "ristretto255", "run": 1,
             "ratio": kg["slope_ratio_measured"], "pred": kg["slope_ratio_predicted_from_counts"],
             "r2": min(kg["fits"]["cbas"]["r2"], kg["fits"]["verma"]["r2"])})
allr = [r["ratio"] for r in runs]
ok(len(runs) == 11, "11 recorded runs")
ok(round(min(allr), 2) == 1.99 and round(max(allr), 2) == 2.48, f"all 11 runs between {min(allr):.2f} and {max(allr):.2f}")
summ = {}
for b, d in ry["backends"].items():
    summ[f"ryzen_{b}"] = {"median": d["ratio_median"], "min": d["ratio_min"], "max": d["ratio_max"],
                          "pred": d["ratio_predicted_median"], "runs_used": d["runs_used"]}
summ["kaggle_ristretto255"] = {"median": kg["slope_ratio_measured"], "pred": kg["slope_ratio_predicted_from_counts"]}
ok(round(summ["ryzen_ristretto255"]["median"], 3) == 2.153 and round(summ["ryzen_p256"]["median"], 3) == 2.366
   and round(summ["kaggle_ristretto255"]["median"], 3) == 2.123, "ratios 2.153 / 2.366 / 2.123 as in RESULTS.md")
claims["timing"] = {"runs": runs, "summary": summ, "kaggle_sweep": {
    "n": kg["sweep"]["n"], "cbas_ms": kg["sweep"]["cbas_ms"], "verma_ms": kg["sweep"]["verma_ms"],
    "ed25519_ms": kg["sweep"]["ed25519_ms"], "fits": kg["fits"], "primitives_ms": kg["primitives_ms"]}}
for b_, d_ in ry["backends"].items():       # B9 states: medians are unchanged by the r2 >= 0.99 filter
    all_med = statistics.median([r["ratio_measured"] for r in d_["runs"]])
    ok(abs(all_med - d_["ratio_median"]) < 1e-9, f"{b_}: median over all 5 runs ({all_med:.4f}) equals the filtered median")
ok(min(allr) > 1.9, "lowest recorded run ratio is " + f"{min(allr):.3f} (RESULTS.md's '1.86' is not in the tracked data)")

OUT.parent.mkdir(exist_ok=True)
OUT.write_text(json.dumps(claims, indent=2, default=str))
print(f"\nall claims verified; wrote {OUT.relative_to(ROOT)}")
