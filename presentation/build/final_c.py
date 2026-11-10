"""Part III: faster verification (slides 14-16). Part IV: the aggregator (slides 17-19)."""
import theme as T
from final_common import C, FIG, N, card, num_badge, tag_pill
from lib import arrow, box, chip, grid, image, party, tb, takeaway


def build(d):
    op = C["optimisation"]
    p, r = op["p256"], op["ristretto255"]
    ag = C["aggregator"]

    # ------------------------------------------------------------------ 14. the objection
    s = d.slide("Part III · Faster verification", "Would a real implementation close the gap?",
                tags=["IMPLEMENTATION", "EXPERIMENT"], notes=N("""
        SAY: A fair objection to the interim: nobody verifies term by term. A real verifier would batch the work. So we optimised verification twice, and gave both schemes exactly the same treatment.
        THE TWO OPTIMISATIONS: one, multi-scalar multiplication: the whole verification equation evaluated in a single native call, OpenSSL's EC_POINTs_mul, instead of one call per term. Two, a prepared sensor roster: an industrial fleet is fixed, so each sensor's encodings and its certificate hash h_0 never change and can be computed once.
        THE MISTAKE WE CAUGHT: our first measurement gave the roster to Qiao's scheme but not to Verma's, and showed a ratio of 1.63, as if optimising closed the gap. That was unequal treatment. With both schemes optimised the same way, the ratio is about 3.
        TIME: 45 seconds.
        NEXT: the numbers.
    """))
    card(s, 0.6, 1.75, 5.9, 2.25, "① Multi-scalar multiplication",
         ["Evaluate the whole check $zP = Σ…$ in one native call (OpenSSL `EC_POINTs_mul`), not one call per term."],
         tag="IMPLEMENTATION", hsize=18, bsize=16)
    card(s, 6.83, 1.75, 5.9, 2.25, "② A prepared sensor roster",
         ["A factory's sensors are fixed, so each one's encodings and $h_{0}$ are computed once, not per batch."],
         tag="IMPLEMENTATION", hsize=18, bsize=16)
    box(s, 0.6, 4.25, 12.13, 1.8, fill=T.AGG_T, line=T.AGG, lw=1.5, radius=0.1)
    tb(s, 0.85, 4.35, 11.6, 1.6, [
        {"text": "A mistake we caught: equal treatment", "bold": True, "size": 18, "after": 6},
        {"text": "Our first version gave the roster to Qiao's scheme only and showed a ratio of ×1.63, as if optimising closed the gap.", "size": 16, "after": 4},
        {"text": "Verma's $h_{0}$ is just as fixed. With both schemes optimised the same way, the ratio goes the other way.", "size": 16}],
       lsp=0.97)
    takeaway(s, "Both optimisations, applied to both schemes.")

    # ------------------------------------------------------------------ 15. the result
    s = d.slide("Part III · The result", f"Optimising both schemes widens the gap: ×{p['ratio_naive']:.1f} → ×{p['ratio_optimised']:.1f}",
                tags=["EXPERIMENT", "OUR AUDIT"], notes=N(f"""
        SAY: Per-signer cost of aggregate verification on P-256, both schemes, three stages. As specified: {p['slopes']['cbas']['naive']:.0f} against {p['slopes']['verma']['naive']:.0f} microseconds, ratio {p['ratio_naive']:.2f}. Fully optimised: {p['slopes']['cbas']['prepared']:.0f} against {p['slopes']['verma']['prepared']:.0f}, ratio {p['ratio_optimised']:.2f}. Over four runs the optimised ratio was 2.95 to 3.07.
        WHY IT GROWS: once everything is one multi-scalar multiplication, cost follows the number of terms. Qiao's equation has 3n + 1 terms, Verma's n + 2: at n = 500, {p['msm_terms']['cbas']} against {p['msm_terms']['verma']}, a ratio of 2.99. The measured ratio converges to the term ratio.
        AUDIENCE SHOULD GET: the paper's "same cost as Verma" claim moves further from the truth in a good implementation, not closer.
        TIME: 1 minute.
        IF ASKED 'why P-256?': it has a native multi-scalar routine; Ristretto255 in libsodium does not (next slide).
    """))
    image(s, FIG / "final_optimisation.png", 0.6, 1.62, w=7.3)
    box(s, 8.2, 1.75, 4.53, 4.3, fill=T.PANEL, line=None, radius=0.1)
    tb(s, 8.45, 1.9, 4.1, 4.05, [
        {"text": "Why the gap grows", "bold": True, "size": 18, "after": 8},
        {"text": "Optimised, the cost follows the number of terms in one big sum.", "size": 16, "after": 8},
        {"text": "Qiao: $3n + 1$ terms", "size": 17, "after": 2},
        {"text": "Verma: $n + 2$ terms", "size": 17, "after": 6},
        {"text": f"At $n = 500$: {p['msm_terms']['cbas']} vs {p['msm_terms']['verma']}, ratio 2.99", "size": 16, "after": 8},
        {"text": "The measured ratio approaches the term ratio, not 1.", "size": 16, "color": T.MUTED}], lsp=0.97)
    takeaway(s, "A good implementation moves the paper's “same cost” claim further from the truth.")

    # ------------------------------------------------------------------ 16. library matters
    s = d.slide("Part III · The library matters", "Which optimisation pays depends on the library",
                tags=["EXPERIMENT", "OUR AUDIT"], notes=N(f"""
        SAY: On Ristretto255 through libsodium there is no native multi-scalar routine, so optimising barely helps either scheme, and the ratio still rises: {r['ratio_naive']:.2f} to {r['ratio_optimised']:.2f}. The two libraries also store points differently: libsodium keeps a point as its 32-byte encoding, so encoding is nearly free and addition is expensive; OpenSSL keeps coordinates, so addition is cheap and encoding costs a modular inversion.
        THE INTERIM'S OPEN POINT: at the interim, P-256 timing was about 20 percent above what the operation counts predicted. This explains it. Every hash call encodes its point inputs: Qiao's verification encodes 8 points per signer, Verma's 2; a test counts them. On P-256 that is expensive. Pricing the real hash calls predicts 2.363 to 2.371, and we measured 2.366. It was not interpreter overhead.
        TIME: 45 seconds.
        NEXT: Part IV, the aggregator.
    """))
    rows = [[{"text": ""}, {"text": "P-256 · OPENSSL"}, {"text": "RISTRETTO255 · LIBSODIUM"}],
            [{"text": "Native multi-scalar routine", "bold": True}, "yes", "no"],
            [{"text": "Ratio as specified → optimised", "bold": True}, f"{p['ratio_naive']:.2f} → {p['ratio_optimised']:.2f}",
             f"{r['ratio_naive']:.2f} → {r['ratio_optimised']:.2f}"],
            [{"text": "Encoding a point vs adding two", "bold": True}, "encoding ≈ 2× an addition", "encoding ≈ 1/300 of an addition"]]
    grid(s, 0.6, 1.75, [4.0, 4.0, 4.13], [0.45, 0.5, 0.5, 0.5], rows, size=16.5, hdr_size=12)
    box(s, 0.6, 4.05, 12.13, 2.0, fill=T.WHITE, line=T.INK, lw=1.5, radius=0.1)
    tag_pill(s, 0.85, 4.18, "OUR AUDIT")
    tb(s, 0.85, 4.52, 11.6, 1.5, [
        {"text": "This also closes the interim's open P-256 gap", "bold": True, "size": 18, "after": 6},
        {"text": "Each hash call encodes its point inputs: 8 per signer for Qiao, 2 for Verma (counted by a test). Expensive on P-256.", "size": 16, "after": 4},
        {"text": "Pricing the real hash calls predicts 2.363–2.371; measured 2.366. Not interpreter overhead.", "size": 16, "bold": True}],
       lsp=0.97)
    tb(s, 0.6, 6.08, 12.1, 0.25, "Sources: bench/results/optimization_*.json; tests/test_opcount.py; bench/hashcost.py (three repeats).",
       size=11.5, color=T.MUTED, check=False)
    takeaway(s, "The gap holds on both libraries, and the interim's P-256 residual is explained.", y=6.38)

    # ------------------------------------------------------------------ 17. one bad signature
    s = d.slide("Part IV · The aggregator in practice", "One bad signature sinks the whole batch",
                tags=["PAPER", "OUR FINDING"], notes=N(f"""
        SAY: The paper treats the aggregator as harmless: in its words, it does not use its own private information, it only merges signatures. That is true, and it is why aggregation is secure. But merging is a sum: z is the sum of the z_i. If one signature is bad, from a faulty sensor, a corrupted link or an attacker, the whole aggregate fails, and the sum no longer tells you which one.
        TEST: one corrupted signature in a batch of {ag['n_locate']}: the aggregate fails verification. Nothing in the aggregate identifies the culprit.
        FRAMING: availability, not forgery. The security proof is untouched.
        TIME: 45 seconds.
        NEXT: three ways to run an aggregator.
    """))
    for i in range(6):
        y = 1.8 + i * 0.6
        bad = i == 3
        party(s, "bad" if bad else "sen", 0.6, y, 2.3, 0.48, text=("sensor 4 · bad $z_{4}$" if bad else f"sensor {i + 1}"),
              size=14, bold=bad)
        arrow(s, [(2.9, y + 0.24), (4.2, 3.4)], T.BAD if bad else T.SEN, lw=1.25)
    tb(s, 0.6, 5.42, 2.3, 0.3, "⋮  32 sensors", size=14, color=T.MUTED, align="c")
    party(s, "agg", 4.2, 2.9, 2.6, 1.0, text=[{"text": "AggSign", "bold": True, "size": 18},
                                               {"text": "$z = Σz_{i}$", "size": 16}])
    arrow(s, [(6.8, 3.4), (8.0, 3.4)], T.AGG, lw=2.25)
    party(s, "ver", 8.0, 2.9, 2.3, 1.0, text=[{"text": "AggVerify", "bold": True, "size": 18},
                                               {"text": "result: 0", "size": 16, "color": T.BAD}])
    chip(s, 10.6, 2.6, 2.13, 0.7, "all 32 rejected", "bad", size=15, bold=True)
    chip(s, 10.6, 3.5, 2.13, 0.7, "culprit unknown", "bad", size=15, bold=True)
    box(s, 4.2, 4.35, 8.53, 1.65, fill=T.PANEL, line=None, radius=0.1)
    tb(s, 4.45, 4.45, 8.1, 1.5, [
        {"text": "The paper: the aggregator “does not use their own private information … only merges multiple signatures.”", "size": 15, "after": 6},
        {"text": "True, and it is why aggregation is secure. But a sum hides which term was wrong, so one faulty sensor denies service to every honest one in its batch.", "size": 16}],
       lsp=0.97)
    takeaway(s, "Aggregation is secure but fragile: one bad input loses the batch, and the cause cannot be seen.", color=T.BAD)

    # ------------------------------------------------------------------ 18. three policies
    s = d.slide("Part IV · Three policies", "Three ways to run the aggregator", tags=["IMPLEMENTATION"], notes=N(f"""
        SAY: BLIND is the paper's model: merge everything and hope. PREVERIFY checks every signature first and drops bad ones. RETAIN merges optimistically but keeps the individual signatures; if the aggregate fails, it splits the batch in halves and re-checks each half, recursively.
        WHY RETAIN IS CHEAP: a clean half costs one aggregate verification, whatever its size. One bad signature in {ag['n_locate']} was located with {ag['locate_verifications']} verifications instead of {ag['n_locate']}.
        All three use no secret material, so the security argument is unchanged; a test checks that.
        TIME: 45 seconds.
        NEXT: which policy to use, by numbers.
    """))
    cards = [("BLIND", "the paper's model", ["Merge everything", "One bad signature: whole batch lost, culprit unknown"], "plain"),
             ("PREVERIFY", "check first", ["Verify every signature, merge the good ones", "Bad ones dropped, the rest delivered"], "agg"),
             ("RETAIN", "merge, keep the parts", ["On failure, split in halves and re-check",
                                                   f"1 bad in {ag['n_locate']}: found with {ag['locate_verifications']} checks, not {ag['n_locate']}"], "agg")]
    for i, (name, sub, body, kind) in enumerate(cards):
        x = 0.6 + i * 4.095
        line, fill = ((T.MUTED, T.PANEL) if kind == "plain" else (T.AGG, T.AGG_T))
        box(s, x, 1.75, 3.9, 3.9, fill=fill, line=line, lw=1.5, radius=0.12)
        tb(s, x + 0.25, 1.9, 3.4, 0.5, name, size=24, bold=True, font=T.F_MATH)
        tb(s, x + 0.25, 2.45, 3.4, 0.35, sub, size=15, color=T.MUTED)
        tb(s, x + 0.25, 3.0, 3.4, 2.5, [{"text": b, "after": 8} for b in body], size=16.5, bullets=True)
    tb(s, 0.6, 5.75, 12.1, 0.35, "All three use no secret material, so the paper's security argument is unchanged (a test inspects the code).",
       size=13.5, color=T.MUTED)
    takeaway(s, "RETAIN finds a bad signature in a few checks because a clean half costs one verification.", y=6.3)

    # ------------------------------------------------------------------ 19. which policy
    rows_d = {r_["fault_rate"]: r_ for r_ in ag["rows"]}
    s = d.slide("Part IV · Which policy, when", "Pre-verify by default; an attacker chooses the fault rate",
                tags=["EXPERIMENT"], notes=N(f"""
        SAY: Cost per delivered signature, P-256, batches of {ag['n']}, {ag['trials']} trials per row. BLIND is cheapest while every batch is clean, but from 2 percent it delivered nothing. RETAIN beats PREVERIFY only on clean batches. From about one bad signature per batch of {ag['n']}, the 0.5 percent row, PREVERIFY is cheaper, and it stays nearly flat up to 10 percent.
        WHY THE CROSSOVER IS SO LOW: verifying a signature on its own is only {ag['gap']:.1f} times dearer than its share of an aggregate verification, not ten times.
        RECOMMENDATION: in a factory where sensors almost never fail, RETAIN. Where an attacker may submit bad signatures, the attacker picks the fault rate, so PREVERIFY is the safe default.
        NOT SHOWN: the 0.1 and 5 percent rows (AGGREGATOR.md has all six). At 0.1 percent no trial drew a bad signature, so that row is a second clean batch.
        TIME: 1 minute.
        NEXT: Part V, the sensors themselves.
    """))
    hdr = [{"text": "FAULT RATE"}, {"text": "BAD PER BATCH"}, {"text": "BLIND"}, {"text": "PREVERIFY"}, {"text": "RETAIN"}]
    body = [hdr]
    for rate in (0.0, 0.005, 0.02, 0.1):
        r_ = rows_d[rate]
        vals = {"blind": r_["blind"], "preverify": r_["preverify"], "retain": r_["retain"]}
        best = min((k_ for k_ in ("preverify", "retain")), key=lambda k_: vals[k_])
        row = [f"{rate:.1%}", f"{r_['mean_faults']:.1f}"]
        for k_ in ("blind", "preverify", "retain"):
            v = vals[k_]
            if v is None:
                row.append({"text": "batch lost", "color": T.BAD, "bold": True, "align": "r"})
            else:
                row.append({"text": f"{v:.3f}", "bold": k_ == best, "align": "r",
                            "fill": T.GOOD_T if k_ == best else None})
        body.append(row)
    grid(s, 0.6, 1.75, [1.75, 1.9, 1.75, 1.75, 1.75], [0.45, 0.52, 0.52, 0.52, 0.52], body, size=17, hdr_size=11.5)
    tb(s, 0.6, 4.4, 9.0, 0.3, f"ms per delivered signature · P-256 · batches of {ag['n']} · {ag['trials']} trials per row · green = cheaper of PREVERIFY and RETAIN",
       size=12, color=T.MUTED)
    box(s, 9.65, 1.75, 3.08, 3.0, fill=T.PANEL, line=None, radius=0.1)
    tb(s, 9.85, 1.9, 2.7, 2.75, [
        {"text": "Why the crossover is low", "bold": True, "size": 16, "after": 6},
        {"text": f"Verifying one signature alone costs only {ag['gap']:.1f}× its share of an aggregate check.", "size": 15}],
       lsp=0.97)
    tb(s, 0.6, 4.9, 12.1, 1.2, [
        {"text": "BLIND: cheapest on clean batches; from 2% it delivered nothing.", "after": 4},
        {"text": "RETAIN: wins only on clean batches. PREVERIFY: cheaper from about one bad signature per batch, and nearly flat to 10%."}],
       size=15.5, bullets=True)
    takeaway(s, "Rare faults: RETAIN. An attacker who can submit bad signatures: PREVERIFY.")
