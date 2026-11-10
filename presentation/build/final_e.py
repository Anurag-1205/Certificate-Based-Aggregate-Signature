"""Part VI: evidence, results, what holds, scope, conclusion (slides 26-30), then Thank You."""
import theme as T
from final_common import C, N, card, num_badge, tag_pill
from lib import box, grid, pill, tb, takeaway, terminal


def build(d):
    ts = C["tests"]
    rc, ko, nr, op, ag = C["recap"], C["keyonly"], C["nonce"], C["optimisation"], C["aggregator"]

    # ------------------------------------------------------------------ 26. evidence
    s = d.slide("Part VI · How we know", "Every result on these slides runs as code", tags=["IMPLEMENTATION", "EXPERIMENT"], notes=N(f"""
        SAY: Nothing in this talk is an argument on paper only. The implementation has {ts['total']} tests: {ts['per_backend']} run on both group libraries, Ristretto255 through libsodium and NIST P-256 through OpenSSL, and {ts['independent']} need no group at all. A separate self-test runs {ts['selftest']} algebra checks across the two libraries. And every number on these slides is recomputed and asserted by one audit script, which stops if any claim fails.
        WHY TWO LIBRARIES: two independent implementations must agree on every result and every operation count; if one had a bug, they would disagree.
        TIME: 30 seconds.
        IF ASKED 'can we run it?': yes, the commands are on the slide; make verify runs everything.
    """))
    stats = [(str(ts["total"]), "tests", f"{ts['per_backend']} × 2 libraries + {ts['independent']} without a group"),
             (str(ts["selftest"]), "self-test checks", "algebra of both group libraries"),
             ("2", "group libraries", "Ristretto255 / libsodium · P-256 / OpenSSL"),
             ("1", "audit script", "recomputes and asserts every number shown")]
    for i, (big, what, sub) in enumerate(stats):
        x = 0.6 + i * 3.07
        box(s, x, 1.75, 2.9, 2.3, fill=T.PANEL, line=None, radius=0.12)
        tb(s, x + 0.2, 1.85, 2.5, 0.9, big, size=44, bold=True, font=T.F_MATH)
        tb(s, x + 0.2, 2.75, 2.5, 0.4, what, size=17, bold=True)
        tb(s, x + 0.2, 3.15, 2.5, 0.8, sub, size=13.5, color=T.MUTED, lsp=0.95)
    terminal(s, 0.6, 4.3, 12.13, 1.75, ["\\$ make verify      # self-test, all tests, both demos",
                                        "\\$ make attack      # Demo 1     \\$ make nonce    # Demo 2",
                                        "\\$ make optimize    \\$ make dos   # Parts III and IV",
                                        "\\$ .venv/bin/python presentation/audit/verify_claims_final.py   # every number on these slides"],
             size=14.5)
    takeaway(s, "Two independent libraries must agree on every result, so a bug in one would show.")

    # ------------------------------------------------------------------ 27. all results
    s = d.slide("Part VI · All results", "All results at a glance", tags=[], notes=N("""
        SAY: The whole project in one table. Read the left column only, and point at the tags: the first row reproduces the paper; the other eight are ours, an audit of the paper's claims, a measurement, or a new finding.
        PROVENANCE IS THE POINT: we never present the paper's attack as ours; it is tagged reproduced.
        TIME: 45 seconds.
    """))
    R = [("The paper's KGC forgery breaks Verma's scheme", "REPRODUCED", f"{rc['verma_forged']} / {rc['trials']}"),
         ("The repair blocks it, because of the $T_{i}$ binding", "OUR AUDIT", f"{rc['qiao_forged']} / {rc['trials']}; ablation {rc['ablated_forged']} / {rc['trials']}"),
         ("The repaired scheme costs about twice its printed row", "OUR AUDIT", f"×{rc['factor']:.2f} at n = 100"),
         ("Anyone with a public key forges Verma; Table II is wrong", "OUR FINDING", f"{ko['verma_forged']} / {ko['trials']}"),
         ("Hashing $T$ and hashing $R$ each block their own attack", "OUR FINDING", "2 × 2, 8 trials per cell"),
         ("Best-effort optimisation of both schemes does not close the gap", "EXPERIMENT", f"×{op['p256']['ratio_naive']:.1f} → ×{op['p256']['ratio_optimised']:.1f}"),
         ("Pre-verifying a batch is cheap, so one bad signature need not sink it", "OUR FINDING", f"{ag['gap']:.1f}× per signature"),
         ("A reused nonce leaks every key: 3 signatures, or 2 for the KGC", "OUR FINDING", f"{nr['outsider3']} / {nr['trials']}"),
         ("The replay and forward-security claims do not hold", "OUR FINDING", "both tested")]
    body = [[{"text": "RESULT"}, {"text": "KIND"}, {"text": "EVIDENCE"}]]
    for res, tag, ev in R:
        body.append([res, "", ev])
    grid(s, 0.6, 1.65, [7.6, 2.0, 2.53], [0.4] + [0.45] * len(R), body, size=15, hdr_size=11.5)
    for i, (_, tag, _) in enumerate(R):
        tag_pill(s, 8.3, 1.65 + 0.4 + i * 0.45 + 0.095, tag)
    takeaway(s, "One result reproduces the paper; the other eight are ours.", y=6.38)

    # ------------------------------------------------------------------ 28. what the paper gets right
    s = d.slide("Part VI · Fairness", "What the paper gets right", tags=["PAPER", "EXPERIMENT"], notes=N(f"""
        SAY: To be fair to the authors. Their central claim holds up: Verma's scheme is broken by a malicious KGC, and their repair resists that attack. It also resisted the key-only forgery: {ko['qiao_forged']} of {ko['trials']}, with the paper's attack also at {ko['qiao_forged']} of {ko['trials']}. Both of its hash bindings turn out to be necessary. The fourth card is different: the aggregator uses no secrets, which a test checks, but that aggregate security follows from it is the paper's argument, which we did not audit; so it carries no tick.
        WHAT WE DID NOT CHECK: their security proof. Nothing we found contradicts it; our findings are about cost, deployment and the extra claims in section V-C.
        TIME: 30 seconds.
    """))
    good = [("The diagnosis is right", "Verma's scheme is forgeable by a malicious KGC, exactly as §IV-B says."),
            ("The repair holds", f"It resisted every forgery we tried: the paper's attack and the key-only attack, {ko['qiao_forged']} / {ko['trials']} each."),
            ("Both bindings are needed", "Removing either opens a forgery (the $R$ one by public-key replacement)."),
            ("Aggregation, per the paper", "The aggregator uses no secrets (a test checks). That aggregate security follows is the paper's argument, not audited by us.")]
    for i, (h, b) in enumerate(good):
        x = 0.6 + (i % 2) * 6.23
        y = 1.75 + (i // 2) * 1.75
        if i < 3:
            card(s, x, y, 5.9, 1.55, "✓  " + h, [b], line=T.GOOD, hsize=18, bsize=15.5, gap=4)
        else:
            card(s, x, y, 5.9, 1.55, h, [b], tag="PAPER", line=T.RULE, hsize=16, bsize=14, gap=2)
    box(s, 0.6, 5.35, 12.13, 0.7, fill=T.PANEL, line=None, radius=0.1)
    tb(s, 0.85, 5.35, 11.6, 0.7, "Not audited by us: the paper's EUF-CMA proof (Theorem 1). Nothing we found contradicts it.", size=16, anchor="m")
    takeaway(s, "The repair is sound against every forgery we tried; our findings concern cost, deployment and §V-C.", color=T.GOOD)

    # ------------------------------------------------------------------ 29. scope and limitations
    s = d.slide("Part VI · Scope", "Scope and limitations of our results", tags=[], notes=N("""
        SAY: What our results do not claim. We did not audit the proof. We implemented Verma's scheme from Qiao et al.'s description of it, not from Verma's own paper. Our timings run in Python over native libraries, so we report ratios and per-signer slopes, never absolute times. The nonce fault is simulated in software. The R-binding cell of the 2 by 2 needs public-key replacement, not just a public key. And the hedged-nonce fix is a standard technique, not a new one.
        WHY THIS SLIDE: every result above is stated within these limits, so a question about any of them has an answer here.
        TIME: 30 seconds.
    """))
    lim = [("The security proof", "Theorem 1 and its lemmas: not audited."),
           ("Verma's scheme", "Implemented from Qiao et al.'s description (§IV-A), not from Verma's paper."),
           ("Timing", "Python over native libraries: we report ratios and slopes, not absolute times."),
           ("The RNG fault", "Simulated in software, not observed on a real sensor."),
           ("The $R$-binding cell", "Needs public-key replacement, not only a public key."),
           ("The fix", "Hedged nonces are a standard technique; applying and testing them here is ours.")]
    for i, (h, b) in enumerate(lim):
        x = 0.6 + (i % 2) * 6.23
        y = 1.72 + (i // 2) * 1.47
        box(s, x, y, 5.9, 1.3, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.1)
        tb(s, x + 0.22, y + 0.1, 5.45, 1.12, [{"text": h, "bold": True, "size": 16.5, "after": 3},
                                             {"text": b, "size": 14.5, "color": T.MUTED}], lsp=0.97)
    takeaway(s, "Every result is stated within these limits.", y=6.3)

    # ------------------------------------------------------------------ 30. conclusion
    s = d.slide("Part VI · Conclusion", "Three things to remember", tags=["OUR FINDING", "EXPERIMENT"], notes=N("""
        SAY: One: Verma's scheme is broken more simply than the paper says; anyone holding a public key can forge, and the paper's own Table II gets this wrong. Two: the repair works, but it is not as cheap as printed: about twice its printed cost, about 2.4 times Verma's, and optimising both schemes does not change that. Three: the repaired scheme still needs care in deployment: one bad signature sinks a batch, a repeated nonce gives away every key, and its replay and forward-security claims do not hold. Each of these has a concrete fix.
        TIME: 40 seconds. Then stop: thank you, questions.
    """))
    pts = [("Verma's scheme is broken more simply than the paper says",
            "Anyone holding a public key can forge; the paper's Table II says it is secure against $F_{1}$."),
           ("The repair works, but costs more than printed",
            f"About ×2 its printed row, about ×{op['p256']['ratio_optimised']:.1f} Verma's, and optimising both schemes does not change that."),
           ("Deploying the repair still needs care",
            "Pre-verify against bad signatures, hedge the nonce, add freshness. Two §V-C claims do not hold.")]
    for i, (h, b) in enumerate(pts):
        y = 1.75 + i * 1.45
        box(s, 0.6, y, 12.13, 1.28, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.1)
        num_badge(s, 0.85, y + 0.38, i + 1, d=0.52)
        tb(s, 1.65, y + 0.12, 10.9, 1.08, [{"text": h, "bold": True, "size": 20, "after": 4},
                                           {"text": b, "size": 16, "color": T.MUTED}], lsp=0.97)
    takeaway(s, "We reproduced the paper, then went past it: a stronger attack, the real cost, deployment fixes.")

    # ------------------------------------------------------------------ thank you
    s = d.dark(notes=N("""
        STOP HERE. The main talk ends on this slide.
        SAY: Thank you. We are happy to take questions.
        WHICH BACKUP FOR WHICH QUESTION: both schemes in full: B1, B2. The key-only algebra and the fixed-point search: B3. The two ablations: B4. The 2 by 2 as tests: B5. Nonce-reuse algebra: B6. The hedged nonce: B7. Forward security: B8. Optimisation in detail: B9. Fault localisation and sub-batching: B10. The interim's operation counts: B11. The P-256 timing model: B12. Demo fallbacks: B13. Tests and commands: B14. The paper's own attack, step by step: B15. References: B16.
    """))
    tb(s, 0.8, 2.55, 11.7, 1.6, "Thank you", size=84, color="#FFFFFF", bold=True, font=T.F_MATH, align="c", check=False)
    tb(s, 0.8, 4.35, 11.7, 0.8, "Questions?", size=38, color="#9FB3C8", align="c", check=False)
