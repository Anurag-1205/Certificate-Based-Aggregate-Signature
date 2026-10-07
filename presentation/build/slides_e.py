"""Part VI: performance investigation (slides 24-30)."""
import json
import pathlib
import textwrap

import theme as T
from lib import arrow, box, chip, cue, grid, image, line, party, pill, tb, takeaway, text_width

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIG = ROOT / "presentation" / "figures"
C = json.loads((ROOT / "presentation" / "data" / "claims.json").read_text())


def N(s):
    return textwrap.dedent(s).strip()


def tagged_card(s, x, y, w, h, tag, head, body=None, hsize=16, bsize=13.5, kind=None):
    box(s, x, y, w, h, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.08)
    pill(s, x + 0.15, y + 0.12, 0.16 + 0.092 * len(tag), 0.26, tag, T.TAGS[tag], size=10)
    paras = [{"text": head, "bold": True, "size": hsize, "after": 3}]
    if body:
        for k, line_ in enumerate(body.split("\n")):
            paras.append({"text": line_, "size": bsize, "color": T.MUTED, "after": 4 if k == 0 and "\n" in body else 0})
    tb(s, x + 0.15, y + 0.46, w - 0.3, h - 0.5, paras, lsp=0.95)


def build(d):
    n100 = C["n100"]
    # ------------------------------------------------------------------ 24. the paper's claim
    s = d.slide("Part VI · The performance claim", "The paper's claim: security at no extra cost", tags=["PAPER"], notes=N("""
        SAY: Now the third question. The paper compares computation costs in its Tables II and III using three units: T_e, a scalar multiplication in the group; T_a, a point addition; T_h, one hash. Look at the two rows: Verma et al.'s scheme, which the paper shows is insecure, and the paper's own repaired scheme. Every cost is identical: Sign, single Verify, AggSign and AggVerify. The introduction says the proposal has the same high computational efficiency as Verma et al.'s scheme but is more secure; and Fig. 4 reports 12.729 ms for both at n = 100.
        AUDIENCE SHOULD GET: the claim under test, in the paper's own words and numbers: it comes straight from the paper. We are not yet saying it is wrong.
        THE QUESTION: the repaired Sign computes two hashes, v_i and u_i; the repaired verification has an extra term u_i R_i for every signer and an extra hash. Can the cost still be identical?
        Table IV, the unit costs on the paper's own PC (Core i5-4200H, PBC library): T_e = 0.112 ms, T_a = 0.005 ms, T_h = 0.004 ms. The paper does not name its curve.
        NEXT: how we test this, step by step.
        IF ASKED 'why does the discrepancy matter?' (professor question 13): the paper's central comparative argument, secure and as cheap as the insecure scheme, rests on these tables, and Figs. 3 to 5 are computed from them.
    """))
    rows = [
        [{"text": "SCHEME"}, {"text": "SIGN · TABLE II"}, {"text": "VERIFY · TABLE II"}, {"text": "AGGSIGN · TABLE III"}, {"text": "AGGVERIFY · TABLE III"}],
        [{"text": "Verma et al.  [11]", "bold": True}, "$1T_{e} + 1T_{h}$", "$3T_{e} + 2T_{a} + 2T_{h}$", "$(n−1)T_{a}$", "$(n+2)T_{e} + (n+1)T_{a} + 2nT_{h}$"],
        [{"text": "Qiao et al.  “Our CBS / CBAS scheme”", "bold": True, "color": T.GOOD}, "$1T_{e} + 1T_{h}$", "$3T_{e} + 2T_{a} + 2T_{h}$", "$(n−1)T_{a}$", "$(n+2)T_{e} + (n+1)T_{a} + 2nT_{h}$"],
    ]
    grid(s, 0.6, 1.7, [2.7, 1.5, 2.3, 1.95, 2.85], [0.5, 0.8, 0.95], rows, size=16.5, hdr_size=11, hdr_spc=10)
    line(s, 11.82, 2.35, 11.82, 3.9, T.INK, 2.0)
    tb(s, 11.92, 2.9, 0.85, 0.55, "identical", size=14, bold=True, color=T.INK, lsp=0.95, check=False)
    box(s, 0.6, 4.2, 12.13, 1.3, fill=T.PANEL, line=None, radius=0.1)
    pill(s, 0.8, 4.32, 1.9, 0.26, "PAPER · SECTION I-D", T.TAGS["PAPER"], size=10)
    tb(s, 0.8, 4.66, 11.7, 0.8, "“… our proposal has the same high computational efficiency as Verma et al.'s CBAS scheme, but our scheme is more secure.”",
       size=19, font=T.F_MATH, lsp=0.95)
    tb(s, 0.6, 5.65, 12.1, 0.5, "$T_{e}$: scalar multiplication in $G$   ·   $T_{a}$: point addition in $G$   ·   $T_{h}$: one hash   ·   paper's Table IV: 0.112, 0.005, 0.004 ms",
       size=14.5, color=T.MUTED)
    takeaway(s, "The repaired Sign computes two hashes, and verification gains a term per signer. Can the cost still be identical?", size=17.5)

    # ------------------------------------------------------------------ 25. the evidence chain
    s = d.slide("Part VI · The evidence chain", "From the paper's formula to a measurement", tags=["PAPER", "OUR AUDIT", "EXPERIMENT"], notes=N("""
        SAY: We do not jump from '12.729 ms' to 'the paper is wrong'. We follow a chain, and each step is a separate object that can be checked. One: the paper's formula for aggregate verification. Two: an operation count of the paper's own printed verification equation; we do it by an instrumented counter, and the same counter reproduces Verma's printed rows exactly. Three: the paper's own cost model, Table IV. Four: the expected time that follows; at n = 100, 12.729 ms printed against 25.324 ms. Five: measured time, on three configurations; we compare per-signer slopes of the two schemes, because absolute times are not comparable with the paper. Six: comparison. The printed rows imply a ratio of exactly 1.00; the counts predict 1.99 to 2.14; measurement gives 2.12 to 2.37.
        AUDIENCE SHOULD GET: the structure of the argument. The coloured bar on each box says whose it is: grey the paper's, magenta our audit, indigo an experiment.
        The next four slides take the steps in order. A tracker in the eyebrow line shows where we are.
        NEXT: step two, the count.
        IF ASKED 'could this just be a unit or convention difference?': the same convention, applied to Verma's equation, reproduces Verma's printed row. That is the calibration on the next slide.
    """))
    chain = [("1 · PAPER FORMULA", "PAPER", "$(n+2)T_{e} + (n+1)T_{a} + 2nT_{h}$", "Table III"),
             ("2 · OPERATION COUNT", "OUR AUDIT", "$(2n+2)T_{e} + 3nT_{a} + 3nT_{h}$", "from the paper's own equation"),
             ("3 · COST MODEL", "PAPER", "$T_{e} = 0.112$\n$T_{a} = 0.005$\n$T_{h} = 0.004$ ms", "Table IV"),
             ("4 · EXPECTED TIME", "OUR AUDIT", "n = 100:\n12.729 ms printed\n25.324 ms recount", "model arithmetic"),
             ("5 · MEASURED TIME", "EXPERIMENT", "per-signer ratio, Qiao ÷ Verma:\n2.12 – 2.37", "slopes, 3 configurations"),
             ("6 · COMPARISON", None, "printed rows imply 1.00\ncounts predict 1.99 – 2.14\nmeasured 2.12 – 2.37", "the printed rows do not survive")]
    bw, gap = 1.78, 0.29
    for i, (head, tag, main, sub) in enumerate(chain):
        x = 0.6 + i * (bw + gap)
        c = T.TAGS[tag] if tag else T.INK
        box(s, x, 1.8, bw, 3.95, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.08)
        box(s, x, 1.8, bw, 0.13, fill=c, line=None, radius=0.06)
        tb(s, x + 0.12, 2.05, bw - 0.2, 0.5, head, size=11.5, bold=True, color=c, spc=40, lsp=0.95)
        tb(s, x + 0.12, 2.62, bw - 0.22, 1.9, main, size=15, bold=True, lsp=0.98)
        tb(s, x + 0.12, 4.5, bw - 0.22, 1.2, sub, size=12.5, color=T.MUTED, lsp=0.95)
        if i < 5:
            arrow(s, [(x + bw + 0.02, 3.4), (x + bw + gap - 0.02, 3.4)], T.INK, lw=2.25)
    takeaway(s, "We do not jump from “12.729 ms” to “the paper is wrong”. Every step can be checked on its own.", size=18)
    cue(s, "Equation → count → cost → measure.")

    # ------------------------------------------------------------------ 26. the recount
    s = d.slide("Part VI · Evidence chain 2 / 6 · operation count", "Counting the operations in the paper's own equation", tags=["OUR AUDIT"], notes=N("""
        SAY: Left, the paper's verification equation from its section V-A, term by term. zP: one scalar multiplication. The sum of T_i: n minus 1 additions. The sum of u_i R_i: n scalar multiplications and n minus 1 additions; this term exists only in the repaired scheme. The master-key term: one scalar multiplication with the accumulated scalar. The sum of v_i pk_i: n scalar multiplications and n minus 1 additions. Combining the four terms: 3 additions. Total: (2n+2) scalar multiplications and 3n additions. Per signer the verifier recomputes h_0, v_i and u_i, so 3n hashes.
        Right: printed versus recount. Sign: two hashes, not one, because the paper's own step (b) computes both v_i and u_i. Single Verify: 4, 3, 3 rather than 3, 2, 2. AggVerify: (2n+2), 3n, 3n against (n+2), (n+1), 2n. AggSign: our implementation performs no group operation at all, just n minus 1 scalar additions; the table charges (n−1) T_a, so on this row the paper overstates its own cost; this is in the paper's favour and we report it.
        CALIBRATION (the key point): the same counter, run on Verma's equation, reproduces Verma's printed AggVerify, AggSign and Verify rows exactly, on both backends. A method that gets Verma's rows right and the repaired scheme's wrong locates the error in the row, not in the method. Verma's printed Sign omits one point addition; negligible, and in backup B7.
        PROFESSOR QUESTION 16 (why does the paper's formula differ from the implementation?): the formula we compare against is the paper's own printed verification equation, section V-A(6); the implementation follows that equation term by term. Their Table III row equals Verma's row, which is correct for Verma's equation but not for this one. We do not know how the row was derived; the likeliest reading is that Verma's row was reused.
        NEXT: is there any convention under which the printed row is right?
    """))
    rows = [[{"text": "TERM OF THE EQUATION"}, {"text": "$T_{e}$", "align": "c"}, {"text": "$T_{a}$", "align": "c"}],
            ["$zP$", {"text": "1", "align": "c"}, {"text": "–", "align": "c"}],
            ["$ΣT_{i}$", {"text": "0", "align": "c"}, {"text": "$n−1$", "align": "c"}],
            ["$Σu_{i}R_{i}$", {"text": "$n$", "align": "c", "color": T.BAD, "bold": True}, {"text": "$n−1$", "align": "c"}],
            ["$(Σu_{i}h^{i}_{0})P^{k}_{TA}$", {"text": "1", "align": "c"}, {"text": "–", "align": "c"}],
            ["$Σv_{i}pk_{i}$", {"text": "$n$", "align": "c"}, {"text": "$n−1$", "align": "c"}],
            ["combine the four terms", {"text": "–", "align": "c"}, {"text": "3", "align": "c"}],
            [{"text": "total", "bold": True}, {"text": "$2n+2$", "align": "c", "bold": True}, {"text": "$3n$", "align": "c", "bold": True}]]
    grid(s, 0.6, 1.75, [3.45, 1.2, 1.55], [0.4] + [0.42] * 7, rows, size=16, hdr_size=11.5)
    tb(s, 0.6, 5.2, 6.2, 0.4, "hashes per signer: $h^{i}_{0}$, $v_{i}$, $u_{i}$   →   $3nT_{h}$", size=16)
    rows = [[{"text": ""}, {"text": "PAPER"}, {"text": "RECOUNT"}],
            [{"text": "Sign", "bold": True}, "$1T_{e} + 1T_{h}$", {"text": "$1T_{e} + 2T_{h}$", "color": T.BAD, "bold": True}],
            [{"text": "Verify", "bold": True}, "$3T_{e} + 2T_{a} + 2T_{h}$", {"text": "$4T_{e} + 3T_{a} + 3T_{h}$", "color": T.BAD, "bold": True}],
            [{"text": "AggSign", "bold": True}, "$(n−1)T_{a}$", {"text": "no group operation", "color": T.GOOD, "bold": True}],
            [{"text": "AggVerify", "bold": True}, "$(n+2)T_{e} + (n+1)T_{a} + 2nT_{h}$", {"text": "$(2n+2)T_{e} + 3nT_{a} + 3nT_{h}$", "color": T.BAD, "bold": True}]]
    grid(s, 7.1, 1.75, [1.3, 2.17, 2.16], [0.4, 0.55, 0.7, 0.55, 0.95], rows, size=14.5, hdr_size=11.5)
    box(s, 7.1, 5.0, 5.63, 1.15, fill=T.GOOD_T, line=T.GOOD, lw=1.5, radius=0.08)
    tb(s, 7.3, 5.02, 5.25, 1.12, "**Calibration.** The same counter reproduces Verma's printed AggVerify, AggSign and Verify rows exactly: the discrepancy is in the printed row, not in the method.",
       size=14.5, anchor="m", lsp=0.95)
    takeaway(s, "The paper's own equation needs two scalar multiplications per signer, $u_{i}R_{i}$ and $v_{i}pk_{i}$, not one.", color=T.INK, size=18.5)

    # ------------------------------------------------------------------ 27. caching
    s = d.slide("Part VI · Evidence chain 2 / 6 · stress test", "We tested the obvious objection: caching", tags=["OUR AUDIT"], notes=N("""
        SAY: The strongest objection is that the verifier could precompute per-signer constants. h_0 and the point R_i + h_0 P_TA depend only on static per-signer data. So we tested it. With every per-signer constant cached, the single-signature verification of the repaired scheme drops to 3, 2, 2: exactly the printed Table II row. We say so explicitly.
        But look at the next column: under the same caching rule, Verma's single verification drops too, to 2, 2, 1, so the two rows still cannot be identical. And the aggregate: with caching, the repaired scheme still needs 2n+1 scalar multiplications: 201 at n = 100, against the printed n+2, which is 102. The hash count does match the printed 2n; the scalar-multiplication count does not.
        The other two objections: folding the sum of u_i R_i into one multiplication is algebraically possible using c_i P = R_i + h_0 P_TA, but it needs the certificate c_i, which is secret; a verifier does not have it. Our test confirms the identity holds and that the secret is needed. Multi-scalar multiplication is a genuine speed-up but it is a different cost model, applies to both schemes, and Table III is plainly a naive count since it charges additions linearly.
        PROFESSOR QUESTION 14 (could caching explain the discrepancy?): it can explain the single-Verify row, but not the aggregate row, and it changes Verma's row too.
        STATUS: the repository's tests cover the h_0 caching and folding objections; the full-constant caching counts were checked by our audit script (presentation/audit/verify_claims.py) on both backends and are not yet a repository test.
        NEXT: what this means in milliseconds.
    """))
    rows = [[{"text": "CONVENTION"}, {"text": "QIAO · ONE VERIFY"}, {"text": "VERMA · ONE VERIFY"}, {"text": "QIAO · AGGVERIFY $T_{e}$"}],
            [{"text": "No caching: the convention behind Verma's printed row", "size": 14.5}, "$4T_{e} + 3T_{a} + 3T_{h}$",
             "$3T_{e} + 2T_{a} + 2T_{h}$\n[[grn|= printed row]]", {"text": "$2n + 2$", "bold": True}],
            [{"text": "Cache every per-signer constant: $h^{i}_{0}$ and $C_{i} = R_{i} + h^{i}_{0}P^{k}_{TA}$ (Verma: $h^{i}_{0}P^{k}_{TA}$)", "size": 14}, "$3T_{e} + 2T_{a} + 2T_{h}$\n[[grn|= printed Table II row]]",
             "$2T_{e} + 2T_{a} + 1T_{h}$", {"text": "$2n + 1$", "bold": True}]]
    grid(s, 0.6, 1.7, [4.2, 2.85, 2.75, 2.33], [0.45, 0.85, 1.1], rows, size=15, hdr_size=11.5)
    tagged_card(s, 0.6, 4.35, 12.13, 1.75, "OUR AUDIT", "Aggregate, n = 100, with caching",
                "$201T_{e} + 299T_{a} + 200T_{h}$ against the printed $102T_{e} + 101T_{a} + 200T_{h}$: $T_{h}$ matches, $T_{e}$ does not.\nFolding $Σu_{i}R_{i}$ needs the secret $c_{i}$; multi-scalar multiplication is a different cost model (backup B8).",
                hsize=17, bsize=16)
    takeaway(s, "Caching reproduces the single-signature row, but aggregate verification still needs at least $2n+1$ scalar multiplications, against the printed $n+2$.", color=T.INK, size=17)

    # ------------------------------------------------------------------ 28. n = 100
    s = d.slide("Part VI · Evidence chain 4 / 6 · expected time", "At n = 100 the paper's own costs give about twice the printed time", tags=["PAPER", "OUR AUDIT"], title_size=28, notes=N("""
        SAY: Take the paper's own unit costs and apply them to each count. The printed row gives 12.729 milliseconds, which is exactly the bar in the paper's own Fig. 4. The recount of the paper's algorithm gives 25.324 milliseconds, a factor of 1.99. Even if the verifier caches every per-signer constant, it is 24.807, a factor of 1.95. Per signer the cost goes from 125 to 251 microseconds under Table IV.
        AUDIENCE SHOULD GET: the nuance. This is not a typo. The printed row reproduces exactly in Fig. 4, which means Fig. 4 was computed from Table III and inherits whatever Table III says; but the row does not follow from the printed verification equation. That is stronger and more precise than 'the paper has a typo'.
        These are model values, not measurements: they use the paper's costs, not ours; the chart's source line says so.
        NEXT: the same arithmetic against the other schemes in the paper, and then measurement.
        IF ASKED 'does this invalidate the cryptographic construction?' (professor question 17): no. The security argument and the attack/repair results are separate from the cost rows. The cost discrepancy affects the comparative efficiency claim only.
    """))
    image(s, FIG / "fig_n100_bars.png", 0.6, 1.65, w=6.3)
    tagged_card(s, 7.2, 1.7, 5.53, 1.4, "PAPER", "12.729 ms is the bar in the paper's own Fig. 4", "So Fig. 4 was computed from Table III, and carries its count.", hsize=16.5, bsize=14.5)
    tagged_card(s, 7.2, 3.22, 5.53, 1.4, "OUR AUDIT", "×1.99 from the paper's algorithm; ×1.95 even with caching",
                "Per signer under Table IV: 125 → 251 µs (×2.01).", hsize=16.5, bsize=14.5)
    tagged_card(s, 7.2, 4.74, 5.53, 1.4, "OUR AUDIT", "Not a one-off typo",
                "A printed row that reproduces exactly in a figure, yet does not follow from the printed algorithm.", hsize=16.5, bsize=14.5)
    takeaway(s, "The printed row agrees with Fig. 4 and disagrees with the printed verification equation.", size=19)

    # ------------------------------------------------------------------ 29. figures inherit; scheme [6]
    s = d.slide("Part VI · What follows from the paper's own numbers", "The paper's figures and its comparison with [6] inherit the count", tags=["PAPER", "OUR AUDIT"], title_size=27, notes=N("""
        SAY: We recomputed the paper's Figs. 3, 4 and 5 from its tables and Table IV. Every value printed on Figs. 3 and 4 reproduces exactly; Fig. 5 has no printed values, and its two lines end where the formulas say, about 63 and 126 ms at n = 500 (we read the endpoints from the plot rather than extracting its data). So the figures are calculations from the tables, not independent measurements, and they carry the table's count. On this chart, grey is the repaired scheme as printed. The wide pale line is the paper's own row for scheme [6], the earlier pairing-free scheme it compares against. The dashed line is the repaired scheme recounted from its algorithm: it lies on top of [6]'s line. At n = 100 that is 25.324 ms against 25.319 ms: five microseconds apart, one point addition.
        WHAT FOLLOWS, AND ONLY THAT: using the paper's own numbers for [6], the roughly 49 percent computational advantage drawn in its Fig. 4 (13.224 against 25.814 ms in total) is not supported. The bandwidth advantage over [6], n group elements against 2n (Table VI), is unaffected.
        CAVEAT, SAY IT ALOUD: we have not implemented or verified scheme [6]. We do not claim anything about [6]'s real speed. Its row is the paper's, taken as printed. We also note that on one row the paper is generous to itself in the opposite direction: AggSign.
        AUDIENCE SHOULD GET: that the consequence is limited to the paper's own comparison, and exactly how limited.
        NEXT: does a clock agree with the count?
        IF ASKED 'is [6]'s AggSign cost overstated too?': Table VI shows its aggregate keeps 2n group elements, which suggests so, but we have not read [6].
    """))
    image(s, FIG / "fig_fig5_recomputed.png", 0.6, 1.65, w=6.5)
    tagged_card(s, 7.35, 1.7, 5.38, 1.2, "OUR AUDIT", "Figs. 3–5 are table formulas × Table IV", "Figs. 3 and 4: every label reproduces exactly. Fig. 5: line ends match, read from the plot.", hsize=15.5, bsize=12.5)
    tagged_card(s, 7.35, 3.0, 5.38, 1.4, "PAPER", "Using the paper's own row for [6]",
                "25.324 ms (Qiao recount) vs 25.319 ms ([6]) at n = 100. The ≈ 49% advantage in Fig. 4 (13.224 vs 25.814 ms) is not supported.", hsize=15.5, bsize=13.5)
    box(s, 7.35, 4.52, 5.38, 0.8, fill=T.AGG_T, line=T.AGG, lw=1.5, radius=0.08,
        text="We have not verified scheme [6]. No claim about its real speed.", size=15.5, bold=True, color=T.INK)
    tb(s, 7.35, 5.45, 5.38, 0.5, "Unchanged: bandwidth, $n|G|$ vs $2n|G|$ (paper Table VI).", size=14.5, color=T.MUTED)
    takeaway(s, "Only from the paper's own numbers: its computational advantage over [6] disappears; its bandwidth advantage does not.", size=18)

    # ------------------------------------------------------------------ 30. measured
    s = d.slide("Part VI · Evidence chain 5 / 6 · measured time", "Independent measurements are consistent with the higher cost", tags=["EXPERIMENT"], notes=N("""
        SAY: Counting is one instrument; timing is a second, independent one. We timed aggregate verification of both schemes at n = 50 to 500, fitted straight lines and compared per-signer slopes. Left, one machine (an Intel Xeon on Kaggle, Ristretto255): Qiao's slope is 356 microseconds per signer and Verma's 168; the dotted red line is what Qiao would look like if its row equalled Verma's, as Table III says; the measured points are not on it. Right, all 11 recorded runs on three configurations: every ratio lies between 1.99 and 2.48, never near the 1.00 the printed rows require. Diamonds are the ratios predicted from the operation counts.
        AUDIENCE SHOULD GET: two independent instruments, counting and timing, point the same way. This does not depend on the paper's absolute numbers: we compare ratios, because our curve, library and language differ from the paper's. The paper does not name its curve; ours are Ristretto255 via libsodium and NIST P-256 via OpenSSL.
        METHOD (backup B9): the laptop's clock ramps by about 2x under load, which once made n = 100 look cheaper than n = 50; so the CPU is warmed to a steady clock first, all workloads are interleaved across schemes and n, medians are taken, and runs with a poor fit (r squared under 0.99) are excluded from the median; the medians are the same with or without the exclusion.
        THE P-256 GAP: the simple Te/Ta/Th model predicts 1.99 on P-256, but measurement gives about 2.37. Our audit found why: the model prices a hash as a bare SHA-512 call, but the real hash calls also serialise points, 8 per signer for Qiao and 2 for Verma, and serialisation is expensive in OpenSSL. Pricing them predicts about 2.37 (measured today, three repeats, 2.37 each). This is an audit finding, not a repository test yet; do not call it interpreter overhead.
        LIMITS: three of four machine-and-backend combinations; the Xeon run is one sweep; P-256 was timed on one machine.
        NEXT: what we established.
        IF ASKED 'why is aggregate verification slower than n Ed25519 checks?': our aggregate verification drives about five ctypes calls per signer from Python while Ed25519 is one native call; aggregation here buys bandwidth, not verifier CPU.
    """))
    image(s, FIG / "fig_measured_vs_n.png", 0.6, 1.65, w=5.9)
    image(s, FIG / "fig_ratio_runs.png", 6.83, 1.65, w=5.9)
    tb(s, 0.6, 5.88, 12.1, 0.4, "P-256: pricing the real hash calls (point serialisation) lifts the prediction from 1.99 to ≈ 2.37 (our audit). Ratios only: absolute times are not comparable with the paper's.",
       size=12.5, color=T.MUTED, lsp=0.95)
    takeaway(s, "Counting and timing both point the same way: per-signer cost is about twice Verma's, not equal.", size=18.5)
