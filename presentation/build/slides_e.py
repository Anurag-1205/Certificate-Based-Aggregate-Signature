"""Part VI: the cost claim (slides 24 and 25).

Slide 24 is the claim against the recount; slide 25 shows where the extra cost comes from, term by term. The detail
behind them is in the backups: B7 (operation counts), B8 (caching), B9 (benchmark method), B13 (the paper's figures
and scheme [6]) and B14 (measured time).
"""
import json
import pathlib
import textwrap

import theme as T
from lib import box, cue, image, line, pill, tb, takeaway

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIG = ROOT / "presentation" / "figures"
C = json.loads((ROOT / "presentation" / "data" / "claims.json").read_text())


def N(s):
    return textwrap.dedent(s).strip()


def claim_card(s, x, y, w, h, tag, tag_label, head, formula, note, formula_color=T.INK):
    box(s, x, y, w, h, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.08)
    pill(s, x + 0.18, y + 0.14, 0.2 + 0.092 * len(tag_label), 0.27, tag_label, T.TAGS[tag], size=10)
    tb(s, x + 0.18, y + 0.52, w - 0.36, 0.32, head, size=17, bold=True)
    tb(s, x + 0.18, y + 0.92, w - 0.36, 0.45, formula, size=23, color=formula_color, font=T.F_MATH, check=True)
    tb(s, x + 0.18, y + 1.45, w - 0.36, 0.5, note, size=14.5, color=T.MUTED, lsp=0.95)


def build(d):
    n100 = C["n100"]
    printed, recount, cached = n100["printed_ms"], n100["recount_ms"], n100["cached_ms"]
    f, fc = n100["factor"], n100["factor_cached"]

    # ------------------------------------------------------------------ 24. is the repaired scheme as cheap as Verma's?
    s = d.slide("Part VI · The cost claim", "Is the repaired scheme really as cheap as Verma's?", tags=["PAPER", "OUR AUDIT"], notes=N(f"""
        SAY FIRST: Now the third question: is the repaired scheme really as cheap as Verma's? The paper says yes. Its Tables II and III give the two schemes identical costs, and its Fig. 4 reports {printed:.3f} ms for both at n = 100. The introduction says the proposal has the same high computational efficiency as Verma et al.'s scheme, but is more secure.
        THE CARDS MEAN: T_e is one scalar multiplication, T_a one point addition, T_h one hash; the paper's own Table IV prices them at 0.112, 0.005 and 0.004 ms. Top card: the paper's printed cost of verifying an aggregate of n signatures. Bottom card: our recount of the paper's own verification equation, its section V-A: (2n+2) scalar multiplications, 3n point additions and 3n hashes, where the paper prints (n+2), (n+1) and 2n. The next slide shows where the extra scalar multiplications come from. At n = 100, with the paper's own unit costs: {printed:.3f} ms printed against {recount:.3f} ms recounted, a factor of {f:.2f}.
        CACHING, one sentence: if the verifier caches every per-signer constant, the single-signature row can match the printed one, but the aggregate still needs at least 2n+1 scalar multiplications: {cached:.3f} ms, a factor of {fc:.2f}. Backup B8.
        MODEL VALUES, NOT MEASUREMENTS: these use the paper's unit costs, not ours. Our own timing agrees and is one line on the conclusion slide: per-signer cost 2.12 to 2.37 times Verma's on three setups, where the printed rows imply 1.00. Detail: backup B14.
        TAKEAWAY: The paper's own equation, priced with the paper's own unit costs, gives about twice the printed time at n = 100.
        NEXT: Where the extra cost comes from: the same equation, term by term.
        IF ASKED 'is this just a typo?': the printed row agrees with Fig. 4 ({printed:.3f} ms), so Fig. 4 was computed from Table III; but the row does not follow from the printed verification equation. How the row arose we do not know; the likeliest reading is that Verma's row was reused.
        IF ASKED 'why does it matter?' (professor question 13): the paper's comparative claim, secure and as cheap as the insecure scheme, rests on these tables, and its Figs. 3 to 5 are computed from them.
        IF ASKED 'does this invalidate the construction?' (professor question 17): no. The attack and repair results are separate from the cost rows; this affects the comparative efficiency claim only.
        IF ASKED 'could caching explain it?' (professor question 14): it explains the single-Verify row, not the aggregate row, and it lowers Verma's row too (backup B8).
        IF ASKED about scheme [6] or the paper's Figs. 3 to 5: backup B13. We have not implemented or verified [6].
        STATUS: the operation counts are repository tests (tests/test_opcount.py, tests/test_verma.py); the full-constant caching counts and the model arithmetic come from presentation/audit/verify_claims.py and are not yet repository tests.
    """))
    cx, cw = 0.6, 6.15
    claim_card(s, cx, 1.7, cw, 1.9, "PAPER", "PAPER · TABLES II–III", "Printed: the same cost as Verma's scheme",
               "$(n+2)T_{e} + (n+1)T_{a} + 2nT_{h}$", "Aggregate verification of $n$ signatures. Fig. 4 plots this row.")
    claim_card(s, cx, 3.74, cw, 1.9, "OUR AUDIT", "OUR AUDIT", "Recount of the paper's own equation",
               "$(2n+2)T_{e} + 3nT_{a} + 3nT_{h}$", "Two scalar multiplications per signer, $u_{i}R_{i}$ and $v_{i}pk_{i}$, not one.",
               formula_color=T.BAD)
    image(s, FIG / "fig_n100_bars.png", 7.05, 1.72, w=5.68)
    tb(s, 7.05, 5.8, 5.68, 0.5, f"Even if the verifier caches every per-signer constant,\nit is still {cached:.3f} ms (×{fc:.2f}).",
       size=14, color=T.MUTED, lsp=0.95)
    tb(s, 0.6, 5.8, 6.15, 0.5, "$T_{e}$ scalar multiplication · $T_{a}$ point addition · $T_{h}$ hash\nUnit costs: the paper's Table IV (0.112, 0.005, 0.004 ms).",
       size=14, color=T.MUTED, lsp=0.95)
    takeaway(s, "With the paper's own unit costs, its own equation gives about twice the printed time at n = 100.", size=19)
    cue(s, "Model values, not measurements.")

    # ------------------------------------------------------------------ 25. where the extra cost comes from
    s = d.slide("Part VI · The cost claim, term by term", "Where the extra cost comes from", tags=["PAPER", "OUR AUDIT"], notes=N("""
        SAY FIRST: Why does the recount come out at twice the printed cost? Here are the two verification equations, term by term, with the number of scalar multiplications under each term. The equations are the paper's; the counts are ours.
        THE PICTURE MEANS: Top, Verma et al. zP is one scalar multiplication. R is the sum of the commitments, already part of the aggregate signature, so it costs none. The master-key term is one scalar multiplication. The sum of v_i pk_i is n, one per signer. Total n+2: exactly the printed row. That is our calibration: the same counter reproduces Verma's printed row.
        Bottom, the repaired equation from the paper's section V-A. The same terms, and one more, the sum of u_i R_i, in red: n more scalar multiplications, one per signer. It exists only in the repaired scheme, because the response z_i now multiplies the certificate by u_i. The sum of the T_i needs no multiplication, and the master-key term is one multiplication with the accumulated scalar. Total 2n+2. The paper prints n+2 for this scheme, the same as Verma's.
        TAKEAWAY: The repaired equation has one extra term per signer: 2n+2, not the printed n+2. Verma's equation counts to exactly the printed n+2.
        NOT ON THE SLIDE: point additions and hashes. The recount has 3n of each, against the printed n+1 and 2n; the full table is backup B7. In our implementation AggSign uses no group operation at all, so on that row the paper overstates its own cost, in its own favour; we report it.
        NEXT: What we established, and what we did not.
        IF ASKED 'why does the paper's formula differ from the implementation?' (professor question 16): the formula we compare against is the paper's own printed verification equation, section V-A(6); the implementation follows it term by term. Its Table III row equals Verma's row, which is correct for Verma's equation but not for this one. We do not know how the row was derived; the likeliest reading is that Verma's row was reused.
        IF ASKED 'could caching remove the extra term?' (professor question 14): folding the sum of u_i R_i into one multiplication needs the certificate c_i, which is the signer's secret; a verifier does not have it. Caching per-signer constants helps the single-signature row, but the aggregate still needs at least 2n+1 scalar multiplications (backup B8).
        STATUS: the counts come from our instrumented backend and are repository tests (tests/test_opcount.py, tests/test_verma.py), identical on both backends.
    """))
    tb(s, 0.6, 1.08, 12.1, 0.35, "The paper's verification equations. Under each term: its scalar multiplications (our count).", size=16, color=T.MUTED)
    cols = [(0.85, 1.0), (1.95, 1.9), (3.95, 2.0), (6.05, 2.7), (8.85, 1.7)]   # zP =, commitments, u_i R_i, master-key term, v_i pk_i

    def strip(y0, head, terms, counts, total, total_note, total_color, note_color, slot):
        box(s, 0.6, y0, 12.13, 1.95, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.08)
        slot()   # the extra-term slot sits on the card, behind the text
        tb(s, 0.85, y0 + 0.14, 9.5, 0.35, head, size=17, bold=True)
        for (x, w), tm, ct in zip(cols, terms, counts):
            tb(s, x, y0 + 0.62, w, 0.5, tm["text"], size=tm.get("size", 21), color=tm.get("color", T.INK), font=T.F_MATH, align="c", anchor="m")
            tb(s, x, y0 + 1.22, w, 0.5, ct["text"], size=24, color=ct.get("color", T.INK), bold=ct.get("bold", False), font=T.F_MATH, align="c", anchor="m")
        line(s, 10.62, y0 + 0.62, 10.62, y0 + 1.72, T.RULE, 1.5)
        tb(s, 10.72, y0 + 0.55, 1.85, 0.6, total, size=30, color=total_color, bold=True, font=T.F_MATH, align="c", anchor="m")
        tb(s, 10.72, y0 + 1.22, 1.85, 0.5, total_note, size=13.5, color=note_color, align="c", anchor="m", lsp=0.95)

    y_a, y_b = 1.62, 3.67
    strip(y_a, "Verma et al.: aggregate verification",
          [{"text": "$zP =$"}, {"text": "$R$"}, {"text": "no such term", "size": 14.5, "color": T.MUTED},
           {"text": "+ $(Σh^{i}_{0})P^{k}_{TA}$", "size": 19}, {"text": "+ $Σv_{i}pk_{i}$"}],
          [{"text": "$1$"}, {"text": "$0$"}, {"text": "–", "color": T.MUTED}, {"text": "$1$"}, {"text": "$n$"}],
          "$n+2$", "= the printed row", T.INK, T.GOOD,
          lambda: box(s, 3.95, y_a + 0.52, 2.0, 1.22, fill=None, line=T.MUTED, lw=1.25, dash=True, radius=0.06))
    strip(y_b, "Qiao et al., the repaired scheme: aggregate verification",
          [{"text": "$zP =$"}, {"text": "$ΣT_{i}$"}, {"text": "+ $Σu_{i}R_{i}$", "color": T.BAD},
           {"text": "+ $(Σu_{i}h^{i}_{0})P^{k}_{TA}$", "size": 19}, {"text": "+ $Σv_{i}pk_{i}$"}],
          [{"text": "$1$"}, {"text": "$0$"}, {"text": "$n$", "color": T.BAD, "bold": True}, {"text": "$1$"}, {"text": "$n$"}],
          "$2n+2$", "printed: $n+2$", T.BAD, T.MUTED,
          lambda: box(s, 3.95, y_b + 0.52, 2.0, 1.22, fill=T.BAD_T, line=T.BAD, lw=1.5, radius=0.06))
    tb(s, 0.6, 5.8, 12.1, 0.35, "Point additions and hashes: $3n$ and $3n$ against the printed $n+1$ and $2n$ (backup B7).", size=14, color=T.MUTED)
    takeaway(s, "The repaired equation has one extra term per signer: $2n+2$, not the printed $n+2$.", size=19)
