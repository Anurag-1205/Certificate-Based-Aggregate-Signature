"""Part VII: conclusion (slide 26) and what remains (slide 27); thank you (28); appendix divider (29) and backups B1-B14."""
import json
import pathlib
import textwrap

import theme as T
from lib import arrow, box, chip, cue, grid, image, line, party, pill, tb, takeaway, terminal, bullets

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIG = ROOT / "presentation" / "figures"
C = json.loads((ROOT / "presentation" / "data" / "claims.json").read_text())
A = json.loads((ROOT / "presentation" / "data" / "audit_checks.json").read_text())


def N(s):
    return textwrap.dedent(s).strip()


def tagged_card(s, x, y, w, h, tag, head, body=None, hsize=16, bsize=13.5):
    box(s, x, y, w, h, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.08)
    pill(s, x + 0.15, y + 0.12, 0.16 + 0.092 * len(tag), 0.26, tag, T.TAGS[tag], size=10)
    paras = [{"text": head, "bold": True, "size": hsize, "after": 3}]
    if body:
        for k, line_ in enumerate(body.split("\n")):
            paras.append({"text": line_, "size": bsize, "color": T.MUTED, "after": 4 if k == 0 and "\n" in body else 0})
    tb(s, x + 0.15, y + 0.46, w - 0.3, h - 0.5, paras, lsp=0.95)


def build(d):
    # ------------------------------------------------------------------ 26. conclusion
    s = d.slide("Part VII · Conclusion", "What we established, and what we did not", tags=["REPRODUCED", "OUR AUDIT", "EXPERIMENT"], notes=N("""
        SAY: Three columns. Reproduced from the paper: the malicious-KGC forgery against Verma et al.'s scheme works, 8 of 8 on two backends; the same strategy fails against the repaired scheme, 0 of 8. Our own audit: the ablation shows that removing only the T_i binding brings the attack back; the cost row the paper gives for its own scheme does not follow from its own equation, about twice at n = 100, and our timing agrees. Not established: the formal security of the repaired scheme, which is the paper's proof and which we have not audited; fidelity to Verma's original paper, because we implemented Qiao et al.'s description of it; and the paper's absolute timings, because we compare ratios only.
        Leave with three things: how the KGC forges without r_2i or sk_i; why binding T_i changes the algebra; why the cost row does not follow from the equation.
        TIMING LINE: three setups, 11 runs in all. The per-signer cost of the repaired scheme against Verma's is 2.12 to 2.37 as medians of the three setups (1.99 to 2.48 across all 11 runs); the printed rows imply 1.00. Detail: backup B14.
        IF ASKED about scheme [6]: backup B13. We have not implemented or verified [6] and make no claim about its real speed.
        NEXT: what remains for the final presentation.
        ---- Q&A PREPARATION ----
        1. Why does the KGC not need r_2i? The new nonce is v'r_2i/v; the attacker only has to produce a commitment and a response that are consistent, and linearity guarantees that. It never needs the value itself.
        2. How does alpha help? It packages the secret-bearing part so it can be rescaled by v'.
        3. Why does T_i prevent the old attack? The new commitment must be fixed before the new coefficient can be computed, but it is defined in terms of that coefficient: circular.
        4. Does a failed attack prove security? No. One failed attack is evidence about one attack.
        5. What did the paper prove? Theorem 1: if DL is hard, the CBAS scheme is EUF-CMA secure in the random-oracle model, via Lemma 2 (user adversary, fork on H_0) and Lemma 3 (malicious KGC, fork on H_1); aggregate security because AggSign uses no secret. Not audited by us.
        6. What did we reproduce? The section IV-B forgery against Verma et al.'s scheme, executed end to end on two group backends; the repaired scheme's resistance to that attack.
        7. What is our original contribution? The ablation as a causal test; the cost audit (recount, calibration, caching stress test); the independent timing confirmation. The attack and the repair are the paper's.
        8. Why two hash functions H_1 and H_2? Independent coefficients on the certificate and secret-key terms, which the paper's two-adversary proof uses. In our audit a single-hash variant still resisted the KGC rescaling, so we do not claim it is needed against this attack.
        9. Why is R_i in the new hash? The paper: R_i is part of the public key, and hashing it stops public-key replacement from detaching the certificate. We did not test that.
        10. Why certificate-based signatures? No key escrow, and no certificate lookup or revocation channel.
        11. Is a malicious KGC realistic? The paper's Postbank example: a master key taken from a data centre.
        12. What does the ablation prove? The T_i binding is necessary against this attack, everything else fixed. Not sufficiency, not security.
        13. Why does the discrepancy matter? The paper's comparative claim, as cheap as the insecure scheme, rests on the tables, and Figs. 3 to 5 are computed from them.
        14. Could caching explain it? It reproduces the single-Verify row but not the aggregate row, and it changes Verma's row too.
        15. Why both Ristretto255 and P-256? Independent implementations must agree; results are not an artefact of one curve or library; P-256 is what industrial stacks deploy; Ristretto255 gives a prime-order group.
        16. Why does the paper's formula differ from the implementation? We compare against the paper's own printed verification equation; its Table III row equals Verma's, which fits Verma's equation, not this one. How it arose we do not know.
        17. Does the discrepancy invalidate the construction? No; cost rows only.
        18. Reproduction versus original contribution? Reproduction: re-running the paper's attack and claims. Original: results the paper does not contain: the ablation, the recount, the caching test, the measurements.
    """))
    cols = [("REPRODUCED", "Reproduced from the paper", [
        "A malicious KGC forges Verma signatures from one observed signature (§IV-B): 8 / 8, two backends",
        "The same strategy fails against Qiao's repaired scheme: 0 / 8"]),
        ("OUR AUDIT", "Our original audit", [
            "Removing only the $T_{i}$ binding brings the attack back: 8 / 8",
            "The paper's AggVerify cost row does not follow from its own equation: about ×2 at n = 100",
            "Timing on 3 setups: per-signer ratio 2.12 – 2.37, where the printed rows imply 1.00"]),
        ("PAPER", "Not established", [
            "Formal security of the repaired scheme: the paper's proof, not audited",
            "Fidelity to Verma's original paper: we implemented Qiao's description",
            "The paper's absolute timings: we compare ratios only"])]
    for i, (tag, head, items) in enumerate(cols):
        x = 0.6 + i * 4.1
        c = T.TAGS[tag] if i < 2 else T.MUTED
        box(s, x, 1.75, 3.93, 3.5, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.1)
        box(s, x, 1.75, 3.93, 0.13, fill=c, line=None, radius=0.06)
        tb(s, x + 0.2, 2.05, 3.55, 0.4, head, size=19, bold=True, font=T.F_MATH)
        tb(s, x + 0.2, 2.6, 3.55, 2.6, [{"text": t, "after": 9} for t in items], size=16.5, bullets=True, lsp=0.97)
    for i, t in enumerate(["① how the KGC forges without $r_{2i}$ or $sk_{i}$", "② why binding $T_{i}$ changes the algebra",
                           "③ why the cost row does not follow from the equation"]):
        chip(s, 0.6 + i * 4.1, 5.42, 3.93, 0.6, t, "plain", size=15, bold=True)
    takeaway(s, "We reproduced the paper's attack, tested what in its repair stops it, and recounted its cost claim.", size=18.5)
    cue(s, "3 things to remember.")

    # ------------------------------------------------------------------ 27. what remains for the final presentation
    s = d.slide("Part VII · What comes next", "What remains for the final presentation", tags=[], notes=N("""
        SAY FIRST: Today we reproduced the paper's attack, tested its repair, and audited its cost claims. For the final presentation we plan to go one step further and test the repaired scheme itself. Four pieces of work.
        THE FOUR ITEMS: One, faster verification: does batching and precomputation (multi-scalar multiplication, cached signer data) change the cost comparison when both schemes get exactly the same treatment? Two, the aggregator in practice: what happens to availability when one signature in a batch is bad, and can the faulty signature be located? Three, a second look at the attack: is the paper's attack the weakest one against Verma's scheme, and which change in the repair closes which door? Four, open analysis: nonce reuse on sensors, and the paper's forward-security claim, which we have not examined yet.
        TAKEAWAY: Next we move from reproducing the paper to testing the repaired scheme itself.
        STATUS (for you, not for the slide; from PRESENTATION_2_FINAL.md on main): items one to three already have code, tests and write-ups in the repository (OPTIMIZATION.md, AGGREGATOR.md, KEYONLY_FORGERY.md). Item four is not started.
        IF PRESSED about results for items one to three: say honestly that the code exists and the results will be presented in the final talk. Do not improvise numbers or claims today; today's claims are the ones on the earlier slides.
        NEXT: Thank you and questions.
    """))
    items = [("Faster verification", "Does batching and precomputation change the cost comparison, if both schemes get the same treatment?"),
             ("The aggregator in practice", "What happens when one signature in a batch is bad, and can the faulty one be found?"),
             ("A second look at the attack", "Is the paper's attack the weakest one against Verma's scheme? Which change in the repair closes which door?"),
             ("Open analysis", "Nonce reuse on sensors, and the paper's forward-security claim.")]
    for i, (head, q) in enumerate(items):
        y = 1.7 + i * 1.13
        box(s, 0.6, y, 12.13, 1.03, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.1)
        box(s, 0.6, y, 0.12, 1.03, fill=T.INK, line=None, radius=0.05)
        tb(s, 0.95, y + 0.12, 11.6, 0.4, head, size=21, bold=True, font=T.F_MATH)
        tb(s, 0.95, y + 0.58, 11.6, 0.38, q, size=17, color=T.MUTED)
    takeaway(s, "Next: from reproducing the paper to testing the repaired scheme itself.")

    # ------------------------------------------------------------------ thank you (the talk ends here)
    s = d.dark(notes=N("""
        STOP HERE. The main presentation ends on this slide.
        SAY: Thank you. I am happy to take questions.
        Do NOT advance into the appendix unless a question needs it. Backup slides are for questions only. Jump to them by slide number or from the list on the next slide.
        WHICH BACKUP FOR WHICH QUESTION: the full attack algebra: B3. Both complete schemes: B1 and B2. Correctness of aggregate verification: B4. The adversaries and the paper's proof (not audited by us): B5. Why T_i is in both hashes: B6. The complete operation counts: B7. Caching objections in full: B8. Benchmark method and the P-256 gap: B9. Tests and commands: B10. The terminal demo failed or took too long: B11 (Demos 1 and 2) and B12 (Demo 3). The paper's Figs. 3 to 5 or scheme [6]: B13. The timing measurements: B14.
        The Q&A preparation for the 18 likely questions is in the notes of slide 26.
    """))
    tb(s, 0.8, 2.55, 11.7, 1.6, "Thank you", size=84, color="#FFFFFF", bold=True, font=T.F_MATH, align="c", check=False)
    tb(s, 0.8, 4.35, 11.7, 0.8, "Questions?", size=38, color="#9FB3C8", align="c", check=False)

    # ------------------------------------------------------------------ appendix divider
    s = d.dark(bg="#34414F", notes=N("""
        BACKUP SLIDES. Use only if a question calls for them; do not present them as part of the talk.
        B1 and B2: the complete Verma and Qiao schemes. B3: the full attack derivation. B4: correctness of aggregate verification. B5: the two adversaries and the paper's proof, which we did not audit. B6: why T_i is hashed into both H_1 and H_2. B7: the complete operation-count table. B8: caching and precomputation in full. B9: benchmark method and the P-256 gap. B10: tests and reproducibility. B11 and B12: captured demo output, if the terminal fails. B13: the paper's Figs. 3 to 5 and scheme [6]. B14: the timing measurements.
        Each backup slide has its own speaker notes.
    """))
    tb(s, 0.8, 0.9, 9, 0.35, "BACKUP · ONLY IF ASKED", size=14, color="#B7C3D0", bold=True, spc=140, check=False)
    tb(s, 0.8, 1.35, 11, 1.0, "Appendix", size=48, color="#FFFFFF", bold=True, font=T.F_MATH)
    items = ["B1  The complete Verma scheme", "B2  The complete Qiao scheme", "B3  The full malicious-KGC derivation",
             "B4  Correctness of aggregate verification", "B5  Security models and the paper's proof", "B6  Why $T_{i}$ is in both hashes",
             "B7  The complete operation-count table", "B8  Caching and precomputation", "B9  Benchmark methodology",
             "B10 Testing and reproducibility", "B11 Demo fallback: Demos 1 and 2", "B12 Demo fallback: Demo 3",
             "B13 The paper's figures and scheme [6]", "B14 Timing: measured ratios"]
    for i, t_ in enumerate(items):
        col, row = divmod(i, 7)
        tb(s, 0.8 + col * 6.1, 2.6 + row * 0.58, 5.8, 0.5, t_, size=19, color="#E4EAF0")

    # ------------------------------------------------------------------ B1
    s = d.slide("Backup · Verma et al.", "B1 · The complete Verma scheme", tags=["PAPER"], appendix="B1", title_size=28, notes=N("""
        The scheme as Qiao et al. review it in their section IV-A; our implementation follows this description (src/cbas/verma.py). We did not cross-check Verma et al.'s original paper.
        Notation: s^k_TA is the master secret key, P^k_TA the KGC public key, h^i_0 the per-signer certificate hash, Delta the public state information. 'Very' is the paper's name for the aggregate verification algorithm.
        The certificate check c_i P = R_1i + H_0(id_i||pk_i) P_TA lets anyone verify a certificate from public values.
    """))
    rows = [[{"text": "ALGORITHM"}, {"text": "DEFINITION"}],
            [{"text": "Setup", "bold": True}, "$s ←_{R} Z^{*}_{p}$,  $s^{k}_{TA} = s$,  $P^{k}_{TA} = sP$\n$Params = (G, p, P, H_{0}, H_{1}, P^{k}_{TA}, Δ)$"],
            [{"text": "KeyGen", "bold": True}, "$s_{i} ←_{R} Z^{*}_{p}$,  $sk_{i} = s_{i}$,  $pk_{i} = s_{i}P$"],
            [{"text": "CertGen", "bold": True}, "$r_{1i} ←_{R} Z^{*}_{p}$,  $R_{1i} = r_{1i}P$,  $c_{i} = r_{1i} + s^{k}_{TA}H_{0}(id_{i}‖pk_{i})$\n$Cert_{i} = (R_{1i}, c_{i})$,  checked by $c_{i}P = R_{1i} + H_{0}(id_{i}‖pk_{i})P^{k}_{TA}$"],
            [{"text": "Sign", "bold": True}, "$r_{2i} ←_{R} Z^{*}_{p}$,  $R_{i} = R_{1i} + r_{2i}P$,  $v_{i} = H_{1}(m_{i}‖pk_{i}‖id_{i}‖Δ)$\n$z_{i} = r_{2i} + c_{i} + sk_{i}v_{i}$,  $δ_{i} = (R_{i}, z_{i})$"],
            [{"text": "AggSign", "bold": True}, "$R = ΣR_{i}$,  $z = Σz_{i}$,  $δ = (R, z)$"],
            [{"text": "AggVerify", "bold": True}, "$h^{i}_{0} = H_{0}(id_{i}‖pk_{i})$,  $v_{i} = H_{1}(m_{i}‖pk_{i}‖id_{i}‖Δ)$\naccept iff  $zP = R + (Σh^{i}_{0})P^{k}_{TA} + Σv_{i}pk_{i}$"]]
    grid(s, 0.6, 1.6, [1.75, 10.38], [0.4, 0.85, 0.5, 0.9, 0.9, 0.5, 0.9], rows, size=16.5, hdr_size=11.5)
    tb(s, 0.6, 6.62, 12.1, 0.3, "Source: Qiao et al., §IV-A. Code: verma.py. “Very” is the paper's name for AggVerify.", size=12.5, color=T.MUTED)

    # ------------------------------------------------------------------ B2
    s = d.slide("Backup · Qiao et al.", "B2 · The complete Qiao scheme", tags=["PAPER"], appendix="B2", title_size=28, notes=N("""
        The repaired scheme from the paper's section V-A; our implementation is src/cbas/scheme.py, a direct transliteration.
        Two printed typos in the paper are corrected in our code: KeyGen prints pk_i = s_i, which we implement as s_i P; and the certificate check prints R_1i, which we implement as R_i.
        Other inconsistencies we noticed in the paper's text: Setup declares H_1 and H_2 over five inputs with no slot for T_i, while Sign and Very hash six fields including T_i; we follow Sign and Very. Lemma 3's H_1 table omits T_i. Z*_q and Z*_p are used interchangeably.
        Hash instantiation (ours): SHA-512 over a length-prefixed encoding with a distinct domain label for each of H_0, H_1, H_2, reduced mod p.
        Notation map: s^k_TA is s in code, P^k_TA is pk_ta, h^i_0 is h0, Delta is delta, 'Very' is agg_verify.
    """))
    rows = [[{"text": "ALGORITHM"}, {"text": "DEFINITION"}],
            [{"text": "Setup", "bold": True}, "$s ←_{R} Z^{*}_{p}$,  $s^{k}_{TA} = s$,  $P^{k}_{TA} = sP$\n$Params = (G, p, P, H_{0}, H_{1}, H_{2}, P^{k}_{TA}, Δ)$"],
            [{"text": "KeyGen", "bold": True}, "$s_{i} ←_{R} Z^{*}_{p}$,  $sk_{i} = s_{i}$,  $pk_{i} = s_{i}P$"],
            [{"text": "CertGen", "bold": True}, "$r_{i} ←_{R} Z^{*}_{p}$,  $R_{i} = r_{i}P$,  $c_{i} = r_{i} + s^{k}_{TA}H_{0}(id_{i}‖pk_{i}‖R_{i})$\n$Cert_{i} = (c_{i}, R_{i})$,  $R_{i}$ public;  check $c_{i}P = R_{i} + H_{0}(id_{i}‖pk_{i}‖R_{i})P^{k}_{TA}$"],
            [{"text": "Sign", "bold": True}, "$t_{i} ←_{R} Z^{*}_{p}$,  $T_{i} = t_{i}P$,   $v_{i} = H_{1}(m_{i}‖pk_{i}‖R_{i}‖id_{i}‖[[grn|T_{i}]]‖Δ)$\n$u_{i} = H_{2}(m_{i}‖pk_{i}‖R_{i}‖id_{i}‖[[grn|T_{i}]]‖Δ)$,   $z_{i} = t_{i} + c_{i}u_{i} + sk_{i}v_{i}$,   $δ_{i} = (T_{i}, z_{i})$"],
            [{"text": "AggSign", "bold": True}, "$z = Σz_{i}$,  $δ = (T, z)$ with $T = (T_{1}, …, T_{n})$"],
            [{"text": "AggVerify", "bold": True}, "$h^{i}_{0} = H_{0}(id_{i}‖pk_{i}‖R_{i})$,  $v_{i}$, $u_{i}$ recomputed as in Sign\naccept iff  $zP = ΣT_{i} + Σu_{i}R_{i} + (Σu_{i}h^{i}_{0})P^{k}_{TA} + Σv_{i}pk_{i}$"]]
    grid(s, 0.6, 1.6, [1.75, 10.38], [0.4, 0.8, 0.48, 0.85, 0.85, 0.48, 0.85], rows, size=16, hdr_size=11.5)
    tb(s, 0.6, 6.4, 12.1, 0.55, "Printed typos corrected in our code: KeyGen prints $pk_{i} = s_{i}$ (we use $s_{i}P$); the certificate check prints $R_{1i}$ (we use $R_{i}$).  Notation → code: $s^{k}_{TA}$ → s · $P^{k}_{TA}$ → pk_ta · $h^{i}_{0}$ → h0 · $Δ$ → delta · “Very” → agg_verify.",
       size=12, color=T.MUTED, lsp=0.95)

    # ------------------------------------------------------------------ B3
    s = d.slide("Backup · The attack", "B3 · The full malicious-KGC derivation", tags=["PAPER", "REPRODUCED"], appendix="B3", title_size=28, notes=N("""
        Steps (2a) to (2d) and the check (3) are the paper's section IV-B. The right-hand column also shows the one-line form with lambda = v-prime over v_i, which is ours: R-prime = R_1i + lambda (R_i - R_1i) and z-prime = c_i + lambda (z_i - c_i). It works because, once the certificate is removed, (z_i - c_i) P = (R_i - R_1i) + v_i pk_i, and multiplying both sides by lambda turns the coefficient v_i into v-prime.
        The table maps each paper step to the lines of forge_verma in src/cbas/attack.py. The function takes no secret key as an argument; a test checks this.
        Why it verifies: z-prime P = (v-prime r_2i / v_i) P + c_i P + sk_i v-prime P; substitute c_i P = R_1i + H_0 P_TA and pk_i = sk_i P.
    """))
    tb(s, 0.6, 1.62, 6.9, 0.3, "STEPS (2a)–(2d), PAPER §IV-B", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    tb(s, 0.6, 1.95, 6.95, 4.3, [
        {"text": "(a)  $r_{2i}P = R_{i} − R_{1i}$,    $r_{2i} + sk_{i}v_{i} = z_{i} − c_{i}$", "after": 9},
        {"text": "(b)  $α = (1/v_{i})(z_{i} − c_{i}) = r_{2i}/v_{i} + sk_{i}$", "after": 2},
        {"text": "      $A = (1/v_{i})(R_{i} − R_{1i}) = (r_{2i}/v_{i})P$", "after": 9},
        {"text": "(c)  $v′_{i} = H_{1}(m′_{i}‖pk_{i}‖id_{i}‖Δ)$", "after": 2},
        {"text": "      $R′_{i} = R_{1i} + v′_{i}A = R_{1i} + (v′_{i}r_{2i}/v_{i})P$", "after": 2},
        {"text": "      $z′_{i} = v′_{i}α + c_{i} = v′_{i}r_{2i}/v_{i} + c_{i} + sk_{i}v′_{i}$", "after": 9},
        {"text": "(d)  output $δ′_{i} = (R′_{i}, z′_{i})$"}], size=17.5)
    tb(s, 7.9, 1.62, 4.8, 0.3, "(3) IT VERIFIES", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    tb(s, 7.9, 1.95, 4.85, 2.2, [
        {"text": "$z′_{i}P = (v′_{i}r_{2i}/v_{i})P + c_{i}P + sk_{i}v′_{i}P$", "after": 4},
        {"text": "$= (v′_{i}r_{2i}/v_{i})P + R_{1i} + H_{0}(id_{i}‖pk_{i})P^{k}_{TA} + v′_{i}pk_{i}$", "after": 4},
        {"text": "$= R′_{i} + H_{0}(id_{i}‖pk_{i})P^{k}_{TA} + v′_{i}pk_{i}$"}], size=14.5, lsp=0.97)
    box(s, 7.9, 4.0, 4.83, 1.25, fill=T.BAD_T, line=T.BAD, lw=1.5, radius=0.08)
    tb(s, 8.05, 4.05, 4.55, 1.15, [{"text": "The same attack in one line, $λ = v′_{i}/v_{i}$  (our rewriting)", "bold": True, "size": 13, "after": 3},
                                   {"text": "$R′_{i} = R_{1i} + λ(R_{i} − R_{1i})$", "size": 16, "after": 1},
                                   {"text": "$z′_{i} = c_{i} + λ(z_{i} − c_{i})$", "size": 16}], lsp=0.97)
    rows = [[{"text": "PAPER STEP"}, {"text": "attack.py · forge_verma"}],
            ["(a) $v_{i}$ and $1/v_{i}$", "lines 73–74"], ["(b) $α$, $A$", "lines 77–78"], ["(c) $v′_{i}$, $R′_{i}$, $z′_{i}$", "lines 81–83"]]
    grid(s, 0.6, 5.0, [2.7, 2.6], [0.35, 0.36, 0.36, 0.36], rows, size=13.5, hdr_size=11)
    tb(s, 7.9, 5.4, 4.8, 0.6, "The function takes no secret key; a test checks its signature.", size=13, color=T.MUTED)

    # ------------------------------------------------------------------ B4
    s = d.slide("Backup · Correctness", "B4 · Why aggregate verification accepts honest signatures", tags=["PAPER"], appendix="B4", title_size=28, notes=N("""
        Both derivations are one-line substitutions. For Qiao et al., c_i = r_i + s h^i_0 and R_i = r_i P, T_i = t_i P, pk_i = sk_i P. For Verma et al., c_i P = R_1i + h^i_0 P_TA and R_i = R_1i + r_2i P.
        These are the paper's own derivations (section V-A for Qiao et al.). Our tests check correctness for n up to 17 and tamper rejection on both backends.
        The operation count of the Qiao equation is on slide 25 (scalar multiplications, term by term) and in backup B7; this slide is only about correctness.
    """))
    tb(s, 0.6, 1.65, 6, 0.3, "QIAO ET AL.", size=12, color=T.GOOD, bold=True, spc=100, check=False)
    tb(s, 0.6, 2.0, 12.1, 2.1, [
        {"text": "$zP = Σ(t_{i} + c_{i}u_{i} + sk_{i}v_{i})P$", "after": 5},
        {"text": "$= Σt_{i}P + Σu_{i}(r_{i} + s^{k}_{TA}h^{i}_{0})P + Σsk_{i}v_{i}P$", "after": 5},
        {"text": "$= ΣT_{i} + Σu_{i}R_{i} + (Σu_{i}h^{i}_{0})P^{k}_{TA} + Σv_{i}pk_{i}$"}], size=22)
    tb(s, 0.6, 4.2, 6, 0.3, "VERMA ET AL.", size=12, color=T.BAD, bold=True, spc=100, check=False)
    tb(s, 0.6, 4.55, 12.1, 1.9, [
        {"text": "$zP = Σ(r_{2i}P + c_{i}P + v_{i}pk_{i})$,    with $c_{i}P = R_{1i} + h^{i}_{0}P^{k}_{TA}$ and $R_{i} = R_{1i} + r_{2i}P$", "after": 5},
        {"text": "$= Σ(R_{i} + h^{i}_{0}P^{k}_{TA} + v_{i}pk_{i}) = R + (Σh^{i}_{0})P^{k}_{TA} + Σv_{i}pk_{i}$"}], size=20)

    # ------------------------------------------------------------------ B5
    s = d.slide("Backup · Security models", "B5 · The two adversaries and the paper's proof", tags=["PAPER"], appendix="B5", title_size=28, notes=N("""
        The security games are the paper's section III-B; the proof is its section V-B. We have NOT audited the proofs. The bounds are quoted as printed.
        F1, the malicious user, models public-key replacement: it can know sk* but never the certificate of the challenge identity. F2, the malicious KGC, knows the master key, so every certificate, but never sk*.
        Theorem 1 follows from two lemmas on the single-signer scheme; aggregate security follows because the aggregator uses no secret. Lemma 2 forks the random oracle H_0 and Lemma 3 forks H_1.
        Inconsistencies we noticed in the lemma texts: Lemma 3's H_1 table omits T_i although signing hashes it; Lemma 3 declares H_0 over {0,1}* x G while the construction uses x G x G; Z*_q and Z*_p are mixed; Lemma 3's secret-key query returns pk_i. We do not claim these invalidate the proof; we simply did not audit it.
    """))
    rows = [[{"text": "ADVERSARY"}, {"text": "CAN"}, {"text": "CANNOT"}],
            [{"text": "$F_{1}$  malicious user", "bold": True}, "replace the public key of any user; ask for keys, certificates and signatures",
             "know the master key; replace $pk^{*}$ of the challenge identity; ask for $Cert^{*}$"],
            [{"text": "$F_{2}$  malicious KGC", "bold": True}, "know the master key, so every certificate; ask for keys and signatures",
             "replace public keys; ask for the secret key $sk^{*}$ of the challenge identity"]]
    grid(s, 0.6, 1.65, [2.55, 4.85, 4.73], [0.4, 0.85, 0.85], rows, size=14.5, hdr_size=11.5)
    box(s, 0.6, 3.95, 12.13, 2.4, fill=T.PANEL, line=None, radius=0.1)
    pill(s, 0.85, 4.07, 0.9, 0.26, "PAPER", T.TAGS["PAPER"], size=10)
    tb(s, 1.9, 4.04, 10.5, 0.3, "Theorem 1: if the discrete logarithm problem is hard, the CBAS construction is EUF-CMA secure (random-oracle model).", size=14.5, bold=True)
    tb(s, 0.85, 4.5, 11.7, 1.8, [
        {"text": "Lemma 2 ($F_{1}$): fork on $H_{0}$.   Advantage $≥ (1 − 1/e)·ε_{1} / (e·q_{0}(x_{1} + x_{2} + 1))$", "after": 4},
        {"text": "Lemma 3 ($F_{2}$): fork on $H_{1}$.   Advantage $≥ (1 − 1/e)·ε_{2} / (e·q_{h}(x_{1} + x_{3} + 1))$", "after": 4},
        {"text": "Aggregate security follows because AggSign uses no secret material."},
        {"text": "We did not audit these proofs, and noticed inconsistencies in the lemma texts (for example, Lemma 3's $H_{1}$ table omits $T_{i}$).", "color": T.BAD, "before": 6}],
       size=14.5, lsp=0.97)

    # ------------------------------------------------------------------ B6
    s = d.slide("Backup · Our audit", "B6 · Why $T_{i}$ appears in both hashes", tags=["OUR AUDIT"], appendix="B6", title_size=28, notes=N("""
        This is an audit check of ours (presentation/audit/dagger_checks.py), run on both backends; it is not part of the repository's test suite. It tests two one-shot rescaling attacks against four placements of T_i.
        The KGC attack strips c_i u_i and rescales the part carrying sk_i v_i. It needs v-prime to be computable before the new commitment, so it succeeds exactly when T_i is not in H_1. The mirror attack is by a malicious user who knows sk_i but not c_i; it strips sk_i v_i and rescales the part carrying c_i u_i, and succeeds exactly when T_i is not in H_2. So each hash protects the coefficient of one secret.
        Also checked: a variant that uses a single hash for both coefficients (u equal to v) with T_i bound still resisted the KGC rescaling. So we do NOT claim that separating H_1 and H_2 is needed to block this attack; it matches the paper's three-hash model, and the proof structure uses two independent coefficients.
        The mirror attack is a forgery by an adversary of the paper's type F1 (knows sk, not the certificate); it is not described in the paper.
    """))
    rows = [[{"text": "WHERE $T_{i}$ IS HASHED"}, {"text": "KGC RESCALING ATTACK"}, {"text": "MIRROR ATTACK BY A MALICIOUS USER"}],
            [{"text": "$H_{1}$ only", "bold": True}, {"text": "blocked", "color": T.GOOD, "bold": True}, {"text": "forges", "color": T.BAD, "bold": True}],
            [{"text": "$H_{2}$ only", "bold": True}, {"text": "forges", "color": T.BAD, "bold": True}, {"text": "blocked", "color": T.GOOD, "bold": True}],
            [{"text": "both: Qiao et al.", "bold": True}, {"text": "blocked", "color": T.GOOD, "bold": True}, {"text": "blocked", "color": T.GOOD, "bold": True}],
            [{"text": "neither: the ablation", "bold": True}, {"text": "forges", "color": T.BAD, "bold": True}, {"text": "forges", "color": T.BAD, "bold": True}]]
    grid(s, 0.6, 1.65, [3.3, 3.8, 5.03], [0.45, 0.58, 0.58, 0.58, 0.58], rows, size=17, hdr_size=11.5)
    tb(s, 0.6, 4.6, 12.1, 1.8, [
        {"text": "The KGC attack scales the term $sk_{i}v_{i}$, so it needs $v′_{i}$ before $T′_{i}$: it works unless $T_{i}$ is in $H_{1}$.", "after": 5},
        {"text": "The mirror attack (a user who knows $sk_{i}$ but not $c_{i}$) scales $c_{i}u_{i}$: it works unless $T_{i}$ is in $H_{2}$.", "after": 5},
        {"text": "A variant with one hash for both coefficients, $T_{i}$ bound, still blocked the KGC attack, so we do not claim the split is needed against it.", "after": 5},
        {"text": "With $T_{i}$ in $H_{1}$, rescaling $T′_{i} = λT_{i}$ needs $H_{1}(m′_{i}‖pk_{i}‖R_{i}‖id_{i}‖λT_{i}‖Δ) = λ·v_{i}$: a search over hash outputs."}],
       size=15, bullets=True)
    tb(s, 0.6, 6.4, 12.1, 0.5, "Source: presentation/audit/dagger_checks.py, both backends; not in the repository's test-suite.", size=12.5, color=T.MUTED)

    # ------------------------------------------------------------------ B7
    s = d.slide("Backup · Counts", "B7 · The complete operation-count table", tags=["PAPER", "OUR AUDIT"], appendix="B7", title_size=28, notes=N("""
        Both tables are printed row against counted row. Counts come from the instrumented backend and are identical on Ristretto255 and P-256; Verma's counted rows reproduce the printed rows except Sign, where the printed row omits one point addition (R_i = R_1i + r_2i P): negligible, and it does not affect the argument, since the Table III rows carry it.
        Qiao's AggSign is zero group operations: n minus 1 scalar additions modulo p. The paper's (n-1) T_a overstates it; in the paper's favour, and we report it.
        The chart: per-signer cost under the paper's Table IV: 125 microseconds printed against 251 recounted (ratio 2.008). The scalar multiplication T_e dominates in both.
        Source for the counts: presentation/audit/verify_claims.py (reads the code), regression-tested in tests/test_opcount.py and tests/test_verma.py.
    """))
    q = [[{"text": "QIAO ET AL."}, {"text": "PAPER"}, {"text": "COUNTED"}],
         [{"text": "Sign", "bold": True}, "$1T_{e} + 1T_{h}$", {"text": "$1T_{e} + 2T_{h}$", "color": T.BAD, "bold": True}],
         [{"text": "Verify", "bold": True}, "$3T_{e} + 2T_{a} + 2T_{h}$", {"text": "$4T_{e} + 3T_{a} + 3T_{h}$", "color": T.BAD, "bold": True}],
         [{"text": "AggSign", "bold": True}, "$(n−1)T_{a}$", {"text": "0 group ops", "color": T.GOOD, "bold": True}],
         [{"text": "AggVerify", "bold": True}, "$(n+2)T_{e} + (n+1)T_{a} + 2nT_{h}$", {"text": "$(2n+2)T_{e} + 3nT_{a} + 3nT_{h}$", "color": T.BAD, "bold": True}]]
    grid(s, 0.6, 1.6, [1.25, 2.85, 2.9], [0.36, 0.4, 0.4, 0.4, 0.6], q, size=13.5, hdr_size=11)
    v = [[{"text": "VERMA ET AL."}, {"text": "PAPER"}, {"text": "COUNTED"}],
         [{"text": "Sign", "bold": True}, "$1T_{e} + 1T_{h}$", "$1T_{e} + 1T_{a} + 1T_{h}$"],
         [{"text": "Verify", "bold": True}, "$3T_{e} + 2T_{a} + 2T_{h}$", {"text": "same ✓", "color": T.GOOD, "bold": True}],
         [{"text": "AggSign", "bold": True}, "$(n−1)T_{a}$", {"text": "same ✓", "color": T.GOOD, "bold": True}],
         [{"text": "AggVerify", "bold": True}, "$(n+2)T_{e} + (n+1)T_{a} + 2nT_{h}$", {"text": "same ✓", "color": T.GOOD, "bold": True}]]
    grid(s, 0.6, 3.95, [1.25, 2.85, 2.9], [0.36, 0.4, 0.4, 0.4, 0.6], v, size=13.5, hdr_size=11)
    image(s, FIG / "fig_per_signer.png", 7.6, 1.65, w=5.1)
    tb(s, 0.6, 6.4, 12, 0.3, "Counted on both backends (identical); Verma's printed Sign omits one $T_{a}$ (negligible).", size=12.5, color=T.MUTED)

    # ------------------------------------------------------------------ B8
    s = d.slide("Backup · Caching", "B8 · Caching and precomputation, in full", tags=["OUR AUDIT"], appendix="B8", title_size=28, notes=N("""
        Full table behind the caching note on slide 24. 'Cache h_0' stores the hash h^i_0 per signer: derived by subtracting one hash per signer from each scheme (the repository's test covers this objection). 'Cache C_i' stores the per-signer point C_i = R_i + h^i_0 P_TA (for Verma, h^i_0 P_TA); the counts in the last row were measured by our audit script on both backends and are not yet a repository test.
        Under every row the two schemes still differ, and aggregate verification stays above the printed n + 2 scalar multiplications.
        Folding: sum of u_i R_i + (sum of u_i h^i_0) P_TA equals (sum of u_i c_i) P, a single multiplication, but c_i is the signer's secret certificate, unavailable to a verifier; the identity itself is checked by a repository test.
        Multi-scalar multiplication (Straus, Pippenger) lowers the cost of a sum of products but is a different cost model and applies equally to both schemes.
    """))
    rows = [[{"text": "CONVENTION"}, {"text": "QIAO · ONE VERIFY"}, {"text": "VERMA · ONE VERIFY"}, {"text": "QIAO · AGGVERIFY, n = 100"}],
            [{"text": "none", "bold": True}, "$4T_{e} + 3T_{a} + 3T_{h}$", "$3T_{e} + 2T_{a} + 2T_{h}$", "$202T_{e} + 300T_{a} + 300T_{h}$"],
            [{"text": "cache $h^{i}_{0}$ only (derived)", "bold": True}, "$4T_{e} + 3T_{a} + 2T_{h}$", "$3T_{e} + 2T_{a} + 1T_{h}$", "$202T_{e} + 300T_{a} + 200T_{h}$"],
            [{"text": "cache $C_{i}$ (Verma: $h^{i}_{0}P^{k}_{TA}$)", "bold": True}, "$3T_{e} + 2T_{a} + 2T_{h}$", "$2T_{e} + 2T_{a} + 1T_{h}$", "$201T_{e} + 299T_{a} + 200T_{h}$"],
            [{"text": "printed (Tables II and III)", "bold": True, "color": T.MUTED}, "$3T_{e} + 2T_{a} + 2T_{h}$", "$3T_{e} + 2T_{a} + 2T_{h}$", "$102T_{e} + 101T_{a} + 200T_{h}$"]]
    grid(s, 0.6, 1.65, [3.4, 2.75, 2.75, 3.23], [0.42, 0.62, 0.62, 0.62, 0.62], rows, size=15, hdr_size=11)
    tb(s, 0.6, 4.85, 12.1, 1.5, [
        {"text": "$C_{i} = R_{i} + h^{i}_{0}P^{k}_{TA}$ equals $c_{i}P$: static per signer, so a verifier serving a fixed fleet could store it.", "after": 5},
        {"text": "Folding: $Σu_{i}R_{i} + (Σu_{i}h^{i}_{0})P^{k}_{TA} = (Σu_{i}c_{i})P$ is one multiplication, but needs the secret $c_{i}$.", "after": 5},
        {"text": "Multi-scalar multiplication: a different cost model; it applies to both schemes."}], size=15.5, bullets=True)

    # ------------------------------------------------------------------ B9
    s = d.slide("Backup · Timing", "B9 · Benchmark methodology and the P-256 gap", tags=["EXPERIMENT", "OUR AUDIT"], appendix="B9", title_size=28, notes=N("""
        Method, from bench/harness.py and bench/sweep.py. The laptop (Ryzen 5 7520U, powersave governor, boost on) ramps its clock by about 2.07x once loaded; a first sweep reported n = 100 as cheaper than n = 50 for that reason. stabilize() spins on real group operations until the cost is steady for several chunks and at least four seconds have passed. measure_many() times every workload once per round, interleaved across schemes as well as n, because the headline result is a ratio.
        Runs with r squared under 0.99 are reported but excluded from the median: for both Ryzen backends the medians (2.153 and 2.366) are the same with all five runs. Machines: Ryzen 5 7520U (Python 3.12.3) and an Intel Xeon at 2.20 GHz on Kaggle (Python 3.12.13), both libsodium 1.0.18. All timings are Python plus ctypes plus the library; ratios and slopes are the defensible quantities.
        P-256: the Te/Ta/Th model predicts 1.99 on P-256 but the measured median is 2.37 (range 2.18 to 2.40). Our audit prices the real hash calls, which also serialise points: 8 point serialisations per Qiao signer against 2 for Verma, about 2.2 point additions each on OpenSSL; the predicted ratio becomes 2.37 (three fresh repeats: 2.365, 2.372, 2.374). It is an audit result and not yet a repository test.
        On absolute cost: n independent Ed25519 verifications are faster here than one aggregate verification (47.3 ms against 177.7 ms at n = 500 on the Xeon): aggregation buys bandwidth, not verifier CPU, in this implementation.
    """))
    bullets(s, 0.6, 1.7, 6.5, 4.6, [
        "Warm the CPU to a steady clock first: it ramps ≈ 2× under load, which once made n = 100 look cheaper than n = 50",
        "Time every workload (both schemes, every $n$) once per round, interleaved; median of 7 rounds",
        "Calibrate repetitions so each sample lasts ≥ 20 ms; report medians",
        "Fit a line over $n$ = 50 … 500; the per-signer slope ratio is the measured quantity",
        "Exclude runs with fit $r^{2} < 0.99$ from the median: the medians are unchanged without the exclusion"], size=15.5, after=8)
    rows = [[{"text": "MACHINE"}, {"text": "SOFTWARE"}],
            ["AMD Ryzen 5 7520U, powersave, boost on", "Python 3.12.3 · libsodium 1.0.18"],
            ["Intel Xeon @ 2.20 GHz (Kaggle)", "Python 3.12.13 · libsodium 1.0.18"]]
    grid(s, 7.4, 1.7, [2.9, 2.43], [0.38, 0.62, 0.62], rows, size=13, hdr_size=11)
    tb(s, 7.4, 3.5, 5.3, 0.3, "P-256 PREDICTED RATIO", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    real = [r["real_hash"] for r in A["timing_model"]["p256"]]
    rows = [["bare $T_{e}/T_{a}/T_{h}$ model", "1.99"], ["with real hash calls priced", f"{sum(real)/len(real):.2f}"],
            ["measured median (range 2.18 – 2.40)", "2.37"]]
    grid(s, 7.4, 3.85, [4.1, 1.23], [0.45, 0.45, 0.45], rows, size=14, header=False)
    box(s, 7.4, 5.35, 5.33, 0.95, fill=T.PANEL, line=None, radius=0.08)
    tb(s, 7.55, 5.38, 5.05, 0.9, "n × Ed25519 verification: 47.3 ms vs 177.7 ms aggregate at n = 500 (Xeon). Aggregation buys bandwidth, not verifier CPU.",
       size=13, anchor="m", lsp=0.95)

    # ------------------------------------------------------------------ B10
    s = d.slide("Backup · Reproducibility", "B10 · Testing and reproducibility", tags=["IMPLEMENTATION", "EXPERIMENT"], appendix="B10", title_size=28, notes=N("""
        All commands run from the repository root with the project's virtual environment. Code checkpoint: git tag presentation-1-interim (commit 881b7b0), branch presentation-1-work. On main, `make attack` prints a third target that belongs to a later presentation.
        Test counts are collected by pytest: 221 in total. Every fixture runs on both backends (101 tests each) except 19 that do not use a backend (encoding, harness and one hashing test). The self-test has 62 checks: 31 per backend.
        The audit scripts under presentation/audit/ recompute every number used in this deck from the code and the tracked benchmark JSON files, with assertions; the figures are drawn from the data they write (presentation/data/).
        Not in the repository's test-suite: the C_i-caching counts, the recomputation of the paper's Figs. 3 to 5, the T_i placement checks and the P-256 real-hash prediction; they are in presentation/audit/.
    """))
    pf = C["tests"]["per_file"]
    names = {"test_backend_algebra.py": "Backend algebra", "test_encoding.py": "Encoding", "test_hashing.py": "Hashing",
             "test_scheme_roundtrip.py": "Scheme", "test_verma.py": "Verma", "test_forgery.py": "Attack and ablation",
             "test_opcount.py": "Operation counts", "test_bench.py": "Timing harness"}
    rows = [[{"text": "AREA"}, {"text": "TESTS", "align": "r"}]]
    for k, lab in names.items():
        rows.append([lab, {"text": str(pf[k]), "align": "r"}])
    rows.append([{"text": "total", "bold": True}, {"text": str(C["tests"]["total"]), "align": "r", "bold": True}])
    grid(s, 0.6, 1.65, [3.3, 1.2], [0.38] + [0.43] * 9, rows, size=15, hdr_size=11)
    tb(s, 0.6, 5.95, 4.5, 0.6, "101 tests × 2 backends + 19 backend-independent. Self-test: 62 checks.", size=13, color=T.MUTED, lsp=0.95)
    terminal(s, 5.5, 1.65, 7.23, 4.55, [
        r"[[tmut|\$]] make selftest",
        r"[[tmut|\$]] make test",
        r"[[tmut|\$]] make attack",
        r"[[tmut|\$]] .venv/bin/python -m cbas.demo",
        r"[[tmut|\$]] .venv/bin/python -m pytest \\",
        r"      tests/test_forgery.py -k ablat -vv",
        r"[[tmut|\$]] .venv/bin/python -m pytest \\",
        r"      tests/test_opcount.py tests/test_verma.py \\",
        r'      -k "opcount or published_row" -vv',
        r"[[tmut|\$]] .venv/bin/python \\",
        r"      presentation/audit/verify_claims.py",
        r"[[tmut|\$]] .venv/bin/python \\",
        r"      presentation/audit/dagger_checks.py",
    ], size=13)
    tb(s, 5.5, 6.3, 7.2, 0.5, "Checkpoint: tag presentation-1-interim (881b7b0), branch presentation-1-work.", size=12.5, color=T.MUTED)

    # ------------------------------------------------------------------ B11, B12: demo fallbacks
    DF = ROOT / "presentation" / "demo_fallback"
    s = d.slide("Backup · If the terminal fails", "B11 · Demo fallback: captured output of `make attack`", tags=["EXPERIMENT"], appendix="B11", title_size=28, notes=N("""
        USE THIS if the terminal fails, the command errors, or the environment is slow. Say: 'here is the output from my earlier run' and walk the same three points as the live demo.
        LEFT, Demo 1 (Target 1, Verma et al.): the honest signature verifies; the attacker is the KGC and does not know sk_i; the forged signature on the SHUTDOWN message verifies; it also survives aggregation.
        RIGHT, Demo 2 (Target 2, Qiao et al.): the honest signature verifies; the forgery attempt does not succeed; 16 candidates T-prime are tried and all are different. The candidate prefixes differ on every run because the keys are random.
        These are the actual stdout lines of `make attack` captured on 2026-10-07 on branch presentation-1-work (tag presentation-1-interim); nothing is edited. The files are also in presentation/demo_fallback/.
        WORDING: the repaired implementation does not admit this forgery route. That is evidence, not a proof of security.
    """))
    image(s, DF / "demo1_target1.png", 0.6, 1.7, w=5.8)
    image(s, DF / "demo2_target2.png", 6.93, 1.7, w=5.8)
    tb(s, 0.6, 4.5, 5.8, 1.6, [{"text": "Demo 1", "bold": True, "size": 18, "color": T.BAD, "after": 3},
                               {"text": "forged signature verifies: True", "size": 16, "after": 2},
                               {"text": "it also survives aggregation", "size": 16}], size=16)
    tb(s, 0.6, 6.45, 12.1, 0.4, "Actual captured stdout, 2026-10-07, branch presentation-1-work. Candidate bytes differ on every run.", size=12.5, color=T.MUTED)

    s = d.slide("Backup · If the terminal fails", "B12 · Demo fallback: captured output of the ablation tests", tags=["EXPERIMENT"], appendix="B12", title_size=28, notes=N("""
        USE THIS if the pytest command fails or is slow. Say: 'here is the output from my earlier run.'
        What to point at: ten tests, all PASSED. Eight are the forgery-restored cases of the ablated variant (4 target messages on each of 2 backends); two check that the ablated variant is still a working scheme that keeps R_i in the hashes and separate u and v.
        The line at the bottom says 10 passed. Long test ids are shortened with an ellipsis in this screenshot; nothing else is edited. The file is also presentation/demo_fallback/demo3_ablation.png.
        WORDING: the ablation isolates the T_i binding as the critical difference for blocking the reproduced rescaling attack. It does not show that the other changes are unnecessary, or that the full scheme is secure.
    """))
    image(s, DF / "demo3_ablation.png", 0.6, 1.75, w=12.13)
    tb(s, 0.6, 5.55, 12.1, 0.8, [{"text": "8 forgery-restored cases (4 messages × 2 backends) + 2 checks that the ablated variant is still a working scheme", "size": 16}], size=16)
    tb(s, 0.6, 6.45, 12.1, 0.4, "Actual captured stdout, 2026-10-07. Long test ids are shortened with an ellipsis.", size=12.5, color=T.MUTED)

    # ------------------------------------------------------------------ B13: the paper's figures and scheme [6] (was a main slide)
    s = d.slide("Backup · Scheme [6]", "B13 · The paper's figures and its comparison with [6]", tags=["PAPER", "OUR AUDIT"], appendix="B13", title_size=28, notes=N("""
        USE THIS only if asked about the paper's Figs. 3 to 5 or about scheme [6]; the main talk does not use them.
        SAY FIRST: We recomputed the paper's Figs. 3, 4 and 5 from its tables and Table IV. Every value printed on Figs. 3 and 4 reproduces exactly; Fig. 5 has no printed values, and its two lines end where the formulas say, about 63 and 126 ms at n = 500 (we read the endpoints from the plot rather than extracting its data). So the figures are calculations from the tables, not independent measurements, and they carry the table's count.
        THE CHART MEANS: Grey: the repaired scheme as printed. The wide pale line: the paper's own row for scheme [6], the earlier pairing-free scheme it compares against. The dashed line: the repaired scheme recounted from its algorithm; it lies on top of [6]'s line. At n = 100 that is 25.324 against 25.319 ms: five microseconds apart, one point addition.
        WHAT FOLLOWS, AND ONLY THAT: using the paper's own numbers for [6], the roughly 49 percent computational advantage drawn in its Fig. 4 (13.224 against 25.814 ms in total) is not supported. The bandwidth advantage over [6], n group elements against 2n (Table VI), is unaffected.
        SAY ALOUD: We have not implemented or verified scheme [6]. We make no claim about [6]'s real speed; its row is the paper's, taken as printed. On one row the paper is generous to itself in the opposite direction: AggSign (backup B7).
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

    # ------------------------------------------------------------------ B14: measured time (was a main slide)
    s = d.slide("Backup · Timing", "B14 · Measured time is consistent with the higher cost", tags=["EXPERIMENT"], appendix="B14", title_size=28, notes=N("""
        USE THIS if asked 'did you measure it?', about the method, or about the P-256 gap. The main talk gives the result in one line on slide 26.
        SAY FIRST: Counting is one instrument; timing is a second, independent one. We timed aggregate verification of both schemes for n from 50 to 500, fitted straight lines and compared the per-signer slopes.
        THE CHARTS MEAN: Left, one machine, an Intel Xeon on Kaggle: Qiao's slope is 356 microseconds per signer and Verma's 168. The dotted red line is what Qiao would look like if its row equalled Verma's, as Table III says; the measured points are nowhere near it. Right, all 11 recorded runs on three configurations: every ratio lies between 1.99 and 2.48, never near the 1.00 the printed rows require; the medians of the three configurations are 2.12 to 2.37. Diamonds are the ratios predicted from the operation counts.
        TAKEAWAY: Independent measurements are consistent with the higher cost: about twice Verma's, not equal. We compare ratios, because our curve, library and language differ from the paper's; we make no claim about the paper's absolute hardware timings.
        METHOD (backup B9): the laptop's clock ramps about 2x under load, so the CPU is warmed first, workloads are interleaved, medians are taken, and runs with a poor fit are excluded from the median; the medians are the same with or without the exclusion.
        THE P-256 GAP: the simple model predicts 1.99 on P-256 but measurement gives about 2.37. Our audit found why: real hash calls also serialise points, 8 per signer for Qiao and 2 for Verma, which is expensive in OpenSSL; pricing them predicts about 2.37 (three fresh repeats). An audit result, not yet a repository test; do not call it interpreter overhead.
        LIMITS: three of four machine-and-backend combinations; the Xeon is one sweep; P-256 on one machine.
        IF ASKED 'why is aggregate verification slower than n Ed25519 checks?': our aggregate verification makes about five ctypes calls per signer from Python; Ed25519 is one native call. Aggregation buys bandwidth, not verifier CPU.
    """))
    image(s, FIG / "fig_measured_vs_n.png", 0.6, 1.65, w=5.7)
    image(s, FIG / "fig_ratio_runs.png", 7.03, 1.65, w=5.7)
    tb(s, 0.6, 5.88, 12.1, 0.4, "P-256: pricing the real hash calls (point serialisation) lifts the prediction from 1.99 to ≈ 2.37 (our audit). Ratios only: absolute times are not comparable with the paper's.",
       size=12.5, color=T.MUTED, lsp=0.95)
    takeaway(s, "Counting and timing both point the same way: per-signer cost is about twice Verma's, not equal.", size=18.5)
