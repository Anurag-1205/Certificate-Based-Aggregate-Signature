"""Part IV: the repair (slides 17-22) and Part V: implementation and validation (slide 23)."""
import textwrap

import theme as T
from diagrams import protocol
from lib import arrow, box, chip, cue, grid, line, lock, party, pill, tb, takeaway, terminal, text_width


def N(s):
    return textwrap.dedent(s).strip()


def build(d):
    # ------------------------------------------------------------------ 17. Qiao protocol
    s = d.slide("Part IV · The repair", "Qiao et al.: the same six algorithms, with new objects", tags=["PAPER"], notes=N("""
        SAY: Same system, same six algorithms, now with Qiao et al.'s objects. Setup is unchanged in spirit: a master secret and public parameters. The certificate changes: the KGC picks r_i, forms R_i = r_i P, and computes c_i using a hash that includes R_i. R_i is public, treated as part of the public key; c_i stays secret. At signing the sensor picks a fresh t_i and commits to it as T_i = t_i P, and T_i goes into the hashes. The signature is (T_i, z_i). The aggregator sums the z_i but must keep every T_i, so the aggregate is (T, z) with T the list of all commitments. The verifier recomputes every hash and checks one equation.
        AUDIENCE SHOULD GET: who generates what, what is secret (padlocks), and that T_i, in green, is the new object that travels with every signature.
        Grey dashed steps are unspecified in the paper: certificate delivery and how the verifier gets id_i, pk_i and R_i. We have not invented them.
        The price of the repair: the aggregate is no longer constant size; only the scalar half compresses (paper Table VI: n|G| + |Z_q*|).
        NEXT: exactly which equations changed.
        IF ASKED 'why is R_i included in the new hashes?' (professor question 9): the paper says R_i is part of the public key and is hashed so that 'the effect of the certificate for the signature will not be removed by public key replacement' (its section V-A). It targets a different attacker, a malicious user replacing public keys. Our ablation does not test that; it removes only T_i.
    """))
    protocol(s, concrete=True)

    # ------------------------------------------------------------------ 18. diff table
    s = d.slide("Part IV · The repair", "What Qiao et al. changed", tags=["PAPER"], notes=N("""
        SAY: Left column Verma, right column Qiao, one row per change. The certificate now binds R_i into its hash and R_i becomes public. The sensor's commitment is a fresh T_i = t_i P instead of R_1i + r_2i P. The hash inputs now include R_i and T_i, and there are two hash functions: H_1 gives v_i for the secret-key term, H_2 gives u_i for the certificate term. The response becomes t_i + c_i u_i + sk_i v_i. The aggregate keeps all T_i. The verification equation gains the per-signer term u_i R_i.
        AUDIENCE SHOULD GET: several things changed. We do not say 'the difference is one line'. For this attack, the change that matters is that T_i now enters the hashes; the ablation two slides on is how we know.
        Why two hash functions H_1 and H_2 (professor question 8)? In the paper, the certificate term and the secret-key term carry independent random-oracle coefficients u_i and v_i; its proof forks H_0 for the user adversary and H_1 for the KGC adversary. In our own audit check, a variant with one hash for both coefficients still resisted the KGC rescaling attack, so we do not claim the separation is needed to block this attack: it matches the paper's three-hash model. Backup B6.
        Two printed typos in the paper's section V-A are corrected in our code: KeyGen prints pk_i = s_i (we use s_i P) and the certificate check prints R_1i (we use R_i).
        NEXT: why does T_i in the hash matter so much?
    """))
    H = lambda t, c=T.MUTED: {"text": t, "color": c, "bold": True}
    rows = [
        [H("VERMA ET AL.", T.INK) | {"text": "", "color": T.INK}, H("VERMA ET AL.", T.BAD), H("QIAO ET AL.", T.GOOD)],
        [{"text": "Certificate", "bold": True, "color": T.MUTED},
         "$c_{i} = r_{1i} + s^{k}_{TA}H_{0}(id_{i}‖pk_{i})$",
         "$c_{i} = r_{i} + s^{k}_{TA}H_{0}(id_{i}‖pk_{i}‖R_{i})$,   $R_{i}$ public"],
        [{"text": "Commitment", "bold": True, "color": T.MUTED}, "$R_{i} = R_{1i} + r_{2i}P$", "$[[grn|T_{i} = t_{i}P]]$"],
        [{"text": "Hash inputs", "bold": True, "color": T.MUTED}, "$v_{i} = H_{1}(m_{i}‖pk_{i}‖id_{i}‖Δ)$",
         "$v_{i} = H_{1}(m_{i}‖pk_{i}‖R_{i}‖id_{i}‖[[grn|T_{i}]]‖Δ)$\n$u_{i} = H_{2}$ of the same input"],
        [{"text": "Response", "bold": True, "color": T.MUTED}, "$z_{i} = r_{2i} + c_{i} + sk_{i}v_{i}$", "$z_{i} = t_{i} + c_{i}u_{i} + sk_{i}v_{i}$"],
        [{"text": "Aggregate", "bold": True, "color": T.MUTED}, "$(R, z) = (ΣR_{i}, Σz_{i})$   one point + one scalar",
         "$(T, z)$,  $T = (T_{1}, …, T_{n})$,  $z = Σz_{i}$"],
        [{"text": "Verification", "bold": True, "color": T.MUTED}, "$zP = R + (Σh^{i}_{0})P^{k}_{TA} + Σv_{i}pk_{i}$",
         "$zP = ΣT_{i} + Σu_{i}R_{i} + (Σu_{i}h^{i}_{0})P^{k}_{TA} + Σv_{i}pk_{i}$"],
    ]
    rows[0][0] = {"text": "", "color": T.INK}
    rows[0][1] = {"text": "VERMA ET AL.", "color": T.BAD, "bold": True}
    rows[0][2] = {"text": "QIAO ET AL.", "color": T.GOOD, "bold": True}
    # row 3 has two lines: split into paragraphs via a list
    rows[3][2] = {"text": ""}
    for ri in (1, 5, 6):                       # certificate, aggregate, verification: context, not the point
        rows[ri][1] = {"text": rows[ri][1], "color": T.MUTED}
        rows[ri][2] = {"text": rows[ri][2], "color": T.MUTED}
    grid(s, 0.6, 1.7, [1.65, 4.35, 6.13], [0.4, 0.58, 0.58, 0.95, 0.58, 0.58, 0.6], rows, size=15.5, hdr_size=13)
    # second hash line in row 3 (drawn as its own text so the cell stays one paragraph)
    xq = 0.6 + 1.65 + 4.35 + 0.1
    tb(s, xq, 3.36, 5.9, 0.35, "$v_{i} = H_{1}(m_{i}‖pk_{i}‖R_{i}‖id_{i}‖[[grn|T_{i}]]‖Δ)$", size=15.5)
    tb(s, xq, 3.78, 5.9, 0.35, "$u_{i} = H_{2}$ of the same input", size=15.5)
    tb(s, 0.6, 5.98, 12.1, 0.3, "Typos in §V-A, corrected in our code: KeyGen prints $pk_{i} = s_{i}$ (we use $s_{i}P$); the certificate check prints $R_{1i}$ (we use $R_{i}$).",
       size=12.5, color=T.MUTED)
    takeaway(s, "Several things change. For this attack, what matters is that $T_{i}$ now enters the hashes.", color=T.GOOD, size=19)

    # ------------------------------------------------------------------ 19. old vs new hash dependency
    s = d.slide("Part IV · Why the repair changes the algebra", "Old vs new: is the commitment coupled to the hash?", tags=["PAPER"], title_size=28, notes=N("""
        SAY: Left, the old scheme. The message goes into the hash and gives v_i. The randomness r_2i goes into R_i. The two are not coupled through the hash: the red dashed line is the missing edge. So an attacker can work in this order: pick a message, compute its coefficient v-prime, then build R-prime and z-prime. Right, the new scheme. The commitment T_i = t_i P goes into the same hash as the message, and into H_2 as well. Now the rescaling attack needs a new commitment T-prime equal to (v-prime / v_i) T_i, but v-prime is the hash of a string that contains T-prime. Each needs the other. The attacker would have to find a scalar lambda whose scaled commitment hashes to lambda times v_i: a search over hash outputs, not algebra.
        AUDIENCE SHOULD GET: the structural difference in one picture. Old: message and randomness are not coupled through the hash. New: message and commitment together are inputs to the hash.
        WORDING (professor questions 3, 4, 5): the paper proves EUF-CMA security under the discrete logarithm assumption in the random-oracle model; we have not audited that proof. Our reasoning here explains why this specific reproduced route no longer applies; it is not a security proof.
        The paper states the principle itself: the commitment T_i of the signing randomness should be hashed into the core element of the signature; otherwise a malicious KGC can forge from a known signature (its section V-A).
        NEXT: we tested it.
        IF ASKED 'why does T_i prevent the old attack?' (professor question 3): the attack must fix the new commitment before it can compute the new coefficient, but the new commitment is defined in terms of that coefficient. The circularity is the missing route.
    """))
    for (x, kind, head, sub, hc) in ((0.6, "bad", "OLD · Verma et al.", "message and commitment are not coupled through the hash", T.BAD),
                                      (6.78, "good", "NEW · Qiao et al.", "message and commitment are both inputs to the hash", T.GOOD)):
        box(s, x, 1.7, 5.95, 4.42, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.1)
        tb(s, x + 0.2, 1.78, 5.5, 0.35, head, size=19, bold=True, color=hc)
        tb(s, x + 0.2, 2.15, 5.6, 0.3, sub, size=13.5, color=T.MUTED)
    # OLD
    chip(s, 0.8, 2.7, 2.55, 0.5, "$m_{i}, pk_{i}, id_{i}, Δ$", "plain", size=15)
    arrow(s, [(3.35, 2.95), (3.75, 2.95)], T.INK)
    box(s, 3.75, 2.7, 0.85, 0.5, fill=T.PANEL, line=T.INK, lw=1.5, radius=0.06, text="$H_{1}$", size=17, bold=True)
    arrow(s, [(4.6, 2.95), (5.0, 2.95)], T.INK)
    chip(s, 5.0, 2.7, 0.75, 0.5, "$v_{i}$", "plain", size=16)
    chip(s, 0.8, 3.7, 1.2, 0.5, "$r_{2i}$", "sen", size=16, dash=True, align="l", pad=0.4)
    lock(s, 0.88, 3.78, 0.27, T.SEN)
    arrow(s, [(2.0, 3.95), (2.35, 3.95)], T.SEN)
    chip(s, 2.35, 3.7, 2.6, 0.5, "$R_{i} = R_{1i} + r_{2i}P$", "sen", size=15)
    line(s, 4.17, 3.7, 4.17, 3.22, T.BAD, 2.25, dash=True)
    tb(s, 4.3, 3.35, 1.7, 0.3, "✗ not hashed", size=14, bold=True, color=T.BAD, check=False)
    tb(s, 0.8, 4.35, 5.5, 0.3, "THE ATTACKER'S ORDER", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    tb(s, 0.8, 4.62, 5.5, 1.0, [{"text": "① pick any $m′_{i}$", "after": 1},
                                 {"text": "② compute $v′_{i}$, which needs no $R′_{i}$", "after": 1},
                                 {"text": "③ build $R′_{i}$ and $z′_{i}$"}], size=15)
    chip(s, 0.8, 5.68, 2.6, 0.36, "forgery verifies", "bad", size=14, bold=True)
    # NEW
    chip(s, 6.98, 2.7, 1.0, 0.5, "$t_{i}$", "sen", size=16, dash=True, align="l", pad=0.4)
    lock(s, 7.04, 2.78, 0.27, T.SEN)
    arrow(s, [(7.98, 2.95), (8.2, 2.95)], T.SEN)
    chip(s, 8.2, 2.7, 1.3, 0.5, "$[[grn|T_{i}]] = t_{i}P$", "sen", size=15)
    arrow(s, [(9.5, 2.95), (9.95, 2.95)], T.GOOD, lw=3.5)
    box(s, 9.95, 2.7, 1.15, 0.5, fill=T.PANEL, line=T.INK, lw=1.5, radius=0.06, text="$H_{1}, H_{2}$", size=16, bold=True)
    arrow(s, [(11.1, 2.95), (11.35, 2.95)], T.INK)
    chip(s, 11.35, 2.7, 1.25, 0.5, "$v_{i}, u_{i}$", "plain", size=15)
    chip(s, 8.8, 3.5, 3.3, 0.42, "$m_{i}, pk_{i}, R_{i}, id_{i}, Δ$", "plain", size=14)
    arrow(s, [(10.52, 3.5), (10.52, 3.22)], T.INK)
    tb(s, 6.98, 4.05, 5.6, 0.3, "THE RESCALING ATTACK NOW NEEDS BOTH AT ONCE", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    chip(s, 6.98, 4.42, 2.45, 0.5, "$T′_{i} = (v′_{i}/v_{i})·T_{i}$", "plain", size=14)
    chip(s, 10.1, 4.42, 2.5, 0.5, "$v′_{i} = H_{1}(m′_{i}‖…‖T′_{i}‖Δ)$", "plain", size=13)
    arrow(s, [(9.43, 4.67), (10.1, 4.67)], T.BAD, lw=2.25, both=True)
    tb(s, 9.2, 4.98, 1.2, 0.3, "circular", size=13, bold=True, color=T.BAD, align="c", check=False)
    tb(s, 6.98, 5.22, 5.65, 0.4, "$T′_{i}$ affects $v′_{i}$, and $v′_{i}$ affects $T′_{i}$", size=17)
    chip(s, 6.98, 5.7, 4.2, 0.38, "the old direct rescaling route is broken", "good", size=14, bold=True)
    takeaway(s, "This explains why the reproduced rescaling route no longer applies. Formal security is the paper's EUF-CMA proof.", color=T.GOOD, size=18)
    cue(s, "Key idea: $T_{i}$ enters the hash.")

    # ------------------------------------------------------------------ 20. demo 2
    s = d.slide("Part IV · Testing the repair · Demo 2", "Demo 2: the same strategy against the repaired scheme", tags=["EXPERIMENT"], title_size=28, notes=N("""
        DEMO: scroll the same `make attack` output to Target 2. The program's banner says 'same attacker, same capabilities, same attack'. Precisely, it is the same strategy adapted to Qiao's equation: the attacker strips c_i u_i instead of c_i, and there is no R_1i. It is a different function (attempt_forge_fixed in attack.py), not literally the same code.
        POINT AT: (1) the honest signature still verifies; (2) the attempt iterates 16 times: each round computes the coefficient a candidate T-prime would induce, then the T-prime the attack actually requires; (3) every candidate is different and none verifies. The candidate prefixes change on every run because the keys are random; the demo prints 'all distinct', and a test checks it (24 rounds, 24 distinct).
        EVIDENCE: 0 of 8 attempts succeed (4 messages x 2 backends); all 16 candidates are distinct in every one.
        WORDING: the paper proves EUF-CMA security under the discrete logarithm assumption in the random-oracle model. Our experiment reproduces the specific malicious-KGC attack against the previous construction, and the repaired implementation does not admit this same algebraic forgery route. A failed attack is not a proof of security (professor question 4).
        What did the paper prove (professor question 5)? Theorem 1: if DL is hard, the CBAS scheme is EUF-CMA secure in the random-oracle model, via Lemma 2 (user adversary, forking on H_0) and Lemma 3 (malicious-KGC adversary, forking on H_1); aggregate security follows because AggSign uses no secret. We did not audit these proofs.
        NEXT: which of the changes is responsible? An ablation.
    """))
    box(s, 0.6, 1.8, 5.2, 0.7, fill=T.TERM_BG, line=None, radius=0.08)
    tb(s, 0.85, 1.8, 4.8, 0.7, r"[[tmut|\$]] [[ter|make attack]]", size=22, font=T.F_MONO, anchor="m", color="#DDE5EE")
    tb(s, 0.6, 2.62, 5.2, 0.3, "WHAT TO POINT AT", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    pts = ["The honest signature still verifies.", "Same strategy, adapted: strip $c_{i}u_{i}$, not $c_{i}$.",
           "16 candidates $T′_{i}$, all different, none verifies."]
    for i, t in enumerate(pts):
        y = 2.9 + i * 0.7
        pill(s, 0.6, y + 0.09, 0.42, 0.42, str(i + 1), T.INK, size=15)
        tb(s, 1.2, y, 4.6, 0.6, t, size=17, anchor="m", lsp=0.95)
    terminal(s, 6.05, 1.8, 6.68, 3.0, [
        "[[tmut|TARGET 2  Qiao et al., repaired CBAS (IEEE Syst. J. 2023)]]",
        "  honest sig verifies : [[tgrn|True]]",
        "  forgery succeeded   : [[tgrn|False]]",
        "  iterations tried    : 16",
        "  [[tmut|candidate T' per iteration (first 8 bytes):]]",
        "     1. 7a30fa1d6d0e2eb4...   [[tmut|(values differ per run)]]",
        "     2. 26a9b48630a0b741...",
        "     ... 10 more, all distinct",
    ], size=13, title="(scroll to Target 2)")
    for i, (tag, head, body) in enumerate([
            ("PAPER", "proves EUF-CMA security", "under the discrete logarithm assumption, in the random-oracle model (Theorem 1)"),
            ("EXPERIMENT", "this implementation", "does not admit this same algebraic forgery route: 0 / 8 attempts succeed"),
            ("OUR AUDIT", "not shown here", "a proof of security: one failed attack is evidence about one attack")]):
        x = 0.6 + i * 4.1
        box(s, x, 5.0, 3.93, 1.12, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.08)
        pill(s, x + 0.15, 5.1, 0.16 + 0.092 * len(tag), 0.26, tag, T.TAGS[tag], size=10)
        tb(s, x + 0.15, 5.4, 3.65, 0.7, [{"text": head, "bold": True, "size": 14.5}, {"text": body, "size": 13, "color": T.MUTED}], lsp=0.95)
    takeaway(s, "The repaired implementation does not admit this forgery route. That is evidence, not a proof of security.", color=T.GOOD, size=19)
    cue(s, "Terminal fails? → Backup B11", y=1.18, name="PresenterCue_B11")

    # ------------------------------------------------------------------ 21. ablation design
    s = d.slide("Part IV · Which change matters? · Ablation (1/2)", "A controlled experiment: remove only the $T_{i}$ binding", tags=["IMPLEMENTATION", "EXPERIMENT"], title_size=28, notes=N("""
        SAY: Failing against the repaired scheme does not say which of its changes is responsible. So we built a control: the repaired scheme with exactly one thing removed. Row A is Verma. Row B is Qiao. Row C is Qiao with T_i dropped from H_1 and H_2, and nothing else touched. The ablated variant imports the real Setup, KeyGen, CertGen, AggSign and verification equation from the repaired code; R_i is still hashed into H_0, H_1 and H_2; u and v still come from separate hash functions. Only the hash labels are renamed, and one hash input is gone.
        AUDIENCE SHOULD GET: C is a working scheme. Honest signatures verify and other messages are rejected, in all 8 trials; it is not a broken build. If the attack comes back here and only here, the T_i binding is what blocks it.
        This ablation is our design (an implementation choice, tagged), and its result is an experiment.
        The code calls the T_i binding 'Fix #2' in comments; those labels are ours, not the paper's.
        NEXT: the result.
        IF ASKED 'does the ablation remove only T_i?': yes. Same H_0 function object, R_i still in H_1 and H_2, separate u and v; a test checks both of those (test_ablated_variant_still_has_fixes_1_and_3).
    """))
    rows = [
        [{"text": "SCHEME"}, {"text": "WHAT $v_{i}$ IS HASHED FROM"}, {"text": "COMMITMENT IN THE HASH?"}],
        [{"text": "A · Verma et al.", "bold": True}, "$m_{i}, pk_{i}, id_{i}, Δ$", {"text": "✗  no: $R_{i}$ is not hashed", "bold": True, "color": T.BAD}],
        [{"text": "B · Qiao et al.", "bold": True, "color": T.GOOD}, "$m_{i}, pk_{i}, R_{i}, id_{i}, [[grn|T_{i}]], Δ$", {"text": "✓  yes: $T_{i}$ is hashed", "bold": True, "color": T.GOOD}],
        [{"text": "C · Qiao, $T_{i}$ removed", "bold": True, "color": T.BAD}, "$m_{i}, pk_{i}, R_{i}, id_{i}, Δ$", {"text": "✗  no: $T_{i}$ removed", "bold": True, "color": T.BAD}],
    ]
    grid(s, 0.6, 1.75, [3.4, 4.9, 3.83], [0.45, 0.85, 0.85, 0.85], rows, size=17, hdr_size=12)
    box(s, 0.6, 4.95, 5.95, 1.2, fill=T.PANEL, line=None, radius=0.1)
    tb(s, 0.8, 5.02, 5.6, 0.3, "EVERYTHING ELSE IN C IS THE REPAIRED CODE", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    tb(s, 0.8, 5.32, 5.6, 0.8, [{"text": "same setup, keys, certificate, aggregation, verification"},
                                 {"text": "$R_{i}$ still hashed; $u_{i}$ and $v_{i}$ still separate"}], size=14.5, bullets=True, after=3)
    box(s, 6.78, 4.95, 5.95, 1.2, fill=T.PANEL, line=None, radius=0.1)
    tb(s, 6.98, 5.02, 5.6, 0.3, "CONTROLS: C IS A WORKING SCHEME", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    tb(s, 6.98, 5.32, 5.6, 0.8, [{"text": "honest signatures verify, in 8 / 8 trials"},
                                 {"text": "a different message is rejected, in 8 / 8 trials"}], size=14.5, bullets=True, after=3)
    takeaway(s, "Between B and C, only the $T_{i}$ binding differs.", color=T.INK)

    # ------------------------------------------------------------------ 22. ablation result
    s = d.slide("Part IV · Which change matters? · Ablation (2/2) · Demo 3", "Remove the $T_{i}$ binding, and the attack returns", tags=["EXPERIMENT", "OUR AUDIT"], title_size=28, notes=N("""
        SAY: Three cases, same attacker, same strategy, same four target messages on two group backends. A, Verma: the forgery verifies in 8 of 8 trials. B, Qiao: it fails in 8 of 8, with 16 distinct candidates each. C, Qiao with only the T_i binding removed: it verifies again in 8 of 8.
        DEMO 3: run `.venv/bin/python -m pytest tests/test_forgery.py -k ablat -vv`. It prints ten test names ending PASSED and '10 passed'. Eight of them are the forgery-restored cases (4 messages x 2 backends); two check that the ablated variant is still an honest scheme and still has R_i and the separate u/v. We use -vv because the project's pytest configuration adds -q.
        WHAT THE ABLATION ESTABLISHES (professor question 12): the T_i binding is necessary for blocking this reproduced rescaling attack, with everything else held fixed. The ablation isolates the T_i binding as the critical difference for blocking the reproduced rescaling attack.
        WHAT IT DOES NOT ESTABLISH: that the other changes are unnecessary (R_i in H_0 targets a different attacker, public-key replacement, which we did not test), or that the full scheme is secure. This ablation is ours: it is not in the paper.
        AUDIENCE SHOULD GET: causal evidence. Full repair: attack fails. Remove only T_i: attack succeeds.
        NEXT: before measuring performance, why trust our implementation?
        IF ASKED 'is that original?': yes for the ablation as a causal test. The attack and the repair are the paper's.
    """))
    cards = [("A", "Original Verma construction", "$v_{i} = H_{1}(m_{i}‖pk_{i}‖id_{i}‖Δ)$", "ATTACK SUCCEEDS", "8 / 8 forgeries verify", "bad"),
             ("B", "Qiao repaired construction", "$v_{i} = H_{1}(…‖R_{i}‖id_{i}‖[[grn|T_{i}]]‖Δ)$", "ATTACK FAILS", "0 / 8 verify; 16 distinct candidates each", "good"),
             ("C", "Qiao with the $T_{i}$ binding removed", "$v_{i} = H_{1}(…‖R_{i}‖id_{i}‖Δ)$", "ATTACK SUCCEEDS", "8 / 8 forgeries verify", "bad")]
    for i, (k, name, hashline, verdict, stat, kind) in enumerate(cards):
        x = 0.6 + i * 4.1
        c = T.BAD if kind == "bad" else T.GOOD
        party(s, kind, x, 1.75, 3.93, 3.15, lw=2.0)
        pill(s, x + 0.2, 1.88, 0.5, 0.5, k, c, size=18)
        tb(s, x + 0.85, 1.85, 2.95, 0.6, name, size=16.5, bold=True, anchor="m", lsp=0.95)
        tb(s, x + 0.2, 2.62, 3.6, 0.7, hashline, size=15, lsp=0.95)
        tb(s, x + 0.2, 3.3, 3.55, 0.6, verdict, size=24, bold=True, color=c, anchor="m")
        tb(s, x + 0.2, 3.95, 3.55, 0.8, stat, size=15, color=T.INK, lsp=0.95)
    terminal(s, 0.6, 5.05, 12.13, 0.5, [r"[[tmut|\$]] .venv/bin/python -m pytest tests/test_forgery.py -k ablat -vv     [[tgrn|10 passed]]     [[tmut|fallback: B12]]"], size=13.5)
    tb(s, 0.6, 5.62, 12.1, 0.55, "Shown: the $T_{i}$ binding is necessary against this attack. Not shown: that the other changes are unnecessary ($R_{i}$ in $H_{0}$ targets a different attack), or that the full scheme is secure.",
       size=13.5, color=T.MUTED, lsp=0.95)
    takeaway(s, "The ablation isolates the $T_{i}$ binding as the critical difference for blocking the reproduced rescaling attack.", color=T.GOOD, size=18)
    cue(s, "Only the $T_{i}$ binding is removed.")

    # ------------------------------------------------------------------ 23. implementation and validation
    s = d.slide("Part V · Implementation and validation", "How we built it, and how we checked it", tags=["IMPLEMENTATION", "EXPERIMENT"], notes=N("""
        SAY: Everything is written against one group interface. scheme.py is a direct transliteration of the six algorithms, with names matching the paper. verma.py is Verma et al.'s scheme as Qiao et al. describe it. attack.py has the forgery and the failed attempt. ablation.py is the weakened variant. Below them, hashing is SHA-512 reduced to integers mod p, with a separate domain label for each of H_0, H_1 and H_2 and length-prefixed fields so concatenation is unambiguous. Below that, one backend interface through which every group operation and hash passes, which is how we count operations. At the bottom, two unrelated prime-order groups: Ristretto255 via libsodium, and NIST P-256 via OpenSSL.
        WHY TWO BACKENDS (professor question 15): the results cannot be an artefact of one curve or library, and two independent implementations must agree on every accept/reject outcome and every operation count. Ristretto255 gives a prime-order group, which the algebra needs, since the attack divides by hash values; plain Curve25519 has cofactor 8. P-256 is also what real industrial stacks deploy.
        NUMBERS: the standalone self-test has 62 checks (31 per backend); the test suite has 221 tests, which is 101 tests run on each of two backends plus 19 that do not use a backend. Both backends give identical operation counts. Do not say the backends 'agree on every signature': different groups produce different signatures; they agree on outcomes and counts.
        Implementation choices of ours, not the paper's: the group instantiation, the hash construction, the epoch label for Delta, and correcting two printed typos.
        NEXT: now the performance claim.
        IF ASKED 'is the domain separation essential for security?': we do not claim that. It matches the paper's three distinct hash functions.
    """))
    tb(s, 0.6, 1.72, 7.4, 0.3, "THE CODE, LAYER BY LAYER", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    for i, (name, sub, kind) in enumerate([("scheme.py", "six algorithms", "good"), ("verma.py", "CB-CAS, as reviewed", "plain"),
                                           ("attack.py", "forgery and failed attempt", "bad"), ("ablation.py", "$T_{i}$ unbound", "bad")]):
        x = 0.6 + i * 1.88
        party(s, kind, x, 2.05, 1.76, 0.95, text=[{"text": name, "bold": True, "size": 15.5, "font": None},
                                                  {"text": sub, "size": 12, "color": T.MUTED}], dash=(name == "ablation.py"))
    arrow(s, [(4.3, 3.0), (4.3, 3.2)], T.MUTED)
    box(s, 0.6, 3.2, 7.4, 0.8, fill=T.PANEL, line=T.RULE, radius=0.08,
        text=[{"text": "hashing.py and encoding.py", "bold": True, "size": 15},
              {"text": "SHA-512 reduced mod $p$ · separate labels for $H_{0}, H_{1}, H_{2}$ · length-prefixed fields", "size": 12.5, "color": T.MUTED}])
    arrow(s, [(4.3, 4.0), (4.3, 4.2)], T.MUTED)
    box(s, 0.6, 4.2, 7.4, 0.8, fill=T.PANEL, line=T.RULE, radius=0.08,
        text=[{"text": "one backend interface", "bold": True, "size": 15},
              {"text": "every group operation and hash passes through it, so $T_{e}, T_{a}, T_{h}$ can be counted", "size": 12.5, "color": T.MUTED}])
    arrow(s, [(2.3, 5.0), (2.3, 5.2)], T.MUTED)
    arrow(s, [(6.3, 5.0), (6.3, 5.2)], T.MUTED)
    box(s, 0.6, 5.2, 3.6, 0.85, fill=T.WHITE, line=T.INK, lw=1.5, radius=0.08,
        text=[{"text": "Ristretto255", "bold": True, "size": 15.5}, {"text": "via libsodium", "size": 12.5, "color": T.MUTED}])
    box(s, 4.4, 5.2, 3.6, 0.85, fill=T.WHITE, line=T.INK, lw=1.5, radius=0.08,
        text=[{"text": "NIST P-256", "bold": True, "size": 15.5}, {"text": "via OpenSSL", "size": 12.5, "color": T.MUTED}])
    tiles = [("62", "self-test checks, 31 per backend"), ("221", "tests: 101 × 2 backends + 19"), ("=", "identical operation counts and accept/reject outcomes on both backends")]
    for i, (big, lab) in enumerate(tiles):
        y = 1.8 + i * 1.5
        box(s, 8.4, y, 4.33, 1.3, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.1)
        tb(s, 8.6, y, 1.4, 1.3, big, size=36, bold=True, color=T.INK, anchor="m", align="c", font=T.F_MATH)
        tb(s, 10.05, y, 2.55, 1.3, lab, size=14.5, anchor="m", lsp=0.95)
    takeaway(s, "Every result in this talk comes from code that passes the same checks on two independent group implementations.", size=18)
