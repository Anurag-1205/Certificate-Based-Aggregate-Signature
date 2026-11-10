"""Part II: a second look at the attack (slides 7-13)."""
import theme as T
from final_common import C, DEMO, N, card, num_badge, tag_pill, verdict
from lib import box, chip, cue, grid, image, party, tb, takeaway, terminal


def build(d):
    ko = C["keyonly"]
    k = ko["trials"]

    # ------------------------------------------------------------------ 7. is it the weakest attack?
    s = d.slide("Part II · A second look at the attack", "Is the paper's attack the weakest one against Verma's scheme?",
                tags=["PAPER", "OUR FINDING"], title_size=28, notes=N("""
        SAY: The paper's attacker is strong: a malicious KGC with the master key and the certificate it issued, and it must first see one signature from the victim. We asked whether a much weaker attacker can do the same. The answer is yes: someone who holds nothing but the victim's public key, and has seen no signature at all.
        TERMS: Goldwasser, Micali and Rivest (1988) classify attacks by what the attacker is given, and forgeries by what it produces. A key-only attack sees only public keys. A universal forgery is valid on any message the attacker likes. Key-only plus universal is the strongest combination.
        TIME: 45 seconds.
        NEXT: how it works, in one equation.
    """))
    party(s, "kgc", 0.6, 1.75, 5.85, 2.65, text=[
        {"text": "The paper's attacker (§IV-B)", "bold": True, "size": 18, "after": 8},
        {"text": "a malicious KGC", "size": 16, "after": 4},
        {"text": "holds the master key and the victim's certificate", "size": 16, "after": 4},
        {"text": "must first observe one valid signature", "size": 16}], align="l", anchor="t", pad=0.25)
    party(s, "bad", 6.88, 1.75, 5.85, 2.65, text=[
        {"text": "Our attacker", "bold": True, "size": 18, "after": 8},
        {"text": "anyone at all", "size": 16, "after": 4},
        {"text": "holds only public values: $P_{TA}$, $id_{i}$, $pk_{i}$", "size": 16, "after": 4},
        {"text": "has never seen a signature", "size": 16}], align="l", anchor="t", pad=0.25)
    tb(s, 6.48, 2.7, 0.4, 0.5, "→", size=30, color=T.MUTED, align="c", check=False)
    box(s, 0.6, 4.65, 12.13, 1.35, fill=T.PANEL, line=None, radius=0.1)
    tb(s, 0.85, 4.75, 11.6, 1.2, [
        {"text": "Standard terms (Goldwasser, Micali, Rivest, SIAM J. Computing 1988)", "bold": True, "size": 14, "color": T.MUTED, "after": 4},
        {"text": "**Key-only attack**: the attacker sees only public keys.   **Universal forgery**: a valid signature on any message it chooses.", "size": 16, "after": 3},
        {"text": "Key-only + universal is the strongest combination: the least access, the most damaging result.", "size": 16}], lsp=0.97)
    takeaway(s, "Can someone who holds only a public key forge? For Verma's scheme, yes.", color=T.BAD)

    # ------------------------------------------------------------------ 8. the mechanism
    s = d.slide("Part II · The mechanism", "Verma's commitment $R_{i}$ is in no hash, so we can solve for it",
                tags=["OUR FINDING"], title_size=28, notes=N("""
        SAY: Verma's verification equation is z P = R + h_0 P_TA + v pk. Look at the two hash values: h_0 hashes the identity and public key; v hashes the message, public key, identity and Delta. Neither contains R, and R sits in the equation with coefficient one. R also travels inside the signature, so the signer, or a forger, chooses it.
        THE THREE STEPS: pick any z, for example zero. Compute h_0 and v from public data. Set R = z P minus h_0 P_TA minus v pk. The pair (R, z) satisfies the equation by construction. Point arithmetic only: no discrete logarithm, no secret, no signature observed.
        WHY IT IS FAMILIAR: Schnorr signatures hash the commitment together with the message, c = H(R, m), exactly so that R cannot be chosen after the challenge is known. With c = H(m) a Schnorr signature is forgeable the same way.
        TIME: 1 minute 15 seconds. This is the key slide of Part II.
        IF ASKED 'is R not fixed by the certificate?': no; in Verma's scheme R_i = R_1i + r_2i P is part of each signature, fresh every time. The verifier has no fixed value to compare it with.
        Code: src/cbas/keyonly_attack.py, forge_verma_keyonly (about ten lines).
    """))
    box(s, 0.6, 1.7, 12.13, 1.15, fill=T.WHITE, line=T.INK, lw=1.5, radius=0.1)
    tb(s, 0.85, 1.76, 4, 0.3, "VERMA'S CHECK", size=12, color=T.MUTED, bold=True, spc=100, check=False)
    tb(s, 0.85, 2.05, 11.7, 0.7, "$zP = [[red|R]] + h_{0}P_{TA} + v·pk$,   $h_{0} = H_{0}(id‖pk)$,   $v = H_{1}(m‖pk‖id‖Δ)$   ← neither hash contains $R$",
       size=21)
    steps = [("Pick any $z$", "for example $z = 0$"),
             ("Compute $h_{0}$ and $v$", "public inputs only"),
             ("Set $R = zP − h_{0}P_{TA} − v·pk$", "the equation now holds")]
    for i, (a, b) in enumerate(steps):
        x = 0.6 + i * 4.095
        box(s, x, 3.1, 3.9, 1.5, fill=T.BAD_T if i == 2 else T.PANEL, line=T.BAD if i == 2 else None, lw=1.5, radius=0.1)
        num_badge(s, x + 0.2, 3.25, i + 1, fill=T.BAD if i == 2 else T.INK)
        tb(s, x + 0.2, 3.78, 3.55, 0.75, [{"text": a, "size": 17, "bold": True, "after": 2},
                                          {"text": b, "size": 14, "color": T.MUTED}], lsp=0.95)
    box(s, 0.6, 4.85, 12.13, 1.2, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.1)
    tb(s, 0.85, 4.93, 11.7, 1.05, [
        {"text": "The same reason Schnorr signatures hash the commitment with the message", "bold": True, "size": 15, "after": 4},
        {"text": "$c = H(R, m)$ fixes $R$ before the challenge.  With $c = H(m)$, $R$ could be solved for exactly as here.", "size": 16}],
       lsp=0.97)
    takeaway(s, "A forgery from public values alone: no secret, no observed signature, no discrete logarithm.", color=T.BAD)

    # ------------------------------------------------------------------ 9. contradicts Table II
    s = d.slide("Part II · Against the paper's own table", "This contradicts the paper's Table II",
                tags=["PAPER", "OUR FINDING"], notes=N(f"""
        SAY: The paper's Table II rates Verma's scheme, reference 11, as secure against F_1, the malicious user, and insecure against F_2, the malicious KGC. The F_2 entry is the paper's own attack, which we reproduced. The F_1 entry cannot be right: our forger has strictly less power than F_1, since F_1 may also ask for keys and signatures. Whatever a key-only forger can do, F_1 can do too.
        RESULT: {ko['verma_forged']} of {k} key-only forgeries verify (4 messages, 2 libraries), and {ko['verma_agg']} of {k} also pass aggregate verification next to an honest signature.
        TIME: 45 seconds.
        IF ASKED 'is this in the literature already?': the underlying principle, hashing the commitment, is textbook. We have not found this attack on Verma's scheme stated anywhere, but we did not do an exhaustive literature search, so we say 'not discussed in the paper', not 'new to the field'.
        NEXT: we run it.
    """))
    rows = [[{"text": "TABLE II (PAPER)"}, {"text": "SIGN"}, {"text": "VERIFY"}, {"text": "SECURE AGAINST $F_{1}$"}, {"text": "SECURE AGAINST $F_{2}$"}],
            [{"text": "Scheme [11], Verma et al.", "bold": True}, "$1T_{e} + 1T_{h}$", "$3T_{e} + 2T_{a} + 2T_{h}$",
             {"text": "Yes", "bold": True, "fill": T.BAD_T, "color": T.BAD, "align": "c"}, {"text": "No", "align": "c"}]]
    grid(s, 0.6, 1.8, [3.4, 1.9, 2.6, 2.13, 2.1], [0.48, 0.62], rows, size=17, hdr_size=11.5)
    tb(s, 0.6, 3.0, 12.1, 0.3, "Source: Qiao et al., Table II, row for scheme [11].", size=12.5, color=T.MUTED)
    card(s, 0.6, 3.5, 5.9, 2.5, "Secure against $F_{2}$: No", ["Correct. The paper's own attack (§IV-B), which we reproduced at the interim: 8 / 8."],
         tag="REPRODUCED", hsize=18, bsize=16)
    card(s, 6.83, 3.5, 5.9, 2.5, "Secure against $F_{1}$: Yes", [f"Not correct. A forger with less power than $F_{{1}}$ succeeds: {ko['verma_forged']} / {k}, and {ko['verma_agg']} / {k} inside an aggregate."],
         tag="OUR FINDING", line=T.BAD, lw=1.75, hsize=18, bsize=16)
    takeaway(s, "Verma's scheme is broken by anyone, not only by a malicious KGC.", color=T.BAD)

    # ------------------------------------------------------------------ 10. demo 1
    s = d.slide("Part II · Demo 1", "Demo 1: a forgery from a public key alone", tags=["EXPERIMENT"], notes=N(f"""
        RUN: make attack, and scroll to TARGET 3. About 2 seconds.
        POINT AT: (1) attacker capability: it sees P_TA and this sensor's public key, nothing else. (2) forged sig verifies: True, marked UNIVERSAL FORGERY. (3) the same attack on the repaired scheme: False.
        SAY: The sensor's key is a real, honestly enrolled key; the forger never touches its secret key, certificate or any signature.
        FALLBACK: if the terminal fails or is slow, this slide already shows the captured output of the same command. Say 'this is the output of the same command, captured earlier'. Backup B13 has it larger.
        TIME: 1 minute 30 seconds including the demo.
        NEXT: why the repaired scheme survives.
    """))
    terminal(s, 0.6, 1.75, 4.4, 0.75, ["\\$ make attack"], size=22)
    tb(s, 0.6, 2.75, 4.4, 0.3, "WHAT TO POINT AT", size=12, color=T.MUTED, bold=True, spc=100, check=False)
    pts = ["Attacker sees only $P_{TA}$ and $pk_{i}$", "Forged signature verifies: True", "Same attack on the repair: False"]
    for i, p in enumerate(pts):
        num_badge(s, 0.6, 3.15 + i * 0.72, i + 1)
        tb(s, 1.15, 3.12 + i * 0.72, 3.85, 0.5, p, size=16.5, anchor="m")
    image(s, DEMO / "final_demo1_keyonly.png", 5.3, 1.75, w=7.43)
    tb(s, 5.3, 4.25, 7.43, 0.3, "Captured output of the same command (fallback if the terminal fails).", size=12.5, color=T.MUTED)
    for i, (txt, kind) in enumerate(((f"{ko['verma_forged']} / {k} forgeries verify", "bad"),
                                     (f"{ko['verma_agg']} / {k} pass aggregate verification", "bad"),
                                     (f"{ko['qiao_forged']} / {k} against the repaired scheme", "good"))):
        chip(s, 0.6 + i * 4.095, 5.45, 3.9, 0.55, txt, kind, size=15, bold=True)
    cue(s, "Terminal fails? This slide's panel shows the output; B13 has it larger.", x=8.2, y=4.65, w=4.53, h=0.62)
    takeaway(s, "A real sensor's key, no secrets, no observed signature: the forgery verifies.", color=T.BAD)

    # ------------------------------------------------------------------ 11. why the repair resists
    s = d.slide("Part II · The repair", "Why the repaired scheme resists it", tags=["PAPER", "EXPERIMENT"], notes=N(f"""
        SAY: In the repaired scheme R appears in all three hashes: h_0, u and v are hashes of R, and also of T. To solve the equation for R, the attacker needs h_0, u and v first; to compute them it needs R first. So the only route is a fixed-point search: guess R, compute the hashes, solve for the R the equation would need, compare. We ran that search: each round gives a new candidate, {ko['qiao_distinct_min']} distinct candidates in every trial, and {ko['qiao_forged']} of {k} forgeries.
        WORDING: this shows that this attack does not apply. It is not a proof of security; the paper's proof covers that, and we have not audited it.
        TIME: 45 seconds.
        NEXT: two changes are made at once. Which one does the work?
    """))
    box(s, 0.6, 1.7, 12.13, 1.2, fill=T.WHITE, line=T.INK, lw=1.5, radius=0.1)
    tb(s, 0.85, 1.76, 4, 0.3, "QIAO'S CHECK", size=12, color=T.MUTED, bold=True, spc=100, check=False)
    tb(s, 0.85, 2.05, 11.7, 0.75, "$zP = T + u·R + u·h_{0}P_{TA} + v·pk$,   $h_{0} = H_{0}(id‖pk‖[[grn|R]])$,   $u, v = H_{2}, H_{1}(m‖pk‖[[grn|R]]‖id‖[[grn|T]]‖Δ)$",
       size=20)
    box(s, 0.6, 3.15, 5.9, 2.85, fill=T.PANEL, line=None, radius=0.1)
    tb(s, 0.85, 3.3, 5.45, 2.6, [
        {"text": "The circle", "bold": True, "size": 18, "after": 8},
        {"text": "To solve for $R$ you need $h_{0}$, $u$, $v$.", "size": 17, "after": 6},
        {"text": "To compute $h_{0}$, $u$, $v$ you need $R$.", "size": 17, "after": 6},
        {"text": "What is left is searching for a fixed point of a hash: guessing, not algebra.", "size": 16, "color": T.MUTED}], lsp=0.97)
    tr = ko["sample_trace"]["rounds"]
    terminal(s, 6.83, 3.15, 5.9, 2.85, [f"fixed-point search, one trial ({ko['sample_trace']['backend']})",
                                        *(f"  round {i + 1}  R = {h}…" for i, h in enumerate(tr)),
                                        "  …        every round different", "",
                                        f"  {ko['qiao_distinct_min']} distinct candidates per trial",
                                        f"  forgeries: {ko['qiao_forged']} / {k}"], size=14)
    takeaway(s, "With $R$ inside every hash, solving for it becomes circular. This attack does not apply.", color=T.GOOD)

    # ------------------------------------------------------------------ 12. the 2x2
    s = d.slide("Part II · Which change does the work?", "Each binding closes its own door, and only its own",
                tags=["OUR FINDING", "EXPERIMENT"], notes=N(f"""
        SAY: The repair changes two things at once: it hashes T and it hashes R. To see which does what, we remove one at a time, keeping everything else, and attack each variant both ways: solving for T and solving for R.
        THE CELLS: Top left, the real scheme: both attempts fail. Bottom left, T not hashed (the interim's ablation): solving for T forges, {ko['t_cell']} of {k}, with the victim's real certificate; solving for R still fails. Top right, R not hashed: solving for R forges, {ko['r_cell']} of {k}; solving for T still fails. Bottom right, Verma: R free.
        THE CAVEAT, important: the two open doors are not the same kind of attack. T travels in every signature, so the bottom-left forgery is a true key-only forgery. In Qiao's scheme R belongs to the certificate, so the top-right forgery only verifies if the verifier accepts an attacker-chosen R: {ko['r_cell_needs_replaced_R']} of {k} fail with the real R. That is public-key replacement, the power the paper gives F_1, and it is exactly why the paper says it hashes R. So that cell confirms the paper's reason, with code.
        TIME: 1 minute 15 seconds.
        IF ASKED 'so is R in the hash really needed?': against an attacker who can replace R, yes; this cell shows it. Against a verifier that pins each sensor's R, the T binding alone blocks both attempts here.
        NEXT: the general lesson.
    """))
    colw = [2.6, 4.75, 4.75]
    rows = [[{"text": ""}, {"text": "$R$ HASHED"}, {"text": "$R$ NOT HASHED"}],
            [{"text": "$T$ hashed", "bold": True},
             {"text": "**Qiao, the real scheme**\nboth attempts fail", "fill": T.GOOD_T, "color": T.INK},
             {"text": f"**R removed**: solve for $R$ forges {ko['r_cell']} / {k}\nneeds a replaced $R$ (public-key replacement)", "fill": T.BAD_T}],
            [{"text": "$T$ not hashed", "bold": True},
             {"text": f"**T removed**: solve for $T$ forges {ko['t_cell']} / {k}\nwith the real certificate: key-only", "fill": T.BAD_T},
             {"text": "**Verma**: solve for $R$ forges\n$R$ travels in the signature: key-only", "fill": T.BAD_T}]]
    grid(s, 0.6, 1.75, colw, [0.5, 1.45, 1.45], rows, size=16, hdr_size=12.5, valign="m")
    tb(s, 0.6, 5.3, 12.1, 0.75, [
        {"text": f"In each broken variant, the other attempt still fails ({ko['t_cell_r_safe']} / {k} and {ko['r_cell_t_safe']} / {k}). "
                 "Code: ablation.py removes $T$, ablation_r.py removes $R$; nothing else changes.", "after": 2},
        {"text": f"The top-right forgery fails under the real certificate $R$ in {ko['r_cell_needs_replaced_R']} / {k} trials."}],
       size=14, color=T.MUTED)
    takeaway(s, "Hashing $T$ and hashing $R$ are both needed; each blocks a different attack.")

    # ------------------------------------------------------------------ 13. the lesson
    s = d.slide("Part II · The lesson", "A commitment outside every hash is a free variable", tags=["PAPER", "OUR FINDING"], notes=N("""
        SAY: One rule explains every cell. If a value appears in the verification equation but in no hash, and its coefficient is known, an attacker can choose everything else and solve for it. Verma leaves R free. Removing the T binding leaves T free. Removing the R binding leaves R free, for an attacker who may replace it.
        THE PAPER: states this rule for T only, in section V-A, in the context of the one attack it found. We show the same mechanism for either commitment, independently.
        TIME: 30 seconds.
        NEXT: Part III, cost.
    """))
    box(s, 0.6, 1.75, 12.13, 1.45, fill=T.INK, line=None, radius=0.12)
    tb(s, 0.95, 1.85, 11.5, 1.25, "If a value appears in the verification equation with a known coefficient, but in no hash, "
                                  "an attacker can fix everything else and solve for it.", size=23, color="#FFFFFF", bold=True,
       font=T.F_MATH, anchor="m", lsp=0.95)
    ex = [("Verma et al.", "$R$ in no hash", "key-only forgery"),
          ("Qiao without $T$ binding", "$T$ in no hash", "key-only forgery"),
          ("Qiao without $R$ binding", "$R$ in no hash", "forgery by replacing $R$")]
    for i, (a, b, c_) in enumerate(ex):
        x = 0.6 + i * 4.095
        card(s, x, 3.45, 3.9, 1.6, a, [b, c_], line=T.BAD, hsize=17, bsize=16)
    tb(s, 0.6, 5.25, 12.1, 0.8, "The paper (§V-A) states the rule for $T_{i}$ alone: “the promised value $T_{i}$ … should be used to generate the core element of signature … Otherwise, any malicious KGC can … forge.”",
       size=14, color=T.MUTED, lsp=0.97)
    takeaway(s, "Hash every commitment that appears in the verification equation.")
