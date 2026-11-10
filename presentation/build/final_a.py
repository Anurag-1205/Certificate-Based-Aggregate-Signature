"""Part I: title, roadmap, the problem, recap of the interim, open questions (slides 1-7)."""
import theme as T
from final_common import C, N, card, num_badge, tag_pill
from lib import arrow, box, chip, grid, party, tb, takeaway, text_width


def build(d):
    rc = C["recap"]
    # ------------------------------------------------------------------ 1. title
    s = d.dark(notes=N("""
        SAY: At the interim we reproduced this paper's attack, tested its repair and audited its cost claims. Today we go beyond the paper: we test the repaired scheme and the claims around it, and we look for attacks the paper did not consider.
        AUDIENCE SHOULD GET: same paper, same team, new questions.
        TIME: 20 seconds.
        NEXT: what we covered last time and what is new today.
    """))
    tb(s, 0.8, 0.62, 9, 0.3, "MTECH FINAL RESEARCH PRESENTATION", size=13, color="#9FB3C8", bold=True, spc=140, check=False)
    tb(s, 0.8, 1.2, 9.0, 2.7, ["An Efficient Certificate-Based", "Aggregate Signature Scheme With", "Provable Security for Industrial",
                               "Internet of Things"], size=40, color="#FFFFFF", bold=True, font=T.F_MATH, lsp=0.95)
    tb(s, 0.8, 4.05, 9.4, 0.45, "Beyond the paper: a stronger forgery, a key-recovery risk, and three claims tested",
       size=20, color="#C3D0DF", check=False)
    box(s, 0.8, 4.85, 7.6, 1.15, fill="#17283B", line="#2B3F55", lw=1.0, radius=0.1)
    tb(s, 1.05, 4.95, 7.1, 0.25, "PAPER UNDER STUDY", size=11.5, color="#8FA1B3", bold=True, spc=120, check=False)
    tb(s, 1.05, 5.25, 7.1, 0.3, "Zirui Qiao et al.  ·  IEEE Systems Journal, Vol. 17, No. 1, 2023", size=15, color="#FFFFFF", check=False)
    tb(s, 1.05, 5.58, 7.1, 0.3, "DOI: 10.1109/JSYST.2022.3188012", size=13.5, color="#B4C3D4", check=False)
    tb(s, 0.8, 6.4, 11.8, 0.34, "Anurag Kaushal (2025202013)  ·  Pranav Vyas (2025202015)  ·  Taufique (2025202007)", size=16,
       color="#DDE5EE", bold=True, check=False)
    tb(s, 0.8, 6.8, 11.8, 0.3, "Research in Information Security  ·  IIIT Hyderabad", size=14, color="#9FB3C8", check=False)

    def mix(c, bg="#14202E", a=0.38):
        c, bg = c.lstrip("#"), bg.lstrip("#")
        return "#" + "".join(f"{round(int(c[i:i + 2], 16) * a + int(bg[i:i + 2], 16) * (1 - a)):02X}" for i in (0, 2, 4))
    ys = (1.75, 2.6, 3.45, 4.3)
    for (name, c), y in zip((("KGC", T.KGC), ("Sensors", T.SEN), ("Aggregator", T.AGG), ("Cloud verifier", T.VER)), ys):
        box(s, 10.5, y, 2.1, 0.52, fill=mix(c), line=c, lw=1.5, radius=0.1, text=name, size=15, bold=True, color="#E4EAF0")
    for y in ys[:-1]:
        arrow(s, [(11.55, y + 0.52), (11.55, y + 0.85)], color="#6F8195", lw=1.5)

    # ------------------------------------------------------------------ 2. roadmap
    s = d.slide("Roadmap", "From the interim to today", notes=N("""
        SAY: One slide on why this paper matters, then three slides recapping the interim, as asked. Then four new parts, one for each open question we listed at the end of the interim. Two live demos, on slides 11 and 22.
        AUDIENCE SHOULD GET: where we are going, and that the new work is most of the talk.
        TIME: 20 seconds. Do not read the list; point at the two columns.
        NEXT: the recap.
    """))
    box(s, 0.6, 1.7, 3.9, 4.35, fill=T.PANEL, line=None, radius=0.12)
    tb(s, 0.85, 1.85, 3.4, 0.3, "PROBLEM · INTERIM RECAP", size=12.5, color=T.MUTED, bold=True, spc=120, check=False)
    tb(s, 0.85, 2.25, 3.45, 3.7, [{"text": "Slides 3–6", "bold": True, "size": 18, "after": 8},
                                  {"text": "Why this paper matters", "after": 6},
                                  {"text": "The repaired scheme's architecture", "after": 6},
                                  {"text": "The paper's attack, reproduced, and which change in the repair stops it", "after": 6},
                                  {"text": "The paper's cost rows, recounted"}], size=16, color=T.INK)
    arrow(s, [(4.55, 3.85), (5.05, 3.85)], T.MUTED, lw=2.25)
    parts = [("Part II", "A second look at the attack", "8–13", "Demo 1"),
             ("Part III", "Faster verification", "14–16", None),
             ("Part IV", "The aggregator in practice", "17–19", None),
             ("Part V", "Open analysis: nonce reuse, replay, forward security", "20–25", "Demo 2"),
             ("Part VI", "Evidence, results, scope, conclusion", "26–30", None)]
    for i, (p, name, rng, demo) in enumerate(parts):
        y = 1.7 + i * 0.89
        box(s, 5.1, y, 7.63, 0.77, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.1)
        tb(s, 5.3, y + 0.04, 1.2, 0.69, p, size=15, color=T.MUTED, bold=True, anchor="m")
        tb(s, 6.45, y + 0.04, 4.5, 0.69, name, size=17.5, bold=True, anchor="m", font=T.F_MATH, lsp=0.92)
        tb(s, 10.95, y + 0.04, 0.85, 0.69, rng, size=14, color=T.MUTED, anchor="m", align="r")
        if demo:
            chip(s, 11.88, y + 0.2, 0.75, 0.37, demo, "agg", size=11.5, bold=True)
    takeaway(s, "The problem and a three-slide recap, then four parts of new work: one per open question.")

    # ------------------------------------------------------------------ 3. why this paper matters
    s = d.slide("Part I · The problem", "Can sensor data be signed without trusting the key authority?", tags=["PAPER"],
                title_size=28, notes=N("""
        SAY: The setting is an industrial plant: thousands of sensors sign their readings, an aggregator merges the signatures, and a cloud server checks them. Aggregation means one check and fewer bytes for n readings. Certificate-based signatures mean the sensor makes its own key and a key generation centre, the KGC, only certifies it, so the KGC cannot sign alone and there is no certificate lookup. The danger is the KGC itself: the paper cites an employee at South Africa's Postbank who took a master key and stole 3.2 million dollars. A good scheme must stay unforgeable even then.
        THE STORY: Verma et al. proposed such a scheme in 2020. The paper we study, Qiao et al. 2023, shows that a malicious KGC can forge Verma signatures and proposes a repair it calls secure and as cheap as Verma's. We checked both halves of that claim, and then looked further.
        TIME: 45 seconds.
        NEXT: what the repaired scheme looks like.
    """))
    cards = [("Aggregate signatures", "n readings, one aggregate signature: one accept-or-reject check, fewer bytes sent"),
             ("Certificate-based keys", "The sensor makes its own key; the KGC (key generation centre) only certifies it. Neither can sign alone: no key escrow, no certificate lookup"),
             ("The threat", "The KGC holds the master key. If it leaks or turns malicious, it must still not be able to forge (the paper's example: a stolen Postbank master key, §I-C)")]
    for i, (h, b) in enumerate(cards):
        x = 0.6 + i * 4.095
        card(s, x, 1.75, 3.9, 2.35, h, [b], hsize=18, bsize=15, gap=6, line=(T.BAD if i == 2 else T.RULE))
    steps = [("2020", "Verma et al. propose a certificate-based aggregate signature for IIoT (CB-CAS)", T.MUTED),
             ("2023", "The paper (Qiao et al.): a malicious KGC forges Verma signatures; a repair, proved secure, claimed as cheap", T.KGC),
             ("Us", "Reproduce the attack, audit the repair's claims, and test it further: attacks, cost, deployment", T.GOOD)]
    for i, (yr, txt, c) in enumerate(steps):
        y = 4.3 + i * 0.6
        box(s, 0.6, y, 1.0, 0.48, fill=c, line=None, radius=0.08, text=yr, size=15, bold=True, color="#FFFFFF")
        tb(s, 1.8, y, 10.9, 0.48, txt, size=16, anchor="m")
    takeaway(s, "Question: is the paper's repair as secure and as cheap as it claims, and what does it still miss?")

    # ------------------------------------------------------------------ 3. recap: architecture of the repaired scheme
    s = d.slide("Part I · Recap 1 of 3", "The repaired scheme: who computes and sends what", tags=["PAPER"], notes=N("""
        SAY: The architecture from the interim, now drawn with the values the repaired scheme actually sends. The KGC publishes the parameters and gives each sensor a certificate, c_i and R_i, after receiving its public key. A sensor signs its reading: delta_i is the commitment T_i and the response z_i. The aggregator adds the z_i and keeps every T_i. The cloud checks one equation for all n readings.
        THE REPAIR, bottom strip: u_i and v_i hash the message together with both commitments, R_i and T_i, and H_0 hashes R_i. Verma's hashes contained neither commitment. Which values go into the hash decides everything in this talk.
        THE ORANGE MARKERS: where today's parts land on this picture. Part V at the sensor (its nonce t_i) and at the cloud (replay); Part IV at the aggregator (one bad signature); Part III at the cloud (the cost of this equation). Part II is about Verma's scheme, the one this repair replaces.
        TIME: 40 seconds.
        NEXT: what the paper's attack does to Verma's scheme, and what the repair changes.
    """))
    box(s, 0.6, 3.05, 6.85, 3.0, fill=None, line=T.MUTED, lw=1.25, dash=True, radius=0.15)
    tb(s, 0.78, 3.1, 3, 0.3, "factory area", size=13, color=T.MUTED)
    for y, name in ((3.45, "Sensor 1"), (4.25, "Sensor 2"), (5.3, "Sensor n")):
        party(s, "sen", 0.9, y, 2.35, 0.66, text=[{"text": name, "size": 16, "bold": True},
                                                    {"text": "② KeyGen · ④ Sign", "size": 12.5, "color": T.SEN}])
    tb(s, 0.9, 4.95, 2.35, 0.3, "⋮", size=20, color=T.MUTED, align="c", check=False)
    party(s, "agg", 4.7, 4.1, 2.5, 1.05, text=[{"text": "Aggregator", "size": 17, "bold": True},
                                                 {"text": "⑤ AggSign: $z = Σz_{i}$", "size": 13.5, "color": T.AGG}])
    party(s, "kgc", 5.1, 1.62, 3.0, 1.05, text=[{"text": "KGC", "size": 17, "bold": True},
                                                  {"text": "holds $s^{k}_{TA}$", "size": 13, "color": T.MUTED},
                                                  {"text": "① Setup · ③ CertGen", "size": 13.5, "color": T.KGC}])
    party(s, "ver", 9.45, 3.95, 3.28, 1.2, text=[{"text": "Cloud server", "size": 17, "bold": True},
                                                   {"text": "⑥ AggVerify: accept all n, or reject", "size": 12.5, "color": T.VER}])
    arrow(s, [(8.1, 2.15), (12.45, 2.15), (12.45, 3.95)], T.KGC)
    tb(s, 8.25, 1.68, 2.8, 0.42, "① $Params$: $P^{k}_{TA}$, $H_{0}$, $H_{1}$, $H_{2}$, $Δ$", size=13.5, color=T.KGC, bold=True)
    arrow(s, [(5.1, 1.9), (1.85, 1.9), (1.85, 3.45)], T.KGC)
    tb(s, 2.0, 1.5, 3.05, 0.36, "③ $Cert_{i} = (c_{i}, R_{i})$", size=14.5, color=T.KGC, bold=True)
    arrow(s, [(2.55, 3.45), (2.55, 2.4), (5.1, 2.4)], T.SEN)
    tb(s, 2.72, 2.45, 2.3, 0.36, "② $pk_{i}$", size=14.5, color=T.SEN, bold=True)
    arrow(s, [(3.25, 3.78), (3.95, 3.78), (3.95, 4.35), (4.7, 4.35)], T.SEN)
    arrow(s, [(3.25, 4.58), (4.7, 4.58)], T.SEN)
    arrow(s, [(3.25, 5.63), (3.95, 5.63), (3.95, 4.88), (4.7, 4.88)], T.SEN)
    tb(s, 3.38, 3.27, 4.0, 0.36, "④ $m_{i}$, $δ_{i} = (T_{i}, z_{i})$", size=14.5, color=T.SEN, bold=True)
    arrow(s, [(7.2, 4.6), (9.45, 4.6)], T.AGG, lw=2.25)
    tb(s, 7.5, 3.6, 1.9, 0.95, "⑤ $m_{1}, …, m_{n}$ and $δ = (T_{1}, …, T_{n}, z)$", size=13, color=T.AGG, bold=True, lsp=0.95)
    box(s, 7.65, 5.35, 5.08, 0.62, fill=T.PANEL, line=None, radius=0.08,
        text="$zP = ΣT_{i} + Σu_{i}R_{i} + (Σu_{i}h^{i}_{0})P^{k}_{TA} + Σv_{i}pk_{i}$", size=14)
    for x, y, w, label in ((4.3, 5.62, 3.05, "Part V: a sensor repeats its nonce $t_{i}$"), (4.7, 3.68, 2.5, "Part IV: one bad $δ_{i}$"),
                           (9.45, 3.45, 2.85, "Part III: cost · Part V: replay")):
        box(s, x, y, w, 0.34, fill=T.WHITE, line=T.TAGS["OUR FINDING"], lw=1.25, radius=0.08, text=label, size=11.5,
            bold=True, color=T.TAGS["OUR FINDING"], pad=0.06)
    box(s, 0.6, 6.2, 12.13, 0.72, fill=T.GOOD_T, line=T.GOOD, lw=1.25, radius=0.08)
    tb(s, 0.85, 6.22, 11.7, 0.68, "The repair: $v_{i}, u_{i} = H_{1}, H_{2}(m_{i}‖pk_{i}‖[[grn|R_{i}]]‖id_{i}‖[[grn|T_{i}]]‖Δ)$ and "
                                  "$h^{i}_{0} = H_{0}(id_{i}‖pk_{i}‖[[grn|R_{i}]])$. Verma's hashes contained neither commitment.",
       size=15, anchor="m", lsp=0.95)

    # ------------------------------------------------------------------ 4. recap: attack and ablation
    s = d.slide("Part I · Recap 2 of 3", "The paper's attack breaks Verma; the $T_{i}$ binding stops it",
                tags=["REPRODUCED", "OUR AUDIT"], notes=N(f"""
        SAY: At the interim we ran the paper's attack. A malicious KGC that has seen one signature rescales it into a valid signature on any message: {rc['verma_forged']} of {rc['trials']} trials on two curve libraries. Against Qiao's repair the same attack fails, {rc['qiao_forged']} of {rc['trials']}. Then our ablation: Qiao's scheme with only the T_i binding removed lets the attack through again, {rc['ablated_forged']} of {rc['trials']}.
        PROVENANCE: the attack and the repair are the paper's (reproduced). The ablation is ours.
        TIME: 45 seconds.
        NEXT: the cost claim.
        Numbers recomputed today on the current code by presentation/audit/verify_claims_final.py.
    """))
    cards = [("A", "Verma et al.", "ATTACK SUCCEEDS", f"{rc['verma_forged']} / {rc['trials']} forgeries verify", "bad"),
             ("B", "Qiao et al., repaired", "ATTACK FAILS", f"{rc['qiao_forged']} / {rc['trials']} verify", "good"),
             ("C", "Qiao without the $T_{i}$ binding", "ATTACK SUCCEEDS", f"{rc['ablated_forged']} / {rc['trials']} verify", "bad")]
    for i, (lab, name, res, cnt, kind) in enumerate(cards):
        x = 0.6 + i * 4.095
        line, fill = (T.BAD, T.BAD_T) if kind == "bad" else (T.GOOD, T.GOOD_T)
        box(s, x, 1.75, 3.9, 2.05, fill=fill, line=line, lw=1.75, radius=0.12)
        num_badge(s, x + 0.25, 1.92, lab, fill=line)
        tb(s, x + 0.8, 1.9, 2.95, 0.5, name, size=17, bold=True, anchor="m")
        tb(s, x + 0.25, 2.55, 3.4, 0.5, res, size=24, bold=True, color=line, font=T.F_MATH)
        tb(s, x + 0.25, 3.15, 3.4, 0.4, cnt, size=17)
    box(s, 0.6, 3.98, 12.13, 1.5, fill=T.WHITE, line=T.INK, lw=1.25, radius=0.1)
    tb(s, 0.85, 4.04, 11.7, 1.4, [
        {"text": "How the attack works (paper §IV-B)", "bold": True, "size": 15.5, "after": 3},
        {"text": "Verma signs with $z_{i} = r_{2i} + c_{i} + sk_{i}v_{i}$, where $v_{i} = H_{1}(m_{i}‖pk_{i}‖id_{i}‖Δ)$ ignores the nonce commitment $R_{i}$. "
                 "The KGC knows $c_{i}$, so it strips it and rescales the rest by $λ = v′/v_{i}$ for any new message:", "size": 15, "after": 3},
        {"text": "$R′ = R_{1i} + λ(R_{i} − R_{1i})$,   $z′ = c_{i} + λ(z_{i} − c_{i})$: valid, without ever learning $sk_{i}$.   Full derivation: backup B15.", "size": 15}],
       lsp=0.97)
    tb(s, 0.6, 5.6, 12.1, 0.55, "Attacker: a malicious KGC (the paper's adversary $F_{2}$) holding the master key and the certificate, with one observed signature. "
                               "Trials: 4 target messages × 2 group libraries.", size=13, color=T.MUTED, lsp=0.95)
    takeaway(s, "Removing only the $T_{i}$ binding brings this attack back, so that binding is what stops it.")

    # ------------------------------------------------------------------ 5. recap: cost
    s = d.slide("Part I · Recap 3 of 3", "The repaired scheme costs about twice what the paper prints",
                tags=["PAPER", "OUR AUDIT", "EXPERIMENT"], notes=N(f"""
        SAY: The paper gives its own scheme exactly the same aggregate-verification cost as Verma's. Counting the operations in its own verification equation gives about twice as many scalar multiplications. With the paper's own unit costs at n = 100: {rc['printed_ms']} ms printed against {rc['recount_ms']} ms recounted. Timing on three setups agreed: per-signer ratio {rc['timing_median_lo']} to {rc['timing_median_hi']}, where the printed rows imply 1.00.
        AUDIENCE SHOULD GET: the "as cheap as Verma" claim does not follow from the paper's own algorithm. Today, Part III asks whether a better implementation rescues it.
        TIME: 45 seconds.
        NEXT: the four questions we left open.
    """))
    card(s, 0.6, 1.75, 5.9, 1.65, "Printed (Tables II–III)", ["$(n+2)T_{e} + (n+1)T_{a} + 2nT_{h}$", "identical to Verma's row"],
         tag="PAPER", hsize=16, bsize=18)
    card(s, 0.6, 3.6, 5.9, 1.65, "Counted from the paper's own equation", ["$(2n+2)T_{e} + 3nT_{a} + 3nT_{h}$",
                                                                          "two scalar multiplications per signer, not one"],
         tag="OUR AUDIT", hsize=16, bsize=18)
    rows = [[{"text": "AT n = 100, PAPER'S TABLE IV COSTS"}, {"text": "MS"}],
            ["Printed row", {"text": f"{rc['printed_ms']:.3f}", "align": "r"}],
            ["Recounted", {"text": f"{rc['recount_ms']:.3f}", "align": "r", "bold": True, "color": T.BAD}],
            [{"text": "Factor", "bold": True}, {"text": f"×{rc['factor']:.2f}", "align": "r", "bold": True, "color": T.BAD}]]
    grid(s, 6.9, 1.8, [4.3, 1.5], [0.42, 0.5, 0.5, 0.5], rows, size=17, hdr_size=11.5)
    box(s, 6.9, 4.05, 5.83, 1.2, fill=T.PANEL, line=None, radius=0.1)
    tag_pill(s, 7.1, 4.17, "EXPERIMENT")
    tb(s, 7.1, 4.5, 5.45, 0.7, f"Measured per-signer ratio {rc['timing_median_lo']}–{rc['timing_median_hi']} (3 setups); "
                               "the printed rows imply 1.00.", size=15.5)
    tb(s, 0.6, 5.45, 12.1, 0.6, "$T_{e}$ = scalar multiplication, $T_{a}$ = point addition, $T_{h}$ = hash; unit costs from the paper's Table IV "
                               "(0.112, 0.005, 0.004 ms). Ratio = per-signer aggregate-verification cost, Qiao ÷ Verma.",
       size=13, color=T.MUTED, lsp=0.95)
    takeaway(s, "The paper's own equation costs about twice its printed cost row.")

    # ------------------------------------------------------------------ 6. the four promises
    s = d.slide("Part I · What we promised", "At the interim we left four questions open. All four are answered today.",
                tags=[], title_size=27, notes=N("""
        SAY: These are the four questions from the last slide of the interim, word for word on the left. On the right, today's one-line answer and where it is. The order of the talk differs slightly: the attack comes first, because it is the strongest result.
        THE TAGS: the coloured pills on every slide say whose claim it is. Paper: claimed by Qiao et al. Reproduced: we re-ran it. Implementation: our design choice. Experiment: we measured it. Our audit and our finding: original to this project. Known techniques we only applied are labelled as such on the slide.
        TIME: 40 seconds. Read the four answers only.
        NEXT: Part II, the attack.
    """))
    rows = [("A second look at the attack", "Is the paper's attack the weakest one against Verma's scheme?",
             "No: anyone holding just a public key can forge.", "8–13"),
            ("Faster verification", "Does optimisation change the cost comparison, if both schemes get it?",
             "No: best-effort for both, the gap stays about ×2.4.", "14–16"),
            ("The aggregator in practice", "What happens when one signature in a batch is bad?",
             "The batch fails and hides the culprit; pre-verifying is cheap.", "17–19"),
            ("Open analysis", "Nonce reuse on sensors, and the forward-security claim.",
             "A repeated nonce leaks every key; two claims do not hold.", "20–25")]
    for i, (head, q, a, sl) in enumerate(rows):
        y = 1.65 + i * 1.02
        box(s, 0.6, y, 12.13, 0.92, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.1)
        box(s, 0.6, y, 0.12, 0.92, fill=T.GOOD, line=None, radius=0.05)
        tb(s, 0.95, y + 0.08, 5.3, 0.36, head, size=17, bold=True, font=T.F_MATH)
        tb(s, 0.95, y + 0.47, 5.3, 0.4, q, size=13, color=T.MUTED)
        tb(s, 6.45, y + 0.06, 5.1, 0.8, "✓  " + a, size=16, bold=True, color=T.GOOD, anchor="m", lsp=0.95)
        tb(s, 11.6, y + 0.06, 1.0, 0.8, f"slides {sl}", size=12.5, color=T.MUTED, anchor="m", align="r")
    legend = (("PAPER", "the paper's claim"), ("REPRODUCED", "we re-ran it"), ("IMPLEMENTATION", "our design"),
              ("EXPERIMENT", "we measured it"), ("OUR AUDIT", "our recount"), ("OUR FINDING", "new, ours"))
    widths = [0.16 + 0.092 * len(lab) + 0.08 + text_width(mean, 11.5) for lab, mean in legend]
    gap = (12.13 - sum(widths)) / (len(legend) - 1)
    x = 0.6
    for (lab, mean), wd in zip(legend, widths):
        w = tag_pill(s, x, 5.86, lab)
        tb(s, x + w + 0.08, 5.84, wd - w, 0.3, mean, size=11.5, color=T.MUTED, check=False)
        x += wd + gap
    takeaway(s, "Each open question now has a tested answer.", y=6.3)
