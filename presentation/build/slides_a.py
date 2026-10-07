"""Part I: motivation (slides 1-5)."""
import textwrap

import theme as T
from lib import (arrow, box, chip, grid, image, line, lock, party, pill, tb, takeaway, terminal)


def N(s):
    return textwrap.dedent(s).strip()


def build(d):
    # ------------------------------------------------------------------ 1. title
    s = d.dark(notes=N("""
        SAY: We investigated one IEEE paper end to end: we ran its attack, tested its repair, and recomputed its performance numbers. Two of the results you will see are the paper's own, reproduced. One is a discrepancy the paper does not mention.
        AUDIENCE SHOULD GET: this is an investigation with a question, not a paper summary.
                NEXT: start with where this scheme is meant to run.
        IF ASKED 'what is your contribution?': the attack and the repair are the paper's; what we add is the causal ablation, the cost audit and its independent timing check (slide 31 has the full list).
    """))
    tb(s, 0.8, 0.62, 9, 0.3, "MTECH INTERIM RESEARCH PRESENTATION", size=13, color="#9FB3C8", bold=True, spc=140, check=False)
    tb(s, 0.8, 1.2, 9.0, 2.7, ["An Efficient Certificate-Based", "Aggregate Signature Scheme With", "Provable Security for Industrial", "Internet of Things"],
       size=40, color="#FFFFFF", bold=True, font=T.F_MATH, lsp=0.95)
    tb(s, 0.8, 4.05, 9.2, 0.45, "Reproducing an attack, testing its repair, and auditing the cost claims", size=20, color="#C3D0DF", check=False)
    box(s, 0.8, 4.85, 7.6, 1.15, fill="#17283B", line="#2B3F55", lw=1.0, radius=0.1)
    tb(s, 1.05, 4.95, 7.1, 0.25, "PAPER UNDER STUDY", size=11.5, color="#8FA1B3", bold=True, spc=120, check=False)
    tb(s, 1.05, 5.25, 7.1, 0.3, "Zirui Qiao et al.  ·  IEEE Systems Journal, Vol. 17, No. 1, 2023", size=15, color="#FFFFFF", check=False)
    tb(s, 1.05, 5.58, 7.1, 0.3, "DOI: 10.1109/JSYST.2022.3188012", size=13.5, color="#B4C3D4", check=False)
    tb(s, 0.8, 6.4, 11.8, 0.34, "Anurag Kaushal (2025202013)  ·  Pranav Vyas (2025202015)  ·  Taufique (2025202007)", size=16,
       color="#DDE5EE", bold=True, check=False)
    tb(s, 0.8, 6.8, 11.8, 0.3, "Research in Information Security  ·  IIIT Hyderabad", size=14, color="#9FB3C8", check=False)
    # the four parties, one colour each: quieter (tinted fill, coloured outline) so the paper title stays the focus
    def mix(c, bg="#14202E", a=0.38):
        c, bg = c.lstrip("#"), bg.lstrip("#")
        return "#" + "".join(f"{round(int(c[i:i + 2], 16) * a + int(bg[i:i + 2], 16) * (1 - a)):02X}" for i in (0, 2, 4))
    ys = (1.75, 2.6, 3.45, 4.3)
    for (name, c), y in zip((("KGC", T.KGC), ("Sensors", T.SEN), ("Aggregator", T.AGG), ("Cloud verifier", T.VER)), ys):
        box(s, 10.5, y, 2.1, 0.52, fill=mix(c), line=c, lw=1.5, radius=0.1, text=name, size=15, bold=True, color="#E4EAF0")
    for y in ys[:-1]:
        arrow(s, [(11.55, y + 0.52), (11.55, y + 0.85)], color="#6F8195", lw=1.5)
    tb(s, 10.35, 4.98, 2.4, 0.5, "the four parties, with one colour each throughout", size=11.5, color="#8FA1B3", align="c")

    # ------------------------------------------------------------------ 2. architecture
    s = d.slide("Part I · The setting", "Can a malicious key authority forge sensor data?", tags=["PAPER"],
                notes=N("""
        SAY: Why is this paper interesting? One question: can a malicious key authority forge sensor data? To see why it matters, here is the system the paper targets. Smart sensors on a production line produce readings. An aggregator in their area collects them. A cloud server analyses them. The KGC, the key generation centre, is a trusted authority that is involved only at the start: it publishes parameters and enrols each sensor once.
        AUDIENCE SHOULD GET: who the four parties are, and the five phases: Setup, KeyGen, CertGen, signing and aggregation, verification. Colours are fixed for the whole talk: violet KGC, blue sensors, amber aggregator, slate cloud.
        Algorithm names are exactly the paper's: Setup, KeyGen, CertGen, Sign, AggSign, AggVerify.
        NOTE: parameters reach users through the cloud server (paper section I-A); we draw no other communication than the paper does.
        NEXT: why does the aggregator combine signatures at all?
        IF ASKED 'what is a KGC?': the key generation centre, called a trusted authority (TA) in the paper. It has a master secret key and issues certificates.
    """))
    tb(s, 0.6, 1.08, 9.0, 0.35, "Sensors sign, an aggregator combines, the cloud verifies", size=17, color=T.MUTED, check=False)
    z = box(s, 0.6, 3.15, 6.95, 3.0, fill=None, line=T.MUTED, lw=1.25, dash=True, radius=0.15)
    tb(s, 0.78, 3.2, 3, 0.3, "factory area", size=13, color=T.MUTED)
    for y, name in ((3.55, "Sensor 1"), (4.35, "Sensor 2"), (5.4, "Sensor n")):
        party(s, "sen", 0.9, y, 2.35, 0.68, text=[{"text": name, "size": 17, "bold": True},
                                                    {"text": "② KeyGen · ④ Sign", "size": 13, "color": T.SEN}])
    tb(s, 0.9, 5.07, 2.35, 0.3, "⋮", size=20, color=T.MUTED, align="c", check=False)
    party(s, "agg", 4.75, 4.2, 2.45, 1.0, text=[{"text": "Aggregator", "size": 18, "bold": True},
                                                   {"text": "④ AggSign", "size": 14, "color": T.AGG}])
    party(s, "kgc", 5.2, 1.65, 2.9, 1.05, text=[{"text": "KGC", "size": 18, "bold": True},
                                                   {"text": "trusted authority", "size": 13, "color": T.MUTED},
                                                   {"text": "① Setup · ③ CertGen", "size": 14, "color": T.KGC}])
    party(s, "ver", 9.55, 4.1, 3.1, 1.25, text=[{"text": "Cloud server", "size": 18, "bold": True},
                                                   {"text": "⑤ AggVerify", "size": 14, "color": T.VER}])
    chip(s, 9.6, 5.62, 1.45, 0.46, "1 · all n valid", "good", size=13, bold=True)
    chip(s, 11.2, 5.62, 1.45, 0.46, "0 · reject", "bad", size=13, bold=True)
    arrow(s, [(11.1, 5.35), (11.1, 5.62)], T.VER)
    # ① parameters
    arrow(s, [(8.1, 2.2), (11.1, 2.2), (11.1, 4.1)], T.KGC)
    tb(s, 8.3, 1.8, 2.7, 0.35, "① public parameters", size=15, color=T.KGC, bold=True)
    tb(s, 8.3, 2.27, 2.7, 0.3, "published through the cloud", size=12.5, color=T.MUTED)
    # ③ certificate and ② public key
    arrow(s, [(5.2, 1.95), (1.9, 1.95), (1.9, 3.55)], T.KGC)
    tb(s, 2.15, 1.58, 2.9, 0.35, "③ certificate → sensor", size=15, color=T.KGC, bold=True)
    arrow(s, [(2.6, 3.55), (2.6, 2.45), (5.2, 2.45)], T.SEN)
    tb(s, 2.8, 2.5, 2.3, 0.35, "② public key → KGC", size=15, color=T.SEN, bold=True)
    # ④ sensors -> aggregator -> cloud
    arrow(s, [(3.25, 3.89), (4.0, 3.89), (4.0, 4.45), (4.75, 4.45)], T.SEN)
    arrow(s, [(3.25, 4.69), (4.75, 4.69)], T.SEN)
    arrow(s, [(3.25, 5.74), (4.0, 5.74), (4.0, 4.95), (4.75, 4.95)], T.SEN)
    tb(s, 3.4, 3.45, 4.0, 0.35, "④ reading $m_{i}$ + signature $δ_{i}$", size=15, color=T.SEN, bold=True)
    arrow(s, [(7.2, 4.7), (9.55, 4.7)], T.AGG, lw=2.25)
    tb(s, 7.62, 3.72, 1.9, 0.85, "④ n readings + 1 aggregate signature", size=14, color=T.AGG, bold=True)
    tb(s, 7.62, 4.78, 1.9, 0.3, "over the Internet", size=12.5, color=T.MUTED)
    # phase strip
    xs = 0.6
    for label, k in (("① Setup · KGC", "kgc"), ("② KeyGen · sensor", "sen"), ("③ CertGen · KGC", "kgc"),
                     ("④ Sign · AggSign", "agg"), ("⑤ AggVerify · cloud", "ver")):
        chip(s, xs, 6.38, 2.3, 0.5, label, k, size=15, bold=True)
        xs += 2.4575

    # ------------------------------------------------------------------ 3. aggregation
    s = d.slide("Part I · Why aggregate?", "One verification decision instead of n", tags=["PAPER"], notes=N("""
        SAY: Each sensor signs its own reading. The aggregator takes the n signatures and combines them into one aggregate signature. The cloud then runs one check and either accepts all n readings or rejects.
        AUDIENCE SHOULD GET: what AggSign and AggVerify are for, informally. The paper's motivation is lower communication overhead, and a single decision at the verifier.
        Do not say aggregation makes verification faster. In our own measurements one aggregate verification is slower than n separate Ed25519 checks; what aggregation buys is fewer signature bytes and one accept/reject decision. Part VI measures the cost of the schemes against each other.
        NEXT: signatures need keys, so who holds them?
        IF ASKED 'how much smaller is the aggregate?': it depends on the scheme. Verma's is one point plus one scalar for any n; Qiao's keeps all n commitments T_i, so only the scalar half compresses (paper Table VI).
    """))
    labels = ["$m_{1}, δ_{1}$", "$m_{2}, δ_{2}$", "⋮", "$m_{n}, δ_{n}$"]
    for i, (lab, y) in enumerate(zip(labels, (1.85, 2.55, 3.2, 3.55))):
        if lab == "⋮":
            tb(s, 0.7, y - 0.05, 2.0, 0.4, "⋮", size=22, color=T.MUTED, align="c", check=False)
            continue
        party(s, "sen", 0.7, y, 2.0, 0.55, text=lab, size=18)
    tb(s, 0.7, 4.2, 2.0, 0.55, "n signatures, one per reading", size=14, color=T.MUTED, align="c")
    for y in (2.12, 2.82, 3.82):
        arrow(s, [(2.7, y), (3.9, 3.05 if y < 3 else 3.35)], T.SEN, lw=1.5)
    party(s, "agg", 3.9, 2.55, 2.1, 1.0, text=[{"text": "AggSign", "size": 20, "bold": True},
                                                {"text": "aggregator", "size": 14, "color": T.MUTED}])
    arrow(s, [(6.0, 3.05), (7.1, 3.05)], T.AGG, lw=2.25)
    chip(s, 7.1, 2.6, 2.7, 0.9, [{"text": "$m_{1}, …, m_{n}$", "size": 18},
                                 {"text": "one aggregate signature $δ$", "size": 15, "color": T.MUTED}], "plain")
    arrow(s, [(9.8, 3.05), (10.55, 3.05)], T.INK, lw=2.25)
    party(s, "ver", 10.55, 2.55, 2.15, 1.0, text=[{"text": "AggVerify", "size": 20, "bold": True},
                                                   {"text": "1 = accept all · 0 = reject", "size": 13, "color": T.MUTED}])
    box(s, 0.7, 4.95, 5.9, 1.1, fill=T.PANEL, line=None, radius=0.1,
        text=[{"text": "Without aggregation", "bold": True, "size": 17, "color": T.MUTED},
              {"text": "n signatures sent · n verification calls", "size": 17}], align="l", pad=0.2)
    box(s, 6.8, 4.95, 5.9, 1.1, fill=T.WHITE, line=T.INK, lw=1.75, radius=0.1,
        text=[{"text": "With aggregation", "bold": True, "size": 17},
              {"text": "one aggregate signature · one verification call", "size": 17}], align="l", pad=0.2)
    takeaway(s, "Aggregation shrinks what is sent and gives one accept-or-reject decision for all n readings.")

    # ------------------------------------------------------------------ 4. who holds the keys
    s = d.slide("Part I · Why certificate-based? · PKI, identity-based: standard background", "Who holds the signing key?", tags=["PAPER"], notes=N("""
        SAY: Three ways to arrange keys. In a public-key infrastructure the user makes a key and a certificate authority certifies it, which brings certificate distribution and revocation overhead. In identity-based signatures the authority computes the whole private key, so it can sign as anyone: that is key escrow. In certificate-based signatures the sensor makes its own key pair, and the KGC issues a certificate; signing needs both.
        AUDIENCE SHOULD GET: the design goal. Neither party alone should be able to sign. A scheme in which the KGC alone can sign has collapsed back into identity-based signatures with escrow.
        The paper frames it as: the certificate is part of the user's private information, used together with the secret key (section III).
        NEXT: what if the KGC itself goes bad?
        IF ASKED 'why certificate-based?' (professor question 10): no key escrow, because the KGC never sees sk_i, and no separate certificate lookup or revocation channel, because the certificate is implicit in signing.
    """))
    cards = [("Public-key infrastructure", "sen", "user's key", "A CA certifies the key", "Certificates must be stored, distributed and revoked", "User alone signs", "plain"),
             ("Identity-based", "kgc", "KGC computes the key", "The KGC derives the whole private key", "The KGC can sign as anyone: key escrow", "KGC alone can sign", "bad"),
             ("Certificate-based", None, None, "The user makes $sk_{i}$ and $pk_{i}$ itself", "The KGC issues $Cert_{i}$; signing needs both", "Neither alone can sign", "good")]
    for i, (name, kind, barlab, l1, l2, verdict, vk) in enumerate(cards):
        x = 0.6 + i * 4.095
        cbc = kind is None
        box(s, x, 1.8, 3.9, 4.25, fill=T.WHITE, line=(T.GOOD if cbc else T.RULE), lw=(3 if cbc else 1.25), radius=0.12)
        tb(s, x + 0.25, 1.95, 3.4, 0.4, name, size=20, bold=True, font=T.F_MATH)
        if cbc:
            party(s, "sen", x + 0.25, 2.6, 1.7, 0.6, text="$sk_{i}$ · user", size=16, bold=True)
            party(s, "kgc", x + 1.95, 2.6, 1.7, 0.6, text="$Cert_{i}$ · KGC", size=16, bold=True)
        else:
            party(s, kind, x + 0.25, 2.6, 3.4, 0.6, text=barlab, size=16, bold=True)
        tb(s, x + 0.25, 3.5, 3.4, 1.6, [{"text": l1, "after": 8}, {"text": l2, "color": T.MUTED}], size=17, bullets=True)
        chip(s, x + 0.25, 5.2, 3.4, 0.55, verdict, vk, size=17, bold=True)
    takeaway(s, "Design goal: the KGC alone must not be able to sign.", color=T.GOOD)

    # ------------------------------------------------------------------ 5. threat + questions
    s = d.slide("Part I · The threat and our questions", "What if the KGC is the attacker?", tags=["PAPER"], notes=N("""
        SAY: The paper motivates the threat with a real incident: an employee at South Africa's Postbank took the master secret key of the data centre and stole 3.2 million dollars. Whoever holds the master key can act for every user. The paper's requirement: a practical CBAS scheme must remain secure even when the KGC is malicious.
        AUDIENCE SHOULD GET: why the malicious-KGC model is not an exotic assumption, and the three questions the rest of the talk answers.
        Q1: can a malicious KGC forge in Verma et al.'s scheme? The paper says yes (its section IV); we run it. Q2: does Qiao et al.'s repair stop that attack, and which change is responsible? Q3: Qiao et al. report the same cost as Verma's scheme; does the algorithm they print agree?
        Point out the five coloured tags at the bottom: every slide says whose claim it shows.
        IF ASKED 'is the Postbank case evidence about CBAS?' (professor question 11): no, it is the paper's example of why a master key can leak; it motivates the threat model.
    """))
    box(s, 0.6, 1.8, 4.5, 4.0, fill=T.BAD_T, line=T.BAD, lw=1.5, radius=0.12)
    tb(s, 0.85, 1.95, 4.0, 0.3, "THE THREAT", size=12.5, color=T.BAD, bold=True, spc=120, check=False)
    tb(s, 0.85, 2.3, 4.0, 1.0, "A KGC that goes bad holds every certificate.", size=22, bold=True, font=T.F_MATH, lsp=0.95)
    tb(s, 0.85, 3.4, 4.0, 2.3, [
        {"text": "Postbank, South Africa: an employee took the data centre's master secret key and stole 3.2 million dollars (cited in the paper, §I-C).", "after": 8},
        {"text": "The paper's requirement: a practical CBAS scheme must stay secure even if the KGC is malicious."}],
       size=16, bullets=True)
    qs = [("Q1", "Can a malicious KGC forge signatures in Verma et al.'s scheme?", "Paper: yes (§IV). We run the attack."),
          ("Q2", "Does Qiao et al.'s repair stop it, and which change is responsible?", "Paper: yes (§V). We test it, and remove one change."),
          ("Q3", "Is the repaired scheme really as cheap as Verma's?", "Paper: identical cost. We recount and measure.")]
    for i, (q, a, b) in enumerate(qs):
        y = 1.8 + i * 1.38
        box(s, 5.4, y, 7.33, 1.2, fill=T.WHITE, line=T.INK, lw=1.5, radius=0.1)
        box(s, 5.4, y, 0.95, 1.2, fill=T.INK, line=None, radius=0.1, text=q, size=26, bold=True, color="#FFFFFF")
        tb(s, 6.55, y + 0.12, 6.05, 0.62, a, size=18, bold=True, lsp=0.95)
        tb(s, 6.55, y + 0.78, 6.05, 0.35, b, size=15, color=T.MUTED)
    legend = [("PAPER", "claim by Qiao et al."), ("REPRODUCED", "we re-ran it"), ("IMPLEMENTATION", "our design choice"),
              ("EXPERIMENT", "we measured it"), ("OUR AUDIT", "our own finding")]
    x = 0.6
    for lab, mean in legend:
        w = 0.16 + 0.092 * len(lab)
        pill(s, x, 6.12, w, 0.28, lab, T.TAGS[lab], size=10.5)
        tb(s, x, 6.45, 2.4, 0.3, mean, size=13, color=T.MUTED)
        x += 2.45
