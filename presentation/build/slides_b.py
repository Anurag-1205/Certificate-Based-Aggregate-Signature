"""Part II: the existing scheme (slides 6-10)."""
import textwrap

import theme as T
from diagrams import protocol
from lib import PARTY, arrow, box, chip, cue, line, lock, party, pill, tb, takeaway, text_width


def N(s):
    return textwrap.dedent(s).strip()


def eq(s, x, y, w, markup, size=24, color=T.INK, h=0.5, align="l"):
    return tb(s, x, y, w, h, markup, size=size, color=color, align=align, check=True)


def build(d):
    # ------------------------------------------------------------------ 6. protocol overview (generic)
    s = d.slide("Part II · Any CBAS scheme", "Six algorithms, four parties", tags=["PAPER"], notes=N("""
        SAY: Here is the same system as an event diagram. Time runs left to right; each row is a party. Setup runs at the KGC and produces public parameters and a master secret. Each sensor runs KeyGen, then sends its public key to the KGC, which runs CertGen and returns a certificate. Sensors sign their readings with Sign. The aggregator runs AggSign on the n signatures. The cloud runs AggVerify and gets 1 or 0.
        AUDIENCE SHOULD GET: which party generates each object. The padlocks mark secrets. Grey dashed items are steps the paper does not specify: how the certificate reaches the sensor, and how the verifier obtains each signer's public key. We show them as abstracted rather than inventing a protocol.
        The paper calls AggVerify 'Very' in its sections IV and V; it is the same algorithm.
        NEXT: a first concrete scheme: Verma et al.'s.
        IF ASKED 'why is Cert_i private?': the paper says the certificate is part of the user's private information, used together with the secret key (section III).
    """))
    protocol(s, concrete=False)

    # ------------------------------------------------------------------ 7. Verma I: keys and certificate
    s = d.slide("Part II · Verma et al., as described by Qiao et al. (1/3)", "Verma et al.: every sensor gets a certificate from the KGC", tags=["PAPER"], notes=N("""
        SAY: Notation first, only what we need: P generates a group G of prime order p; aP means P added to itself a times; H0 hashes strings into integers mod p. The sensor picks a random s_i, sets its secret key sk_i = s_i and publishes pk_i = s_i times P. The KGC has a master secret s with public key P_TA. For each sensor it picks a random r_1i, forms R_1i = r_1i P, and computes c_i = r_1i + s times H0 of id_i and pk_i. The certificate is the pair (R_1i, c_i).
        AUDIENCE SHOULD GET: two facts. The certificate c_i is known to the KGC because the KGC computed it. The secret key sk_i is known only to the sensor.
        The check c_i P = R_1i + H0(id_i || pk_i) P_TA lets anyone verify a certificate using only public values.
        This is Verma et al.'s scheme as Qiao et al. review it in their section IV-A; our code follows that description (verma.py). We did not cross-check Verma's original paper.
        NEXT: how a sensor signs.
        IF ASKED 'why two random values r_1i and r_2i later?': r_1i belongs to the certificate (chosen by the KGC); r_2i is chosen by the sensor afresh for every signature.
    """))
    box(s, 0.6, 1.65, 12.13, 0.55, fill=T.PANEL, line=None, radius=0.06,
        text="$P$ generates a prime-order group $G$  ·  $aP$ is $P$ added to itself $a$ times  ·  $H_{0}$ hashes into $Z^{*}_{p}$  ·  $id_{i}$ is the sensor's identity",
        size=15, align="l", pad=0.2)
    party(s, "sen", 0.6, 2.4, 5.0, 2.85, lw=1.75)
    tb(s, 0.85, 2.5, 4.5, 0.4, "Sensor $i$ · KeyGen", size=19, bold=True, color=T.SEN)
    tb(s, 0.85, 3.0, 4.5, 0.5, "$sk_{i} = s_{i}$", size=26)
    chip(s, 3.1, 3.08, 2.3, 0.38, "secret, stays here", "sen", size=13, dash=True, align="l", pad=0.34)
    lock(s, 3.17, 3.13, 0.26, T.SEN)
    tb(s, 0.85, 3.65, 4.5, 0.5, "$pk_{i} = s_{i}P$", size=26)
    tb(s, 3.1, 3.72, 2.3, 0.4, "public", size=14, color=T.MUTED)
    tb(s, 0.85, 4.35, 4.5, 0.6, "$s_{i}$ is random in $Z^{*}_{p}$", size=15, color=T.MUTED)
    party(s, "kgc", 7.45, 2.4, 5.28, 2.85, lw=1.75)
    tb(s, 7.7, 2.5, 4.8, 0.4, "KGC · Setup, then CertGen", size=19, bold=True, color=T.KGC)
    tb(s, 7.7, 2.98, 4.8, 0.4, "$P^{k}_{TA} = sP$     master secret $s^{k}_{TA} = s$", size=17, color=T.INK)
    tb(s, 7.7, 3.52, 4.8, 0.4, "$R_{1i} = r_{1i}P$", size=21)
    tb(s, 7.7, 3.98, 4.9, 0.45, "$c_{i} = r_{1i} + s^{k}_{TA}·H_{0}(id_{i}‖pk_{i})$", size=21)
    tb(s, 7.7, 4.5, 4.8, 0.45, "$Cert_{i} = (R_{1i}, c_{i})$", size=21, color=T.KGC, bold=True)
    arrow(s, [(5.6, 3.3), (7.45, 3.3)], T.SEN, lw=2.0)
    tb(s, 5.65, 2.95, 1.75, 0.3, "$pk_{i}$", size=16, color=T.SEN, bold=True, align="c")
    arrow(s, [(7.45, 4.4), (5.6, 4.4)], T.KGC, lw=2.0)
    tb(s, 5.65, 4.05, 1.75, 0.3, "$Cert_{i}$", size=16, color=T.KGC, bold=True, align="c")
    box(s, 0.6, 5.4, 12.13, 0.7, fill=T.WHITE, line=T.RULE, lw=1.25, radius=0.08,
        text="Anyone can check a certificate against public values:   $c_{i}P = R_{1i} + H_{0}(id_{i}‖pk_{i})·P^{k}_{TA}$",
        size=19, align="c")
    takeaway(s, "The KGC knows $Cert_{i}$ because it made it. Only the sensor knows $sk_{i}$.")

    # ------------------------------------------------------------------ 8. Verma II: sign
    s = d.slide("Part II · Verma et al., as described by Qiao et al. (2/3)", "Signing mixes a fresh nonce, the certificate and the secret key", tags=["PAPER"], notes=N("""
        SAY: To sign a reading m_i the sensor picks a fresh random r_2i and forms R_i = R_1i + r_2i P, a commitment to its randomness that also carries the certificate point. It hashes the message with its public key, its identity and the state information Delta, giving v_i. The response is z_i = r_2i + c_i + sk_i times v_i. The signature is the pair (R_i, z_i).
        AUDIENCE SHOULD GET: z_i is a sum of three terms: a fresh nonce only the sensor knows, the certificate which the KGC also knows, and the secret key scaled by a hash that anyone can compute.
        Look at the bottom: the hash v_i takes m_i, pk_i, id_i and Delta. It does not take R_i, and it does not depend on r_2i. Hold that thought; the whole attack follows from it.
        Delta is public state information; the paper does not say more, and our code uses an epoch label.
        NEXT: how verification works, and why this design was attractive.
        IF ASKED 'what is Delta?': public state information published with the parameters. The paper leaves it open; if it changes per epoch it also separates epochs, which a test of ours confirms.
    """))
    eq(s, 0.6, 1.85, 6.5, "$R_{i} = R_{1i} + r_{2i}P$", size=26)
    eq(s, 0.6, 2.5, 7.4, "$v_{i} = H_{1}(m_{i}‖pk_{i}‖id_{i}‖Δ)$", size=26)
    eq(s, 0.6, 3.15, 7.4, "$z_{i} = [[blu|r_{2i}]] + [[vio|c_{i}]] + [[blu|sk_{i}v_{i}]]$", size=28)
    eq(s, 0.6, 3.8, 6.5, "$δ_{i} = (R_{i}, z_{i})$", size=26, color=T.INK)
    tb(s, 8.4, 1.82, 4.3, 0.3, "WHO KNOWS EACH TERM OF $z_{i}$", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    chip(s, 8.4, 2.2, 4.33, 0.62, [{"text": "$r_{2i}$   fresh nonce", "size": 16},
                                   {"text": "sensor only", "size": 12.5, "color": T.MUTED}], "sen", dash=True, align="l", pad=0.2)
    chip(s, 8.4, 3.0, 4.33, 0.62, [{"text": "$c_{i}$   certificate", "size": 16},
                                   {"text": "the KGC knows it too", "size": 12.5, "color": T.MUTED}], "kgc", align="l", pad=0.2)
    chip(s, 8.4, 3.8, 4.33, 0.62, [{"text": "$sk_{i}·v_{i}$   secret key × hash", "size": 16},
                                   {"text": "$sk_{i}$ sensor only; $v_{i}$ anyone", "size": 12.5, "color": T.MUTED}], "sen", align="l", pad=0.2)
    box(s, 0.6, 4.7, 12.13, 1.4, fill=T.PANEL, line=None, radius=0.1)
    tb(s, 0.85, 4.78, 5, 0.3, "WHAT GOES INTO THE HASH $v_{i}$", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    xs = 0.85
    for t in ("$m_{i}$", "$pk_{i}$", "$id_{i}$", "$Δ$"):
        chip(s, xs, 5.15, 1.15, 0.5, t, "plain", size=17)
        xs += 1.3
    arrow(s, [(xs - 0.1, 5.4), (xs + 0.4, 5.4)], T.INK, lw=2.0)
    box(s, xs + 0.4, 5.15, 0.9, 0.5, fill=T.WHITE, line=T.INK, lw=1.5, radius=0.06, text="$H_{1}$", size=18, bold=True)
    chip(s, 7.45, 5.15, 2.85, 0.5, "$R_{i}$, $r_{2i}$ are not inputs", "bad", size=15, bold=True, dash=True)
    takeaway(s, "$v_{i}$ never sees $R_{i}$ or $r_{2i}$.", color=T.BAD)

    # ------------------------------------------------------------------ 9. Verma III: verify
    s = d.slide("Part II · Verma et al., as described by Qiao et al. (3/3)", "Verification, and the appeal of a constant-size aggregate", tags=["PAPER"], notes=N("""
        SAY: The aggregator just adds up: R is the sum of the R_i and z is the sum of the z_i. The aggregate is one point and one scalar, whatever n is; that is the scheme's selling point, 'compact aggregation'. The verifier recomputes h_0 and v_i for every signer and checks one equation: zP equals R plus the sum of the h_0 times the KGC public key plus the sum of v_i times pk_i.
        AUDIENCE SHOULD GET: why this was attractive, and the trade-off the authors made. The paper says it directly: to obtain an aggregate of fixed length, Verma et al. remove the random value from the hash, and because of that the construction is insecure.
        Why does it verify? For one signer, z_i P = r_2i P + c_i P + sk_i v_i P, and c_i P = R_1i + h_0 P_TA, so z_i P = R_i + h_0 P_TA + v_i pk_i. Summing over signers gives the verification equation. The full derivation is in backup B4.
        NEXT: now the attacker.
        IF ASKED 'is the aggregate really constant size?': yes for Verma: one group element and one scalar (paper Table VI; our test checks it). Qiao's repaired scheme gives that up: its aggregate carries all n commitments T_i.
    """))
    tb(s, 0.6, 1.8, 6, 0.3, "AGGREGATION", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    xs = 0.6
    for i, lab in enumerate(["$R_{1}, z_{1}$", "$R_{2}, z_{2}$", "⋯", "$R_{n}, z_{n}$"]):
        if lab == "⋯":
            tb(s, xs, 2.18, 0.6, 0.5, "⋯", size=20, color=T.MUTED, align="c", check=False)
            xs += 0.7
            continue
        party(s, "sen", xs, 2.15, 1.6, 0.5, text=lab, size=16)
        xs += 1.72
    arrow(s, [(xs, 2.4), (xs + 0.55, 2.4)], T.AGG, lw=2.25)
    chip(s, xs + 0.55, 2.1, 3.7, 0.6, "$R = ΣR_{i}$,   $z = Σz_{i}$,   $δ = (R, z)$", "agg", size=18)
    tb(s, 0.6, 2.8, 12, 0.35, "one point and one scalar, for any number of signers (paper Table VI)", size=15, color=T.MUTED)
    box(s, 0.6, 3.35, 12.13, 1.2, fill=T.WHITE, line=T.VER, lw=1.75, radius=0.1)
    tb(s, 0.85, 3.42, 11.6, 0.3, "AGGVERIFY (CALLED “VERY” IN THE PAPER'S SECTIONS IV–V)", size=11.5, color=T.VER, bold=True, spc=100, check=False)
    tb(s, 0.85, 3.75, 11.6, 0.55, "accept iff   $zP = R + (Σh^{i}_{0})·P^{k}_{TA} + Σv_{i}·pk_{i}$", size=26)
    tb(s, 0.6, 4.65, 12, 0.35, "with $h^{i}_{0} = H_{0}(id_{i}‖pk_{i})$ and $v_{i} = H_{1}(m_{i}‖pk_{i}‖id_{i}‖Δ)$ recomputed for every signer", size=16, color=T.MUTED)
    box(s, 0.6, 5.15, 12.13, 0.95, fill=T.PANEL, line=None, radius=0.1)
    tb(s, 0.85, 5.2, 11.6, 0.9,
       "“… to obtain an aggregate signature with the fixed length, Verma et al. remove the random value selected by the signature algorithm from the calculation of hash function. However, due to this reason, the above construction is insecure.”   — Qiao et al., §V-D",
       size=14.5, color=T.INK, anchor="m", font=T.F_MATH)
    takeaway(s, "The compact aggregate comes from keeping $R_{i}$ out of the hash.")

    # ------------------------------------------------------------------ 10. what the KGC knows
    s = d.slide("Part III · The malicious-KGC attack", "The attacker: a KGC that has gone bad", tags=["PAPER"], notes=N("""
        SAY: This is the paper's adversary F2, the malicious KGC. It holds the master secret, so it knows every certificate; it issued them. It sees one valid signature from the sensor it targets: in the paper's game it can request signatures on messages. What it does not know is the two secrets inside z_i: the sensor's secret key sk_i and this signature's nonce r_2i. Its goal is a valid signature on a new message for the same identity.
        AUDIENCE SHOULD GET: exactly what is known and what is not. Everything on the violet card is available to the attacker; the two red sealed values are not.
        The attack needs one observed signature per victim sensor.
        This is the threat certificate-based cryptography exists to stop: signing is supposed to need both sk_i and the certificate.
        NEXT: the puzzle.
        IF ASKED 'does it need the master secret or only the certificate?' (professor question): the attack uses the certificate (R_1i, c_i) the KGC issued, plus one signature. The master secret is how the KGC has the certificate.
    """))
    party(s, "sen", 0.6, 1.8, 3.1, 3.9, lw=1.75)
    tb(s, 0.8, 1.9, 2.8, 0.6, [{"text": "Legitimate sensor", "bold": True, "size": 18, "color": T.SEN},
                                {"text": "$id_{i}$", "size": 14, "color": T.MUTED}], check=False)
    tb(s, 0.8, 2.7, 2.8, 0.9, "signs a reading $m_{i}$", size=17)
    chip(s, 0.8, 3.45, 2.7, 0.75, [{"text": "valid signature", "size": 13.5, "color": T.MUTED},
                                    {"text": "$δ_{i} = (R_{i}, z_{i})$", "size": 18}], "sen")
    tb(s, 0.8, 4.4, 2.8, 1.1, "The KGC sees this one signature.", size=15, color=T.MUTED)
    arrow(s, [(3.7, 3.82), (4.1, 3.82)], T.INK, lw=2.25)
    party(s, "kgc", 4.1, 1.8, 4.3, 3.9, lw=1.75)
    tb(s, 4.3, 1.9, 3.9, 0.35, "THE KGC KNOWS", size=13, color=T.KGC, bold=True, spc=110, check=False)
    tb(s, 4.3, 2.35, 3.95, 3.3, [
        {"text": "✓  master secret $s^{k}_{TA} = s$", "after": 9},
        {"text": "✓  the certificate it issued: $R_{1i}$, $c_{i}$", "after": 9},
        {"text": "✓  public: $id_{i}$, $pk_{i}$, $Δ$, $P^{k}_{TA}$", "after": 9},
        {"text": "✓  one valid pair: $m_{i}$ and $(R_{i}, z_{i})$"}], size=17)
    party(s, "bad", 8.7, 1.8, 4.03, 3.9, lw=2.0)
    tb(s, 8.9, 1.9, 3.7, 0.35, "THE KGC DOES NOT KNOW", size=13, color=T.BAD, bold=True, spc=110, check=False)
    chip(s, 8.9, 2.45, 3.63, 0.75, [{"text": "$sk_{i}$", "size": 22}, {"text": "the sensor's secret key", "size": 13, "color": T.MUTED}],
         "bad", dash=True, align="l", pad=0.62)
    lock(s, 9.05, 2.7, 0.36, T.BAD)
    chip(s, 8.9, 3.4, 3.63, 0.75, [{"text": "$r_{2i}$", "size": 22}, {"text": "this signature's nonce", "size": 13, "color": T.MUTED}],
         "bad", dash=True, align="l", pad=0.62)
    lock(s, 9.05, 3.65, 0.36, T.BAD)
    tb(s, 8.9, 4.4, 3.65, 1.2, "Goal: a valid $δ′_{i}$ on a new message $m′_{i}$, for the same identity $id_{i}$.", size=16, bold=True, color=T.BAD)
    takeaway(s, "The KGC holds everything except the two secrets inside $z_{i}$.", color=T.BAD)
    cue(s, "KGC does NOT know $sk_{i}$ or $r_{2i}$.")
