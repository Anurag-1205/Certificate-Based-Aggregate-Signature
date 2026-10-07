"""Part III: the malicious-KGC attack (slides 11-16)."""
import textwrap

import theme as T
from diagrams import attack_diagram, rail
from lib import arrow, box, chip, cue, line, lock, party, pill, tb, takeaway, terminal, text_width


def N(s):
    return textwrap.dedent(s).strip()


def sealed_eq(s, x, y, left, sealed, right="", size=30, h=0.62):
    """One equation line `left [sealed] right` with a red sealed box drawn behind the middle part."""
    f = 1.045
    wl = text_width(left, size) * f if left else 0.0
    ws = text_width(sealed, size) * f
    box(s, x + wl - 0.15, y - 0.02, ws + 0.55, h, fill=T.BAD_T, line=T.BAD, lw=1.75, dash=True, radius=0.08)
    tb(s, x, y, 8.3, h, left + sealed + right, size=size, check=False, anchor="m")
    lock(s, x + wl - 0.1, y - 0.27, 0.26, T.BAD)
    return x + wl - 0.15, ws + 0.55


def build(d):
    # ------------------------------------------------------------------ 11. the puzzle
    s = d.slide("Part III · The malicious-KGC attack", "The puzzle", tags=["PAPER"], notes=N("""
        SAY: Here is what makes this surprising. Take everything the KGC knows and subtract it from the signature. What is left is z_i minus c_i, which equals r_2i plus sk_i times v_i. One number built from two unknowns. A forgery on a new message needs the same kind of number for a new hash value, so it seems the KGC is stuck: it knows neither secret.
        AUDIENCE SHOULD GET: the question. Let it hang for a moment before answering.
        The resolution on the next slides: the KGC never opens the box. It rescales it. It needs sk_i times v_i-prime, and it can obtain that by multiplying a number it holds by a ratio of two hash values it can compute.
        This is the paper's attack in its section IV-B.
        NEXT: three algebra steps.
        IF ASKED 'why does the KGC not need r_2i?' (professor question 1): because the forgery is built from a rescaled copy of the signature's own hidden part. The new nonce is v_i-prime r_2i / v_i. The attacker never has to know it; it only has to produce a commitment and a response that are consistent with each other, and linearity guarantees that.
    """))
    box(s, 0.6, 1.8, 12.13, 1.55, fill=T.BAD_T, line=T.BAD, lw=2.0, radius=0.12)
    tb(s, 0.9, 1.8, 11.5, 1.55, "How can the KGC forge a new signature if it does NOT know $r_{2i}$ or $sk_{i}$?", size=32, bold=True,
       color=T.INK, font=T.F_MATH, anchor="m", lsp=0.95)
    tb(s, 0.6, 3.65, 6, 0.3, "WHAT THE KGC CAN COMPUTE", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    chip(s, 0.6, 4.0, 5.6, 0.7, "$r_{2i}P = R_{i} − R_{1i}$       a point", "plain", size=22, align="l", pad=0.2)
    wl = text_width("$z_{i} − c_{i}$   =", 22)
    chip(s, 0.6, 4.85, 5.6, 0.7, "$z_{i} − c_{i}$   =", "plain", size=22, align="l", pad=0.2)
    chip(s, 0.6 + 0.2 + wl + 0.15, 4.92, 2.9, 0.56, "$r_{2i} + sk_{i}v_{i}$", "bad", size=21, dash=True)
    lock(s, 0.6 + 0.2 + wl + 0.2, 4.9, 0.26, T.BAD)
    tb(s, 7.0, 3.65, 5.7, 0.3, "WHAT A FORGERY ON $m′_{i}$ WOULD NEED", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    chip(s, 7.0, 4.0, 5.73, 1.55, [{"text": "a matching commitment and response", "size": 20, "bold": True, "after": 4},
                                    {"text": "for a new hash value $v′_{i}$", "size": 20, "after": 6},
                                    {"text": "with $sk_{i}$ and $r_{2i}$ still unknown", "size": 17, "color": T.BAD}], "plain", align="l", pad=0.25)
    takeaway(s, "Hint: it does not have to open the sealed number. It only has to rescale it.", color=T.BAD)
    cue(s, "Pause. Answer: rescale, don't open.")

    # ------------------------------------------------------------------ 12. step 1
    s = d.slide("Part III · The attack", "Step 1: strip off the certificate", tags=["PAPER"], notes=N("""
        SAY: The KGC issued R_1i and c_i, so it can subtract them. From the commitment: R_i minus R_1i equals r_2i times P. That is a group element, a point the KGC can compute, although it cannot take its discrete logarithm. From the response: z_i minus c_i equals r_2i plus sk_i times v_i. v_i itself is public: anyone can hash m_i, pk_i, id_i and Delta.
        AUDIENCE SHOULD GET: the left side of the second equation is one number made of two unknowns. We draw it sealed. Nothing here is solved.
        This is step (2a) of the paper's section IV-B; our code does it in attack.py lines 73 to 74 (compute v and invert it).
        NEXT: normalise by v_i.
        IF ASKED 'is r_2i P enough to get r_2i?': no. That would be solving a discrete logarithm.
    """))
    rail(s, {0})
    tb(s, 4.2, 1.8, 8.5, 0.6, "The KGC issued $R_{1i}$ and $c_{i}$, so it can subtract them:", size=21)
    tb(s, 4.2, 2.6, 8.5, 0.7, "$r_{2i}P = R_{i} − R_{1i}$", size=34)
    tb(s, 4.2, 3.28, 8.5, 0.4, "a group element: the KGC can compute it, but cannot take its discrete logarithm", size=15, color=T.MUTED)
    sealed_eq(s, 4.3, 4.45, "", "$r_{2i} + sk_{i}v_{i}$", "    $= z_{i} − c_{i}$", size=34, h=0.72)
    tb(s, 4.2, 5.2, 8.5, 0.4, "two unknowns in one number: it stays sealed", size=15, color=T.BAD)
    tb(s, 4.2, 5.62, 8.5, 0.4, "where $v_{i} = H_{1}(m_{i}‖pk_{i}‖id_{i}‖Δ)$ can be computed by anyone", size=16, color=T.MUTED)
    takeaway(s, "Known: the point $r_{2i}P$. Sealed: the number $r_{2i} + sk_{i}v_{i}$.", color=T.BAD)
    cue(s, "Step 1: subtract the certificate.")

    # ------------------------------------------------------------------ 13. step 2
    s = d.slide("Part III · The attack", "Step 2: normalise by $v_{i}$", tags=["PAPER"], notes=N("""
        SAY: Divide by v_i. v_i is a public hash value, non-zero with overwhelming probability, so it has an inverse mod p; that is where the prime-order group matters. This gives alpha, equal to z_i minus c_i all over v_i, which is r_2i over v_i plus sk_i. And A, equal to R_i minus R_1i all over v_i, which is r_2i over v_i times P.
        AUDIENCE SHOULD GET: alpha is a number the KGC holds. What it is made of, r_2i over v_i plus sk_i, stays sealed; the attacker does not separate the two terms. A is a point it holds. Neither one reveals r_2i or sk_i on its own.
        This is the step that only works because v_i does not depend on r_2i: the division by v_i can be done before anything is fixed. Code: attack.py lines 77 to 78.
        NEXT: choose a new message.
        IF ASKED 'how does alpha help the attacker?' (professor question 2): alpha packages the secret-bearing part so that it can be rescaled. Multiplying alpha by a new hash value v-prime gives exactly r_2i v-prime / v plus sk_i v-prime, which is the secret-bearing part a signature on the new message needs.
    """))
    rail(s, {1})
    tb(s, 4.2, 1.8, 8.5, 0.9, "Divide by $v_{i}$: it is public, and non-zero, so it can be inverted in a prime-order group.", size=19, lsp=0.95)
    sealed_eq(s, 4.3, 3.15, "$α = (z_{i} − c_{i})/v_{i} =$    ", "$r_{2i}/v_{i} + sk_{i}$", "", size=30)
    tb(s, 4.2, 3.85, 8.5, 0.4, "$α$ is a number the KGC holds; what it is made of stays sealed", size=15, color=T.BAD)
    tb(s, 4.2, 4.5, 8.5, 0.7, "$A = (R_{i} − R_{1i})/v_{i} = (r_{2i}/v_{i})P$", size=30)
    tb(s, 4.2, 5.15, 8.5, 0.4, "$A$ is a group element the KGC holds", size=15, color=T.MUTED)
    takeaway(s, "Both are scaled by $1/v_{i}$. Neither reveals $r_{2i}$ or $sk_{i}$ on its own.", color=T.BAD)
    cue(s, "Step 2: normalise by $v_{i}$.")

    # ------------------------------------------------------------------ 14. step 3
    s = d.slide("Part III · The attack", "Step 3: rescale to any message", tags=["PAPER"], notes=N("""
        SAY: Pick any new message m-prime. Compute v-prime, the hash of m-prime with pk_i, id_i and Delta. This is possible immediately, because R-prime is not an input. Then build R-prime as R_1i plus v-prime times A, and z-prime as v-prime times alpha plus c_i. Expand them: R-prime is R_1i plus (v-prime r_2i over v_i) times P, and z-prime is v-prime r_2i over v_i plus c_i plus sk_i v-prime.
        AUDIENCE SHOULD GET: that is exactly the shape of an honest signature, with a fresh nonce equal to v-prime r_2i over v_i. Nobody knows that nonce, including the attacker, and nobody needs to.
        The decisive point is the red box: v-prime can be computed before R-prime exists. Remember it for the repair.
        Code: attack.py lines 81 to 83.
        NEXT: the whole thing on one diagram, and the verifier's verdict.
        IF ASKED 'is the forged signature distinguishable?': no; it has the form of an honest signature, and our tests check that its encoded size matches.
    """))
    rail(s, {2, 3, 4})
    tb(s, 4.2, 1.8, 5.3, 0.6, "$v′_{i} = H_{1}(m′_{i}‖pk_{i}‖id_{i}‖Δ)$", size=26)
    chip(s, 9.55, 1.76, 3.18, 0.72, [{"text": "computable now:", "size": 14, "bold": True, "color": T.BAD},
                                     {"text": "$R′_{i}$ is not an input", "size": 15}], "bad", dash=True)
    tb(s, 4.2, 2.65, 8.5, 0.55, "$R′_{i} = R_{1i} + v′_{i}·A$", size=28)
    tb(s, 4.5, 3.2, 8.2, 0.4, "$= R_{1i} + (v′_{i}r_{2i}/v_{i})P$", size=19, color=T.MUTED)
    tb(s, 4.2, 3.85, 8.5, 0.55, "$z′_{i} = v′_{i}·α + c_{i}$", size=28)
    tb(s, 4.5, 4.4, 8.2, 0.4, "$= v′_{i}r_{2i}/v_{i} + c_{i} + sk_{i}v′_{i}$", size=19, color=T.MUTED)
    tb(s, 4.2, 5.05, 5.0, 0.55, "$δ′_{i} = (R′_{i}, z′_{i})$", size=28, bold=True, color=T.BAD)
    chip(s, 7.7, 5.0, 5.03, 0.62, [{"text": "looks honest: fresh nonce $v′_{i}r_{2i}/v_{i}$", "size": 15}], "plain")
    takeaway(s, "The result has exactly the form of an honest signature.", color=T.BAD)
    cue(s, "New $v′_{i}$ → $R′_{i}$ → $z′_{i}$ → VALID")

    # ------------------------------------------------------------------ 15. the event diagram
    s = d.slide("Part III · The attack, end to end", "The forgery verifies, and the sealed values were never opened", tags=["PAPER"], title_size=28,
                notes=N("""
        SAY: Read it left to right. The sensor sends one valid signature. The malicious KGC knows the master secret, the certificate and that signature, but not sk_i or r_2i. It runs five steps, all of them arithmetic on values it holds: strip the certificate, normalise by v_i, hash the new message, build R-prime, build z-prime. Look at the red sealed boxes: the two unknowns only ever appear inside them, and the later steps multiply those boxes but never open them. The forged signature goes to the verifier, which checks the ordinary verification equation and accepts. It also passes aggregate verification alongside honest signatures.
        AUDIENCE SHOULD GET: this is the central point of the talk. The attacker never decrypts or recovers anything. It transforms the signature algebraically.
        The whole attack in one line: with lambda equal to v-prime over v_i, R-prime is R_1i plus lambda times (R_i minus R_1i), and z-prime is c_i plus lambda times (z_i minus c_i). Why it verifies: z-prime P = (v-prime r_2i / v_i) P + c_i P + sk_i v-prime P, and c_i P = R_1i + H_0 P_TA, so the right side equals R-prime + H_0 P_TA + v-prime pk_i. Full derivation in backup B3.
        This attack is the paper's section IV-B. Our contribution is the reproduction, next.
        NEXT: we ran it.
        IF ASKED 'what exactly did the paper prove here, versus what did you do?' (professor question 6): the paper gives the attack and its algebra; we implemented Verma's scheme and the attack and ran it on two group implementations.
    """))
    attack_diagram(s)
    cue(s, "Say it: it never learns $r_{2i}$ or $sk_{i}$.", y=1.16)

    # ------------------------------------------------------------------ 16. demo 1
    s = d.slide("Part III · Reproduction · Demo 1", "Demo 1: we run the attack on Verma et al.", tags=["REPRODUCED", "EXPERIMENT"], notes=N("""
        DEMO: run `make attack` from the repository, on branch presentation-1-work (tag presentation-1-interim). It takes about a second and prints two targets; today we look at Target 1 only, and come back to Target 2 shortly. Keep a screenshot ready as a fallback.
        POINT AT: (1) the honest signature verifies; (2) the attacker is the KGC and does not know sk_i; (3) the forged signature on the SHUTDOWN message verifies, and it also survives aggregation.
        EVIDENCE BEHIND THE DEMO: 8 of 8 forgeries verify (4 target messages including an empty and a binary one, on 2 group backends); 8 of 8 forged signatures also pass aggregate verification together with an honest one; a test checks that the forging function takes no secret key as an argument. Run `make selftest` first on a new machine.
        AUDIENCE SHOULD GET: this is a reproduction of the paper's attack, not our discovery. What we add is that it executes against an independent implementation on two different curves.
        NEXT: how Qiao et al. repaired the scheme.
        IF ASKED 'what did you reproduce?' (professor question 6): the paper's malicious-KGC forgery against Verma et al.'s scheme (its section IV-B), executed end to end.
    """))
    box(s, 0.6, 1.8, 5.2, 0.7, fill=T.TERM_BG, line=None, radius=0.08)
    tb(s, 0.85, 1.8, 4.8, 0.7, r"[[tmut|\$]] [[ter|make attack]]", size=22, font=T.F_MONO, anchor="m", color="#DDE5EE")
    tb(s, 0.6, 2.75, 5.2, 0.3, "WHAT TO POINT AT", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    pts = ["The honest signature verifies.", "The attacker is the KGC; it does not know $sk_{i}$.",
           "The forged signature verifies, even inside an aggregate."]
    for i, t in enumerate(pts):
        y = 3.05 + i * 0.76
        pill(s, 0.6, y + 0.12, 0.42, 0.42, str(i + 1), T.INK, size=15)
        tb(s, 1.2, y, 4.6, 0.68, t, size=17, anchor="m", lsp=0.95)
    terminal(s, 6.05, 1.8, 6.68, 3.5, [
        "[[tmut|TARGET 1  Verma et al., CB-CAS (IEEE IoT-J 2020)]]",
        "  honest message      : temp=21.4C;line=A;seq=17",
        "  honest sig verifies : [[tgrn|True]]",
        "  [[tmut|attacker is the KGC: holds the master key and]]",
        "  [[tmut|the certificate, has seen ONE signature.]]",
        "  [[tmut|It does NOT know sk_i.]]",
        "  target message      : temp=-40.0C;line=A;seq=17;SHUTDOWN",
        "  forged sig verifies : [[tred|True    <-- FORGERY SUCCEEDED]]",
        "  forgery survives aggregation : [[tred|True]]",
    ], size=13, title=r"\$ make attack")
    for i, t in enumerate(["8 / 8 forgeries verify: 4 messages × 2 backends", "8 / 8 also pass AggVerify with an honest signature",
                           "the forging function takes no secret-key argument"]):
        chip(s, 0.6 + i * 4.1, 5.5, 3.93, 0.62, t, "plain", size=14.5)
    takeaway(s, "Reproduced: one observed signature plus the issued certificate forges messages of the attacker's choice.", color=T.BAD, size=19)
    cue(s, "Terminal fails? → Backup B11", name="PresenterCue_B11")
