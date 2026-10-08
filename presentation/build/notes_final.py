"""Final speaker notes: structured blocks for the difficult slides, plus the 20-minute route on every main slide.

Applied after the slides are built (build_deck.py). Slides not listed in NOTES keep the notes written with the slide.
"""
import textwrap


def N(s):
    return textwrap.dedent(s).strip()


NOTES = {
10: N("""
    SAY FIRST: Now the attacker: a malicious KGC. It knows the master secret, so it knows every certificate, including this sensor's, because it issued them. And it has seen one valid signature from this sensor.
    THE KEY POINT: Everything on the violet card, the KGC has. The two red sealed values it does not have: the sensor's secret key sk_i and this signature's nonce r_2i. Its goal is a valid signature on a new message for the same sensor. This is the paper's adversary F2; the attack needs one observed signature per victim.
    TAKEAWAY: The KGC holds everything except the two secrets inside z_i.
    NEXT: So how can it forge at all? That is the puzzle.
    IF ASKED 'does it need the master secret or only the certificate?': the attack uses the certificate (R_1i, c_i) the KGC issued, plus one signature. The master secret is how the KGC has the certificate.
"""),
11: N("""
    SAY FIRST: Read the question aloud, then pause for a few seconds.
    THE EQUATIONS MEAN: Left box, what the KGC can compute. R_i minus R_1i equals r_2i P: a point; getting r_2i out of it would mean taking a discrete logarithm, which is infeasible. And z_i minus c_i equals r_2i plus sk_i v_i: one number made of two unknowns, drawn sealed. Right box: a forgery on a new message needs a matching commitment and response for a new hash value v-prime, with both secrets still unknown.
    TAKEAWAY: It does not have to open the sealed number. It only has to rescale it.
    NEXT: Three small steps, one slide each.
    IF ASKED 'why does the KGC not need r_2i?' (professor question 1): the forged signature uses a new nonce, v-prime r_2i over v_i, which is just a rescaled copy of the old one. The attacker never has to know it; it only has to produce a commitment and a response that are consistent with each other, and linearity guarantees that.
"""),
12: N("""
    SAY FIRST: The KGC issued R_1i and c_i, so it can simply subtract them.
    THE EQUATIONS MEAN: R_i minus R_1i equals r_2i P: a group element, computable but not invertible. z_i minus c_i equals r_2i plus sk_i v_i: one number, two unknowns, so we draw it sealed. v_i itself is public: anyone can hash m_i, pk_i, id_i and Delta.
    TAKEAWAY: Known: the point r_2i P. Sealed: the number r_2i + sk_i v_i. Nothing has been solved.
    NEXT: Divide by v_i.
    IF ASKED 'is r_2i P enough to get r_2i?': no; that would be a discrete logarithm.
    Code: attack.py lines 73 to 74 (this is step 2a of the paper's section IV-B).
"""),
13: N("""
    SAY FIRST: Divide by v_i. It is a public hash value, non-zero with overwhelming probability, so it has an inverse mod p; that is where the prime-order group matters.
    THE EQUATIONS MEAN: alpha is (z_i minus c_i) over v_i, which equals r_2i over v_i plus sk_i. The KGC holds the number alpha but not its two parts, so what it is made of stays sealed. A is (R_i minus R_1i) over v_i, which equals (r_2i over v_i) times P: a point it holds. Neither reveals r_2i or sk_i on its own.
    TAKEAWAY: Both are just scaled by one over v_i. The attacker does not separate the two parts.
    NEXT: Choose a new message.
    IF ASKED 'how does alpha help the attacker?' (professor question 2): alpha packages the secret-bearing part so that it can be rescaled. Multiplying alpha by a new hash value v-prime gives r_2i v-prime / v_i plus sk_i v-prime, exactly the secret-bearing part a signature on the new message needs. It works only because v_i does not depend on r_2i.
    Code: attack.py lines 77 to 78.
"""),
14: N("""
    SAY FIRST: Pick any new message m-prime. Compute v-prime, the hash of m-prime with pk_i, id_i and Delta. That is possible immediately, because R-prime is not an input to the hash.
    THE EQUATIONS MEAN: R-prime is R_1i plus v-prime times A; z-prime is v-prime times alpha plus c_i. Expand them: R-prime is R_1i plus (v-prime r_2i over v_i) times P, and z-prime is v-prime r_2i over v_i plus c_i plus sk_i v-prime. That is exactly the shape of an honest signature, with a new nonce v-prime r_2i over v_i that nobody knows, the attacker included.
    TAKEAWAY: The result has exactly the form of an honest signature. Do not read three equations; point at v-prime, R-prime and z-prime in turn.
    NEXT: Everything on one diagram, and the verifier's verdict.
    IF ASKED 'is the forged signature distinguishable?': no; it has the form of an honest signature, and our tests check that its encoded size matches.
    Code: attack.py lines 81 to 83.
"""),
15: N("""
    SAY FIRST: Left to right. One valid signature goes in. The malicious KGC knows the master secret, the certificate and that signature, but not sk_i or r_2i. It runs five steps, all of them arithmetic on values it holds.
    THE DIAGRAM MEANS: Look only at the two red sealed boxes. They are the only places the two unknowns appear, and the later steps multiply them but never open them. The forged signature goes to the verifier, which checks the ordinary verification equation and accepts. It also passes aggregate verification alongside honest signatures.
    TAKEAWAY: The attacker never learns r_2i or sk_i. It rescales the sealed combination. It never decrypts or recovers anything.
    WHY IT VERIFIES (only if asked): z-prime P equals (v-prime r_2i over v_i) P plus c_i P plus sk_i v-prime P. With c_i P equal to R_1i plus H_0 P_TA this equals R-prime plus H_0 P_TA plus v-prime pk_i. The whole attack in one line: with lambda equal to v-prime over v_i, R-prime is R_1i plus lambda (R_i minus R_1i), and z-prime is c_i plus lambda (z_i minus c_i). Full derivation: backup B3.
    This attack is the paper's section IV-B. Our contribution is the reproduction, next.
    NEXT: We ran it.
    IF ASKED 'what exactly did you reproduce?' (professor question 6): the paper's malicious-KGC forgery against Verma et al.'s scheme, executed end to end on two group implementations.
"""),
18: N("""
    SAY FIRST: Left Verma, right Qiao, one row per change. Look at the middle three rows; the grey rows are context.
    THE EQUATIONS MEAN: Commitment: R_i = R_1i + r_2i P becomes T_i = t_i P. Hash inputs: v_i now includes R_i and T_i, and there is a second hash H_2 giving u_i from the same input. Response: z_i = t_i + c_i u_i + sk_i v_i. In grey: the certificate now binds R_i, the aggregate keeps every T_i, and verification gains the term u_i R_i.
    TAKEAWAY: Several things change. We do not say 'the difference is one line'. For this attack, what matters is that T_i now enters the hashes; the ablation is how we know.
    NEXT: Why does that matter so much?
    IF ASKED 'why two hash functions H_1 and H_2?' (professor question 8): in the paper, the certificate term and the secret-key term carry independent random-oracle coefficients u_i and v_i; its proof forks H_0 for the user adversary and H_1 for the KGC adversary. In our own audit check, a variant with one hash for both coefficients still resisted the KGC rescaling, so we do not claim the separation is needed to block this attack (backup B6).
    IF ASKED 'why is R_i in the new hash?' (professor question 9): the paper says R_i is part of the public key and is hashed so the effect of the certificate cannot be removed by public-key replacement (section V-A). That targets a different attacker; our ablation does not test it.
    Two printed typos in the paper's section V-A are corrected in our code: KeyGen prints pk_i = s_i (we use s_i P) and the certificate check prints R_1i (we use R_i).
"""),
19: N("""
    SAY FIRST: Left, the old scheme. The message goes into the hash and gives v. The randomness r_2i goes into R_i. The two are not coupled through the hash: the red dashed line is the missing edge. So the attacker can pick a message, compute v-prime, and only then build R-prime and z-prime.
    THE PICTURE MEANS: Right, the new scheme. The commitment T_i = t_i P goes into the same hash as the message. Now rescaling needs a new commitment T-prime equal to (v-prime over v_i) times T_i, but v-prime is the hash of a string that contains T-prime. T-prime affects v-prime, and v-prime affects T-prime. The old direct route is gone.
    TAKEAWAY: This explains why the reproduced rescaling route no longer applies. It does not prove the scheme secure.
    IF ASKED for the exact statement: the attacker would need a scalar lambda with H_1(m-prime, pk, R, id, lambda T, Delta) equal to lambda times v_i: a search over hash outputs, not algebra (backup B6).
    WORDING (professor questions 3, 4, 5): the paper proves EUF-CMA security under the discrete logarithm assumption in the random-oracle model; we have not audited that proof. The paper states the principle itself in its section V-A: the commitment T_i should be hashed into the core element of the signature, otherwise a malicious KGC can forge from a known signature.
    IF ASKED 'why does T_i prevent the old attack?' (professor question 3): the attack must fix the new commitment before it can compute the new coefficient, but the new commitment is defined in terms of that coefficient. The circularity is the missing route.
    NEXT: We tested it.
"""),
21: N("""
    SAY FIRST: Failing against the repaired scheme does not say which of its changes is responsible. So we built a control: the repaired scheme with exactly one thing removed.
    THE TABLE MEANS: Row A is Verma: the commitment R_i is not hashed. Row B is Qiao: T_i is hashed. Row C is Qiao with T_i dropped from H_1 and H_2, and nothing else touched. The ablated variant imports the real Setup, KeyGen, CertGen, AggSign and verification equation from the repaired code; R_i is still hashed into H_0, H_1 and H_2; u and v still come from separate hash functions. Only the hash labels are renamed, and one hash input is gone.
    TAKEAWAY: Between B and C, only the T_i binding differs. C is a working scheme: honest signatures verify and other messages are rejected, in all 8 trials.
    This ablation is our design (an implementation choice, tagged); its result is an experiment. The code calls the T_i binding 'Fix #2' in comments; those labels are ours, not the paper's.
    NEXT: The result.
    IF ASKED 'does the ablation remove only T_i?': yes. Same H_0 function object, R_i still in H_1 and H_2, separate u and v; a test checks the last two (test_ablated_variant_still_has_fixes_1_and_3).
"""),
22: N("""
    SAY FIRST: Three cases, same attacker, same strategy, same four target messages on two group backends. A, Verma: the forgery verifies in 8 of 8 trials. B, Qiao: it fails in 8 of 8, with 16 distinct candidates each. C, Qiao with only the T_i binding removed: it verifies again in 8 of 8.
    WHAT IT MEANS: The ablation isolates the T_i binding as the critical difference for blocking the reproduced rescaling attack. It does not show that the other changes are unnecessary (R_i in H_0 targets a different attacker, public-key replacement, which we did not test), nor that the full scheme is secure. 0 of 8 is an observation about this route, not a mathematical impossibility.
    TAKEAWAY: Full repair: attack fails. Remove only T_i: attack succeeds.
    DEMO 3: run `.venv/bin/python -m pytest tests/test_forgery.py -k ablat -vv`. It prints ten test names ending PASSED and '10 passed': eight forgery-restored cases (4 messages x 2 backends) and two checks that the ablated variant is still a working scheme. Use -vv because the project's pytest configuration adds -q.
    FALLBACK: terminal fails or is slow: open Backup B12 (captured output), or just talk to the three cards.
    NEXT: before measuring performance, why trust our implementation?
    IF ASKED 'what does the ablation prove?' (professor question 12): necessity of the T_i binding against this attack, everything else held fixed. Not sufficiency, not security. IF ASKED 'is that original?': yes for the ablation as a causal test; the attack and the repair are the paper's.
"""),
}

# 20-minute route: KEEP = give it its full time; QUICK = one or two sentences; SKIP = cover in one spoken sentence on the neighbouring slide
ROUTE = {
1: "KEEP (30 s).", 2: "KEEP, quick (45 s): name the four parties and the six algorithms in order.",
3: "SKIP: say it while on slide 2 ('the aggregator combines n signatures into one').",
4: "QUICK (30 s): one sentence per column; end on 'the KGC alone must not be able to sign'.",
5: "KEEP (1 min): the threat and the three questions.",
6: "SKIP: slide 2 already shows who does what; say 'grey dashed steps are not specified by the paper' there.",
7: "QUICK (45 s): keys and certificate; only say 'the KGC knows the certificate'.",
8: "KEEP (1 min): this is where v_i not seeing R_i is planted.",
9: "QUICK (30 s): constant-size aggregate; read the paper quote.",
10: "KEEP (45 s).", 11: "KEEP (30 s): the question, then the pause.",
12: "COMBINE verbally with 13 and 14: about 40 s each, equations only.", 13: "COMBINE verbally with 12 and 14: about 40 s.",
14: "COMBINE verbally with 12 and 13: about 40 s.",
15: "KEEP (1 min): the recap diagram.", 16: "KEEP (1 min): Demo 1 live, or show the screenshot (Backup B11).",
17: "SKIP: mention T_i verbally on slide 18.", 18: "QUICK (45 s): only the three middle rows.",
19: "KEEP (1 min 15 s): the key idea.", 20: "QUICK (30 s): show Target 2 as the screenshot (Backup B11).",
21: "QUICK (30 s): say it together with slide 22.", 22: "KEEP (1 min 15 s): the three cards; Demo 3 only if time allows (Backup B12).",
23: "QUICK (30 s): two backends, 221 tests, identical counts.",
24: "KEEP (1 min 15 s): the two cards and the two bars; say 'model values, not measurements' aloud.",
25: "KEEP, quick (45 s): the red extra term; Verma's equation counts to the printed row.",
26: "KEEP (45 s): three things to remember.",
27: "KEEP, quick (30 s): read the four headings, then stop.",
}

FALLBACK = {
16: "FALLBACK: terminal fails, the command errors or it is slow: open Backup B11 (captured output) and say 'here is the output from my earlier run'. The slide's own panel shows the same lines.",
20: "FALLBACK: as for Demo 1: Backup B11 shows Target 2 beside Target 1.",
}


def apply(prs):
    for i, sl in enumerate(prs.slides, 1):
        if i > 27:
            break
        if not sl.has_notes_slide:
            continue
        tf = sl.notes_slide.notes_text_frame
        base = NOTES.get(i, tf.text.strip())
        parts = [base]
        if i in FALLBACK and FALLBACK[i] not in base:
            parts.append(FALLBACK[i])
        if i in ROUTE:
            parts.append("20-MINUTE ROUTE: " + ROUTE[i])
        tf.text = "\n".join(parts)
