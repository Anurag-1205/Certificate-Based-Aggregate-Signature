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
25: N("""
    SAY FIRST: We do not jump from '12.729 ms' to 'the paper is wrong'. We follow a chain, and every step can be checked on its own.
    THE CHAIN MEANS: One, the paper's formula for aggregate verification. Two, a count of the operations in the paper's own printed verification equation, by an instrumented counter that also reproduces Verma's printed rows. Three, the paper's own cost model, its Table IV. Four, the expected time that follows: 12.729 ms printed against 25.324 ms at n = 100. Five, measured time on three configurations; we compare per-signer slopes of the two schemes. Six, the comparison: the printed rows imply a ratio of 1.00, the counts predict 1.99 to 2.14, measurement gives 2.12 to 2.37.
    TAKEAWAY: Equation, count, cost, measurement. The colour bar on each box says whose it is: grey the paper's, magenta our audit, indigo an experiment.
    NEXT: Step two, the count. A tracker in each slide's eyebrow line shows where we are.
    IF ASKED 'could this be a convention difference?': the same convention applied to Verma's equation reproduces Verma's printed row; that is the calibration on the next slide.
"""),
26: N("""
    SAY FIRST: Left, the paper's own verification equation, term by term. Right, what that count is, against what the paper prints.
    THE TABLE MEANS: zP is one scalar multiplication. The sum of T_i is n minus 1 additions. The sum of u_i R_i is n scalar multiplications and n minus 1 additions; this term exists only in the repaired scheme, which is why n is in red. The master-key term is one multiplication. The sum of v_i pk_i is n multiplications. Combining the four terms: 3 additions. Total (2n+2) multiplications and 3n additions; per signer three hashes. Right: Sign has two hashes, not one, because the paper's own step (b) computes both v_i and u_i; single Verify is 4, 3, 3; AggVerify is (2n+2), 3n, 3n; and AggSign is no group operation at all.
    TAKEAWAY: The paper's own equation needs two scalar multiplications per signer, not one. The calibration box is the key: the same counter reproduces Verma's printed rows exactly, so the discrepancy is in the printed row, not in the method.
    On AggSign the paper overstates its own cost: that is in the paper's favour and we report it. Verma's printed Sign omits one point addition; negligible (backup B7).
    NEXT: Is there any convention under which the printed row is right?
    IF ASKED 'why does the paper's formula differ from the implementation?' (professor question 16): we compare against the paper's own printed verification equation (section V-A(6)); the implementation follows it term by term. Its Table III row equals Verma's row, which fits Verma's equation, not this one. How the row arose we do not know; the likeliest reading is that Verma's row was reused.
"""),
27: N("""
    SAY FIRST: The strongest objection is that the verifier could precompute per-signer constants, so we tested it, and we say the result up front.
    THE TABLE MEANS: With every per-signer constant cached, the repaired scheme's single verification drops to 3, 2, 2: exactly the printed Table II row. But under the same caching Verma's single verification drops too, to 2, 2, 1, so the two rows still cannot be identical. And the aggregate: with caching the repaired scheme still needs 2n+1 scalar multiplications, 201 at n = 100, against the printed n+2, which is 102. The hash count matches the printed 2n; the multiplication count does not.
    TAKEAWAY: Caching reproduces the single-signature row, but aggregate verification still needs at least 2n+1 scalar multiplications, against the printed n+2.
    NEXT: What does this mean in milliseconds?
    IF ASKED about the other objections (professor question 14): folding the sum of u_i R_i into one multiplication is possible algebraically but needs the secret certificate c_i, which a verifier does not have. Multi-scalar multiplication is a different cost model that applies to both schemes; Table III is plainly a naive count. Both are in backup B8.
    STATUS: the h_0 caching and folding objections are repository tests; the full-constant caching counts come from presentation/audit/verify_claims.py (both backends) and are not yet a repository test.
"""),
28: N("""
    SAY FIRST: Take the paper's own unit costs and apply them to each count. The printed row gives 12.729 milliseconds, which is exactly the bar in the paper's own Fig. 4. The recount gives 25.324 milliseconds: a factor of 1.99.
    THE CHART MEANS: Three bars. Grey: the printed row. Middle: the recount if the verifier caches every per-signer constant, 24.807, a factor of 1.95. Dark: the recount from the paper's algorithm. Per signer the cost goes from 125 to 251 microseconds under Table IV. These are model values, not measurements.
    TAKEAWAY: This is not a one-off typo. The printed row agrees with Fig. 4, which was therefore computed from Table III, and disagrees with the printed verification equation.
    NEXT: The same arithmetic against the other scheme in the paper's comparison.
    IF ASKED 'does this invalidate the construction?' (professor question 17): no. The attack and repair results are separate from the cost rows; this affects the comparative efficiency claim only.
    IF ASKED 'why does it matter?' (professor question 13): the paper's central comparative argument, secure and as cheap as the insecure scheme, rests on these tables, and its figures are computed from them.
"""),
29: N("""
    SAY FIRST: We recomputed the paper's Figs. 3, 4 and 5 from its tables and Table IV. Every value printed on Figs. 3 and 4 reproduces exactly; Fig. 5 has no printed values, and its two lines end where the formulas say, about 63 and 126 ms at n = 500 (we read the endpoints from the plot rather than extracting its data).
    THE CHART MEANS: Grey: the repaired scheme as printed. The wide pale line: the paper's own row for scheme [6]. The dashed line: the repaired scheme recounted from its algorithm; it lies on top of [6]'s line. At n = 100 that is 25.324 against 25.319 ms: one point addition apart.
    TAKEAWAY: Only from the paper's own numbers: its roughly 49 percent computational advantage over [6], 13.224 against 25.814 ms in Fig. 4, is not supported; its bandwidth advantage, n group elements against 2n (Table VI), is unaffected.
    SAY ALOUD: We have not implemented or verified scheme [6]. We make no claim about [6]'s real speed; its row is the paper's, taken as printed.
    NEXT: Does a clock agree with the count?
    IF ASKED 'is [6]'s AggSign overstated too?': Table VI shows its aggregate keeps 2n group elements, which suggests so, but we have not read [6].
"""),
30: N("""
    SAY FIRST: Counting is one instrument; timing is a second, independent one. We timed aggregate verification of both schemes for n from 50 to 500, fitted straight lines and compared the per-signer slopes.
    THE CHARTS MEAN: Left, one machine, an Intel Xeon on Kaggle: Qiao's slope is 356 microseconds per signer and Verma's 168. The dotted red line is what Qiao would look like if its row equalled Verma's, as Table III says; the measured points are nowhere near it. Right, all 11 recorded runs on three configurations: every ratio lies between 1.99 and 2.48, never near the 1.00 the printed rows require. Diamonds are the ratios predicted from the operation counts.
    TAKEAWAY: Independent measurements are consistent with the higher cost: about twice Verma's, not equal. We compare ratios, because our curve, library and language differ from the paper's; we make no claim about the paper's absolute hardware timings.
    METHOD (backup B9): the laptop's clock ramps about 2x under load, so the CPU is warmed first, workloads are interleaved, medians are taken, and runs with a poor fit are excluded from the median; the medians are the same with or without the exclusion.
    THE P-256 GAP: the simple model predicts 1.99 on P-256 but measurement gives about 2.37. Our audit found why: real hash calls also serialise points, 8 per signer for Qiao and 2 for Verma, which is expensive in OpenSSL; pricing them predicts about 2.37 (three fresh repeats). An audit result, not yet a repository test; do not call it interpreter overhead.
    LIMITS: three of four machine-and-backend combinations; the Xeon is one sweep; P-256 on one machine.
    NEXT: What we established.
    IF ASKED 'why is aggregate verification slower than n Ed25519 checks?': our aggregate verification makes about five ctypes calls per signer from Python; Ed25519 is one native call. Aggregation buys bandwidth, not verifier CPU.
"""),
}

# 20-minute route: KEEP = give it its full time; QUICK = one or two sentences; SKIP = cover in one spoken sentence on the neighbouring slide
ROUTE = {
1: "KEEP (30 s).", 2: "KEEP, quick (45 s): name the four parties and the five phases.",
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
23: "QUICK (30 s): two backends, 221 tests, identical counts.", 24: "QUICK (30 s): the identical rows and the question.",
25: "QUICK (30 s): the chain, once.", 26: "KEEP (1 min): the table and the calibration box.",
27: "QUICK (30 s): caching explains the single row, not the aggregate row.", 28: "KEEP (45 s): the n = 100 bars.",
29: "QUICK (45 s): the [6] caveat must still be said aloud.", 30: "KEEP (1 min): both charts.",
31: "KEEP (45 s): three things to remember, then stop.",
}

FALLBACK = {
16: "FALLBACK: terminal fails, the command errors or it is slow: open Backup B11 (captured output) and say 'here is the output from my earlier run'. The slide's own panel shows the same lines.",
20: "FALLBACK: as for Demo 1: Backup B11 shows Target 2 beside Target 1.",
}


def apply(prs):
    for i, sl in enumerate(prs.slides, 1):
        if i > 31:
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
