# Speaker notes: CBAS final presentation


## Slide 1: Title slide

SAY: At the interim we reproduced this paper's attack, tested its repair and audited its cost claims. Today we go beyond the paper: we test the repaired scheme and the claims around it, and we look for attacks the paper did not consider.
AUDIENCE SHOULD GET: same paper, same team, new questions.
NEXT: what we covered last time and what is new today.
TIME: 20 s on this slide; 0:20 elapsed at the end of it.


## Slide 2: From the interim to today

SAY: The first three slides recap the interim, as asked. Then four new parts, one for each open question we listed at the end of the interim. Two live demos, on slides 10 and 22.
AUDIENCE SHOULD GET: where we are going, and that the new work is most of the talk.
NEXT: the recap.
TIME: 20 s on this slide; 0:40 elapsed at the end of it. Do not read the list; point at the two columns.


## Slide 3: Sensors sign, an aggregator combines, the cloud verifies

Tags: PAPER

SAY: A quick reminder. A KGC enrols each sensor with a certificate; sensors sign readings; an aggregator combines n signatures into one; the cloud checks them all at once. Six algorithms, numbered one to six as at the interim.
THE TWO SCHEMES: Verma et al. sign with z = r_2 + c + sk v, where v hashes the message, public key, identity and Delta, but no commitment. Qiao et al.'s repair signs with z = t + c u + sk v, where u and v hash the message together with the commitments R_i and T_i. Keep that difference in mind: which values go into the hash decides everything in this talk.
NEXT: what that difference does to the paper's attack.
TIME: 30 s on this slide; 1:10 elapsed at the end of it.


## Slide 4: The paper's attack breaks Verma; the Ti binding stops it

Tags: OUR AUDIT, REPRODUCED

SAY: At the interim we ran the paper's attack. A malicious KGC that has seen one signature rescales it into a valid signature on any message: 8 of 8 trials on two curve libraries. Against Qiao's repair the same attack fails, 0 of 8. Then our ablation: Qiao's scheme with only the T_i binding removed lets the attack through again, 8 of 8.
PROVENANCE: the attack and the repair are the paper's (reproduced). The ablation is ours.
NEXT: the cost claim.
Numbers recomputed today on the current code by presentation/audit/verify_claims_final.py.
TIME: 30 s on this slide; 1:40 elapsed at the end of it.


## Slide 5: The repaired scheme costs about twice what the paper prints

Tags: EXPERIMENT, OUR AUDIT, PAPER

SAY: The paper gives its own scheme exactly the same aggregate-verification cost as Verma's. Counting the operations in its own verification equation gives about twice as many scalar multiplications. With the paper's own unit costs at n = 100: 12.729 ms printed against 25.324 ms recounted. Timing on three setups agreed: per-signer ratio 2.12 to 2.37, where the printed rows imply 1.00.
AUDIENCE SHOULD GET: the "as cheap as Verma" claim does not follow from the paper's own algorithm. Today, Part III asks whether a better implementation rescues it.
NEXT: the four questions we left open.
TIME: 30 s on this slide; 2:10 elapsed at the end of it.


## Slide 6: At the interim we left four questions open. All four are answered today.

SAY: These are the four questions from the last slide of the interim, word for word on the left. On the right, today's one-line answer and where it is. The order of the talk differs slightly: the attack comes first, because it is the strongest result.
THE TAGS: the coloured pills on every slide say whose claim it is. Paper: claimed by Qiao et al. Reproduced: we re-ran it. Implementation: our design choice. Experiment: we measured it. Our audit and our finding: original to this project.
NEXT: Part II, the attack.
TIME: 25 s on this slide; 2:35 elapsed at the end of it. Read the four answers only.


## Slide 7: Is the paper's attack the weakest one against Verma's scheme?

Tags: OUR FINDING, PAPER

SAY: The paper's attacker is strong: a malicious KGC with the master key and the certificate it issued, and it must first see one signature from the victim. We asked whether a much weaker attacker can do the same. The answer is yes: someone who holds nothing but the victim's public key, and has seen no signature at all.
TERMS: Goldwasser, Micali and Rivest (1988) classify attacks by what the attacker is given, and forgeries by what it produces. A key-only attack sees only public keys. A universal forgery is valid on any message the attacker likes. Key-only plus universal is the strongest combination.
NEXT: how it works, in one equation.
TIME: 30 s on this slide; 3:05 elapsed at the end of it.


## Slide 8: Verma's commitment Ri is in no hash, so we can solve for it

Tags: OUR FINDING

SAY: Verma's verification equation is z P = R + h_0 P_TA + v pk. Look at the two hash values: h_0 hashes the identity and public key; v hashes the message, public key, identity and Delta. Neither contains R, and R sits in the equation with coefficient one. R also travels inside the signature, so the signer, or a forger, chooses it.
THE THREE STEPS: pick any z, for example zero. Compute h_0 and v from public data. Set R = z P minus h_0 P_TA minus v pk. The pair (R, z) satisfies the equation by construction. Point arithmetic only: no discrete logarithm, no secret, no signature observed.
WHY IT IS FAMILIAR: Schnorr signatures hash the commitment together with the message, c = H(R, m), exactly so that R cannot be chosen after the challenge is known. With c = H(m) a Schnorr signature is forgeable the same way.
IF ASKED 'is R not fixed by the certificate?': no; in Verma's scheme R_i = R_1i + r_2i P is part of each signature, fresh every time. The verifier has no fixed value to compare it with.
Code: src/cbas/keyonly_attack.py, forge_verma_keyonly (about ten lines).
TIME: 60 s on this slide; 4:05 elapsed at the end of it. This is the key slide of Part II.


## Slide 9: This contradicts the paper's Table II

Tags: OUR FINDING, PAPER

SAY: The paper's Table II rates Verma's scheme, reference 11, as secure against F_1, the malicious user, and insecure against F_2, the malicious KGC. The F_2 entry is the paper's own attack, which we reproduced. The F_1 entry cannot be right: our forger has strictly less power than F_1, since F_1 may also ask for keys and signatures. Whatever a key-only forger can do, F_1 can do too.
RESULT: 8 of 8 key-only forgeries verify (4 messages, 2 libraries), and 8 of 8 also pass aggregate verification next to an honest signature.
IF ASKED 'is this in the literature already?': the underlying principle, hashing the commitment, is textbook. We have not found this attack on Verma's scheme stated anywhere, but we did not do an exhaustive literature search, so we say 'not discussed in the paper', not 'new to the field'.
NEXT: we run it.
TIME: 30 s on this slide; 4:35 elapsed at the end of it.


## Slide 10: Demo 1: a forgery from a public key alone

Tags: EXPERIMENT

RUN: make attack, and scroll to TARGET 3. About 2 seconds.
POINT AT: (1) attacker capability: it sees P_TA and this sensor's public key, nothing else. (2) forged sig verifies: True, marked UNIVERSAL FORGERY. (3) the same attack on the repaired scheme: False.
SAY: The sensor's key is a real, honestly enrolled key; the forger never touches its secret key, certificate or any signature.
FALLBACK: if the terminal fails or is slow, this slide already shows the captured output of the same command. Say 'this is the output of the same command, captured earlier'. Backup B13 has it larger.
NEXT: why the repaired scheme survives.
TIME: 75 s on this slide; 5:50 elapsed at the end of it.


## Slide 11: Why the repaired scheme resists it

Tags: EXPERIMENT, PAPER

SAY: In the repaired scheme R appears in all three hashes: h_0, u and v are hashes of R, and also of T. To solve the equation for R, the attacker needs h_0, u and v first; to compute them it needs R first. So the only route is a fixed-point search: guess R, compute the hashes, solve for the R the equation would need, compare. We ran that search: each round gives a new candidate, 16 distinct candidates in every trial, and 0 of 8 forgeries.
WORDING: this shows that this attack does not apply. It is not a proof of security; the paper's proof covers that, and we have not audited it.
NEXT: two changes are made at once. Which one does the work?
TIME: 30 s on this slide; 6:20 elapsed at the end of it.


## Slide 12: Each binding closes its own door, and only its own

Tags: EXPERIMENT, OUR FINDING

SAY: The repair changes two things at once: it hashes T and it hashes R. To see which does what, we remove one at a time, keeping everything else, and attack each variant both ways: solving for T and solving for R.
THE CELLS: Top left, the real scheme: both attempts fail. Bottom left, T not hashed (the interim's ablation): solving for T forges, 8 of 8, with the victim's real certificate; solving for R still fails. Top right, R not hashed: solving for R forges, 8 of 8; solving for T still fails. Bottom right, Verma: R free.
THE CAVEAT, important: the two open doors are not the same kind of attack. T travels in every signature, so the bottom-left forgery is a true key-only forgery. In Qiao's scheme R belongs to the certificate, so the top-right forgery only verifies if the verifier accepts an attacker-chosen R: 8 of 8 fail with the real R. That is public-key replacement, the power the paper gives F_1, and it is exactly why the paper says it hashes R. So that cell confirms the paper's reason, with code.
IF ASKED 'so is R in the hash really needed?': against an attacker who can replace R, yes; this cell shows it. Against a verifier that pins each sensor's R, the T binding alone blocks both attempts here.
NEXT: the general lesson.
TIME: 60 s on this slide; 7:20 elapsed at the end of it.


## Slide 13: A commitment outside every hash is a free variable

Tags: OUR FINDING, PAPER

SAY: One rule explains every cell. If a value appears in the verification equation but in no hash, and its coefficient is known, an attacker can choose everything else and solve for it. Verma leaves R free. Removing the T binding leaves T free. Removing the R binding leaves R free, for an attacker who may replace it.
THE PAPER: states this rule for T only, in section V-A, in the context of the one attack it found. We show the same mechanism for either commitment, independently.
NEXT: Part III, cost.
TIME: 20 s on this slide; 7:40 elapsed at the end of it.


## Slide 14: Would a real implementation close the gap?

Tags: EXPERIMENT, IMPLEMENTATION

SAY: A fair objection to the interim: nobody verifies term by term. A real verifier would batch the work. So we optimised verification twice, and gave both schemes exactly the same treatment.
THE TWO OPTIMISATIONS: one, multi-scalar multiplication: the whole verification equation evaluated in a single native call, OpenSSL's EC_POINTs_mul, instead of one call per term. Two, a prepared sensor roster: an industrial fleet is fixed, so each sensor's encodings and its certificate hash h_0 never change and can be computed once.
THE MISTAKE WE CAUGHT: our first measurement gave the roster to Qiao's scheme but not to Verma's, and showed a ratio of 1.63, as if optimising closed the gap. That was unequal treatment. With both schemes optimised the same way, the ratio is about 3.
NEXT: the numbers.
TIME: 30 s on this slide; 8:10 elapsed at the end of it.


## Slide 15: Optimising both schemes widens the gap: ×2.4 → ×3.0

Tags: OUR AUDIT, EXPERIMENT

SAY: Per-signer cost of aggregate verification on P-256, both schemes, three stages. As specified: 169 against 71 microseconds, ratio 2.37. Fully optimised: 68 against 22, ratio 3.05. Over four runs the optimised ratio was 2.95 to 3.07.
WHY IT GROWS: once everything is one multi-scalar multiplication, cost follows the number of terms. Qiao's equation has 3n + 1 terms, Verma's n + 2: at n = 500, 1501 against 502, a ratio of 2.99. The measured ratio converges to the term ratio.
AUDIENCE SHOULD GET: the paper's "same cost as Verma" claim moves further from the truth in a good implementation, not closer.
IF ASKED 'why P-256?': it has a native multi-scalar routine; Ristretto255 in libsodium does not (next slide).
TIME: 45 s on this slide; 8:55 elapsed at the end of it.


## Slide 16: Which optimisation pays depends on the library

Tags: OUR AUDIT, EXPERIMENT

SAY: On Ristretto255 through libsodium there is no native multi-scalar routine, so optimising barely helps either scheme, and the ratio still rises: 2.13 to 2.23. The two libraries also store points differently: libsodium keeps a point as its 32-byte encoding, so encoding is nearly free and addition is expensive; OpenSSL keeps coordinates, so addition is cheap and encoding costs a modular inversion.
THE INTERIM'S OPEN POINT: at the interim, P-256 timing was about 20 percent above what the operation counts predicted. This explains it. Every hash call encodes its point inputs: Qiao's verification encodes 8 points per signer, Verma's 2; a test counts them. On P-256 that is expensive. Pricing the real hash calls predicts 2.363 to 2.371, and we measured 2.366. It was not interpreter overhead.
NEXT: Part IV, the aggregator.
TIME: 30 s on this slide; 9:25 elapsed at the end of it.


## Slide 17: One bad signature sinks the whole batch

Tags: OUR FINDING, PAPER

SAY: The paper treats the aggregator as harmless: in its words, it does not use its own private information, it only merges signatures. That is true, and it is why aggregation is secure. But merging is a sum: z is the sum of the z_i. If one signature is bad, from a faulty sensor, a corrupted link or an attacker, the whole aggregate fails, and the sum no longer tells you which one.
TEST: one corrupted signature in a batch of 32: the aggregate fails verification. Nothing in the aggregate identifies the culprit.
FRAMING: availability, not forgery. The security proof is untouched.
NEXT: three ways to run an aggregator.
TIME: 30 s on this slide; 9:55 elapsed at the end of it.


## Slide 18: Three ways to run the aggregator

Tags: IMPLEMENTATION

SAY: BLIND is the paper's model: merge everything and hope. PREVERIFY checks every signature first and drops bad ones. RETAIN merges optimistically but keeps the individual signatures; if the aggregate fails, it splits the batch in halves and re-checks each half, recursively.
WHY RETAIN IS CHEAP: a clean half costs one aggregate verification, whatever its size. One bad signature in 32 was located with 11 verifications instead of 32.
All three use no secret material, so the security argument is unchanged; a test checks that.
NEXT: which policy to use, by numbers.
TIME: 30 s on this slide; 10:25 elapsed at the end of it.


## Slide 19: Pre-verify by default; an attacker chooses the fault rate

Tags: EXPERIMENT

SAY: Cost per delivered signature, P-256, batches of 200, 5 trials per row. BLIND is cheapest while every batch is clean, but from 2 percent it delivered nothing. RETAIN beats PREVERIFY only on clean batches. From about one bad signature per batch of 200, the 0.5 percent row, PREVERIFY is cheaper, and it stays nearly flat up to 10 percent.
WHY THE CROSSOVER IS SO LOW: verifying a signature on its own is only 1.8 times dearer than its share of an aggregate verification, not ten times.
RECOMMENDATION: in a factory where sensors almost never fail, RETAIN. Where an attacker may submit bad signatures, the attacker picks the fault rate, so PREVERIFY is the safe default.
NOT SHOWN: the 0.1 and 5 percent rows (AGGREGATOR.md has all six). At 0.1 percent no trial drew a bad signature, so that row is a second clean batch.
NEXT: Part V, the sensors themselves.
TIME: 45 s on this slide; 11:10 elapsed at the end of it.


## Slide 20: What if a sensor's random-number generator repeats?

Tags: OUR FINDING, PAPER

SAY: Every signature uses a fresh random nonce t_i. The paper simply writes t_i chosen at random and says nothing about how a sensor gets randomness. Sensors are exactly where randomness fails: a generator stuck after a reboot, a firmware image cloned with its seed, too little entropy at boot.
THE EQUATION: z_i = t_i + c_i u_i + sk_i v_i. Anyone can compute u_i and v_i, they are hashes of public data. The unknowns are t_i, the certificate secret c_i and the secret key sk_i. If t_i repeats, every signature under it is one more linear equation in the same three unknowns.
The repeat is easy to spot: T_i = t_i P is in every signature, so a repeated nonce shows up as a repeated T_i.
NEXT: how many such signatures are enough.
TIME: 30 s on this slide; 11:40 elapsed at the end of it.


## Slide 21: How many signatures with one nonce give away the keys?

Tags: EXPERIMENT, OUR FINDING

SAY: Verma's scheme first: its certificate term has coefficient one, so the nonce and the certificate merge into one unknown, and two signatures give the secret key. Qiao's repair multiplies the certificate by the per-message hash u_i, so the certificate is a separate unknown: an outsider needs three signatures, and then recovers t, c and sk by solving three linear equations. With only two, every guess of sk fits some c; picking the right one is a discrete logarithm.
THE KGC: it issued the certificate, so it already knows c. Two signatures give it sk, the very key certificate-based signatures promise it never learns.
RESULTS: outsider with three: 8 of 8 recover both secrets, the forgery verifies 8 of 8 and passes aggregate verification 8 of 8. KGC with two: 8 of 8. Verma with two: 8 of 8.
PROVENANCE: nonce reuse against Schnorr-type signatures is a standard attack. What is ours is working it out for this scheme: the three-versus-two count and the KGC case.
NEXT: we run it.
TIME: 45 s on this slide; 12:25 elapsed at the end of it.


## Slide 22: Demo 2: a stuck RNG gives away a sensor's keys

Tags: EXPERIMENT

RUN: make nonce. About one second.
POINT AT: Step 1: three readings, the same T in each, and every signature verifies, so nothing looks wrong. Step 2: recovered sk matches pk: True; recovered c passes the certificate check: True; the attacker's own message valve=OPEN verifies: KEYS STOLEN, and it passes aggregate verification next to an honest signature. Step 3: the KGC needs only two.
FALLBACK: the panel on this slide is the captured output of the same command. Backup B13 has it larger.
NEXT: the fix, which is step 4 of the same demo.
TIME: 75 s on this slide; 13:40 elapsed at the end of it.


## Slide 23: The fix: derive the nonce from the keys and the message

Tags: EXPERIMENT, IMPLEMENTATION

SAY: The standard defence, used by EdDSA and RFC 6979: do not take the nonce straight from the generator. Hash the secret keys and the message, and mix in the generator's output: a hedged nonce. If the generator is stuck, different messages still get different nonces, because the message is an input. With a stuck generator, the same message signed twice gives the same signature, which reveals nothing new.
NO CHANGE FOR VERIFIERS: the signing equation and the signature format are unchanged, so every existing verifier accepts hedged signatures, also mixed with ordinary ones in one aggregate.
RESULT: with the RNG stuck, all three nonces distinct in 8 of 8, signatures verify 8 of 8, and the attack refuses to start 8 of 8.
PROVENANCE: the technique is standard; applying it to this scheme and checking it is ours. The paper specifies no nonce derivation.
TIME: 30 s on this slide; 14:10 elapsed at the end of it.


## Slide 24: Claim: “resist replay attacks”

Tags: OUR FINDING, PAPER

SAY: The paper's argument is that signing is randomised, so signing the same message twice gives a different signature. True, and we checked it. But a replay attack does not sign anything: it re-sends an old, valid message and signature. That pair still verifies. It even verifies inside a new aggregate, and the same signature can appear twice in one batch.
DELTA: the paper sets Delta once, in Setup, and never says it changes. If a deployment rotated Delta per epoch, old signatures would stop verifying in the next epoch, but replay inside an epoch would still work.
WHAT IS NEEDED: freshness that the verifier checks: a sequence number or timestamp inside the message, or rejecting repeated T_i values.
TIME: 30 s on this slide; 14:40 elapsed at the end of it.


## Slide 25: Claim: “perfect forward security”

Tags: OUR FINDING, PAPER

SAY: This is the paper's entire argument, one sentence, with no definition and no proof. For signatures, forward security has a standard meaning (Bellare and Miner, CRYPTO 1999): time is split into periods, the secret key is updated every period, and a key stolen in one period cannot sign for an earlier one. 'Perfect forward secrecy' is a key-exchange term.
THE SCHEME: sk_i and the certificate are fixed for life, and none of the six algorithms takes a time period. So a key stolen today signs for every period. Our test: keys recovered in epoch 1, through the nonce reuse of the previous slides, sign a back-dated epoch-0 reading, and it verifies. And the premise, 'no one can obtain the random value', is exactly what nonce reuse breaks.
THE PAPER ITSELF: cites a scheme titled 'A forward-secure certificate-based signature scheme', its reference 24 (Li et al. 2015), so the notion was available to the authors. We cite only its title; we have not read it.
IF ASKED 'could the claim be rescued?': only with a different, key-evolving construction like reference 24; not with a change of wording.
NEXT: Part VI, how we know all this.
TIME: 35 s on this slide; 15:15 elapsed at the end of it.


## Slide 26: Every result on these slides runs as code

Tags: EXPERIMENT, IMPLEMENTATION

SAY: Nothing in this talk is an argument on paper only. The implementation has 420 tests: 197 run on both group libraries, Ristretto255 through libsodium and NIST P-256 through OpenSSL, and 26 need no group at all. A separate self-test runs 62 algebra checks across the two libraries. And every number on these slides is recomputed and asserted by one audit script, which stops if any claim fails.
WHY TWO LIBRARIES: two independent implementations must agree on every result and every operation count; if one had a bug, they would disagree.
IF ASKED 'can we run it?': yes, the commands are on the slide; make verify runs everything.
TIME: 20 s on this slide; 15:35 elapsed at the end of it.


## Slide 27: All results at a glance

SAY: The whole project in one table. Read the left column only, and point at the tags: the first row reproduces the paper; the other eight are ours, an audit of the paper's claims, a measurement, or a new finding.
PROVENANCE IS THE POINT: we never present the paper's attack as ours; it is tagged reproduced.
TIME: 30 s on this slide; 16:05 elapsed at the end of it.


## Slide 28: What the paper gets right

Tags: EXPERIMENT, PAPER

SAY: To be fair to the authors. Their central claim holds up: Verma's scheme is broken by a malicious KGC, and their repair resists that attack. It also resisted the key-only forgery: 0 of 8, with the paper's attack also at 0 of 8. Both of its hash bindings turn out to be necessary. And aggregation really uses no secrets, so the aggregate inherits the single-signature security.
WHAT WE DID NOT CHECK: their security proof. Nothing we found contradicts it; our findings are about cost, deployment and the extra claims in section V-C.
TIME: 20 s on this slide; 16:25 elapsed at the end of it.


## Slide 29: Scope and limitations of our results

SAY: What our results do not claim. We did not audit the proof. We implemented Verma's scheme from Qiao et al.'s description of it, not from Verma's own paper. Our timings run in Python over native libraries, so we report ratios and per-signer slopes, never absolute times. The nonce fault is simulated in software. The R-binding cell of the 2 by 2 needs public-key replacement, not just a public key. And the hedged-nonce fix is a standard technique, not a new one.
WHY THIS SLIDE: every result above is stated within these limits, so a question about any of them has an answer here.
TIME: 20 s on this slide; 16:45 elapsed at the end of it.


## Slide 30: Three things to remember

Tags: EXPERIMENT, OUR FINDING

SAY: One: Verma's scheme is broken more simply than the paper says; anyone holding a public key can forge, and the paper's own Table II gets this wrong. Two: the repair works, but it is not as cheap as printed: about twice the printed cost, and three times Verma's once both are optimised. Three: the repaired scheme still needs care in deployment: one bad signature sinks a batch, a repeated nonce gives away every key, and its replay and forward-security claims do not hold. Each of these has a concrete fix.
TIME: 30 s on this slide; 17:15 elapsed at the end of it. Then stop: thank you, questions.


## Slide 31: Thank you (the talk ends here)

STOP HERE. The main talk ends on this slide.
SAY: Thank you. We are happy to take questions.
WHICH BACKUP FOR WHICH QUESTION: both schemes in full: B1, B2. The key-only algebra and the fixed-point search: B3. The two ablations: B4. The 2 by 2 as tests: B5. Nonce-reuse algebra: B6. The hedged nonce: B7. Forward security: B8. Optimisation in detail: B9. Fault localisation and sub-batching: B10. The interim's operation counts: B11. The P-256 timing model: B12. Demo fallbacks: B13. Tests and commands: B14.


## Slide 32: Appendix divider (backup, only if asked)

BACKUP SLIDES. Only if a question calls for them; do not present them as part of the talk. Each has its own notes.
WHICH ONE: schemes B1-B2; key-only algebra B3; ablations B4-B5; nonce algebra B6; hedged nonce B7; forward security B8; optimisation B9; fault localisation B10; interim counts B11; P-256 timing B12; demo fallbacks B13; tests and commands B14.


## Slide B1: B1 · The complete Verma scheme

Tags: PAPER

The scheme as Qiao et al. review it in their section IV-A; our implementation follows this description (src/cbas/verma.py). We did not cross-check Verma et al.'s original paper.
For the key-only forgery, note that R_i is part of each signature (fresh r_2i every time) and is in neither H_0 nor H_1.


## Slide B2: B2 · The complete Qiao scheme

Tags: PAPER

The repaired scheme from the paper's section V-A; our implementation is src/cbas/scheme.py, a direct transliteration.
Two printed typos are corrected in our code: KeyGen prints pk_i = s_i (we use s_i P); the certificate check prints R_1i (we use R_i).
Hash instantiation (ours): SHA-512 over a length-prefixed encoding, one domain label per hash, reduced mod p.


## Slide B3: B3 · The algebra, and why the repair turns it into a search

Tags: OUR FINDING

Left: the forgery on Verma's scheme in full. Any z works; z = 0 is what the code uses. The forged pair satisfies the check by construction, so it verifies for any message.
Right: the same attempt against Qiao's scheme. Fix z and T, guess R, compute the three hashes from the guess, solve for the R the equation would need, and compare. Each round gives a new candidate. A success would be a fixed point of the hash functions; finding one is exhaustive search over the group, not algebra.
Code: src/cbas/keyonly_attack.py (forge_verma_keyonly, attempt_keyonly_forge_fixed). Tests: tests/test_keyonly_attack.py.


## Slide B4: B4 · What each ablation removes, and nothing else

Tags: IMPLEMENTATION

Both ablations are controlled experiments, not schemes anyone should use. Each removes exactly one binding and reuses everything else from the real scheme.
ablation.py (from the interim) drops T_i from H_1 and H_2. ablation_r.py drops R_i from H_0, H_1 and H_2 and keeps T_i. Both remain working schemes: honest signatures verify and other messages are rejected; tests check this and that only the intended input is gone.
The R-removed variant is forged by solving for R, but in Qiao's scheme R_i is the certificate's public point, so the verifier must accept an attacker-chosen R_i: public-key replacement, F_1's power in the paper's model. Under the real R_i the forgery fails in every trial.


## Slide B5: B5 · The 2 × 2 as tests

Tags: EXPERIMENT

Captured output of pytest tests/test_keyonly_attack.py -k ablation -vv, both backends. Use -vv because the project's pytest configuration adds -q.
The first four test pairs are the four claims behind the 2 by 2; the last two check that ablation_r.py is a working scheme and changes only the R binding.


## Slide B6: B6 · The algebra of key recovery

Tags: OUR FINDING

Three signatures on different messages with the same nonce t: z_j = t + c u_j + sk v_j for j = 1, 2, 3. Subtract the first from the others to remove t: two equations in c and sk. Cramer's rule solves them; then t follows from any one signature. The code checks sk P = pk and the certificate equation before returning, so it never returns a wrong answer.
With two signatures there is one equation in c and sk. Every guess of sk fits some c; exactly one guess also satisfies sk P = pk, and finding it by checking guesses is as hard as a discrete logarithm.
The KGC knows c (it issued the certificate), so its single equation has one unknown.
Verma: z = r_2 + c + sk v. With the nonce repeated, z_1 - z_2 = sk (v_1 - v_2), so sk follows; r_2 + c then acts as one known value, enough to sign anything with the same R.
Code: src/cbas/nonce_reuse.py. Tests: tests/test_nonce_reuse.py.


## Slide B7: B7 · The hedged nonce, in detail

Tags: EXPERIMENT, IMPLEMENTATION

sign_hedged in src/cbas/nonce_reuse.py. The nonce is SHA-512 over a domain-separated, length-prefixed encoding of sk, c, the message, pk, R, the identity, Delta and a fresh RNG output, reduced mod p.
Why the secrets: without them the nonce would be computable by anyone. Why the message: so a stuck RNG still gives different nonces for different messages. Why the RNG output: hedging; a purely deterministic nonce is vulnerable to fault attacks that cause two different signatures on the same message, and mixing in randomness keeps that from being a single-point failure.
Same message twice under a stuck RNG gives the same signature: harmless, it reveals nothing new.
Results: distinct nonces 8 / 8, verify unchanged 8 / 8, attack refused 8 / 8; mixed batches of hedged and ordinary signatures aggregate and verify (test).


## Slide B8: B8 · What forward security means for signatures

Tags: PAPER

Bellare and Miner, "A Forward-Secure Digital Signature Scheme", CRYPTO 1999 (building on Anderson's 1997 remark). The public key stays fixed; the secret key evolves through periods by a one-way update, and the old key is erased. A signature names its period. Stealing the key of period j allows signing only for periods j and later.
Qiao et al.'s scheme has none of these parts: no periods, no update algorithm, no period in the signature. The paper's own reference 24 (Li et al., Computer Journal 2015) is titled a forward-secure certificate-based signature scheme; we have not read it, so we cite only its title.
'Perfect forward secrecy' is the key-exchange property that session keys stay safe after a long-term key leaks; it does not apply to a signature scheme.


## Slide B9: B9 · Per-signer cost at each stage, both libraries

Tags: EXPERIMENT

Slopes of a linear fit of aggregate verification time over n = 50 to 500 (microseconds per signer), from the recorded runs bench/results/optimization_*.json (2026-11-10). Over four runs on the current code: P-256 ratio 2.37 to 2.46 as specified and 2.95 to 3.07 optimised; Ristretto255 2.12 to 2.13 and 2.23 to 2.24.
Ristretto255 via libsodium has no native multi-scalar routine, so the multi-scalar path falls back to evaluating terms one by one: no gain. An earlier version of that fallback was slower than naive; it was fixed by adding scalar-one terms directly.
Every fast path is checked against the reference implementation on both backends, for valid and tampered inputs (tests/test_optimized.py).


## Slide B10: B10 · Finding a bad signature without checking every one

Tags: EXPERIMENT, IMPLEMENTATION

locate_faults in src/cbas/aggregator.py: verify a range as one aggregate; if it fails, split it in half and recurse into both halves. A clean range of any size costs one aggregate verification, so f faults among n cost on the order of f log n verifications, not n.
Measured: one bad signature among 32 found with 11 verifications (a test asserts fewer than 32).
Sub-batching, for an aggregator too weak to verify at all: split into batches of k so a fault loses only its batch. AGGREGATOR.md gives the optimum k by fault rate under a measured cost model.


## Slide B11: B11 · The complete operation-count table

Tags: OUR AUDIT, PAPER

Printed rows against counted rows, from the interim. Counts come from the instrumented backend and are identical on both libraries. Verma's counted rows match the printed rows except Sign, which omits one point addition (negligible).
Qiao's AggSign is zero group operations: n - 1 scalar additions; the printed (n - 1) T_a overstates it, in the paper's favour.
Regression-tested in tests/test_opcount.py and tests/test_verma.py.


## Slide B12: B12 · Why P-256 timing exceeded the operation counts

Tags: OUR AUDIT, EXPERIMENT

At the interim, the P-256 per-signer ratio measured about 20 percent above the ratio predicted from operation counts priced with a bare hash. Each hash call also encodes its point arguments. Qiao's verification encodes 8 points per signer (pk and R in H_0; pk, R and T in each of H_1 and H_2), Verma's 2; tests/test_opcount.py counts them. On OpenSSL an encoding costs a modular inversion; on libsodium a Ristretto255 point is stored as its encoding, so encoding is nearly free.
bench/hashcost.py times the real hash calls and predicts 2.363 to 2.371 (three repeats) against a measured 2.366; on Ristretto255 the prediction is unchanged at 2.14. Timing values are from 10 November on the Ryzen 5 7520U; they are not asserted by the audit script because they are timings.


## Slide B13: B13 · Demo fallbacks: captured output

Tags: EXPERIMENT

The real output of make attack (Target 3) and make nonce (steps 1 to 3), captured by presentation/build/make_demo_fallback_final.py, which runs the commands and renders their stdout unedited.
Say: 'this is the output of the same command, captured earlier.' The values T = ... differ from run to run because every run draws fresh keys; the True/False lines are what matter.
Slides 10 and 22 already carry the same captures; this slide is only needed if the audience wants them larger.


## Slide B14: B14 · Tests and commands

Tags: IMPLEMENTATION

420 tests: 197 run once per group library (394) and 26 need no group (fitting and aggregator-model maths). The self-test (62 checks) has no dependency on pytest.
Every number in this deck is recomputed and asserted by presentation/audit/verify_claims_final.py, which writes presentation/data/claims_final.json; the slides read that file.
