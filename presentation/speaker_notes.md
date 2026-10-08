# Speaker notes: CBAS interim presentation


## Slide 1: Title slide

SAY: We investigated one IEEE paper end to end: we ran its attack, tested its repair, and recomputed its performance numbers. Two of the results you will see are the paper's own, reproduced. One is a discrepancy the paper does not mention.
AUDIENCE SHOULD GET: this is an investigation with a question, not a paper summary.
        NEXT: start with where this scheme is meant to run.
IF ASKED 'what is your contribution?': the attack and the repair are the paper's; what we add is the causal ablation, the cost audit and its independent timing check (slide 26 has the full list).
20-MINUTE ROUTE: KEEP (30 s).


## Slide 2: Can a malicious key authority forge sensor data?

Tags: PAPER

SAY: Why is this paper interesting? One question: can a malicious key authority forge sensor data? To see why it matters, here is the system the paper targets. Smart sensors on a production line produce readings. An aggregator in their area collects them. A cloud server analyses them. The KGC, the key generation centre, is a trusted authority that is involved only at the start: it publishes parameters and enrols each sensor once.
AUDIENCE SHOULD GET: who the four parties are, and the six algorithms in order: Setup, KeyGen, CertGen, Sign, AggSign, AggVerify. Colours are fixed for the whole talk: violet KGC, blue sensors, amber aggregator, slate cloud.
Algorithm names are exactly the paper's: Setup, KeyGen, CertGen, Sign, AggSign, AggVerify.
NOTE: parameters reach users through the cloud server (paper section I-A); we draw no other communication than the paper does.
NEXT: why does the aggregator combine signatures at all?
IF ASKED 'what is a KGC?': the key generation centre, called a trusted authority (TA) in the paper. It has a master secret key and issues certificates.
20-MINUTE ROUTE: KEEP, quick (45 s): name the four parties and the six algorithms in order.


## Slide 3: One verification decision instead of n

Tags: PAPER

SAY: Each sensor signs its own reading. The aggregator takes the n signatures and combines them into one aggregate signature. The cloud then runs one check and either accepts all n readings or rejects.
AUDIENCE SHOULD GET: what AggSign and AggVerify are for, informally. The paper's motivation is lower communication overhead, and a single decision at the verifier.
Do not say aggregation makes verification faster. In our own measurements one aggregate verification is slower than n separate Ed25519 checks; what aggregation buys is fewer signature bytes and one accept/reject decision. Part VI measures the cost of the schemes against each other.
NEXT: signatures need keys, so who holds them?
IF ASKED 'how much smaller is the aggregate?': it depends on the scheme. Verma's is one point plus one scalar for any n; Qiao's keeps all n commitments T_i, so only the scalar half compresses (paper Table VI).
20-MINUTE ROUTE: SKIP: say it while on slide 2 ('the aggregator combines n signatures into one').


## Slide 4: Who holds the signing key?

Tags: PAPER

SAY: Three ways to arrange keys. In a public-key infrastructure the user makes a key and a certificate authority certifies it, which brings certificate distribution and revocation overhead. In identity-based signatures the authority computes the whole private key, so it can sign as anyone: that is key escrow. In certificate-based signatures the sensor makes its own key pair, and the KGC issues a certificate; signing needs both.
AUDIENCE SHOULD GET: the design goal. Neither party alone should be able to sign. A scheme in which the KGC alone can sign has collapsed back into identity-based signatures with escrow.
The paper frames it as: the certificate is part of the user's private information, used together with the secret key (section III).
NEXT: what if the KGC itself goes bad?
IF ASKED 'why certificate-based?' (professor question 10): no key escrow, because the KGC never sees sk_i, and no separate certificate lookup or revocation channel, because the certificate is implicit in signing.
20-MINUTE ROUTE: QUICK (30 s): one sentence per column; end on 'the KGC alone must not be able to sign'.


## Slide 5: What if the KGC is the attacker?

Tags: PAPER

SAY: The paper motivates the threat with a real incident: an employee at South Africa's Postbank took the master secret key of the data centre and stole 3.2 million dollars. Whoever holds the master key can act for every user. The paper's requirement: a practical CBAS scheme must remain secure even when the KGC is malicious.
AUDIENCE SHOULD GET: why the malicious-KGC model is not an exotic assumption, and the three questions the rest of the talk answers.
Q1: can a malicious KGC forge in Verma et al.'s scheme? The paper says yes (its section IV); we run it. Q2: does Qiao et al.'s repair stop that attack, and which change is responsible? Q3: Qiao et al. report the same cost as Verma's scheme; does the algorithm they print agree?
Point out the five coloured tags at the bottom: every slide says whose claim it shows.
IF ASKED 'is the Postbank case evidence about CBAS?' (professor question 11): no, it is the paper's example of why a master key can leak; it motivates the threat model.
20-MINUTE ROUTE: KEEP (1 min): the threat and the three questions.


## Slide 6: Six algorithms, four parties

Tags: PAPER

SAY: Here is the same system as an event diagram. Time runs left to right; each row is a party. Setup runs at the KGC and produces public parameters and a master secret. Each sensor runs KeyGen, then sends its public key to the KGC, which runs CertGen and returns a certificate. Sensors sign their readings with Sign. The aggregator runs AggSign on the n signatures. The cloud runs AggVerify and gets 1 or 0.
AUDIENCE SHOULD GET: which party generates each object. The padlocks mark secrets. Grey dashed items are steps the paper does not specify: how the certificate reaches the sensor, and how the verifier obtains each signer's public key. We show them as abstracted rather than inventing a protocol.
The paper calls AggVerify 'Very' in its sections IV and V; it is the same algorithm.
NEXT: a first concrete scheme: Verma et al.'s.
IF ASKED 'why is Cert_i private?': the paper says the certificate is part of the user's private information, used together with the secret key (section III).
20-MINUTE ROUTE: SKIP: slide 2 already shows who does what; say 'grey dashed steps are not specified by the paper' there.


## Slide 7: Verma et al.: every sensor gets a certificate from the KGC

Tags: PAPER

SAY: Notation first, only what we need: P generates a group G of prime order p; aP means P added to itself a times; H0 hashes strings into integers mod p. The sensor picks a random s_i, sets its secret key sk_i = s_i and publishes pk_i = s_i times P. The KGC has a master secret s with public key P_TA. For each sensor it picks a random r_1i, forms R_1i = r_1i P, and computes c_i = r_1i + s times H0 of id_i and pk_i. The certificate is the pair (R_1i, c_i).
AUDIENCE SHOULD GET: two facts. The certificate c_i is known to the KGC because the KGC computed it. The secret key sk_i is known only to the sensor.
The check c_i P = R_1i + H0(id_i || pk_i) P_TA lets anyone verify a certificate using only public values.
This is Verma et al.'s scheme as Qiao et al. review it in their section IV-A; our code follows that description (verma.py). We did not cross-check Verma's original paper.
NEXT: how a sensor signs.
IF ASKED 'why two random values r_1i and r_2i later?': r_1i belongs to the certificate (chosen by the KGC); r_2i is chosen by the sensor afresh for every signature.
20-MINUTE ROUTE: QUICK (45 s): keys and certificate; only say 'the KGC knows the certificate'.


## Slide 8: Signing mixes a fresh nonce, the certificate and the secret key

Tags: PAPER

SAY: To sign a reading m_i the sensor picks a fresh random r_2i and forms R_i = R_1i + r_2i P, a commitment to its randomness that also carries the certificate point. It hashes the message with its public key, its identity and the state information Delta, giving v_i. The response is z_i = r_2i + c_i + sk_i times v_i. The signature is the pair (R_i, z_i).
AUDIENCE SHOULD GET: z_i is a sum of three terms: a fresh nonce only the sensor knows, the certificate which the KGC also knows, and the secret key scaled by a hash that anyone can compute.
Look at the bottom: the hash v_i takes m_i, pk_i, id_i and Delta. It does not take R_i, and it does not depend on r_2i. Hold that thought; the whole attack follows from it.
Delta is public state information; the paper does not say more, and our code uses an epoch label.
NEXT: how verification works, and why this design was attractive.
IF ASKED 'what is Delta?': public state information published with the parameters. The paper leaves it open; if it changes per epoch it also separates epochs, which a test of ours confirms.
20-MINUTE ROUTE: KEEP (1 min): this is where v_i not seeing R_i is planted.


## Slide 9: Verification, and the appeal of a constant-size aggregate

Tags: PAPER

SAY: The aggregator just adds up: R is the sum of the R_i and z is the sum of the z_i. The aggregate is one point and one scalar, whatever n is; that is the scheme's selling point, 'compact aggregation'. The verifier recomputes h_0 and v_i for every signer and checks one equation: zP equals R plus the sum of the h_0 times the KGC public key plus the sum of v_i times pk_i.
AUDIENCE SHOULD GET: why this was attractive, and the trade-off the authors made. The paper says it directly: to obtain an aggregate of fixed length, Verma et al. remove the random value from the hash, and because of that the construction is insecure.
Why does it verify? For one signer, z_i P = r_2i P + c_i P + sk_i v_i P, and c_i P = R_1i + h_0 P_TA, so z_i P = R_i + h_0 P_TA + v_i pk_i. Summing over signers gives the verification equation. The full derivation is in backup B4.
NEXT: now the attacker.
IF ASKED 'is the aggregate really constant size?': yes for Verma: one group element and one scalar (paper Table VI; our test checks it). Qiao's repaired scheme gives that up: its aggregate carries all n commitments T_i.
20-MINUTE ROUTE: QUICK (30 s): constant-size aggregate; read the paper quote.


## Slide 10: The attacker: a KGC that has gone bad

Tags: PAPER

SAY FIRST: Now the attacker: a malicious KGC. It knows the master secret, so it knows every certificate, including this sensor's, because it issued them. And it has seen one valid signature from this sensor.
THE KEY POINT: Everything on the violet card, the KGC has. The two red sealed values it does not have: the sensor's secret key sk_i and this signature's nonce r_2i. Its goal is a valid signature on a new message for the same sensor. This is the paper's adversary F2; the attack needs one observed signature per victim.
TAKEAWAY: The KGC holds everything except the two secrets inside z_i.
NEXT: So how can it forge at all? That is the puzzle.
IF ASKED 'does it need the master secret or only the certificate?': the attack uses the certificate (R_1i, c_i) the KGC issued, plus one signature. The master secret is how the KGC has the certificate.
20-MINUTE ROUTE: KEEP (45 s).


## Slide 11: The puzzle

Tags: PAPER

SAY FIRST: Read the question aloud, then pause for a few seconds.
THE EQUATIONS MEAN: Left box, what the KGC can compute. R_i minus R_1i equals r_2i P: a point; getting r_2i out of it would mean taking a discrete logarithm, which is infeasible. And z_i minus c_i equals r_2i plus sk_i v_i: one number made of two unknowns, drawn sealed. Right box: a forgery on a new message needs a matching commitment and response for a new hash value v-prime, with both secrets still unknown.
TAKEAWAY: It does not have to open the sealed number. It only has to rescale it.
NEXT: Three small steps, one slide each.
IF ASKED 'why does the KGC not need r_2i?' (professor question 1): the forged signature uses a new nonce, v-prime r_2i over v_i, which is just a rescaled copy of the old one. The attacker never has to know it; it only has to produce a commitment and a response that are consistent with each other, and linearity guarantees that.
20-MINUTE ROUTE: KEEP (30 s): the question, then the pause.


## Slide 12: Step 1: strip off the certificate

Tags: PAPER

SAY FIRST: The KGC issued R_1i and c_i, so it can simply subtract them.
THE EQUATIONS MEAN: R_i minus R_1i equals r_2i P: a group element, computable but not invertible. z_i minus c_i equals r_2i plus sk_i v_i: one number, two unknowns, so we draw it sealed. v_i itself is public: anyone can hash m_i, pk_i, id_i and Delta.
TAKEAWAY: Known: the point r_2i P. Sealed: the number r_2i + sk_i v_i. Nothing has been solved.
NEXT: Divide by v_i.
IF ASKED 'is r_2i P enough to get r_2i?': no; that would be a discrete logarithm.
Code: attack.py lines 73 to 74 (this is step 2a of the paper's section IV-B).
20-MINUTE ROUTE: COMBINE verbally with 13 and 14: about 40 s each, equations only.


## Slide 13: Step 2: normalise by vi

Tags: PAPER

SAY FIRST: Divide by v_i. It is a public hash value, non-zero with overwhelming probability, so it has an inverse mod p; that is where the prime-order group matters.
THE EQUATIONS MEAN: alpha is (z_i minus c_i) over v_i, which equals r_2i over v_i plus sk_i. The KGC holds the number alpha but not its two parts, so what it is made of stays sealed. A is (R_i minus R_1i) over v_i, which equals (r_2i over v_i) times P: a point it holds. Neither reveals r_2i or sk_i on its own.
TAKEAWAY: Both are just scaled by one over v_i. The attacker does not separate the two parts.
NEXT: Choose a new message.
IF ASKED 'how does alpha help the attacker?' (professor question 2): alpha packages the secret-bearing part so that it can be rescaled. Multiplying alpha by a new hash value v-prime gives r_2i v-prime / v_i plus sk_i v-prime, exactly the secret-bearing part a signature on the new message needs. It works only because v_i does not depend on r_2i.
Code: attack.py lines 77 to 78.
20-MINUTE ROUTE: COMBINE verbally with 12 and 14: about 40 s.


## Slide 14: Step 3: rescale to any message

Tags: PAPER

SAY FIRST: Pick any new message m-prime. Compute v-prime, the hash of m-prime with pk_i, id_i and Delta. That is possible immediately, because R-prime is not an input to the hash.
THE EQUATIONS MEAN: R-prime is R_1i plus v-prime times A; z-prime is v-prime times alpha plus c_i. Expand them: R-prime is R_1i plus (v-prime r_2i over v_i) times P, and z-prime is v-prime r_2i over v_i plus c_i plus sk_i v-prime. That is exactly the shape of an honest signature, with a new nonce v-prime r_2i over v_i that nobody knows, the attacker included.
TAKEAWAY: The result has exactly the form of an honest signature. Do not read three equations; point at v-prime, R-prime and z-prime in turn.
NEXT: Everything on one diagram, and the verifier's verdict.
IF ASKED 'is the forged signature distinguishable?': no; it has the form of an honest signature, and our tests check that its encoded size matches.
Code: attack.py lines 81 to 83.
20-MINUTE ROUTE: COMBINE verbally with 12 and 13: about 40 s.


## Slide 15: The forgery verifies, and the sealed values were never opened

Tags: PAPER

SAY FIRST: Left to right. One valid signature goes in. The malicious KGC knows the master secret, the certificate and that signature, but not sk_i or r_2i. It runs five steps, all of them arithmetic on values it holds.
THE DIAGRAM MEANS: Look only at the two red sealed boxes. They are the only places the two unknowns appear, and the later steps multiply them but never open them. The forged signature goes to the verifier, which checks the ordinary verification equation and accepts. It also passes aggregate verification alongside honest signatures.
TAKEAWAY: The attacker never learns r_2i or sk_i. It rescales the sealed combination. It never decrypts or recovers anything.
WHY IT VERIFIES (only if asked): z-prime P equals (v-prime r_2i over v_i) P plus c_i P plus sk_i v-prime P. With c_i P equal to R_1i plus H_0 P_TA this equals R-prime plus H_0 P_TA plus v-prime pk_i. The whole attack in one line: with lambda equal to v-prime over v_i, R-prime is R_1i plus lambda (R_i minus R_1i), and z-prime is c_i plus lambda (z_i minus c_i). Full derivation: backup B3.
This attack is the paper's section IV-B. Our contribution is the reproduction, next.
NEXT: We ran it.
IF ASKED 'what exactly did you reproduce?' (professor question 6): the paper's malicious-KGC forgery against Verma et al.'s scheme, executed end to end on two group implementations.
20-MINUTE ROUTE: KEEP (1 min): the recap diagram.


## Slide 16: Demo 1: we run the attack on Verma et al.

Tags: EXPERIMENT, REPRODUCED

DEMO: run `make attack` from the repository, on branch presentation-1-work (tag presentation-1-interim). It takes about a second and prints two targets; today we look at Target 1 only, and come back to Target 2 shortly. Keep a screenshot ready as a fallback.
POINT AT: (1) the honest signature verifies; (2) the attacker is the KGC and does not know sk_i; (3) the forged signature on the SHUTDOWN message verifies, and it also survives aggregation.
EVIDENCE BEHIND THE DEMO: 8 of 8 forgeries verify (4 target messages including an empty and a binary one, on 2 group backends); 8 of 8 forged signatures also pass aggregate verification together with an honest one; a test checks that the forging function takes no secret key as an argument. Run `make selftest` first on a new machine.
AUDIENCE SHOULD GET: this is a reproduction of the paper's attack, not our discovery. What we add is that it executes against an independent implementation on two different curves.
NEXT: how Qiao et al. repaired the scheme.
IF ASKED 'what did you reproduce?' (professor question 6): the paper's malicious-KGC forgery against Verma et al.'s scheme (its section IV-B), executed end to end.
FALLBACK: terminal fails, the command errors or it is slow: open Backup B11 (captured output) and say 'here is the output from my earlier run'. The slide's own panel shows the same lines.
20-MINUTE ROUTE: KEEP (1 min): Demo 1 live, or show the screenshot (Backup B11).


## Slide 17: Qiao et al.: the same six algorithms, with new objects

Tags: PAPER

SAY: Same system, same six algorithms, now with Qiao et al.'s objects. Setup is unchanged in spirit: a master secret and public parameters. The certificate changes: the KGC picks r_i, forms R_i = r_i P, and computes c_i using a hash that includes R_i. R_i is public, treated as part of the public key; c_i stays secret. At signing the sensor picks a fresh t_i and commits to it as T_i = t_i P, and T_i goes into the hashes. The signature is (T_i, z_i). The aggregator sums the z_i but must keep every T_i, so the aggregate is (T, z) with T the list of all commitments. The verifier recomputes every hash and checks one equation.
AUDIENCE SHOULD GET: who generates what, what is secret (padlocks), and that T_i, in green, is the new object that travels with every signature.
Grey dashed steps are unspecified in the paper: certificate delivery and how the verifier gets id_i, pk_i and R_i. We have not invented them.
The price of the repair: the aggregate is no longer constant size; only the scalar half compresses (paper Table VI: n|G| + |Z_q*|).
NEXT: exactly which equations changed.
IF ASKED 'why is R_i included in the new hashes?' (professor question 9): the paper says R_i is part of the public key and is hashed so that 'the effect of the certificate for the signature will not be removed by public key replacement' (its section V-A). It targets a different attacker, a malicious user replacing public keys. Our ablation does not test that; it removes only T_i.
20-MINUTE ROUTE: SKIP: mention T_i verbally on slide 18.


## Slide 18: What Qiao et al. changed

Tags: PAPER

SAY FIRST: Left Verma, right Qiao, one row per change. Look at the middle three rows; the grey rows are context.
THE EQUATIONS MEAN: Commitment: R_i = R_1i + r_2i P becomes T_i = t_i P. Hash inputs: v_i now includes R_i and T_i, and there is a second hash H_2 giving u_i from the same input. Response: z_i = t_i + c_i u_i + sk_i v_i. In grey: the certificate now binds R_i, the aggregate keeps every T_i, and verification gains the term u_i R_i.
TAKEAWAY: Several things change. We do not say 'the difference is one line'. For this attack, what matters is that T_i now enters the hashes; the ablation is how we know.
NEXT: Why does that matter so much?
IF ASKED 'why two hash functions H_1 and H_2?' (professor question 8): in the paper, the certificate term and the secret-key term carry independent random-oracle coefficients u_i and v_i; its proof forks H_0 for the user adversary and H_1 for the KGC adversary. In our own audit check, a variant with one hash for both coefficients still resisted the KGC rescaling, so we do not claim the separation is needed to block this attack (backup B6).
IF ASKED 'why is R_i in the new hash?' (professor question 9): the paper says R_i is part of the public key and is hashed so the effect of the certificate cannot be removed by public-key replacement (section V-A). That targets a different attacker; our ablation does not test it.
Two printed typos in the paper's section V-A are corrected in our code: KeyGen prints pk_i = s_i (we use s_i P) and the certificate check prints R_1i (we use R_i).
20-MINUTE ROUTE: QUICK (45 s): only the three middle rows.


## Slide 19: Old vs new: is the commitment coupled to the hash?

Tags: PAPER

SAY FIRST: Left, the old scheme. The message goes into the hash and gives v. The randomness r_2i goes into R_i. The two are not coupled through the hash: the red dashed line is the missing edge. So the attacker can pick a message, compute v-prime, and only then build R-prime and z-prime.
THE PICTURE MEANS: Right, the new scheme. The commitment T_i = t_i P goes into the same hash as the message. Now rescaling needs a new commitment T-prime equal to (v-prime over v_i) times T_i, but v-prime is the hash of a string that contains T-prime. T-prime affects v-prime, and v-prime affects T-prime. The old direct route is gone.
TAKEAWAY: This explains why the reproduced rescaling route no longer applies. It does not prove the scheme secure.
IF ASKED for the exact statement: the attacker would need a scalar lambda with H_1(m-prime, pk, R, id, lambda T, Delta) equal to lambda times v_i: a search over hash outputs, not algebra (backup B6).
WORDING (professor questions 3, 4, 5): the paper proves EUF-CMA security under the discrete logarithm assumption in the random-oracle model; we have not audited that proof. The paper states the principle itself in its section V-A: the commitment T_i should be hashed into the core element of the signature, otherwise a malicious KGC can forge from a known signature.
IF ASKED 'why does T_i prevent the old attack?' (professor question 3): the attack must fix the new commitment before it can compute the new coefficient, but the new commitment is defined in terms of that coefficient. The circularity is the missing route.
NEXT: We tested it.
20-MINUTE ROUTE: KEEP (1 min 15 s): the key idea.


## Slide 20: Demo 2: the same strategy against the repaired scheme

Tags: EXPERIMENT

DEMO: scroll the same `make attack` output to Target 2. The program's banner says 'same attacker, same capabilities, same attack'. Precisely, it is the same strategy adapted to Qiao's equation: the attacker strips c_i u_i instead of c_i, and there is no R_1i. It is a different function (attempt_forge_fixed in attack.py), not literally the same code.
POINT AT: (1) the honest signature still verifies; (2) the attempt iterates 16 times: each round computes the coefficient a candidate T-prime would induce, then the T-prime the attack actually requires; (3) every candidate is different and none verifies. The candidate prefixes change on every run because the keys are random; the demo prints 'all distinct', and a test checks it (24 rounds, 24 distinct).
EVIDENCE: 0 of 8 attempts succeed (4 messages x 2 backends); all 16 candidates are distinct in every one.
WORDING: the paper proves EUF-CMA security under the discrete logarithm assumption in the random-oracle model. Our experiment reproduces the specific malicious-KGC attack against the previous construction, and the repaired implementation does not admit this same algebraic forgery route. A failed attack is not a proof of security (professor question 4).
What did the paper prove (professor question 5)? Theorem 1: if DL is hard, the CBAS scheme is EUF-CMA secure in the random-oracle model, via Lemma 2 (user adversary, forking on H_0) and Lemma 3 (malicious-KGC adversary, forking on H_1); aggregate security follows because AggSign uses no secret. We did not audit these proofs.
NEXT: which of the changes is responsible? An ablation.
FALLBACK: as for Demo 1: Backup B11 shows Target 2 beside Target 1.
20-MINUTE ROUTE: QUICK (30 s): show Target 2 as the screenshot (Backup B11).


## Slide 21: A controlled experiment: remove only the Ti binding

Tags: EXPERIMENT, IMPLEMENTATION

SAY FIRST: Failing against the repaired scheme does not say which of its changes is responsible. So we built a control: the repaired scheme with exactly one thing removed.
THE TABLE MEANS: Row A is Verma: the commitment R_i is not hashed. Row B is Qiao: T_i is hashed. Row C is Qiao with T_i dropped from H_1 and H_2, and nothing else touched. The ablated variant imports the real Setup, KeyGen, CertGen, AggSign and verification equation from the repaired code; R_i is still hashed into H_0, H_1 and H_2; u and v still come from separate hash functions. Only the hash labels are renamed, and one hash input is gone.
TAKEAWAY: Between B and C, only the T_i binding differs. C is a working scheme: honest signatures verify and other messages are rejected, in all 8 trials.
This ablation is our design (an implementation choice, tagged); its result is an experiment. The code calls the T_i binding 'Fix #2' in comments; those labels are ours, not the paper's.
NEXT: The result.
IF ASKED 'does the ablation remove only T_i?': yes. Same H_0 function object, R_i still in H_1 and H_2, separate u and v; a test checks the last two (test_ablated_variant_still_has_fixes_1_and_3).
20-MINUTE ROUTE: QUICK (30 s): say it together with slide 22.


## Slide 22: Remove the Ti binding, and the attack returns

Tags: OUR AUDIT, EXPERIMENT

SAY FIRST: Three cases, same attacker, same strategy, same four target messages on two group backends. A, Verma: the forgery verifies in 8 of 8 trials. B, Qiao: it fails in 8 of 8, with 16 distinct candidates each. C, Qiao with only the T_i binding removed: it verifies again in 8 of 8.
WHAT IT MEANS: The ablation isolates the T_i binding as the critical difference for blocking the reproduced rescaling attack. It does not show that the other changes are unnecessary (R_i in H_0 targets a different attacker, public-key replacement, which we did not test), nor that the full scheme is secure. 0 of 8 is an observation about this route, not a mathematical impossibility.
TAKEAWAY: Full repair: attack fails. Remove only T_i: attack succeeds.
DEMO 3: run `.venv/bin/python -m pytest tests/test_forgery.py -k ablat -vv`. It prints ten test names ending PASSED and '10 passed': eight forgery-restored cases (4 messages x 2 backends) and two checks that the ablated variant is still a working scheme. Use -vv because the project's pytest configuration adds -q.
FALLBACK: terminal fails or is slow: open Backup B12 (captured output), or just talk to the three cards.
NEXT: before measuring performance, why trust our implementation?
IF ASKED 'what does the ablation prove?' (professor question 12): necessity of the T_i binding against this attack, everything else held fixed. Not sufficiency, not security. IF ASKED 'is that original?': yes for the ablation as a causal test; the attack and the repair are the paper's.
20-MINUTE ROUTE: KEEP (1 min 15 s): the three cards; Demo 3 only if time allows (Backup B12).


## Slide 23: How we built it, and how we checked it

Tags: EXPERIMENT, IMPLEMENTATION

SAY: Everything is written against one group interface. scheme.py is a direct transliteration of the six algorithms, with names matching the paper. verma.py is Verma et al.'s scheme as Qiao et al. describe it. attack.py has the forgery and the failed attempt. ablation.py is the weakened variant. Below them, hashing is SHA-512 reduced to integers mod p, with a separate domain label for each of H_0, H_1 and H_2 and length-prefixed fields so concatenation is unambiguous. Below that, one backend interface through which every group operation and hash passes, which is how we count operations. At the bottom, two unrelated prime-order groups: Ristretto255 via libsodium, and NIST P-256 via OpenSSL.
WHY TWO BACKENDS (professor question 15): the results cannot be an artefact of one curve or library, and two independent implementations must agree on every accept/reject outcome and every operation count. Ristretto255 gives a prime-order group, which the algebra needs, since the attack divides by hash values; plain Curve25519 has cofactor 8. P-256 is also what real industrial stacks deploy.
NUMBERS: the standalone self-test has 62 checks (31 per backend); the test suite has 221 tests, which is 101 tests run on each of two backends plus 19 that do not use a backend. Both backends give identical operation counts. Do not say the backends 'agree on every signature': different groups produce different signatures; they agree on outcomes and counts.
Implementation choices of ours, not the paper's: the group instantiation, the hash construction, the epoch label for Delta, and correcting two printed typos.
NEXT: now the performance claim.
IF ASKED 'is the domain separation essential for security?': we do not claim that. It matches the paper's three distinct hash functions.
20-MINUTE ROUTE: QUICK (30 s): two backends, 221 tests, identical counts.


## Slide 24: Is the repaired scheme really as cheap as Verma's?

Tags: OUR AUDIT, PAPER

SAY FIRST: Now the third question: is the repaired scheme really as cheap as Verma's? The paper says yes. Its Tables II and III give the two schemes identical costs, and its Fig. 4 reports 12.729 ms for both at n = 100. The introduction says the proposal has the same high computational efficiency as Verma et al.'s scheme, but is more secure.
THE CARDS MEAN: T_e is one scalar multiplication, T_a one point addition, T_h one hash; the paper's own Table IV prices them at 0.112, 0.005 and 0.004 ms. Top card: the paper's printed cost of verifying an aggregate of n signatures. Bottom card: our recount of the paper's own verification equation, its section V-A: (2n+2) scalar multiplications, 3n point additions and 3n hashes, where the paper prints (n+2), (n+1) and 2n. The next slide shows where the extra scalar multiplications come from. At n = 100, with the paper's own unit costs: 12.729 ms printed against 25.324 ms recounted, a factor of 1.99.
CACHING, one sentence: if the verifier caches every per-signer constant, the single-signature row can match the printed one, but the aggregate still needs at least 2n+1 scalar multiplications: 24.807 ms, a factor of 1.95. Backup B8.
MODEL VALUES, NOT MEASUREMENTS: these use the paper's unit costs, not ours. Our own timing agrees and is one line on the conclusion slide: per-signer cost 2.12 to 2.37 times Verma's on three setups, where the printed rows imply 1.00. Detail: backup B14.
TAKEAWAY: The paper's own equation, priced with the paper's own unit costs, gives about twice the printed time at n = 100.
NEXT: Where the extra cost comes from: the same equation, term by term.
IF ASKED 'is this just a typo?': the printed row agrees with Fig. 4 (12.729 ms), so Fig. 4 was computed from Table III; but the row does not follow from the printed verification equation. How the row arose we do not know; the likeliest reading is that Verma's row was reused.
IF ASKED 'why does it matter?' (professor question 13): the paper's comparative claim, secure and as cheap as the insecure scheme, rests on these tables, and its Figs. 3 to 5 are computed from them.
IF ASKED 'does this invalidate the construction?' (professor question 17): no. The attack and repair results are separate from the cost rows; this affects the comparative efficiency claim only.
IF ASKED 'could caching explain it?' (professor question 14): it explains the single-Verify row, not the aggregate row, and it lowers Verma's row too (backup B8).
IF ASKED about scheme [6] or the paper's Figs. 3 to 5: backup B13. We have not implemented or verified [6].
STATUS: the operation counts are repository tests (tests/test_opcount.py, tests/test_verma.py); the full-constant caching counts and the model arithmetic come from presentation/audit/verify_claims.py and are not yet repository tests.
20-MINUTE ROUTE: KEEP (1 min 15 s): the two cards and the two bars; say 'model values, not measurements' aloud.


## Slide 25: Where the extra cost comes from

Tags: OUR AUDIT, PAPER

SAY FIRST: Why does the recount come out at twice the printed cost? Here are the two verification equations, term by term, with the number of scalar multiplications under each term. The equations are the paper's; the counts are ours.
THE PICTURE MEANS: Top, Verma et al. zP is one scalar multiplication. R is the sum of the commitments, already part of the aggregate signature, so it costs none. The master-key term is one scalar multiplication. The sum of v_i pk_i is n, one per signer. Total n+2: exactly the printed row. That is our calibration: the same counter reproduces Verma's printed row.
Bottom, the repaired equation from the paper's section V-A. The same terms, and one more, the sum of u_i R_i, in red: n more scalar multiplications, one per signer. It exists only in the repaired scheme, because the response z_i now multiplies the certificate by u_i. The sum of the T_i needs no multiplication, and the master-key term is one multiplication with the accumulated scalar. Total 2n+2. The paper prints n+2 for this scheme, the same as Verma's.
TAKEAWAY: The repaired equation has one extra term per signer: 2n+2, not the printed n+2. Verma's equation counts to exactly the printed n+2.
NOT ON THE SLIDE: point additions and hashes. The recount has 3n of each, against the printed n+1 and 2n; the full table is backup B7. In our implementation AggSign uses no group operation at all, so on that row the paper overstates its own cost, in its own favour; we report it.
NEXT: What we established, and what we did not.
IF ASKED 'why does the paper's formula differ from the implementation?' (professor question 16): the formula we compare against is the paper's own printed verification equation, section V-A(6); the implementation follows it term by term. Its Table III row equals Verma's row, which is correct for Verma's equation but not for this one. We do not know how the row was derived; the likeliest reading is that Verma's row was reused.
IF ASKED 'could caching remove the extra term?' (professor question 14): folding the sum of u_i R_i into one multiplication needs the certificate c_i, which is the signer's secret; a verifier does not have it. Caching per-signer constants helps the single-signature row, but the aggregate still needs at least 2n+1 scalar multiplications (backup B8).
STATUS: the counts come from our instrumented backend and are repository tests (tests/test_opcount.py, tests/test_verma.py), identical on both backends.
20-MINUTE ROUTE: KEEP, quick (45 s): the red extra term; Verma's equation counts to the printed row.


## Slide 26: What we established, and what we did not

Tags: EXPERIMENT, OUR AUDIT, REPRODUCED

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
20-MINUTE ROUTE: KEEP (45 s): three things to remember.


## Slide 27: What remains for the final presentation

SAY FIRST: Today we reproduced the paper's attack, tested its repair, and audited its cost claims. For the final presentation we plan to go one step further and test the repaired scheme itself. Four pieces of work.
THE FOUR ITEMS: One, faster verification: does batching and precomputation (multi-scalar multiplication, cached signer data) change the cost comparison when both schemes get exactly the same treatment? Two, the aggregator in practice: what happens to availability when one signature in a batch is bad, and can the faulty signature be located? Three, a second look at the attack: is the paper's attack the weakest one against Verma's scheme, and which change in the repair closes which door? Four, open analysis: nonce reuse on sensors, and the paper's forward-security claim, which we have not examined yet.
TAKEAWAY: Next we move from reproducing the paper to testing the repaired scheme itself.
STATUS (for you, not for the slide; from PRESENTATION_2_FINAL.md on main): items one to three already have code, tests and write-ups in the repository (OPTIMIZATION.md, AGGREGATOR.md, KEYONLY_FORGERY.md). Item four is not started.
IF PRESSED about results for items one to three: say honestly that the code exists and the results will be presented in the final talk. Do not improvise numbers or claims today; today's claims are the ones on the earlier slides.
NEXT: Thank you and questions.
20-MINUTE ROUTE: KEEP, quick (30 s): read the four headings, then stop.


## Slide 28: Thank you (the talk ends here)

STOP HERE. The main presentation ends on this slide.
SAY: Thank you. I am happy to take questions.
Do NOT advance into the appendix unless a question needs it. Backup slides are for questions only. Jump to them by slide number or from the list on the next slide.
WHICH BACKUP FOR WHICH QUESTION: the full attack algebra: B3. Both complete schemes: B1 and B2. Correctness of aggregate verification: B4. The adversaries and the paper's proof (not audited by us): B5. Why T_i is in both hashes: B6. The complete operation counts: B7. Caching objections in full: B8. Benchmark method and the P-256 gap: B9. Tests and commands: B10. The terminal demo failed or took too long: B11 (Demos 1 and 2) and B12 (Demo 3). The paper's Figs. 3 to 5 or scheme [6]: B13. The timing measurements: B14.
The Q&A preparation for the 18 likely questions is in the notes of slide 26.


## Slide 29: Appendix divider (backup, only if asked)

BACKUP SLIDES. Use only if a question calls for them; do not present them as part of the talk.
B1 and B2: the complete Verma and Qiao schemes. B3: the full attack derivation. B4: correctness of aggregate verification. B5: the two adversaries and the paper's proof, which we did not audit. B6: why T_i is hashed into both H_1 and H_2. B7: the complete operation-count table. B8: caching and precomputation in full. B9: benchmark method and the P-256 gap. B10: tests and reproducibility. B11 and B12: captured demo output, if the terminal fails. B13: the paper's Figs. 3 to 5 and scheme [6]. B14: the timing measurements.
Each backup slide has its own speaker notes.


## Slide B1: B1 · The complete Verma scheme

Tags: PAPER

The scheme as Qiao et al. review it in their section IV-A; our implementation follows this description (src/cbas/verma.py). We did not cross-check Verma et al.'s original paper.
Notation: s^k_TA is the master secret key, P^k_TA the KGC public key, h^i_0 the per-signer certificate hash, Delta the public state information. 'Very' is the paper's name for the aggregate verification algorithm.
The certificate check c_i P = R_1i + H_0(id_i||pk_i) P_TA lets anyone verify a certificate from public values.


## Slide B2: B2 · The complete Qiao scheme

Tags: PAPER

The repaired scheme from the paper's section V-A; our implementation is src/cbas/scheme.py, a direct transliteration.
Two printed typos in the paper are corrected in our code: KeyGen prints pk_i = s_i, which we implement as s_i P; and the certificate check prints R_1i, which we implement as R_i.
Other inconsistencies we noticed in the paper's text: Setup declares H_1 and H_2 over five inputs with no slot for T_i, while Sign and Very hash six fields including T_i; we follow Sign and Very. Lemma 3's H_1 table omits T_i. Z*_q and Z*_p are used interchangeably.
Hash instantiation (ours): SHA-512 over a length-prefixed encoding with a distinct domain label for each of H_0, H_1, H_2, reduced mod p.
Notation map: s^k_TA is s in code, P^k_TA is pk_ta, h^i_0 is h0, Delta is delta, 'Very' is agg_verify.


## Slide B3: B3 · The full malicious-KGC derivation

Tags: REPRODUCED, PAPER

Steps (2a) to (2d) and the check (3) are the paper's section IV-B. The right-hand column also shows the one-line form with lambda = v-prime over v_i, which is ours: R-prime = R_1i + lambda (R_i - R_1i) and z-prime = c_i + lambda (z_i - c_i). It works because, once the certificate is removed, (z_i - c_i) P = (R_i - R_1i) + v_i pk_i, and multiplying both sides by lambda turns the coefficient v_i into v-prime.
The table maps each paper step to the lines of forge_verma in src/cbas/attack.py. The function takes no secret key as an argument; a test checks this.
Why it verifies: z-prime P = (v-prime r_2i / v_i) P + c_i P + sk_i v-prime P; substitute c_i P = R_1i + H_0 P_TA and pk_i = sk_i P.


## Slide B4: B4 · Why aggregate verification accepts honest signatures

Tags: PAPER

Both derivations are one-line substitutions. For Qiao et al., c_i = r_i + s h^i_0 and R_i = r_i P, T_i = t_i P, pk_i = sk_i P. For Verma et al., c_i P = R_1i + h^i_0 P_TA and R_i = R_1i + r_2i P.
These are the paper's own derivations (section V-A for Qiao et al.). Our tests check correctness for n up to 17 and tamper rejection on both backends.
The operation count of the Qiao equation is on slide 25 (scalar multiplications, term by term) and in backup B7; this slide is only about correctness.


## Slide B5: B5 · The two adversaries and the paper's proof

Tags: PAPER

The security games are the paper's section III-B; the proof is its section V-B. We have NOT audited the proofs. The bounds are quoted as printed.
F1, the malicious user, models public-key replacement: it can know sk* but never the certificate of the challenge identity. F2, the malicious KGC, knows the master key, so every certificate, but never sk*.
Theorem 1 follows from two lemmas on the single-signer scheme; aggregate security follows because the aggregator uses no secret. Lemma 2 forks the random oracle H_0 and Lemma 3 forks H_1.
Inconsistencies we noticed in the lemma texts: Lemma 3's H_1 table omits T_i although signing hashes it; Lemma 3 declares H_0 over {0,1}* x G while the construction uses x G x G; Z*_q and Z*_p are mixed; Lemma 3's secret-key query returns pk_i. We do not claim these invalidate the proof; we simply did not audit it.


## Slide B6: B6 · Why Ti appears in both hashes

Tags: OUR AUDIT

This is an audit check of ours (presentation/audit/dagger_checks.py), run on both backends; it is not part of the repository's test suite. It tests two one-shot rescaling attacks against four placements of T_i.
The KGC attack strips c_i u_i and rescales the part carrying sk_i v_i. It needs v-prime to be computable before the new commitment, so it succeeds exactly when T_i is not in H_1. The mirror attack is by a malicious user who knows sk_i but not c_i; it strips sk_i v_i and rescales the part carrying c_i u_i, and succeeds exactly when T_i is not in H_2. So each hash protects the coefficient of one secret.
Also checked: a variant that uses a single hash for both coefficients (u equal to v) with T_i bound still resisted the KGC rescaling. So we do NOT claim that separating H_1 and H_2 is needed to block this attack; it matches the paper's three-hash model, and the proof structure uses two independent coefficients.
The mirror attack is a forgery by an adversary of the paper's type F1 (knows sk, not the certificate); it is not described in the paper.


## Slide B7: B7 · The complete operation-count table

Tags: OUR AUDIT, PAPER

Both tables are printed row against counted row. Counts come from the instrumented backend and are identical on Ristretto255 and P-256; Verma's counted rows reproduce the printed rows except Sign, where the printed row omits one point addition (R_i = R_1i + r_2i P): negligible, and it does not affect the argument, since the Table III rows carry it.
Qiao's AggSign is zero group operations: n minus 1 scalar additions modulo p. The paper's (n-1) T_a overstates it; in the paper's favour, and we report it.
The chart: per-signer cost under the paper's Table IV: 125 microseconds printed against 251 recounted (ratio 2.008). The scalar multiplication T_e dominates in both.
Source for the counts: presentation/audit/verify_claims.py (reads the code), regression-tested in tests/test_opcount.py and tests/test_verma.py.


## Slide B8: B8 · Caching and precomputation, in full

Tags: OUR AUDIT

Full table behind the caching note on slide 24. 'Cache h_0' stores the hash h^i_0 per signer: derived by subtracting one hash per signer from each scheme (the repository's test covers this objection). 'Cache C_i' stores the per-signer point C_i = R_i + h^i_0 P_TA (for Verma, h^i_0 P_TA); the counts in the last row were measured by our audit script on both backends and are not yet a repository test.
Under every row the two schemes still differ, and aggregate verification stays above the printed n + 2 scalar multiplications.
Folding: sum of u_i R_i + (sum of u_i h^i_0) P_TA equals (sum of u_i c_i) P, a single multiplication, but c_i is the signer's secret certificate, unavailable to a verifier; the identity itself is checked by a repository test.
Multi-scalar multiplication (Straus, Pippenger) lowers the cost of a sum of products but is a different cost model and applies equally to both schemes.


## Slide B9: B9 · Benchmark methodology and the P-256 gap

Tags: OUR AUDIT, EXPERIMENT

Method, from bench/harness.py and bench/sweep.py. The laptop (Ryzen 5 7520U, powersave governor, boost on) ramps its clock by about 2.07x once loaded; a first sweep reported n = 100 as cheaper than n = 50 for that reason. stabilize() spins on real group operations until the cost is steady for several chunks and at least four seconds have passed. measure_many() times every workload once per round, interleaved across schemes as well as n, because the headline result is a ratio.
Runs with r squared under 0.99 are reported but excluded from the median: for both Ryzen backends the medians (2.153 and 2.366) are the same with all five runs. Machines: Ryzen 5 7520U (Python 3.12.3) and an Intel Xeon at 2.20 GHz on Kaggle (Python 3.12.13), both libsodium 1.0.18. All timings are Python plus ctypes plus the library; ratios and slopes are the defensible quantities.
P-256: the Te/Ta/Th model predicts 1.99 on P-256 but the measured median is 2.37 (range 2.18 to 2.40). Our audit prices the real hash calls, which also serialise points: 8 point serialisations per Qiao signer against 2 for Verma, about 2.2 point additions each on OpenSSL; the predicted ratio becomes 2.37 (three fresh repeats: 2.365, 2.372, 2.374). It is an audit result and not yet a repository test.
On absolute cost: n independent Ed25519 verifications are faster here than one aggregate verification (47.3 ms against 177.7 ms at n = 500 on the Xeon): aggregation buys bandwidth, not verifier CPU, in this implementation.


## Slide B10: B10 · Testing and reproducibility

Tags: EXPERIMENT, IMPLEMENTATION

All commands run from the repository root with the project's virtual environment. Code checkpoint: git tag presentation-1-interim (commit 881b7b0), branch presentation-1-work. On main, `make attack` prints a third target that belongs to a later presentation.
Test counts are collected by pytest: 221 in total. Every fixture runs on both backends (101 tests each) except 19 that do not use a backend (encoding, harness and one hashing test). The self-test has 62 checks: 31 per backend.
The audit scripts under presentation/audit/ recompute every number used in this deck from the code and the tracked benchmark JSON files, with assertions; the figures are drawn from the data they write (presentation/data/).
Not in the repository's test-suite: the C_i-caching counts, the recomputation of the paper's Figs. 3 to 5, the T_i placement checks and the P-256 real-hash prediction; they are in presentation/audit/.


## Slide B11: B11 · Demo fallback: captured output of make attack

Tags: EXPERIMENT

USE THIS if the terminal fails, the command errors, or the environment is slow. Say: 'here is the output from my earlier run' and walk the same three points as the live demo.
LEFT, Demo 1 (Target 1, Verma et al.): the honest signature verifies; the attacker is the KGC and does not know sk_i; the forged signature on the SHUTDOWN message verifies; it also survives aggregation.
RIGHT, Demo 2 (Target 2, Qiao et al.): the honest signature verifies; the forgery attempt does not succeed; 16 candidates T-prime are tried and all are different. The candidate prefixes differ on every run because the keys are random.
These are the actual stdout lines of `make attack` captured on 2026-10-07 on branch presentation-1-work (tag presentation-1-interim); nothing is edited. The files are also in presentation/demo_fallback/.
WORDING: the repaired implementation does not admit this forgery route. That is evidence, not a proof of security.


## Slide B12: B12 · Demo fallback: captured output of the ablation tests

Tags: EXPERIMENT

USE THIS if the pytest command fails or is slow. Say: 'here is the output from my earlier run.'
What to point at: ten tests, all PASSED. Eight are the forgery-restored cases of the ablated variant (4 target messages on each of 2 backends); two check that the ablated variant is still a working scheme that keeps R_i in the hashes and separate u and v.
The line at the bottom says 10 passed. Long test ids are shortened with an ellipsis in this screenshot; nothing else is edited. The file is also presentation/demo_fallback/demo3_ablation.png.
WORDING: the ablation isolates the T_i binding as the critical difference for blocking the reproduced rescaling attack. It does not show that the other changes are unnecessary, or that the full scheme is secure.


## Slide B13: B13 · The paper's figures and its comparison with [6]

Tags: OUR AUDIT, PAPER

USE THIS only if asked about the paper's Figs. 3 to 5 or about scheme [6]; the main talk does not use them.
SAY FIRST: We recomputed the paper's Figs. 3, 4 and 5 from its tables and Table IV. Every value printed on Figs. 3 and 4 reproduces exactly; Fig. 5 has no printed values, and its two lines end where the formulas say, about 63 and 126 ms at n = 500 (we read the endpoints from the plot rather than extracting its data). So the figures are calculations from the tables, not independent measurements, and they carry the table's count.
THE CHART MEANS: Grey: the repaired scheme as printed. The wide pale line: the paper's own row for scheme [6], the earlier pairing-free scheme it compares against. The dashed line: the repaired scheme recounted from its algorithm; it lies on top of [6]'s line. At n = 100 that is 25.324 against 25.319 ms: five microseconds apart, one point addition.
WHAT FOLLOWS, AND ONLY THAT: using the paper's own numbers for [6], the roughly 49 percent computational advantage drawn in its Fig. 4 (13.224 against 25.814 ms in total) is not supported. The bandwidth advantage over [6], n group elements against 2n (Table VI), is unaffected.
SAY ALOUD: We have not implemented or verified scheme [6]. We make no claim about [6]'s real speed; its row is the paper's, taken as printed. On one row the paper is generous to itself in the opposite direction: AggSign (backup B7).
IF ASKED 'is [6]'s AggSign cost overstated too?': Table VI shows its aggregate keeps 2n group elements, which suggests so, but we have not read [6].


## Slide B14: B14 · Measured time is consistent with the higher cost

Tags: EXPERIMENT

USE THIS if asked 'did you measure it?', about the method, or about the P-256 gap. The main talk gives the result in one line on slide 26.
SAY FIRST: Counting is one instrument; timing is a second, independent one. We timed aggregate verification of both schemes for n from 50 to 500, fitted straight lines and compared the per-signer slopes.
THE CHARTS MEAN: Left, one machine, an Intel Xeon on Kaggle: Qiao's slope is 356 microseconds per signer and Verma's 168. The dotted red line is what Qiao would look like if its row equalled Verma's, as Table III says; the measured points are nowhere near it. Right, all 11 recorded runs on three configurations: every ratio lies between 1.99 and 2.48, never near the 1.00 the printed rows require; the medians of the three configurations are 2.12 to 2.37. Diamonds are the ratios predicted from the operation counts.
TAKEAWAY: Independent measurements are consistent with the higher cost: about twice Verma's, not equal. We compare ratios, because our curve, library and language differ from the paper's; we make no claim about the paper's absolute hardware timings.
METHOD (backup B9): the laptop's clock ramps about 2x under load, so the CPU is warmed first, workloads are interleaved, medians are taken, and runs with a poor fit are excluded from the median; the medians are the same with or without the exclusion.
THE P-256 GAP: the simple model predicts 1.99 on P-256 but measurement gives about 2.37. Our audit found why: real hash calls also serialise points, 8 per signer for Qiao and 2 for Verma, which is expensive in OpenSSL; pricing them predicts about 2.37 (three fresh repeats). An audit result, not yet a repository test; do not call it interpreter overhead.
LIMITS: three of four machine-and-backend combinations; the Xeon is one sweep; P-256 on one machine.
IF ASKED 'why is aggregate verification slower than n Ed25519 checks?': our aggregate verification makes about five ctypes calls per signer from Python; Ed25519 is one native call. Aggregation buys bandwidth, not verifier CPU.
