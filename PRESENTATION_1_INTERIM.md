# Presenter guide: the interim presentation

This file explains the deck so that you can present it from understanding rather
than from memory. Read sections 1 to 6 once, then use section 7 (the slide guide)
as your rehearsal sheet.

- Deck: `presentation/CBAS_Interim_Presentation.pptx` (PDF beside it)
- Full speaker notes, every slide: `presentation/speaker_notes.md` (also inside the .pptx)
- Code checkpoint: git tag `presentation-1-interim` (commit `881b7b0`)
- The main talk is **27 slides** (the last one is "What remains for the final presentation"), then **Thank You**, then **backup slides B1-B14**
  that you open only if a question needs them.

## 1. The whole talk in one paragraph

Many sensors sign their readings. An aggregator combines the signatures so the
cloud can check them all at once. In a *certificate-based* scheme, signing needs two
secrets held by two parties (the sensor's key and a certificate from the KGC), so the
KGC alone must not be able to sign. Verma et al. proposed such a scheme. Qiao et al.
showed that a malicious KGC can forge a signature on any new message from **one**
valid signature, without ever learning the sensor's secret key or the signature's
random nonce. We ran that attack. Qiao et al. then repaired the scheme by hashing the
signature's commitment `T_i` into the hash; we show that this blocks the reproduced
attack, and that removing only that binding brings the attack back. Finally, we
checked the paper's performance table: the cost printed for the repaired scheme does
not follow from its own verification equation, and our timings are consistent with
the higher cost.

## 2. What the audience must leave with (say these three at the end)

1. **How the KGC forges without `r_2i` or `sk_i`:** it never opens them. It rescales a
   combination that contains them.
2. **Why binding `T_i` changes the algebra:** the new commitment and the new hash value
   would each need the other.
3. **Why the cost rows do not follow from the algorithm:** the printed AggVerify row
   is Verma's row; the paper's own equation needs two scalar multiplications per
   signer, not one.

## 3. Whose claim is it? (say this early, and keep it straight)

Every slide carries a small tag. This is the most important habit to keep.

| Tag | Meaning | Examples in this talk |
|---|---|---|
| PAPER | a claim made by Qiao et al. | the malicious-KGC attack on Verma (their §IV-B); the repair; the EUF-CMA proof; Tables II-IV |
| REPRODUCED | we re-ran it and it held | the attack on Verma: 8 of 8 forgeries verify |
| IMPLEMENTATION | a choice we made | two group backends, hash encoding, the ablated variant |
| EXPERIMENT | something we measured or ran | ablation results, timings, the demos |
| OUR AUDIT | our own finding, not in the paper | recount of the cost rows, the caching test, the ablation as a causal test |

Say it out loud: **"The attack is from the paper; we reproduced it."** Never say we
discovered it. What is ours is the ablation, the cost audit and the measurements.

**What we never claim**

- that we proved the repaired scheme secure (the paper proves EUF-CMA security under
  the discrete-logarithm assumption in the random-oracle model; **we did not audit that
  proof**);
- that a failed attack proves security, or that "0 of 8" means impossible;
- that we verified Verma's original paper (we implemented Qiao's description of it,
  their §IV-A);
- that we benchmarked scheme [6] (we only take the paper's own printed row for it);
- that our timings reproduce the paper's absolute hardware numbers (different curve,
  library and language; we compare ratios).

## 4. Learn the attack in plain words (the technical heart)

**Setting.** A signature from sensor `i` is `(R_i, z_i)` with

- `R_i = R_1i + r_2i P`  (commitment: the certificate's point plus the sensor's nonce)
- `v_i = H_1(m_i || pk_i || id_i || Δ)`  (a hash anyone can compute)
- `z_i = r_2i + c_i + sk_i v_i`  (response)

The KGC issued the certificate `(R_1i, c_i)`, so it knows both. It does **not** know
`r_2i` (fresh randomness) or `sk_i`.

**The one fact that makes it work.** `v_i` does not depend on `R_i` or `r_2i`. So the
KGC can compute the hash for *any* message before it has built a commitment.

**The attack, as steps you can say aloud.**

1. *Subtract the certificate.* `r_2i P = R_i - R_1i` (a point), and
   `z_i - c_i = r_2i + sk_i v_i` (one number made of two unknowns: keep it sealed).
2. *Normalise by `v_i`.* `α = (z_i - c_i)/v_i = r_2i/v_i + sk_i` and
   `A = (R_i - R_1i)/v_i = (r_2i/v_i) P`. The KGC holds both, but not their parts.
3. *Choose a new message `m'`.* `v'_i = H_1(m' || pk_i || id_i || Δ)`, computable at once.
4. *Rescale.* `R'_i = R_1i + v'_i A` and `z'_i = v'_i α + c_i`.
5. *It verifies.* Expanded, `R'_i = R_1i + (v'_i r_2i/v_i) P` and
   `z'_i = v'_i r_2i/v_i + c_i + sk_i v'_i`: exactly an honest signature with a new nonce
   `v'_i r_2i/v_i` that nobody knows.

**A picture to keep in your head.** The KGC holds a sealed envelope containing
`r_2i + sk_i v_i`. It cannot open it. But if a signature on a new message just needs
the envelope's contents multiplied by a number `v'_i/v_i` that it *can* compute, it
multiplies the envelope without opening it.

**One-line form** (backup B3): with `λ = v'_i/v_i`,
`R'_i = R_1i + λ(R_i - R_1i)` and `z'_i = c_i + λ(z_i - c_i)`.

**If a professor interrupts with "but it doesn't know r_2i or sk_i":** "Correct, and it
never learns them. It only scales the combination `r_2i/v_i + sk_i` that it already
holds. The new signature's nonce is `v'_i r_2i/v_i`, which nobody needs to know."

## 5. Learn the repair and the ablation in plain words

**Old:** the message goes into the hash; the commitment `R_i` (carrying `r_2i`) does
not. So the hash for a new message can be computed first.

**New:** the commitment `T_i = t_i P` goes into the same hash as the message
(`v_i` and also `u_i = H_2(...)`). To rescale, the attacker would need a new commitment
`T'_i = (v'_i/v_i) T_i`, but `v'_i` is now the hash of a string that contains `T'_i`.
**`T'_i` affects `v'_i`, and `v'_i` affects `T'_i`.** The old direct route is gone.

Say: *"This explains why the reproduced attack no longer works. It does not prove the
scheme secure; the paper's proof is the formal argument, and we did not audit it."*

**Demo 2** shows the same strategy adapted to Qiao's equation failing: 16 candidates,
all different, none verifies. It is evidence about one route, not a proof.

**Ablation (the causal test).** Three cases, same attacker, 4 messages × 2 backends:

| | Construction | Result |
|---|---|---|
| A | Verma | attack succeeds, 8 of 8 |
| B | Qiao (repaired) | attack fails, 0 of 8 (16 candidates each) |
| C | Qiao with **only** `T_i` removed from the hashes | attack succeeds again, 8 of 8 |

C is a working scheme (honest signatures verify, other messages are rejected), and it
imports everything else from the repaired code. So the ablation **isolates the `T_i`
binding as the critical difference for blocking the reproduced rescaling attack.** It
does *not* show the other changes are unnecessary (the paper hashes `R_i` against a
different attacker, which we did not test), and it does not show the full scheme is
secure.

## 6. Learn the performance audit in plain words

The chain: **equation → count → cost → measurement.** It is the shape of the argument, but the main talk
compresses it into **two slides (24: the claim against the recount; 25: where the extra cost comes from, term by term)**, and gives the timing result as one line on slide 26. The detail is in the
backups: B7 (the full count table), B8 (caching), B9 (benchmark method and the P-256 gap), B13 (the paper's figures
and scheme [6]) and B14 (the timing charts).

1. **Paper formula.** Tables II and III print identical costs for Verma's scheme and
   for the repaired scheme, e.g. AggVerify `(n+2)Te + (n+1)Ta + 2nTh`. (`Te` = one scalar
   multiplication, `Ta` = one point addition, `Th` = one hash.)
2. **Our count of the paper's own equation (slide 25 shows it term by term).**
   `zP = ΣT_i + Σu_iR_i + (Σu_ih_0^i)P_TA + Σv_ipk_i` has two multiplications per signer
   (`u_iR_i` and `v_ipk_i`). Total `(2n+2)Te + 3nTa + 3nTh`. Also: Sign has two hashes,
   single Verify is `4Te + 3Ta + 3Th`, and AggSign has no group operation at all
   (the paper overstates that row, in its own favour).
3. **Calibration.** The same counter, run on Verma's equation, reproduces Verma's
   printed rows exactly. So the discrepancy sits in the printed row, not in the method.
4. **Cost model.** Use the paper's own Table IV (`Te` 0.112, `Ta` 0.005, `Th` 0.004 ms).
   At n = 100: **12.729 ms printed** (exactly the bar in the paper's own Fig. 4) against
   **25.324 ms recounted**, a factor of 1.99 (1.95 if the verifier caches every per-signer
   constant). These are model values, not measurements.
5. **Caching objection (one sentence on slide 24; full table in B8).** Caching reproduces the printed
   single-Verify row, but Verma's row drops too, and aggregate verification still needs
   at least `2n+1` scalar multiplications against the printed `n+2`.
6. **Scheme [6] (backup B13 only; not in the main talk).** Using the paper's own row for [6], our recount lands on it
   (25.324 vs 25.319 ms), so the computational advantage drawn in Fig. 4 is not
   supported *by the paper's own numbers*. **We have not verified scheme [6]** and make no
   claim about its real speed. The bandwidth advantage (n vs 2n group elements) is untouched.
7. **Measurement (one line on slide 26; charts in B14).** Per-signer slope ratio, Qiao ÷ Verma: 2.12 to 2.37 on three
   configurations (11 recorded runs: 1.99 to 2.48), where the printed rows imply 1.00.
   The simple model predicts 1.99 on P-256 but we measure about 2.37; pricing the real
   hash calls (which also serialise points) predicts about 2.37 (our audit).

**The key message:** *the printed AggVerify cost does not follow from the paper's own
verification equation, and independent measurements are consistent with the higher
cost.* It does **not** invalidate the cryptographic construction.

## 7. Slide guide (30-45 seconds each)

"Say first" is your opening sentence. "20-min" is the shortened route (section 8).
Tags are the small coloured chips at the top right of each slide.

### Part I: motivation

| # | Message | Say first | 20-min |
|---|---|---|---|
| 1 | The paper (title slide) | "This is the paper we studied: we ran its attack, tested its repair and checked its cost numbers." | keep |
| 2 | The hook and the setting | "Why is this paper interesting? One question: can a malicious key authority forge sensor data? Here is the system: sensors sign, an aggregator combines, the cloud verifies; the KGC only acts at the start." Name the six algorithms in order: Setup, KeyGen, CertGen, Sign, AggSign, AggVerify. | keep, quick |
| 3 | Why aggregate | "n signatures become one aggregate and one check." | skip |
| 4 | Who holds the key | Three columns; end on "the KGC alone must not be able to sign." (PKI / identity-based are standard background, labelled so.) | quick |
| 5 | The threat | Postbank example from the paper; read the three questions; point at the tag legend. | keep |

### Part II: the existing scheme (Verma et al., as described by Qiao et al.)

| # | Message | Say first | 20-min |
|---|---|---|---|
| 6 | Who generates what | "Same system as an event diagram; padlocks are secrets; grey dashed steps are not specified by the paper." | skip |
| 7 | Keys and certificate | "The KGC knows the certificate because it made it; only the sensor knows its secret key." | quick |
| 8 | Signing | "`z_i` is nonce + certificate + secret key times a hash." Point at the bottom: **`v_i` never sees `R_i` or `r_2i`.** | keep |
| 9 | Verification | "The aggregate is one point and one scalar; that comes from keeping `R_i` out of the hash." | quick |

### Part III: the malicious-KGC attack

| # | Message | Say first | 20-min |
|---|---|---|---|
| 10 | The attacker | "It knows everything except the two sealed secrets." (cue: KGC does NOT know `sk_i` or `r_2i`) | keep |
| 11 | The puzzle | Read the question, pause. "It does not open the sealed number; it rescales it." | keep |
| 12 | Step 1 | Subtract the certificate. | combine 12-14 |
| 13 | Step 2 | Normalise by `v_i`: get `α` and `A`. | combine |
| 14 | Step 3 | New message, new `v'_i`, build `R'_i`, `z'_i`. | combine |
| 15 | End to end | "Look only at the red sealed boxes: they are never opened. The verifier accepts." | keep |
| 16 | **Demo 1** | Run `make attack`; three points: honest verifies, attacker does not know `sk_i`, forgery verifies. | keep |

### Part IV: the repair

| # | Message | Say first | 20-min |
|---|---|---|---|
| 17 | Qiao's objects | "Same six algorithms; `T_i` (green) is the new object that travels with each signature." | skip |
| 18 | What changed | "Look at the three middle rows; grey rows are context." | quick |
| 19 | Old vs new | "Old: message and commitment are not coupled through the hash. New: both are inputs, so `T'` affects `v'` and `v'` affects `T'`." (cue: key idea) | keep |
| 20 | **Demo 2** | Target 2: 16 candidates, none verifies. "Evidence, not proof." | quick, screenshot |
| 21 | Ablation design | "Same repaired code with exactly one thing removed." | quick |
| 22 | Ablation result + **Demo 3** | A succeeds, B fails, C succeeds again. "The ablation isolates the `T_i` binding." | keep |

### Part V: implementation

| # | Message | Say first | 20-min |
|---|---|---|---|
| 23 | Built and checked | "One interface, two independent groups; 62 self-test checks, 221 tests; identical counts on both." | quick |

### Part VI: the cost claim

| # | Message | Say first | 20-min |
|---|---|---|---|
| 24 | Is the repaired scheme really as cheap as Verma's? | "The paper prints the same cost as Verma's scheme. Counting its own verification equation gives two scalar multiplications per signer, not one: 12.729 ms printed against 25.324 ms at n = 100, about twice." Say aloud: **model values, not measurements.** One sentence on caching (24.807 ms, still about twice). Point to B7 / B8 if pressed. (cue: model values, not measurements) | keep (1 min 15 s) |
| 25 | Where the extra cost comes from | "Here are the two verification equations, term by term, with the scalar multiplications under each. Verma's equation counts to n+2, exactly the printed row. The repaired equation has one more term, `Σ u_i R_i`, in red: n more. So 2n+2." Point at the red box. Additions and hashes are in B7. | quick (45 s) |

### Part VII: conclusion and what comes next

| # | Message | Say first | 20-min |
|---|---|---|---|
| 26 | Established / not | Reproduced, our audit (the timing result is one line here: 2.12 to 2.37, where the printed rows imply 1.00), not established. Say the three things to remember. (cue: 3 things to remember) | keep |
| 27 | What remains for the final presentation | "Today we reproduced and audited; next we test the repaired scheme itself." Read the four headings: faster verification, the aggregator in practice, a second look at the attack, open analysis (nonce reuse, forward-security claim). Do not give results for these today. | keep, quick |
| 28 | Thank you | **Stop.** Do not advance into the appendix unless asked. | keep |

**Where the old cost slides went.** The earlier version had seven cost slides. Their content is now slides 24 and 25 plus
backups: the full count table is B7, caching is B8, the method is B9, "the paper's figures and scheme [6]" is **B13**, and
"measured time" is **B14**. Open B13 or B14 only if asked ("what about [6]?", "did you measure it?").

## 8. Timing and the 20-minute route

- **Full talk: about 25 minutes** (an estimate: the cost section is now one slide instead of seven; time
  yourself once), including the three live demos (about 4 to 5 minutes in total), before questions.
- **20-minute route:** the per-slide times in the notes add up to about 18 minutes of speaking, which
  leaves slack for a demo that runs long. Skip 3, 6 and 17 (cover them in one sentence
  on the neighbouring slide); present 12 to 14 together in about two minutes; show
  Demo 2 from the screenshot; keep 1, 2, 5, 8, 10, 11, 15, 16, 19, 22, 24, 25 (quick), 26, 27 (quick);
  everything else quickly. No slide is deleted; the route is marked in each slide's
  speaker notes under "20-MINUTE ROUTE".

## 9. Live demos and fallbacks

Run from a checkout on branch `presentation-1-work` (it is the same code as the tag), or
`git worktree add ../ris-p1-demo presentation-1-interim` and build its own `.venv`. On
`main`, `make attack` prints a third target that belongs to a later talk.

| Demo | Slide | Command | You should see | Fallback |
|---|---|---|---|---|
| 1 | 16 | `make attack` (Target 1) | forged sig verifies `True`, "FORGERY SUCCEEDED" | Backup **B11** |
| 2 | 20 | same output, Target 2 | `forgery succeeded : False`, 16 iterations, "all distinct" | Backup **B11** |
| 3 | 22 | `.venv/bin/python -m pytest tests/test_forgery.py -k ablat -vv` | 10 PASSED, "10 passed" (use `-vv`: the config adds `-q`) | Backup **B12** |

Optional if asked: `make selftest` (62 checks), `.venv/bin/python -m cbas.demo` (claimed vs
measured counts).

The slides themselves already show the expected output, and B11/B12 hold the actual
captured output (also in `presentation/demo_fallback/`). If a command fails or is slow,
say "here is the output from my earlier run" and continue. Do not debug on stage. Do not
run `make bench` live (minutes, and the laptop clock ramps).

**Before the talk:** run `make selftest` once on the presentation machine; use a large
terminal font; keep the PDF open as a second fallback. The title slide already shows the
three names, Research in Information Security and IIIT Hyderabad; no date is shown.

## 10. Presenter cues (the small yellow notes)

Twelve slides carry a small note labelled "PRESENTER CUE" at the top right: slides
10, 11, 12, 13, 14, 15, 16, 19, 20, 22, 24 and 26. They are reminders for you, not
audience content. Slides 16 and 20 click through to B11 in slideshow mode. To produce a
version without them: `/path/to/deckenv/bin/python presentation/build/build_deck.py --no-cues`.

## 11. Likely professor questions: short answers

1. **"The KGC doesn't know `r_2i` or `sk_i`. How does it forge?"** It never needs them.
   It scales the combination `r_2i/v_i + sk_i` it already holds by `v'_i`; the new
   signature's nonce is `v'_i r_2i/v_i`. This works because `v_i` does not depend on `r_2i`.
2. **"Why does `T_i` stop it?"** The attack must fix the new commitment before computing
   the new hash value, but the new commitment is defined from that hash value. Each needs
   the other.
3. **"Does a failed attack prove security?"** No. It is evidence about one route. The
   paper's EUF-CMA proof (discrete logarithm, random-oracle model) is the formal argument,
   and we did not audit it.
4. **"What did you reproduce, and what is original?"** Reproduced: the paper's attack on
   Verma and the repair's resistance to it. Original: the ablation, the cost audit
   (recount, calibration, caching test) and the timing confirmation.
5. **"What does the ablation prove?"** With everything else fixed, the `T_i` binding is
   necessary for blocking this attack. Not that other changes are unnecessary, and not that
   the scheme is secure.
6. **"How do you know your count is right?"** The same counter reproduces Verma's printed
   rows exactly and gives identical counts on two independent backends.
7. **"Could caching explain the discrepancy?"** It explains the single-Verify row but not
   the aggregate row, and it changes Verma's row too; aggregate verification still needs at
   least `2n+1` scalar multiplications against the printed `n+2`.
8. **"Is scheme [6] slower or faster in reality?"** (backup B13) We have not verified it. We only say
   that, using the paper's own row for [6], the advantage drawn in its Fig. 4 is not
   supported by the paper's numbers.
9. **"Why do your milliseconds differ from the paper's?"** Different curve, library and
   language. We compare per-signer ratios (about 2, against 1.00 implied), not absolute times.
10. **"Does this invalidate the paper?"** No. The attack and repair hold up in our runs; the
    discrepancy concerns the cost rows and the comparison that rests on them.

More (why certificate-based, why a malicious KGC is realistic, why `H_1` and `H_2`, why
`R_i` is hashed, why two backends, why 2.37 on P-256, what the paper proves): the notes of
slide 26 hold short answers to all 18 prepared questions.

## 12. Soft spots: know them before you are asked

- The Verma code follows Qiao's §IV-A description; Verma's original paper is not cross-checked.
- The paper's proofs are not audited; we noticed inconsistencies in the lemma texts (B5).
- The caching counts, the recomputation of the paper's Figs. 3-5 (B13), the `T_i` placement
  checks (B6) and the P-256 explanation are audit scripts in `presentation/audit/`, not
  repository tests. Fig. 5 was matched by eye at its endpoints.
- Timings (B9, B14): three of four machine-and-backend combinations; the Xeon is one sweep; P-256
  was timed on one machine. Aggregate verification is slower than `n` separate Ed25519
  checks in our code: aggregation buys bandwidth, not verifier CPU.
- A variant with one hash for both coefficients (`u = v`) still resisted the KGC rescaling
  in our check, so we do **not** claim the split of `H_1` and `H_2` is needed against this
  attack (B6).
- Do not cite Xiong et al. (ePrint 2020/1027) as corroboration: its abstract does not
  mention Verma's CB-CAS and we did not verify the body.

## 13. Where things are

| What | Where |
|---|---|
| Deck, PDF, notes | `presentation/` (`CBAS_Interim_Presentation.pptx`, `.pdf`, `speaker_notes.md`) |
| Rebuild instructions | `presentation/README.md` |
| Every number in the deck | `presentation/data/claims.json`, recomputed by `presentation/audit/verify_claims.py` |
| Cost-table evidence, objections | `VERIFICATION.md` |
| Timing evidence and methodology | `RESULTS.md` |
| Demo fallbacks | `presentation/demo_fallback/` and backup slides B11, B12 |
