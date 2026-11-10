# Presentation 2 (Final) — Beyond the Paper

**Code checkpoint:** `main`, current HEAD. Unlike Presentation 1, this talk
does not need a frozen tag — it presents the project's current state, and can
absorb new work right up to the day of the talk.

## Content readiness

Update this table as work proceeds; it is the honest, at-a-glance status of
this talk's material.

| Section | Status | Where |
|---|---|---|
| Optimisation (widens the gap) | **Done** | `OPTIMIZATION.md`, `src/cbas/optimized.py` |
| Aggregator / DoS vector | **Done** | `AGGREGATOR.md`, `src/cbas/aggregator.py` |
| Key-only universal forgery + 2x2 ablation | **Done** | `KEYONLY_FORGERY.md`, `src/cbas/keyonly_attack.py`, `ablation_r.py` |
| Nonce-reuse key recovery | Not started | — |
| Forward-security claim critique | Not started | — |
| Bandwidth / compactness quantification | Not started (optional) | — |
| MQTT / system simulation | Not started (optional) | — |

The three **Done** rows are each a complete, tested, independently-verified
result — this talk is presentable in full today. The two "Not started" items
below the line are what would round it out further, not what it depends on.

## Objective

Show that this project went beyond faithfully reproducing and correcting the
paper (Presentation 1) to finding things about the *repaired* scheme — the one
the paper claims is secure and efficient — that the paper itself does not
discuss, including one attack its own authors appear to have missed.

## Structure

### 1. Recap (1 slide)

One sentence each: reproduced the paper's forgery, corrected its cost tables,
confirmed on two curves and two machines. This talk builds on that foundation.

### 2. Optimisation: the gap widens, not closes (3–4 slides)

- The naive algorithm costs `2n+2` scalar multiplications for the repaired
  scheme against Verma's `n+2` — a natural objection is "a real implementation
  would batch these; would that change the comparison?"
- Two optimisations, applied to **both** schemes equally: multi-scalar
  multiplication (a native library call — `EC_POINTs_mul` — evaluating the
  whole verification equation in one call instead of one call per term), and a
  prepared signer roster (an IIoT sensor fleet is static, so each signer's
  public-key encoding and one hash are invariant across every batch and can be
  cached).
- **Result**: per-signer cost ratio goes from 2.36 naive to **3.04**
  optimised. Verma's equation has `n+2` terms to this scheme's `3n+1`; as
  per-term cost falls, the ratio converges toward that term-count ratio (2.99)
  rather than toward 1.
- **The self-correction story** (worth telling — it demonstrates the process,
  not just the result): an earlier version of this measurement applied the
  prepared-roster optimisation to one scheme but not the other, and reported
  1.63 — apparently showing optimisation closes the gap. That number was an
  artefact of unequal treatment; the honest, equal-treatment figure is 3.04,
  in the opposite direction. Caught before it became a claim.
- One honest limitation: on the backend without a native multi-scalar
  routine (libsodium), the naive fallback for that optimisation was initially
  a *regression* (slower than naive) until fixed. Worth a sentence — it shows
  the numbers were actually measured, not assumed.

### 3. The aggregator: a denial-of-service vector the paper's model omits (3 slides)

- The paper treats the aggregator as a pure function that "does not use their
  own private information, only merges signatures." True, but it hides a
  problem: once signatures are summed into one scalar, an aggregate with even
  one invalid signature fails entirely, and **the individual bad signature
  cannot be identified** from the aggregate afterward. One faulty sensor
  denies service to every honest sensor batched with it.
- Three policies, measured: `BLIND` (the paper's model — cheapest, but a
  single fault loses the whole batch and the culprit is unrecoverable),
  `PREVERIFY` (check every signature before aggregating), `RETAIN` (aggregate
  optimistically, keep the individuals, and on failure locate the fault by
  divide-and-conquer in `O(f log n)` verifications rather than `n`).
- **Result**: the crossover is low — around a 0.5% fault rate — because
  individual verification is only 2x the amortised aggregate cost, not the
  order of magnitude one might assume. In an adversarial setting, where an
  attacker chooses the fault rate, `PREVERIFY` is the conservative default.
- Framing point: this is a systems-level contribution, not a cryptographic
  one — the security proof is untouched, this is about availability.

### 4. The headline: a key-only universal forgery (5–6 slides + live demo)

This is the strongest result of the project. Give it the most stage time.

- **Set up the comparison.** The paper's own attack (shown in Presentation 1)
  needs the attacker to be a malicious KGC, or to have captured one honest
  signature. Frame the question: is that the *weakest* attack against Verma's
  scheme, or just the one the paper happened to find?
- **The Goldwasser-Micali-Rivest taxonomy** (cite it — this is standard,
  70s/80s-vintage terminology, not invented for this project): attacks are
  classified by what the adversary is given (a *key-only attack* sees nothing
  but the public key), forgeries by what results (a *universal forgery* is
  valid on an arbitrary, verifier-chosen message). Key-only attack + universal
  forgery is the strongest possible combination.
- **The mechanism, one slide, the algebra in full.** Verma's check is
  `z*P == R + h0*P_TA + v*pk`. Neither `h0` nor `v` depends on `R`, and `R`'s
  coefficient is 1. Fix any `z`, solve: `R := z*P - h0*P_TA - v*pk`. Ordinary
  point arithmetic — no discrete log, no signature, no interaction with
  anyone. Draw the parallel explicitly: this is exactly why Schnorr signatures
  hash the commitment together with the message (`c = H(R, m)`, not `H(m)`) —
  standard, citable folklore, confirmed independently against course material
  on Schnorr signatures during this project's research.
- **Live demo**: `make attack`, Target 3 — forge a signature attributed to a
  real, honestly-enrolled victim's public key, having observed nothing.
- **Why the repaired scheme resists it.** `R` is now an input to all three
  hash functions, so solving for it requires already knowing hashes that are
  themselves functions of it — a fixed-point search over a 2^256 space, run
  live in the demo as an iteration that never settles.
- **The closing visual: the 2x2 matrix.** The scheme applies two corrections
  at once, so "the attack fails" does not say which one is responsible. Two
  single-fix ablations (`ablation.py`, `ablation_r.py`) answer it precisely —
  every cell below is a passing or failing test, not an assertion:

  | | `R` bound everywhere | `R` **not** bound |
  |---|---|---|
  | **`T` bound everywhere** | real scheme: safe | broken via **R** |
  | **`T` not bound** | broken via **T** | Verma: broken via **R** |

  Each correction independently closes its own door and does nothing for the
  other's — a cleaner and more general result than "fix #2 stops the known
  attack," because it explains *why*, generalises to a design principle, and
  reveals that the ablation built to demonstrate the paper's known attack was
  *also* vulnerable to a simpler attack nobody had pointed at it before.

### 5. Synthesis (1–2 slides)

State the general principle explicitly, since it's the most transferable
takeaway: **any commitment that appears in a verification equation without
being bound into a hash is a free variable, and a free variable with a known
coefficient can always be solved for.** The paper states a version of this for
one specific variable (`T`), in the context of the one attack it found; this
project's finding is that the same mechanism applies to *either* relevant
variable independently, and generalises the paper's own design lesson.

### 6. Limitations and future work (1–2 slides)

- Honestly flag: nonce-reuse key recovery (derived analytically — because the
  signing equation has two secrets, reuse needs three signatures sharing a
  nonce, not two, to recover both — but not yet implemented as a runnable
  demo) and a critique of the paper's one-sentence, unproven "perfect forward
  security" claim (it does not match the standard definition, since nothing in
  the scheme evolves keys) are both identified but not yet built out.
- The P-256 cross-check between operation counts and measured time does not
  close as tightly as the Ristretto255 one (19% residual vs <1%) — attributed
  to interpreter overhead that is not evenly split between the two schemes.
  Worth stating as a limitation of the timing *model*, not of the underlying
  operation-count claim, which two curves and two machines agree on.

### 7. Conclusion (1 slide)

Three independent findings beyond the paper (optimisation direction,
availability gap, stronger forgery), each verified by running code rather than
asserted, on two unrelated cryptographic backends.

## Live-demo checklist

- [ ] On `main`, up to date.
- [ ] `make test` — confirm the full suite is green before presenting (currently
      378 tests).
- [ ] `make attack` — all three targets; Target 3 is the centrepiece.
- [ ] `make optimize` — the naive-vs-optimised comparison, both schemes.
- [ ] `make dos` — the aggregator policy table.
- [ ] Have `KEYONLY_FORGERY.md`'s 2x2 table ready as a static backup slide in
      case the live fixed-point demo needs a second run (it is probabilistic
      in its exact iteration count, though not in its outcome).

## Anticipated questions

- **"Does the key-only forgery contradict the paper's security proof for the
  repaired scheme?"** No — a key-only attack is strictly weaker than the
  chosen-message attack the proof already covers, so if the proof is correct
  this result is an implication of it, made concrete and explicit. The finding
  is about *Verma's* scheme and about *which* mechanism in the repaired scheme
  is doing the work, not a break of the repaired scheme.
- **"Why is a wider optimisation gap a bad thing for the repaired scheme?"**
  It isn't a security problem — it is a performance-comparison problem. It
  means the paper's claim of comparable efficiency to Verma's scheme
  understates the real cost even further once realistic optimisation is
  applied on both sides.
- **"Is the aggregator DoS vector a flaw in the scheme, or in how someone might
  deploy it?"** The latter — the cryptography is not at fault; the paper's
  system model simply does not address it, and a deployer following the paper
  literally (`BLIND` aggregation) would be exposed.
- **"How confident are you in the 2x2 matrix?"** Every cell is a passing test
  against running code, on two independent backends — not a claim, a
  reproducible experiment.

## Reference material

[OPTIMIZATION.md](OPTIMIZATION.md), [AGGREGATOR.md](AGGREGATOR.md),
[KEYONLY_FORGERY.md](KEYONLY_FORGERY.md).
