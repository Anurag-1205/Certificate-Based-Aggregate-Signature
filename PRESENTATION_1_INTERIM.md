# Presentation 1 (Interim) — Reproduction and a Verified Correction

**Code checkpoint:** git tag `presentation-1-interim` (commit `a8859af`).
Before this presentation, run `git checkout presentation-1-interim` in a clean
copy of the repo (or a worktree) so every live demo matches exactly what is on
the slides — no Phase 3–5 code (optimisation, aggregator, key-only forgery) is
present at this tag, deliberately.

```bash
git worktree add ../ris-p1-demo presentation-1-interim
cd ../ris-p1-demo
python3 -m venv .venv && .venv/bin/pip install -e '.[dev,bench]'
.venv/bin/python -m cbas.backend.selftest   # 62 checks, both backends
.venv/bin/python -m pytest -q               # 227 tests
.venv/bin/python -m cbas.sidebyside         # the forgery, live
```

## Framing this talk correctly

Two very different kinds of claim live in this checkpoint, and the talk should
say so explicitly rather than blur them:

| | What it is | Whose claim |
|---|---|---|
| The malicious-KGC forgery against Verma et al. | **Reproduction** — the paper's own Section IV-B result, implemented and run | The paper's |
| The Table II/III cost correction | **Original** — a discrepancy the paper does not acknowledge, found by us | Ours |

Say this out loud early in the talk. Claiming the forgery as "our finding"
would be inaccurate and an easy thing for a questioner to puncture; claiming
too little for the cost correction undersells the actual contribution. The
honest framing is also the more impressive one: "we reproduced the paper's own
attack faithfully, and *in addition* found something it does not mention."

## Objective

Establish, before anything more ambitious is shown in the final talk: this
project understands the paper's construction precisely enough to reimplement
it correctly, has verified its central security claim by running the break it
describes, and has found and independently confirmed one concrete error in the
paper's own numbers.

## Structure

### 1. Motivation (2 slides)

- Industrial IoT: sensors → aggregator → cloud, why data authentication matters.
- Why *aggregate* signatures (bandwidth), why *certificate-based* specifically
  (no key escrow, unlike identity-based; no certificate-distribution overhead,
  unlike PKI).
- Hook: the Postbank incident cited in the paper's own introduction — a
  malicious insider with the master key stole $3.2M. This is precisely the
  threat certificate-based crypto is supposed to prevent, and precisely the
  threat the paper shows a competing scheme fails to prevent.

### 2. The paper's construction (2–3 slides)

- The six algorithms: `Setup, KeyGen, CertGen, Sign, AggSign, AggVerify`.
- The two-adversary security model: `F1` (malicious user, may know a secret
  key but never the certificate of the target) and `F2` (malicious KGC, may
  know the master key but never a target's secret key).
- Verma et al.'s CB-CAS and its headline feature: a **constant-size** aggregate
  signature, independent of the number of signers.

### 3. Implementation (2 slides)

- Two independent group backends: Ristretto255 via native libsodium, NIST
  P-256 via native OpenSSL — for curve-independent results and differential
  testing (two unrelated implementations must agree on every signature).
- Two implementation-level requirements the paper's pseudocode does not
  specify, both load-bearing: **domain-separated hashing** (`H1` and `H2` are
  applied to identical inputs in the paper; instantiating both as the same
  hash function collapses part of the scheme's security argument) and
  **length-prefixed encoding** of hash inputs (naive concatenation of
  variable-length fields is ambiguous — `("ab","c")` and `("a","bc")`
  concatenate identically).
- This is a good place to signal engineering maturity: the project did not
  just transliterate pseudocode, it found and closed gaps the pseudocode
  leaves open.

### 4. Reproducing the paper's own attack (3 slides + live demo)

- Verma's flaw in one line: the per-signature nonce commitment `R_i` is never
  hashed, so the equation is affine in a coefficient the attacker knows.
- The forgery: a malicious KGC captures one signature, and without ever
  learning the signer's secret key, rescales it to a signature on any message
  of the attacker's choosing.
- **Live**: `make attack` (Target 1) — construct the forgery, show it verifies.
- Then show the same code against the *repaired* scheme (Target 2) failing,
  and explain the one-line fix: binding `T_i` into the hash makes the
  rescaling step circular — a fixed point of a random oracle over a 2^256
  space, not an algebraic shortcut.
- Mention the ablation (`ablation.py`): removing *only* this fix, while
  leaving the paper's other correction intact, reopens exactly this attack —
  confirming which specific change carries the security, rather than just
  trusting the paper's narrative about it.

### 5. The centrepiece: correcting the paper's own cost tables (4–5 slides)

This is the section to spend the most time on — it is verifiable in real time
and does not require the audience to trust a security argument, only
arithmetic.

- **The claim.** Tables II and III give the repaired scheme's own computation
  costs as *identical* to Verma's broken scheme's costs. That cannot be right:
  the repaired verification equation has an extra per-signer term (`u_i R_i`)
  and an extra hash (`H2`) that Verma's does not.
- **The paper's own text, verbatim.** Quote Section V-A directly: Sign
  computes `v_i` *and* `u_i` (two hashes); Verify says "for i from 1 to n,
  compute `h_i0`, `v_i` and `u_i`" (three hashes); AggSign contains no group
  operation at all. Show these next to Table II/III's claimed costs.
- **The decisive check.** The same counting method, applied to Verma's own
  equation, reproduces Verma's published row *exactly*. A method that gets one
  row right and the other wrong locates the error in the row, not the method.
- **The internal contradiction.** Table II charges a competing scheme
  (Verma's PFCBAS, "Scheme [6]") two hash operations for a two-hash `Sign`,
  then charges this paper's own two-hash `Sign` one hash. Same paper, same
  table, two different conventions.
- **The measured numbers**, side by side with the claim:

  | Operation | Paper claims | Measured |
  |---|---|---|
  | `Sign` | `1Te + 1Th` | `1Te + 2Th` |
  | `Verify` (single) | `3Te + 2Ta + 2Th` | `4Te + 3Ta + 3Th` |
  | `AggVerify` | `(n+2)Te + (n+1)Ta + 2nTh` | `(2n+2)Te + 3nTa + 3nTh` |
  | `AggSign` | `(n-1)Ta` | 0 group operations (**overstated**, in the paper's favour) |

- **The smoking gun.** Under the paper's own Table IV per-operation costs, at
  `n = 100` the claimed formula evaluates to **12.729 ms** — which is *exactly*
  the value plotted in the paper's own Fig. 4. The figure was generated from
  the wrong formula and inherits its error. The measured cost is 25.324 ms —
  a factor of 1.99.
- **Independent confirmation, twice over.** The same discrepancy — a
  per-signer cost ratio near 2, not 1 — is reproduced by direct wall-clock
  timing (not just counting operations), on two unrelated curves (Ristretto255
  and NIST P-256, in two unrelated libraries), and on two unrelated machines
  (a laptop and a cloud CPU on Kaggle). Show the sweep graph
  (`bench/out/fig_aggverify_vs_n_*.png`, regenerate with `make bench && make
  plots` before the talk).
- **State the scope explicitly, both ways.** The paper's *security*
  contribution is not in question here — Verma's scheme being forgeable by a
  malicious KGC is independently corroborated by other authors (Xiong et al.,
  IACR ePrint 2020/1027), and is not disputed. Only the cost tables are wrong.
  And be fair in the other direction too: `AggSign`'s cost is *overstated*, not
  just the others understated — this is a correction, not a takedown.

### 6. Status and roadmap (1 slide)

- What is done: everything above, tested (227 tests, both backends), timed on
  two machines.
- Tease, without detail: "we are now asking whether the *repaired* scheme has
  weaknesses of its own that the paper's proof does not rule out in practice —
  that is the final presentation."

## Live-demo checklist

- [ ] `git checkout presentation-1-interim` in a **separate** worktree so the
      main branch (with Phase 3–5 work) is undisturbed.
- [ ] `make selftest` — 62 checks pass, confirms the crypto backend before
      anything else is trusted.
- [ ] `make attack` — the forgery succeeding on Verma, failing on the fix.
- [ ] `make bench && make plots` — regenerate the figures fresh, don't rely on
      stale images.
- [ ] Have `VERIFICATION.md` open to quote the paper's verbatim text if
      challenged on the cost-table claim.

## Anticipated questions

- **"How do you know your counting method is right and not the paper's?"**
  Because it reproduces the paper's *own* published row for Verma's scheme
  exactly, and only diverges on the row that is inconsistent with the
  algorithm the same paper defines two pages earlier.
- **"Does this mean the paper is wrong to trust?"** No — the security proof and
  the central claim (Verma is broken, the fix works) both hold up under our
  own independent reimplementation and attack. Only the performance numbers
  are affected.
- **"Why does the discrepancy matter if the scheme still 'works'?"** Because
  the paper's whole comparative argument — "our scheme is as fast as Verma's
  but secure" — rests on Table II/III being right. It is not; the repaired
  scheme costs roughly twice what the paper claims relative to the insecure
  one.
- **"Could this be a units or convention difference, not an error?"** No — the
  same convention, applied to the same paper's other rows, reproduces them
  exactly. The inconsistency is internal to the paper, not a matter of
  interpretation.

## Reference material

Full technical detail, evidence, and objections considered and rejected:
[UNDERSTANDING.md](UNDERSTANDING.md) (background), [VERIFICATION.md](VERIFICATION.md)
(the cost-table correction, full evidence chain), [RESULTS.md](RESULTS.md) (the
independent wall-clock confirmation).
