# CONTEXT — handoff notes

Working notes for whoever continues this. Untracked by design (see `.gitignore`),
alongside `plan.md` and `UNDERSTANDING.md`.

- **What the paper says and why it matters**: `UNDERSTANDING.md`
- **Decision map / options per stage**: `plan.md`
- **Tracked deliverables**: `README.md`, `VERIFICATION.md`, `RESULTS.md`,
  `OPTIMIZATION.md`, `AGGREGATOR.md`

---

## 1. What this project is

Reimplementation and critical analysis of:

> Z. Qiao et al., "An Efficient Certificate-Based Aggregate Signature Scheme With
> Provable Security for Industrial Internet of Things," *IEEE Systems Journal*
> 17(1):72–82, 2023. doi:10.1109/JSYST.2022.3188012

A university course project. Three strands of output:

1. **Reproduction** — both schemes implemented, the paper's forgery against
   Verma et al.'s CB-CAS runs as working exploit code.
2. **Correction** — the cost rows the paper gives for *its own* scheme in
   Tables II and III are arithmetically wrong. Established by operation counting
   and confirmed independently by wall-clock timing.
3. **Extension** — findings the paper does not contain: which of its three fixes
   carries the security, what happens when both schemes are optimised, and a
   denial-of-service vector its system model does not cover.

**Scope discipline that must be preserved:** the paper's *security* contribution
is not disputed. Verma's scheme being KGC-forgeable is independently corroborated
(Xiong et al., IACR ePrint 2020/1027). Only the cost tables are challenged.
`VERIFICATION.md` states this explicitly; keep it that way.

---

## 2. Current state

Phases 0–4 complete and committed. `main`, 6 commits, clean tree.

```
make selftest   62 checks, both backends
make test       344 tests
make attack     forgery demo
make bench      timing sweep (both backends)
make optimize   optimised verification comparison
make dos        aggregator policy under faults
make verify     selftest + test + demo + attack
```

Everything passes. If something fails on a fresh machine, run `make selftest`
first — it depends on nothing above the group backend.

### Layout

```
src/cbas/
  backend/base.py       Backend ABC, OpCount cost model
  backend/sodium.py     Ristretto255 via libsodium (ctypes)  [default]
  backend/openssl.py    NIST P-256 via OpenSSL (ctypes)
  backend/counter.py    Te/Ta/Th/Ts/Tm counting wrapper
  backend/selftest.py   standalone algebra checks, both backends
  encoding.py           length-prefixed TLV
  hashing.py            domain-separated H0/H1/H2 (+ *_bytes variants)
  scheme.py             the six algorithms — NAIVE REFERENCE, do not optimise
  verma.py              Verma et al.'s CB-CAS — INSECURE, for attack demos
  attack.py             malicious-KGC forgery + why it fails on the fix
  ablation.py           Fix #2 removed — controlled experiment, not a scheme
  optimized.py          MSM + prepared roster + prepared signing
  aggregator.py         policies, fault localisation, sub-batch model
  demo.py, sidebyside.py
bench/
  harness.py            timing, CPU stabilisation, linear fit
  ops.py, baseline.py, sweep.py, repeat.py
  report.py             Phase 2 analysis
  optimization.py       Phase 3
  dos.py                Phase 4
  kaggle/build_kernel.py
  results/              recorded measurements (TRACKED — this is evidence)
  out/                  generated figures/json (ignored)
tests/                  344 tests, every fixture parameterised over both backends
```

---

## 3. Decisions, and why

### 3.1 Group backends

**Ristretto255 via libsodium, ctypes, as default.** The scheme's algebra needs a
**prime-order** group — the security analysis and the Section IV forgery both
invert hash scalars. Raw Curve25519/Ed25519 has cofactor 8 and is *not*
prime-order; using it would invalidate the algebra. Ristretto255 is a
prime-order quotient. Bonus: libsodium's wide scalar reduction gives unbiased
hash-to-scalar free, and canonical-encoding checks close malleability bugs at
the boundary.

**ctypes, not cffi**: the machine has `libsodium.so.23` but *no* `sodium.h`, so
cffi API mode cannot compile. ctypes needs no headers.

**P-256 via OpenSSL as a second backend.** Three reasons, all load-bearing:
curve independence of results; a *different* `Ta/Te` balance so the cost model
is tested against different constants; and differential testing between two
independent implementations. P-256 is also what real IIoT stacks deploy.

A `NullBackend`-style third backend was considered and rejected — it would test
nothing the other two don't.

### 3.2 Hashing and encoding

**Domain-separated `H0`/`H1`/`H2` is not hygiene, it is load-bearing.** The paper
applies `H1` and `H2` to *identical* inputs. Instantiate both as the same hash
and `u == v`, which collapses Fix #3 — the certificate term and secret-key term
stop having independent random-oracle coefficients and the two-sided reduction
no longer applies. `tests/test_hashing.py::test_h1_and_h2_differ_on_identical_input`
is the guard. **Never remove it.**

**Length-prefixed TLV** because the paper writes hash inputs as `a || b || ...`
over variable-length fields, which is not injective: `("ab","c")` and
`("a","bc")` concatenate identically. Field *count* is included so differing
arities cannot collide either.

**SHA-512 → wide reduce** into `Z_p*`: no modular bias, no variable-time
rejection sampling.

**`*_bytes` hash variants** exist so callers holding cached point encodings can
skip re-encoding. The convenience wrappers call straight through, so the two
paths cannot drift and produce different hashes.

### 3.3 `scheme.py` stays naive — deliberately

`scheme.agg_verify` is a direct transliteration costing `2n+2` scalar
multiplications. **That is the algorithm the paper's tables describe**, so it is
the reference the cost analysis measures. All optimisation lives in
`optimized.py`. Do not optimise `scheme.py`; it would invalidate
`VERIFICATION.md`.

### 3.4 Testing

Every fixture in `tests/conftest.py` is parameterised over both backends, so the
whole suite runs twice — this *is* the differential test.

`raw_backend` is **session-scoped**: Hypothesis rejects function-scoped fixtures
because they are not reset between generated examples. Backends are stateless so
sharing is safe.

`src/cbas/backend/selftest.py` is standalone (no pytest) because it is meant to
be the first thing run on a new machine or libsodium version.

---

## 4. Traps discovered — read before touching the backends

These all cost real time. They are the highest-value part of this document.

1. **libsodium's `crypto_scalarmult_ristretto255` returns `-1` for two different
   things**: an invalid input point, *and* a legitimate identity result (`0*P`,
   `k*O`). It writes an all-zero buffer in both cases. Conflating them silently
   substitutes the identity for a real value. Resolved structurally: untrusted
   bytes are validated exactly once at `point_from_bytes`, every `Point` carries
   a `trusted` flag, so `-1` on trusted input unambiguously means identity.

2. **ctypes truncates pointer returns.** Every OpenSSL function returning a
   pointer *must* have `restype = c_void_p` declared, or it is silently truncated
   to `c_int` on 64-bit. See `openssl.py::_declare`. Classic libcrypto-binding
   corruption.

3. **OpenSSL wrapper objects need value equality.** `_BN` and `_PT` originally
   had none, so every scalar/point comparison fell back to identity comparison
   and silently returned False. Found only by running the suite on the second
   backend.

4. **CPU frequency ramping invalidates naive sweeps.** On the dev laptop (Ryzen
   5 7520U, `powersave`, boost on) the clock ramps **2.07x** once loaded. A first
   sweep reported `n=100` as *cheaper* than `n=50`. Fixed by `harness.stabilize()`
   (spin until steady for several chunks AND ≥4 s) and `harness.measure_many()`
   (interleave every workload each round, **across schemes as well as across n**,
   because the headline result is a ratio). The Kaggle Xeon showed no ramp at
   all, so both cases are covered.

5. **An "optimisation" tuned to one backend can pessimise another.** Expressing
   `sum(T_i)` as MSM terms with scalar one made the no-native-MSM fallback pay
   `3n+1` scalar multiplications against naive's `2n+2` — 0.85x, a regression.
   `Backend.multi_scalar_mul` now adds scalar-one terms directly.

6. **Unequal treatment biases comparisons.** An early Phase 3 measurement applied
   the prepared roster to CBAS but only MSM to Verma, and reported 1.63 —
   apparently showing optimisation closes the gap. The honest figure with equal
   treatment is 3.04, in the *opposite* direction. Any scheme-vs-scheme
   comparison must optimise both sides identically.

7. **Check the objective is not degenerate.** The first sub-batch model maximised
   *delivery*, which is trivially optimal at `k=1` — aggregation abandoned.
   Charging `verify(k) = fixed + k*per_sig` from measured costs gives a real
   interior optimum.

8. **Point representation differs by a factor of 767** in encode/add ratio:
   P-256/OpenSSL 2.302, Ristretto255/libsodium 0.003. libsodium stores a point
   *as* its encoding (encoding free, every add pays decode+encode); OpenSSL keeps
   Jacobian coordinates (add cheap, encoding needs a modular inversion). This one
   fact explains both the `Ta/Te` asymmetry in Phase 2 and why cached encodings
   are worth 1.7x on P-256 and nothing on Ristretto.

9. **matplotlib must be in `.venv`**, not just system Python.

10. **Don't future-date commits.** One was set to 23:45 while the clock read
    22:57; amended.

---

## 5. The central claims and their evidence

### Claim: Tables II and III understate this scheme's own cost

| Operation | Published | Measured | Table |
|---|---|---|---|
| `Sign` | `1Te + 1Th` | `1Te + 2Th` | II |
| `Verify` | `3Te + 2Ta + 2Th` | `4Te + 3Ta + 3Th` | II |
| `AggVerify` | `(n+2)Te + (n+1)Ta + 2nTh` | `(2n+2)Te + 3nTa + 3nTh` | III |
| `AggSign` | `(n-1)Ta` | 0 group ops (**over**stated) | III |

Evidence chain:

- **Paper's own text**: Sign step (b) writes two hash calls; Verify step (a) says
  "for i from 1 to n" over three hashes; AggSign contains no group operation.
- **The instrument reproduces Verma's published rows exactly** and fails to
  reproduce this scheme's — locating the error in the row, not the method.
  `tests/test_verma.py::test_verma_aggverify_cost_matches_its_published_row`.
- **Internal contradiction**: Table II charges Scheme [6] `2Th` for a two-hash
  Sign, then charges this scheme's two-hash Sign `1Th`.
- **Objections tested, not asserted**: `h_i0` caching (fails — Verma's is equally
  cacheable); algebraic folding of `sum(u_i R_i)` (the identity holds, but `c_i`
  is secret). Both in `tests/test_opcount.py`.
- **Counts identical on both curves, both machines.**
- **Wall clock agrees**: slope ratios 2.153 (Ristretto/Ryzen), 2.366
  (P-256/Ryzen), 2.123 (Ristretto/Xeon) where published rows require 1.000.
- **`n=100` under the paper's own Table IV costs**: 12.729 ms claimed — *exactly*
  the value plotted in Fig. 4, so that figure inherits the error — against
  25.324 ms actual.

Known soft spot: the P-256 cross-check closes to 19%, not 0.5%, because
interpreter overhead is a larger share where point addition is cheap, and that
overhead is unequal between schemes (CBAS does 3 hashes/signer to Verma's 2).
Stated plainly in `RESULTS.md`; do not quietly drop it.

### Claim: Fix #2 is what carries the security

`ablation.py` is the control — the repaired scheme with **only** Fix #2 removed
(`T` dropped from `H1`/`H2`), Fixes #1 and #3 intact. The variant is a
self-consistent scheme, and the forgery succeeds against it. So binding the nonce
commitment into the hashes is the operative change, not the `R`-in-`H0` binding
nor the two-oracle split.

### Claim: optimising widens the gap

With MSM + prepared roster applied to **both** schemes, the per-signer ratio goes
from 2.379 to **3.005**, tracking the MSM term ratio `3n+1 : n+2` → 2.99. The
defence "a real implementation would batch" runs the wrong way.

---

## 6. Working conventions (the user asked for these)

- **Ask before committing.** Every time. No exceptions.
- **Short, formal commit messages** — subject plus ~4–6 lines saying *what*
  changed at a high level. Rationale belongs in code comments and the tracked
  `.md` files, not the commit body.
- **No attribution lines.** No `Co-Authored-By`, no "Generated with".
- **Untracked**: `docs/` (copyrighted PDFs — must never reach GitHub),
  `plan.md`, `UNDERSTANDING.md`, `CONTEXT.md`, `.venv/`, `bench/out/`,
  `bench/kaggle/build/`.
- **Tracked as evidence**: `bench/results/*.json`.
- **Prove, don't assume.** The user has asked for this explicitly. Profile before
  optimising; check a library exports a symbol before designing around it; run
  the experiment before reporting the number.
- History was rewritten once to squash and backdate (5–6 h gaps). Ongoing commits
  use real timestamps. A future rewrite of pushed history would need care — there
  is no remote yet, but the user intends to add GitHub.
- **Kaggle is available** (`~/.kaggle/kaggle.json`, user `anuragkaushal183`).
  `make kaggle-kernel` builds a self-contained script;
  `kaggle kernels push -p bench/kaggle/build`. **CPU only** — the workload is
  sequential 255-bit modular arithmetic; GPUs and fp16 have nothing to contribute.
  Use it for a *second machine*, which is what it earned its keep as.

---

## 7. Future plan

### Phase 5 (proposed, not started) — security analysis the paper omits

**5a. Rogue-key analysis.** The paper proves single-signer EUF-CMA and argues
aggregate security informally ("the aggregator uses no secrets"). Aggregate
schemes historically break under rogue-key attacks, where an attacker registers
`pk_adv` derived from honest keys. Certificate-based issuance plus `R` bound into
`H0` *plausibly* blocks this, but it is never argued.
*Technically*: try to construct `pk_adv = a*P - sum(honest pk_i)` style keys and
see whether `CertGen` binding defeats it; if it does, write the argument down.
Either a working attack or a proof sketch is a result. Start from
`tests/test_forgery.py` for the harness shape.

**5b. Nonce-reuse key recovery.** Derived but not implemented: because
`z = t + c*u + sk*v` carries **two** secrets, reuse of `t` needs **three**
signatures, not two. Two give one equation in two unknowns; three give two
equations and recover both `c` and `sk`. Implement as a runnable demo — sensor
RNGs are exactly where this happens. Also consider adding hedged nonces
(`t = PRF(sk, m, random)`) as a mitigation, which is defensible for IIoT.

**5c. Forward-security claim.** §V-C.4 is one unproven sentence and does not
match the standard definition — nothing in the scheme evolves keys. State the
mismatch precisely and fairly. This is a *negative* finding; frame it carefully.

### Later, roughly in value order

- **Bandwidth quantification.** Cheap and completes the compactness story:
  Verma's aggregate is `1|G| + 1|Z_q|` (64 B) against this scheme's
  `n|G| + 1|Z_q|` (~16.5 KB at `n=500`, compressed). Put that against real IIoT
  link budgets (ZigBee 250 kbps, LoRaWAN, NB-IoT) and duty cycles.
- **Reduction tightness.** The `1/(e·q·(x1+x2+1))` factor is very loose. What
  curve size is needed for 128-bit *concrete* security? Analysis only, no code.
- **Revocation via `Δ`.** The paper never pins down what `Δ` is. Proposing
  `Δ = epoch identifier` and analysing revocation granularity vs re-issuance cost
  is a small original contribution. CBC is marketed on simplified revocation and
  this scheme does not specify the mechanism.
- **IIoT system simulation.** MQTT over Mosquitto (the actual IIoT protocol; the
  broker is a natural aggregator site), then `tc netem` for realistic links —
  which is where the bandwidth trade actually becomes visible. Ladder is in
  `plan.md` §S7.
- **Post-quantum framing.** Discussion section: the scheme dies to Shor; compare
  Falcon/Dilithium sizes, noting they do not aggregate.

### Deliberately not done, with reasons

- **Python-level Pippenger/Strauss.** Profiled first: per-call overhead dominates
  (measured `Ta/Te` 0.39 where real EC arithmetic gives ~0.003), so trading one
  scalar multiplication for many additions *loses*. Used OpenSSL's native
  `EC_POINTs_mul` instead. Note it is deprecated in OpenSSL 3.0 — still exported
  and functional, but track its removal.
- **GPU MSM.** Technically applicable (the terms are independent) but would not
  change the operation counts the tables report, and no comparison in the paper
  is GPU-based.
- **Leakage resilience** (the paper's own stated future work) — a separate
  research project, not a course project extension.
- **Formal verification** (EasyCrypt/Tamarin) — very high effort; `plan.md` §S10
  levels 6–7 if ever wanted.

---

## 8. If you change something, check this

- Touching `hashing.py` → `test_h1_and_h2_differ_on_identical_input` must still
  pass. That test guards Fix #3.
- Touching `scheme.py` → `tests/test_opcount.py` pins the exact counts. If they
  move, either the transliteration drifted or the counting model changed; both
  need a hard look, and `VERIFICATION.md` / `RESULTS.md` need updating.
- Touching `optimized.py` → `tests/test_optimized.py` compares every fast path
  against the naive reference on both backends. An optimisation that changes
  which signatures are accepted is not an optimisation.
- Adding a backend → implement `Backend`, register in `backend/__init__.py::BACKENDS`,
  and the whole suite plus selftest will run against it automatically.
- Adding a group operation to `Backend` → `CountingBackend` delegates explicitly
  rather than via `__getattr__`, so it will fail loudly until you decide the new
  operation's cost class. That is intentional.
