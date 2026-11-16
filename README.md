# Certificate-Based Aggregate Signature for IIoT

Reference implementation, cryptanalysis, and independent cost evaluation of the
certificate-based aggregate signature (CBAS) scheme proposed in:

> Z. Qiao, Q. Yang, Y. Zhou, B. Yang, Z. Xia, M. Zhang, and T. Wang,
> "An Efficient Certificate-Based Aggregate Signature Scheme With Provable
> Security for Industrial Internet of Things," *IEEE Systems Journal*, vol. 17,
> no. 1, pp. 72–82, Mar. 2023.
> doi: [10.1109/JSYST.2022.3188012](https://doi.org/10.1109/JSYST.2022.3188012)

## Overview

Both the scheme proposed by Qiao et al. and the earlier scheme it replaces
(Verma et al.'s CB-CAS, 2020) are implemented over two independent elliptic
curve backends — Ristretto255 via native libsodium and NIST P-256 via native
OpenSSL. The implementation is used for three things:

1. **Reproduction.** The paper's central security claim — that a malicious key
   generation centre (KGC) can universally forge signatures under Verma et
   al.'s scheme — is run as executable code, against both schemes, on both
   curves.
2. **Correction.** The paper's own computational-cost tables (Tables II and
   III) understate the repaired scheme's cost by close to a factor of two.
   This is established by direct operation counting, by wall-clock timing on
   two curves and two machines, and by cross-checking against the paper's own
   published figures.
3. **Extension.** Analysis beyond the paper: a strictly stronger, key-only
   forgery against Verma's scheme that needs no observed signature; which of
   the repair's two hash bindings stops which forgery; how the cost gap changes
   under realistic optimisation; a denial-of-service vector in the aggregation
   model; key recovery from a reused nonce on sensors; and the paper's replay
   and forward-security claims.

The first reproduces a claim made in the paper; the other two are original to
this project. The table below lists each finding with its evidence.

## Key findings

| # | Finding | Nature | Evidence |
|---|---|---|---|
| 1 | Verma et al.'s CB-CAS is universally forgeable by a malicious KGC | Reproduction of the paper's Section IV-B result | [`attack.py`](src/cbas/attack.py) |
| 2 | Verma et al.'s CB-CAS is also forgeable by a **key-only** attacker who has never observed a signature — a strictly stronger break, contradicting the paper's Table II rating of Verma's scheme as secure against a malicious user | Original | [KEYONLY_FORGERY.md](analysis/KEYONLY_FORGERY.md) |
| 3 | The repaired scheme's own published costs (Tables II, III) are understated by ~2×; the paper's Fig. 4 plots the understated value | Original | [VERIFICATION.md](analysis/VERIFICATION.md), [RESULTS.md](analysis/RESULTS.md) |
| 4 | Realistic optimisation (native multi-scalar multiplication, cached per-signer state), applied best-effort to both schemes, does *not* close the cost gap: about 2.4× before and after | Original | [OPTIMIZATION.md](analysis/OPTIMIZATION.md) |
| 5 | One invalid signature invalidates an aggregate and hides the culprit (a known property of aggregation the paper's model omits); measured: individual verification costs only 1.7× its amortised share, so pre-verifying is cheap from about one bad signature per batch | Known property; measured policy crossover original | [AGGREGATOR.md](analysis/AGGREGATOR.md) |
| 6 | Each of the scheme's two corrective hash bindings independently closes a different forgery; neither protects against the other's | Original | [KEYONLY_FORGERY.md](analysis/KEYONLY_FORGERY.md) |
| 7 | A reused signing nonce gives away all of a sensor's secrets: 3 signatures for an outsider, 2 for the KGC; hedged nonces prevent it with no verifier change | Original application of a standard attack | [OPEN_ANALYSIS.md](analysis/OPEN_ANALYSIS.md) |
| 8 | The paper's "resist replay attacks" and "perfect forward security" claims (Sec. V-C) do not hold: old signatures replay, and a key stolen later signs for earlier periods | Original | [OPEN_ANALYSIS.md](analysis/OPEN_ANALYSIS.md) |

## Getting started

### Requirements

- Python 3.10+
- libsodium ≥ 1.0.18 with Ristretto255 support (accessed via `ctypes`; no
  development headers required)
- OpenSSL ≥ 3.0 (accessed via `ctypes`, for the NIST P-256 backend)

### Installation

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev,bench]'
```

### Verification

Run in this order on a new machine:

```bash
make selftest   # 62 group-algebra checks, both curves — depends on nothing else
make test       # 424 tests: 199 run on both backends, 26 need no backend
```

## Usage

| Command | Purpose |
|---|---|
| `make selftest` | Standalone algebraic self-test of the group backends |
| `make test` | Full test suite |
| `make attack` | The malicious-KGC forgery against both schemes, then the key-only forgery |
| `make bench` | Timing sweep and cost analysis, both backends |
| `make bench-repeat` | Repeated timing sweeps, reported with spread |
| `make hashcost` | Price the real hash calls in the timing model (explains the P-256 gap) |
| `make optimize` | Naive vs. optimised verification, both schemes |
| `make dos` | Aggregator policy comparison under signature faults |
| `make nonce` | Key recovery from a reused nonce, and the hedged-nonce defence |
| `make plots` | Render figures from the most recent `make bench` run |
| `make kaggle-kernel` | Build a self-contained script for a second-machine run |
| `make verify` | Self-test, full test suite, and all three demonstrations (walkthrough, `attack`, `nonce`) |
| `make clean` | Remove caches |

## The KGC forgery

`make attack` runs one attacker against both schemes: a malicious KGC holding
the master secret key and every issued certificate, who has observed exactly
one honest signature and does **not** know any user's secret key.

```
Verma et al. CB-CAS  : BROKEN  — universal forgery by the KGC
Qiao et al. CBAS     : held    — attack does not apply
```

It then runs the key-only forgery (Target 3): an attacker holding only the
victim's public key forges against Verma's scheme and fails against the
repaired scheme.

Verma's flaw is confined to one line: `v_i = H1(m_i‖pk_i‖id_i‖Δ)` omits the
per-signature nonce, so the signing equation is affine in a coefficient the
attacker already knows, and an affine relation with a known coefficient can be
rescaled to any other message. That omission is also what buys the scheme a
constant-size aggregate — the compactness and the vulnerability are the same
design decision.

Against the repaired scheme, binding the nonce commitment `T_i` into the hash
makes the analogous rescaling circular: computing the coefficient for a new
message requires `T_i`, but the attack's own construction defines `T_i` in
terms of that coefficient. `attempt_forge_fixed` runs this as a fixed-point
search and every candidate is distinct — forging reduces to finding a fixed
point of a random oracle, not an algebraic shortcut.

A controlled ablation ([`ablation.py`](src/cbas/ablation.py)) isolates which of
the scheme's two hash-binding corrections is load-bearing for this specific
attack: removing the nonce-commitment binding alone (leaving the other
correction intact) reopens the forgery. See
[KEYONLY_FORGERY.md](analysis/KEYONLY_FORGERY.md) for the complementary experiment and
the full 2×2 result.

## Design decisions

- **Two independent group backends** — Ristretto255/libsodium (default) and
  NIST P-256/OpenSSL. The scheme's algebra requires a prime-order group;
  Curve25519/Ed25519 has cofactor 8 and does not qualify, which is why
  Ristretto255 rather than raw Ed25519. The second backend exists so that no
  result depends on one curve, one library, or one balance of primitive costs,
  and so two independent implementations can be checked against each other.
  Every test that touches the group runs on both.
- **Domain-separated `H0`/`H1`/`H2`** — the paper applies `H1` and `H2` to
  identical inputs; instantiating both as the same hash function collapses
  part of the security argument (see [`hashing.py`](src/cbas/hashing.py)).
- **Length-prefixed encoding of hash inputs** — the paper specifies hash
  inputs by concatenation of variable-length fields, which is not injective
  (see [`encoding.py`](src/cbas/encoding.py)).
- **Instrumented operation counting** — every group operation and hash call is
  routed through a single counted interface
  ([`backend/counter.py`](src/cbas/backend/counter.py)), which is what makes
  the cost measurements in [VERIFICATION.md](analysis/VERIFICATION.md) possible.

## Documentation

| Document | Contents |
|---|---|
| [CBAS_Final_Report.pdf](CBAS_Final_Report.pdf) | The project report (LaTeX source in [report/](report/); `make -C report` rebuilds it) |
| [Final presentation](presentation/CBAS_Final_Presentation.pdf) | The final presentation slides ([.pptx](presentation/CBAS_Final_Presentation.pptx)) |
| [VERIFICATION.md](analysis/VERIFICATION.md) | The Table II/III cost correction: evidence, objections considered, and scope |
| [RESULTS.md](analysis/RESULTS.md) | Independent wall-clock confirmation, two curves, two machines |
| [OPTIMIZATION.md](analysis/OPTIMIZATION.md) | Optimised verification and its effect on the cost comparison |
| [AGGREGATOR.md](analysis/AGGREGATOR.md) | The denial-of-service vector and its mitigations |
| [KEYONLY_FORGERY.md](analysis/KEYONLY_FORGERY.md) | The key-only forgery and the 2×2 ablation result |
| [OPEN_ANALYSIS.md](analysis/OPEN_ANALYSIS.md) | Nonce reuse, and the paper's replay and forward-security claims |

## Repository structure

```
src/cbas/
  backend/
    base.py             group interface and cost model
    sodium.py           Ristretto255 via libsodium (ctypes)
    openssl.py          NIST P-256 via OpenSSL (ctypes)
    counter.py          Te/Ta/Th operation-counting wrapper
    selftest.py         standalone algebraic self-test, both backends
  encoding.py           length-prefixed TLV encoding
  hashing.py            domain-separated H0/H1/H2
  scheme.py             the six algorithms of the repaired scheme (naive reference)
  verma.py              Verma et al.'s CB-CAS — insecure, for attack demonstrations only
  attack.py             the malicious-KGC forgery
  ablation.py           the T binding removed — controlled experiment
  ablation_r.py         the R binding removed — the complementary experiment
  keyonly_attack.py     the key-only universal forgery
  optimized.py          multi-scalar-multiplication and prepared-roster verification
  aggregator.py         pre-verification, fault localisation, sub-batching
  nonce_reuse.py        key recovery from a reused nonce; hedged-nonce signing
  nonce_demo.py         the nonce-reuse demonstration
  demo.py               end-to-end walkthrough of the repaired scheme
  sidebyside.py         both forgeries against both schemes
tests/                  424 tests (199 x 2 backends + 26 backend-independent)
bench/
  harness.py            timing, CPU stabilisation, linear fitting
  ops.py, baseline.py, sweep.py, repeat.py, report.py, plots.py
  optimization.py       naive vs. optimised verification comparison
  hashcost.py           real hash-call cost, for the P-256 timing model
  dos.py                aggregator policy comparison under faults
  kaggle/               self-contained script for a second-machine run
  results/              recorded measurements (tracked as evidence)
analysis/               one write-up per finding (linked above)
report/                 LaTeX source of the project report
presentation/
  CBAS_Final_Presentation.pptx / .pdf   the final slides
  audit/verify_claims_final.py          recomputes and asserts every number in the deck
  data/                                 the numbers the deck uses, written by the audit
  figures/, demo_fallback_final/        figure and captured demo output used in the deck
CBAS_Final_Report.pdf   the project report
```

## Related work cited

- G. K. Verma, B. B. Singh, N. Kumar, and V. Chamola, "CB-CAS: Certificate-Based
  Efficient Signature Scheme With Compact Aggregation for Industrial Internet
  of Things Environment," *IEEE Internet of Things Journal*, vol. 7, no. 4,
  pp. 2563–2572, 2020 — the scheme shown broken.
- S. Goldwasser, S. Micali, and R. L. Rivest, "A Digital Signature Scheme
  Secure Against Adaptive Chosen-Message Attacks," *SIAM J. Computing*,
  vol. 17, no. 2, pp. 281–308, 1988 — the attack/forgery taxonomy used in
  [KEYONLY_FORGERY.md](analysis/KEYONLY_FORGERY.md).

## Scope note

This project does not dispute the paper's central claim (Verma et al.'s scheme
is broken by a malicious KGC, and the repair resists that attack), and it did
not audit the paper's security proof. The findings above concern the paper's
cost tables, its Table II rating of Verma's scheme, its aggregation system
model, nonce generation on sensors, and its replay and forward-security claims
(Sec. V-C). Verma's scheme is implemented from Qiao et al.'s description
(Sec. IV-A), not from Verma et al.'s original article.
