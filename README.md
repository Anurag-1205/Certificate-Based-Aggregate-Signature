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
   forgery against Verma's scheme that needs no observed signature; a
   denial-of-service vector in the repaired scheme's aggregation model; and an
   evaluation of how the cost gap changes under realistic optimisation.

Finding 1 reproduces a claim made in the paper. Findings 2 and 3 are original
to this project.

## Key findings

| # | Finding | Nature | Evidence |
|---|---|---|---|
| 1 | Verma et al.'s CB-CAS is universally forgeable by a malicious KGC | Reproduction of the paper's Section IV-B result | [`attack.py`](src/cbas/attack.py) |
| 2 | Verma et al.'s CB-CAS is also forgeable by a **key-only** attacker who has never observed a signature — a strictly stronger break | Original | [KEYONLY_FORGERY.md](KEYONLY_FORGERY.md) |
| 3 | The repaired scheme's own published costs (Tables II, III) are understated by ~2×; the error also explains a discrepancy in the paper's Fig. 4 | Original | [VERIFICATION.md](VERIFICATION.md), [RESULTS.md](RESULTS.md) |
| 4 | Realistic optimisation (native multi-scalar multiplication, cached per-signer state) *widens* the cost gap between the two schemes, from 2.4× to 3.0× | Original | [OPTIMIZATION.md](OPTIMIZATION.md) |
| 5 | Aggregate verification has an unaddressed denial-of-service vector: one invalid signature invalidates a batch, with no way to identify which signature was at fault | Original | [AGGREGATOR.md](AGGREGATOR.md) |
| 6 | Each of the scheme's two corrective hash bindings independently closes a different forgery; neither protects against the other's | Original | [KEYONLY_FORGERY.md](KEYONLY_FORGERY.md) |

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
make test       # 378 tests, every test parameterised over both backends
```

## Usage

| Command | Purpose |
|---|---|
| `make selftest` | Standalone algebraic self-test of the group backends |
| `make test` | Full test suite |
| `make attack` | Run the forgeries against both schemes, side by side |
| `make bench` | Timing sweep and cost analysis, both backends |
| `make bench-repeat` | Repeated timing sweeps, reported with spread |
| `make optimize` | Naive vs. optimised verification, both schemes |
| `make dos` | Aggregator policy comparison under signature faults |
| `make plots` | Render figures from the most recent `make bench` run |
| `make kaggle-kernel` | Build a self-contained script for a second-machine run |
| `make verify` | Self-test, full suite, and both demonstrations |

## The KGC forgery

`make attack` runs one attacker against both schemes: a malicious KGC holding
the master secret key and every issued certificate, who has observed exactly
one honest signature and does **not** know any user's secret key.

```
Verma et al. CB-CAS  : BROKEN  — universal forgery by the KGC
Qiao et al. CBAS     : held    — attack does not apply
```

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
[KEYONLY_FORGERY.md](KEYONLY_FORGERY.md) for the complementary experiment and
the full 2×2 result.

## Design decisions

- **Two independent group backends** — Ristretto255/libsodium (default) and
  NIST P-256/OpenSSL. The scheme's algebra requires a prime-order group;
  Curve25519/Ed25519 has cofactor 8 and does not qualify, which is why
  Ristretto255 rather than raw Ed25519. The second backend exists so that no
  result depends on one curve, one library, or one balance of primitive costs,
  and so two independent implementations can be checked against each other.
  Every test is parameterised over both.
- **Domain-separated `H0`/`H1`/`H2`** — the paper applies `H1` and `H2` to
  identical inputs; instantiating both as the same hash function collapses
  part of the security argument (see [`hashing.py`](src/cbas/hashing.py)).
- **Length-prefixed encoding of hash inputs** — the paper specifies hash
  inputs by concatenation of variable-length fields, which is not injective
  (see [`encoding.py`](src/cbas/encoding.py)).
- **Instrumented operation counting** — every group operation and hash call is
  routed through a single counted interface
  ([`backend/counter.py`](src/cbas/backend/counter.py)), which is what makes
  the cost measurements in [VERIFICATION.md](VERIFICATION.md) possible.

## Documentation

| Document | Contents |
|---|---|
| [VERIFICATION.md](VERIFICATION.md) | The Table II/III cost correction: evidence, objections considered, and scope |
| [RESULTS.md](RESULTS.md) | Independent wall-clock confirmation, two curves, two machines |
| [OPTIMIZATION.md](OPTIMIZATION.md) | Optimised verification and its effect on the cost comparison |
| [AGGREGATOR.md](AGGREGATOR.md) | The denial-of-service vector and its mitigations |
| [KEYONLY_FORGERY.md](KEYONLY_FORGERY.md) | The key-only forgery and the 2×2 ablation result |
| [PRESENTATION_1_INTERIM.md](PRESENTATION_1_INTERIM.md) | Interim presentation outline (reproduction and correction) |
| [PRESENTATION_2_FINAL.md](PRESENTATION_2_FINAL.md) | Final presentation outline (extensions beyond the paper) |

## Repository structure

```
src/cbas/
  backend/
    base.py            group interface and cost model
    sodium.py           Ristretto255 via libsodium (ctypes)
    openssl.py           NIST P-256 via OpenSSL (ctypes)
    counter.py           Te/Ta/Th operation-counting wrapper
    selftest.py          standalone algebraic self-test, both backends
  encoding.py           length-prefixed TLV encoding
  hashing.py            domain-separated H0/H1/H2
  scheme.py             the six algorithms of the repaired scheme (naive reference)
  verma.py              Verma et al.'s CB-CAS — insecure, for attack demonstrations only
  attack.py             the malicious-KGC forgery
  ablation.py           corrective binding #2 removed — controlled experiment
  ablation_r.py         corrective binding #1 removed — the complementary experiment
  keyonly_attack.py     the key-only universal forgery
  optimized.py          multi-scalar-multiplication and prepared-roster verification
  aggregator.py         pre-verification, fault localisation, sub-batching
  demo.py               end-to-end walkthrough of the repaired scheme
  sidebyside.py         both forgeries against both schemes
tests/                  378 tests, parameterised over both backends
bench/
  harness.py            timing, CPU stabilisation, linear fitting
  ops.py, baseline.py, sweep.py, repeat.py, report.py, plots.py
  optimization.py       naive vs. optimised verification comparison
  dos.py                aggregator policy comparison under faults
  kaggle/                self-contained script for a second-machine run
  results/               recorded measurements (tracked as evidence)
```

## Related work cited

- G. K. Verma, B. B. Singh, N. Kumar, and V. Chamola, "CB-CAS: Certificate-Based
  Efficient Signature Scheme With Compact Aggregation for Industrial Internet
  of Things Environment," *IEEE Internet of Things Journal*, vol. 7, no. 4,
  pp. 2563–2572, 2020 — the scheme shown broken.
- H. Xiong, Y. Hou, X. Huang, and S. Kumari, "Certificate-Based Parallel
  Key-Insulated Aggregate Signature Against Fully Chosen-Key Attacks for
  IIoT," IACR ePrint 2020/1027 — independent corroboration that Verma et al.'s
  scheme is forgeable by a malicious KGC.
- S. Goldwasser, S. Micali, and R. L. Rivest, "A Digital Signature Scheme
  Secure Against Adaptive Chosen-Message Attacks," *SIAM J. Computing*,
  vol. 17, no. 2, pp. 281–308, 1988 — the attack/forgery taxonomy used in
  [KEYONLY_FORGERY.md](KEYONLY_FORGERY.md).

## Scope note

The paper's security proof and its central claim about Verma et al.'s scheme
are not disputed by this project. The corrections and extensions above concern
the paper's *cost* tables and its *aggregation* system model, not the validity
of its security reduction for the repaired scheme.
