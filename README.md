# Certificate-Based Aggregate Signature for IIoT

A Python implementation, over native libsodium, of the certificate-based
aggregate signature (CBAS) scheme of:

> Z. Qiao, Q. Yang, Y. Zhou, B. Yang, Z. Xia, M. Zhang and T. Wang,
> "An Efficient Certificate-Based Aggregate Signature Scheme With Provable
> Security for Industrial Internet of Things," *IEEE Systems Journal*,
> vol. 17, no. 1, pp. 72-82, March 2023. doi:10.1109/JSYST.2022.3188012

## Status

Phase 1 complete. Both schemes implemented, the malicious-KGC forgery runs
against Verma et al.'s CB-CAS, and a controlled ablation isolates which of the
three fixes actually carries the security.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'

make selftest   # backend algebra - run this first on a new machine
make test       # full test suite (112 tests)
make attack     # side-by-side forgery demonstration
make verify     # everything
```

## The forgery

`make attack` runs one attacker against both schemes. It is a malicious KGC: it
holds the master secret key and the certificates it issued, it has seen exactly
one honest signature, and it does **not** know any user's secret key.

```
Verma et al. CB-CAS  : BROKEN  - universal forgery by the KGC
Qiao et al. CBAS     : held    - attack does not apply
```

Against Verma the attacker produces a valid signature on any message it likes,
from a single observed signature, and the forgery aggregates alongside honest
signatures undetected. The flaw is one line: `v_i = H1(m_i || pk_i || id_i || D)`
omits the nonce, so the signing equation is affine in a coefficient the attacker
knows -- and an affine relation with a known coefficient can be rescaled to any
other. That omission is what buys Verma a constant-size aggregate, so the
compactness and the break are the same design decision.

Against the repaired scheme the same attack becomes circular: computing `v'` for
a new message needs `T'`, but the attack defines `T' = (v'/v_i) * T_i` in terms
of `v'`. `attempt_forge_fixed` iterates the fixed-point search and reports every
candidate as distinct -- forging reduces to finding a fixed point of a random
oracle.

### Which fix carries the security

The repaired scheme makes three changes at once, so failing against it does not
by itself say which one matters. `src/cbas/ablation.py` supplies the control:
the repaired scheme with **Fix #2 alone removed** (`T` dropped from `H1` and
`H2`), Fixes #1 and #3 left intact. The ablated variant is a self-consistent
scheme -- it signs, verifies, and rejects tampering -- and **the forgery
succeeds against it**.

So binding the nonce commitment into the hashes is the load-bearing change, not
the `R`-in-`H0` binding and not the two-independent-oracle split.

## Design decisions

**Group: Ristretto255 via native libsodium (ctypes).** The scheme's algebra
assumes a group of *prime* order -- the security analysis and the Section IV
forgery both invert hash scalars. Raw Curve25519/Ed25519 has cofactor 8 and is
not prime-order; Ristretto255 is a prime-order quotient of it. libsodium's
wide scalar reduction also gives unbiased hash-to-scalar for free, and its
canonical-encoding checks close a class of malleability bugs at the boundary.

**Domain-separated `H0`/`H1`/`H2`.** The paper applies `H1` and `H2` to
*identical* inputs. Instantiating both as the same hash makes `u == v`, which
collapses the scheme's third fix: the certificate term and the secret-key term
would no longer have independent random-oracle coefficients, and the two-sided
security reduction would not apply. See `src/cbas/hashing.py`.

**Length-prefixed TLV hash inputs.** The paper writes hash inputs as `a || b ||
...` over variable-length fields, which is ambiguous -- `("ab","c")` and
`("a","bc")` concatenate identically. See `src/cbas/encoding.py`.

**Instrumented operation counting.** Every group operation and hash routes
through one counted chokepoint, which is what makes the cost measurements below
possible. See `src/cbas/backend/counter.py`.

## Measured vs. published costs

The cost rows Qiao et al. give for **their own** scheme in Tables II and III
are identical to the rows they give for Verma et al.'s scheme. They cannot be:
this scheme's verification equation carries an extra per-signer term `u_i R_i`
and an extra hash `H2`. Measured by instrumented counting:

| Operation | Paper's claim | Measured | Where |
|---|---|---|---|
| `Sign` | `1Te + 1Th` | `1Te + 2Th` | Table II |
| `Verify` (single) | `3Te + 2Ta + 2Th` | `4Te + 3Ta + 3Th` | Table II |
| `AggVerify` | `(n+2)Te + (n+1)Ta + 2nTh` | `(2n+2)Te + 3nTa + 3nTh` | Table III |
| `AggSign` | `(n-1)Ta` | `0` group operations | Table III |

Under the paper's own Table IV operation costs at `n = 100`, aggregate
verification is **25.324 ms**, not the claimed **12.729 ms** -- a factor of
1.99. The claimed figure is exactly the bar published in Fig. 4, so that figure
inherits the same error.

Note the last row runs the other way: `AggSign` here performs `n-1` *scalar*
additions and no group operations at all, so Table III overstates it. Verma et
al. genuinely compute `R = sum R_i` in the group, which is where the row came
from.

These are locked in as regression tests in `tests/test_opcount.py`. The full evidence
chain, including objections considered and rejected, is in [VERIFICATION.md](VERIFICATION.md).

## Layout

```
src/cbas/
  backend/
    base.py       group interface + cost model
    sodium.py     ctypes binding to libsodium Ristretto255
    counter.py    Te/Ta/Th counting wrapper
    selftest.py   standalone algebraic self-test
  encoding.py     length-prefixed TLV
  hashing.py      domain-separated H0/H1/H2
  scheme.py       the six algorithms (the repaired scheme)
  verma.py        Verma et al.'s CB-CAS - INSECURE, for attack demos only
  attack.py       the malicious-KGC forgery
  ablation.py     Fix #2 removed - controlled experiment, NOT a real scheme
  demo.py         end-to-end walkthrough
  sidebyside.py   the attack against both schemes
tests/
bench/            (empty; benchmark harness lands in a later stage)
```

## Requirements

- Python 3.10+
- libsodium 1.0.18+ with Ristretto255 (`libsodium.so.23`); no headers needed,
  the binding is ctypes
