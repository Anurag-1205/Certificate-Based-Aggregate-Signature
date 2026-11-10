# Phase 3: optimised aggregate verification

Phases 1 and 2 established that the cost rows Qiao et al. give for their own
scheme describe a cheaper algorithm than the one they specify
([VERIFICATION.md](VERIFICATION.md), [RESULTS.md](RESULTS.md)). Those
measurements used the naive algorithm, evaluating each term of the verification
equation separately — which is the correct baseline, because that is the
algorithm the tables describe.

It is not, however, what a deployment would run. This phase asks whether
optimising changes the conclusion.

Reproduce with `make optimize`.

## The short answer

**No — optimising makes the disparity larger, not smaller.**

| P-256 / OpenSSL | CBAS | Verma | ratio |
|---|---:|---:|---:|
| naive, per signer | 166.8 us | 70.8 us | **2.355** |
| fully optimised, per signer | 67.2 us | 22.1 us | **3.044** |
| speedup from optimising | 2.48x | 3.21x | |

Tables II and III, being identical for both schemes, require that ratio to be
**1.000**. It is 2.36 naive and 3.04 optimised.

## What was optimised

**Multi-scalar multiplication.** The verification equation is one fixed-base
term plus a weighted sum of points. Rearranged so the whole check is a single
sum compared against `z*P`, it becomes exactly the shape of OpenSSL's
`EC_POINTs_mul`, which evaluates it in one native call using an interleaved
windowed method — instead of one crossing of the ctypes boundary per term.

**A prepared roster.** An industrial deployment verifies repeated batches from a
*fixed* set of enrolled sensors. Each signer's public key encoding, certificate
nonce encoding and `h0 = H0(id || pk || R)` are therefore invariant, and can be
computed once per roster rather than once per verification. A profile of the
unprepared path showed `point_to_bytes` alone at **25.4%** of total time — eight
calls per signer, all recomputing the same bytes — against 19.9% for the
multi-scalar multiplication itself.

Preparing removes `H0` from the hot path entirely (`3n` hashes drop to `2n`,
asserted by `test_prepared_path_does_fewer_hashes`) and cuts point encoding from
eight calls per signer to one.

A smaller change: scalars are kept positive and the sum compared against `z*P`,
rather than negating all `3n+1` of them to test against the identity. One extra
scalar multiplication is cheaper than `3n+1` field negations — worth 1.05x.

## Equal treatment

Both schemes receive both optimisations. This matters: an early version of this
measurement applied the prepared roster to CBAS but only the MSM to Verma, and
reported a ratio of **1.63** — appearing to show that optimisation closes the
gap. That number was an artefact of unequal treatment. Verma's `H0(id || pk)` is
static for exactly the same reason, so it gets a prepared roster too, and the
honest figure is **3.04** in the opposite direction.

Comparing an optimised implementation of one scheme against an unoptimised
implementation of the other measures the implementations, not the schemes.

## Why the gap widens

Verma's scheme optimises *better*. Its verification is a multi-scalar
multiplication over `n+2` terms; this scheme's is over `3n+1`:

| | MSM terms | at `n = 500` |
|---|---|---:|
| Verma | `n + 2` | 502 |
| CBAS | `3n + 1` | 1501 |
| ratio | → 3 | 2.99 |

The measured optimised ratio is **3.044** against a term ratio of **2.99**. As
the per-term cost comes to dominate, the timing ratio converges on the ratio of
term counts, which is the structural `3n+1 : n+2` difference between the two
verification equations. The naive ratio of ~2.3 reflects the `2n+2 : n+2` scalar
multiplication counts; the optimised ratio reflects the MSM term counts. Both
exclude parity.

## The signer side

In this setting the sensors are the constrained devices, so saved work matters
more there than at the cloud. `Sign` hashes `pk`, `R` and `T` into each of `H1`
and `H2` — six point encodings per signature, four of them re-encoding values
fixed for the lifetime of the certificate. `prepare_signing` holds those
encodings, leaving one per signature for the fresh nonce commitment.

| Sign, per signature | plain | prepared | speedup |
|---|---:|---:|---:|
| P-256 / OpenSSL | 74.8 us | 43.9 us | **1.70x** |
| Ristretto255 / libsodium | 85.9 us | 86.0 us | 1.00x |

Group operations are unchanged at `1Te + 2Th` on both paths — the saving is
encoding work, not cryptography — and the nonce is still drawn fresh for every
signature, which a test asserts, because an optimisation that cached `T` would
silently destroy the scheme's replay resistance.

## One architectural difference explains both asymmetries

Ristretto255 gains nothing from cached encodings while P-256 gains 1.70x, and in
Phase 2 the `Ta/Te` ratio differed sharply between the same two backends. Both
follow from a single design choice, measured directly:

| | encode | add | encode/add |
|---|---:|---:|---:|
| P-256 / OpenSSL | 5.84 us | 2.54 us | **2.302** |
| Ristretto255 / libsodium | 0.07 us | 23.35 us | **0.003** |

A factor of 767 between the two ratios. libsodium stores a Ristretto255 point
*as* its 32-byte encoding, so encoding is a field read while every addition must
decode both operands and re-encode the result. OpenSSL keeps Jacobian
coordinates, so addition is cheap while encoding costs a modular inversion to
affine.

The consequence is practical: **which optimisation pays depends on the library's
point representation, not on the scheme.** Caching encodings is worth 1.7x on
OpenSSL and nothing on libsodium; conversely, an implementation over libsodium
should minimise point *additions*, which are 9x dearer there. No cost table in
this literature distinguishes these cases — `Ta` and `Te` are treated as
library-independent constants, and they are not.

## The optimisation is a property of the library, not the scheme

On Ristretto255 via libsodium there is **no** native multi-scalar routine, so
the MSM path falls back to naive evaluation and the result is a **regression**:

| Ristretto255 / libsodium | naive | +MSM | +prepared | speedup |
|---|---:|---:|---:|---:|
| CBAS | 252.0 us | 248.9 us | 236.8 us | **1.06x** |
| Verma | 116.9 us | 116.8 us | 106.9 us | 1.09x |

Almost nothing. The ratio still moves the wrong way for the published rows
(2.155 naive, 2.216 optimised), but neither scheme gains materially.

An earlier version of the fallback was *worse* than naive, at 0.85x. Expressing
`sum(T_i)` as multi-scalar terms with scalar one meant a backend without a
native routine paid a full scalar multiplication where the naive path simply
added — `3n+1` scalar multiplications against naive's `2n+2`. The default
implementation now adds scalar-one terms directly. It is a reminder that an
"optimisation" written against one backend's cost profile can be a pessimisation
on another.

This is worth stating plainly: the 2.5x speedup reported above belongs to
OpenSSL's `EC_POINTs_mul`, not to anything about the scheme. A deployment
choosing a curve for this scheme should weigh the availability of a batch
verification primitive, which is a point in P-256's favour and is not visible in
any cost table in the literature.

## Correctness

An optimisation that changes which signatures are accepted is not an
optimisation. Every fast path is checked against the transliterated reference in
`scheme.py` — on both backends, at several values of `n`, for valid signatures
and for tampered messages, tampered `z`, tampered commitments, substituted
public keys and length mismatches. `tests/test_optimized.py`, 54 cases.

The reference implementation is deliberately left unoptimised, so that the cost
analysis in [VERIFICATION.md](VERIFICATION.md) continues to measure the
algorithm the paper actually describes.

## What this does and does not change

It does **not** change the Phase 1 or Phase 2 conclusions. The operation counts
for the naive algorithm are unaffected, and they are what Tables II and III
purport to report.

It adds one finding: the published parity claim is not merely wrong for the
algorithm as specified, it is further from the truth for a well-implemented one.
Any defence of those rows on the grounds that "a real implementation would
batch" runs the wrong way.

## Limitations

- `EC_POINTs_mul` is deprecated in OpenSSL 3.0. It remains exported and
  functional, and the naive path stays available as a fallback, but a
  production implementation should track its removal.
- Absolute timings remain Python-plus-ctypes-plus-library. The optimisation
  reduces the per-term boundary crossings, which is precisely why it helps so
  much here; a native implementation would see a smaller relative gain.
- GPU multi-scalar multiplication was considered and not pursued. The terms are
  independent, so it is technically applicable, but it would not change the
  operation counts that the tables report, and no comparison in the paper is
  GPU-based.
