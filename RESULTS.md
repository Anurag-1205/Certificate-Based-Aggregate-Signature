# Phase 2: measured aggregate verification cost

Wall-clock confirmation of the cost discrepancy established by operation
counting in [VERIFICATION.md](VERIFICATION.md). Counting and timing are
independent instruments; this note reports what the second one says, on two
curves, two cryptographic libraries and two machines.

Reproduce with `make bench`, `make bench-repeat` and `make plots`.

## Summary

| Machine | Curve / library | measured ratio (median, range) | predicted from counts | published rows require |
|---|---|---:|---:|---:|
| AMD Ryzen 5 7520U | Ristretto255 / libsodium | 2.153 `[2.082, 2.218]` | 2.143 | 1.000 |
| AMD Ryzen 5 7520U | NIST P-256 / OpenSSL | 2.366 `[2.184, 2.401]` | 1.986 | 1.000 |
| Intel Xeon @ 2.20 GHz (Kaggle) | Ristretto255 / libsodium | 2.123 | 2.129 | 1.000 |

Ryzen figures are medians over five repeated sweeps per backend, each sweep
covering `n = 50 ... 500`. Runs whose linear fit falls below `r^2 = 0.99` are
reported but excluded from the median: a poor fit means the run was perturbed by
competing load rather than that the scheme behaved differently. Across every run
recorded during this work, including the excluded ones, the lowest ratio observed
on any configuration was 1.86 — still 86% above the value the published rows
require.

The per-signer cost ratio between the two schemes is close to 2 everywhere. The
published rows, being identical for both schemes, require it to be exactly 1.
That is excluded on every configuration tested.

## What was varied, and what did not change

The operation counts are **identical** on both backends, at every `n` tested, on
both machines:

```
ristretto255/libsodium   CBAS   (2n+2)Te + 3nTa + 3nTh
ristretto255/libsodium   Verma   (n+2)Te + (n+1)Ta + 2nTh
p256/openssl             CBAS   (2n+2)Te + 3nTa + 3nTh
p256/openssl             Verma   (n+2)Te + (n+1)Ta + 2nTh
```

Two unrelated curves, in two unrelated libraries, with different field
arithmetic, different point representations and different encodings, agree
exactly. The counts are a property of the algorithms, not of the group they are
instantiated over — and Verma's reproduce that scheme's published row on both.

The whole test suite runs against both backends (`tests/conftest.py`
parameterises every fixture), which is also a differential test: 221 tests
passing on both means two independent group implementations agree on every
signature, verification and count.

## Methodology, and one finding about it

A first attempt at this sweep reported `n = 100` as **cheaper** than `n = 50`.
That was not a coding error. On the Ryzen the core clock ramps by roughly a
factor of two once loaded, and the ramp happened to fall between the two data
points:

```
scalar multiplication, successive chunks during warm-up (ms):
0.1237 0.1213 0.1227 0.1212 0.1230 0.1223 | 0.0699 0.0594 0.0593 0.0591 ...
                                          ^ clock ramps, 2.07x
```

Any sweep that does not control for this produces a slope that is an artefact of
thermal policy. Two measures address it:

- **`stabilize()`** spins on real group operations until the per-operation cost
  has held steady for several consecutive chunks *and* at least four seconds
  have elapsed. Both conditions are needed: the clock holds briefly at an
  intermediate step, so a short run converges on a rate that is not the
  steady-state one.
- **`measure_many()`** times every workload once per round and takes the median
  across rounds. Interleaving is applied across *schemes* as well as across `n`,
  because the headline result is a ratio and a clock change must not be allowed
  to land on one scheme and not the other.

The Kaggle Xeon showed no ramp at all (`0.99x` across warm-up), so the same
methodology covers both a machine that ramps and one that does not.

Repetition counts are auto-calibrated so each sample spans at least 20 ms, which
matters because `Ta` and `Th` are near timer resolution. Medians are reported
rather than means, since these operations have long tails from allocation and
garbage collection.

## Primitive operation costs

Measured at a steady clock. These are **not** comparable with the paper's
Table IV: its curve is a supersingular PBC Type-A curve at roughly 80-bit
security over a 512-bit base field, while Ristretto255 and P-256 are both
128-bit. Absolute times are also Python-plus-ctypes-plus-library, not the
library alone.

| Operation | Ristretto255 (Ryzen) | P-256 (Ryzen) | Ristretto255 (Xeon) | Paper |
|---|---:|---:|---:|---:|
| `Te` scalar mult (variable base) | 0.0595 | 0.0494 | 0.0910 | 0.112 |
| `Te` scalar mult (fixed base) | 0.0271 | 0.0103 | 0.0351 | — |
| `Ta` point addition | 0.0233 | 0.0032 | 0.0309 | 0.005 |
| `Th` hash to scalar | 0.0088 | 0.0040 | 0.0121 | 0.004 |
| `Ts` scalar multiply mod order | 0.0084 | 0.0022 | 0.0113 | not modelled |

All in milliseconds. The `Ta/Te` ratio differs sharply between backends — 0.39
on Ristretto255, 0.065 on P-256 — because OpenSSL's point addition is far
cheaper relative to its scalar multiplication. This is what makes the second
backend a real test rather than a repetition: it changes the predicted ratio.

## Sweep, Ristretto255 on the Ryzen

| `n` | CBAS (ms) | Verma (ms) | `n` x Ed25519 (ms) | CBAS / Verma |
|---:|---:|---:|---:|---:|
| 50 | 12.459 | 5.875 | 3.249 | 2.120 |
| 100 | 24.752 | 11.725 | 6.521 | 2.111 |
| 150 | 37.219 | 17.458 | 9.742 | 2.132 |
| 200 | 49.653 | 23.353 | 13.025 | 2.126 |
| 250 | 61.913 | 29.079 | 16.262 | 2.129 |
| 300 | 74.852 | 34.890 | 19.531 | 2.145 |
| 350 | 86.856 | 40.821 | 22.811 | 2.128 |
| 400 | 99.389 | 46.462 | 26.077 | 2.139 |
| 450 | 111.391 | 52.463 | 29.295 | 2.123 |
| 500 | 124.570 | 58.609 | 32.616 | 2.125 |

Linear fits are strong: `r^2 >= 0.99` on the runs used, typically `>= 0.995`,
and `0.9999` on the quieter Kaggle machine.

## The cross-check, and where it does not close exactly

Converting operation counts to predicted times using the measured primitive
costs, and comparing against the directly measured slopes:

| Configuration | predicted | measured | residual |
|---|---:|---:|---:|
| Ristretto255, Ryzen | 2.143 | 2.153 | +0.5% |
| Ristretto255, Xeon | 2.129 | 2.123 | -0.3% |
| P-256, Ryzen | 1.986 | 2.366 | +19% |

On Ristretto255 the agreement is essentially exact on both machines. On P-256 the
measurement **exceeds** the prediction by about 20%, and the reason is visible in
the numbers rather than hypothetical: P-256's point addition is seven times
cheaper (`Ta` 0.0032 against 0.0233 ms), so the group operations are a smaller
share of the total and the Python interpreter's share is correspondingly larger.

That interpreter overhead is **not equal between the schemes**. CBAS hashes three
times per signer to Verma's two, and performs two scalar multiplications per
signer to Verma's one, so the loop, the TLV encoding and the attribute access all
cost more per signer for CBAS. Where the cryptography is cheap, that pushes the
measured ratio above what the `Te`/`Ta`/`Th` model alone predicts.

This is a limitation of the model, not evidence against the counts. The counts
themselves are exact and backend-independent; the timing model omits interpreter
work by construction. Both instruments point the same way, and both exclude the
published rows by a wide margin:

```
published rows say 1.000       -> off by 1.12 to 1.37
measured counts say 1.99-2.14  -> off by 0.006 to 0.38
```

On the two Ristretto255 configurations the counts predict the measurement to
within 0.5%. Even on P-256, where the model is weakest, the counts are an order
of magnitude closer to the measurement than the published rows are.

## Under the paper's own Table IV costs

At `n = 100`, with `Te = 0.112`, `Ta = 0.005`, `Th = 0.004` ms:

- published expression `(n+2)Te + (n+1)Ta + 2nTh` = **12.729 ms**
- measured counts `(2n+2)Te + 3nTa + 3nTh` = **25.324 ms**
- factor **1.989**

Fig. 4 of the paper plots 12.729 ms, so that figure was derived from Table III
and carries the same discrepancy.

## A note on the Ed25519 reference

`n` independent Ed25519 verifications are **faster** than one aggregate
verification here — 32.6 ms against 124.6 ms at `n = 500` on Ristretto255. That
comparison is not scheme-versus-scheme and should not be read as one:
libsodium's `crypto_sign_verify_detached` is a single native call, whereas our
aggregate verification drives roughly five ctypes round-trips per signer from
Python. A C implementation would close most of that gap.

What the line does show is that **aggregation here buys bandwidth, not verifier
CPU**. The aggregate is one scalar plus `n` group elements instead of `n` full
signatures, and the certificate-based structure removes certificate
distribution; neither is a verification-time saving. Any claim that aggregate
verification is cheaper than individual verification needs to be made against a
comparable implementation, and is not supported by these measurements.

## Second machine

The full pipeline — 31 backend self-tests, the forgery demonstration, operation
counts on both backends, and the timing sweep — was also executed on Kaggle, on
an Intel Xeon @ 2.20 GHz under a different kernel, Python and OpenSSL. Everything
reproduced: self-tests passed, the forgery succeeded against Verma and failed
against the repaired scheme, the counts were identical, and the slope ratio came
out at 2.123 against a prediction of 2.129.

`make kaggle-kernel` regenerates the self-contained script; results are recorded
in `bench/results/sweep_kaggle-xeon.json`.

CPU only. The workload is sequential 255-bit modular arithmetic, so GPUs and
fp16 have nothing to contribute to it. GPU multi-scalar multiplication is a real
technique and is a candidate for Phase 3 optimisation, but it would not change
the operation counts that Tables II and III report.

## Limitations

- Absolute times include Python and ctypes overhead and are not the cost of the
  cryptography alone. Ratios and slopes are the defensible quantities.
- The `Te`/`Ta`/`Th` model omits interpreter work, which is why the P-256
  cross-check closes to 20% rather than 1%.
- `AggVerify` is deliberately the naive `2n+2` scalar multiplications.
  Multi-scalar multiplication (Strauss, Pippenger) would reduce it substantially
  and is deferred to Phase 3, so that the baseline compared against the paper's
  own naive counts is itself naive.
