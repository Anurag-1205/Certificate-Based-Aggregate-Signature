# Phase 4: the aggregator, and the failure the scheme does not model

Reproduce with `make dos`.

## The gap

The paper models the aggregator as a pure function — it "does not use their own
private information when aggregating, but only merges multiple signatures". That
is true, and it is exactly what lets the security of the aggregate scheme reduce
to the single-signer scheme. But it leaves an availability problem unaddressed,
and the security proof cannot see it because nothing cryptographic goes wrong.

Aggregation sums the scalars: `z = sum z_i`. Once summed, the individual `z_i`
are not recoverable. So if any single signature is invalid — a faulty sensor, a
corrupted link, a deliberate attacker — the aggregate fails verification and
**the verifier cannot tell which signature caused it**. One bad member denies
service to every honest sensor in its group, and the verifier has no basis on
which to exclude it.

`tests/test_aggregator.py` demonstrates both halves: a single corrupted
signature makes a 10-signature aggregate fail, and the aggregate carries no
information identifying the culprit.

## Three policies

| | aggregator work | on a clean batch | under faults |
|---|---|---|---|
| `BLIND` | none | cheapest | whole batch lost, culprit unknown |
| `PREVERIFY` | verify each submission | `n` individual verifications | bad signatures excluded, rest delivered |
| `RETAIN` | aggregate, keep individuals | one aggregate verification | locate by divide and conquer, then re-aggregate |

`BLIND` is the paper's model. The other two are availability measures, not
security ones: the aggregator still uses no secret material under any policy, so
the security argument is untouched. A test asserts that by inspection of the
class source.

## Fault localisation

`RETAIN` finds the bad signatures by divide and conquer over the retained set:
verify a range as an aggregate, and on failure split it. A clean range costs one
aggregate verification *regardless of its size*, so `f` faults among `n` cost
`O(f log n)` verifications rather than `n` individual ones.

This works because aggregate verification is cheaper per signature than
individual verification — the fixed terms are paid once for the whole range.
Measured on P-256 at `n = 200`:

```
one signature, verified individually      0.3113 ms
200 signatures, as one aggregate         31.3240 ms   (0.1566 ms per signature)
individual verification is 2.0x dearer per signature
```

A single fault among 32 signatures is located in fewer than 32 verifications,
which a test asserts.

## Which policy, and when

Cost per delivered signature, P-256, `n = 200` — total aggregator plus cloud
work divided by the signatures that actually arrive verified:

| fault rate | BLIND | PREVERIFY | RETAIN | best |
|---:|---:|---:|---:|---|
| 0.000 | 0.1566 | 0.4324 | 0.3564 | RETAIN |
| 0.001 | 0.1566 | 0.4334 | 0.3147 | RETAIN |
| 0.005 | 0.3915 | 0.4223 | 0.5736 | PREVERIFY |
| 0.020 | batch lost | 0.3762 | 0.7970 | PREVERIFY |
| 0.050 | batch lost | 0.5005 | 1.7278 | PREVERIFY |
| 0.100 | batch lost | 0.7223 | 2.5508 | PREVERIFY |

The crossover is low — around a 0.5% fault rate — and the reason is that
individual verification is only **2x** the amortised per-signature cost of
aggregate verification, not the order of magnitude one might assume. That makes
`PREVERIFY` affordable, and it degrades gracefully: 0.72 ms per delivered
signature even at a 10% fault rate, against `RETAIN`'s 2.55 ms, because
localisation runs on nearly every batch once faults are common.

For a healthy industrial deployment, where sensors fail rarely, `RETAIN` is the
cheaper choice. `PREVERIFY` is right when faults are common, when an adversary
may be *deliberately* injecting them — which is the case the DoS framing is
about, and where the fault rate is chosen by the attacker — or when the
aggregator must guarantee the cloud never sees a failing aggregate.

That last point decides it for an adversarial setting: an attacker who can
submit signatures chooses the operating point, and `RETAIN`'s cost rises with
the fault rate while `PREVERIFY`'s barely moves. **`PREVERIFY` is the
conservative default**, and it costs roughly 2.8x a blind aggregation on a clean
batch.

## If the aggregator cannot verify at all

An aggregator too constrained to verify can still bound the blast radius by
splitting into sub-batches of `k`. Delivery alone is the wrong objective — it is
maximised at `k = 1`, which is aggregation abandoned — so the model charges
`verify(k) = fixed + k x per_signature`, fitted to this backend's measurements
(`0.1555 + k x 0.1558 ms`). The optimum is then interior:

| fault rate | best `k` | cost per delivered | delivered |
|---:|---:|---:|---:|
| 0.001 | 25 | 0.1662 ms | 97.5% |
| 0.005 | 10 | 0.1802 ms | 95.1% |
| 0.020 | 5 | 0.2068 ms | 90.4% |
| 0.050 | 5 | 0.2416 ms | 77.4% |
| 0.100 | 2 | 0.2884 ms | 81.0% |

The optimal batch shrinks as faults rise, and aggregating 500 signatures in one
batch is catastrophic at any appreciable fault rate — at 5% it delivers
essentially nothing.

## Relation to the rest of the project

This does not bear on the cost-table analysis of Phases 1–3; it is a separate
observation about the scheme's system model. The paper's treatment of the
aggregator is correct as far as it goes, and its security claim is unaffected.
What is missing is that the aggregate's compactness — the property the whole
construction is built around — is also what destroys the information needed to
attribute a failure, and that trade is not discussed.
