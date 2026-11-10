"""The aggregator: policy, pre-verification, and fault localisation.

Why this module exists
----------------------
The paper models the aggregator as a pure function: it "does not use their own
private information when aggregating, but only merges multiple signatures to
reduce the length of signatures". That is true, and it is what lets the security
of the aggregate scheme reduce to the single-signer scheme. But it leaves a
availability problem unaddressed.

Aggregation sums the scalars: ``z = sum z_i``. Once summed, the individual
``z_i`` are not recoverable from the aggregate. So if any one signature is
invalid -- a faulty sensor, a corrupted link, or a deliberate attacker -- the
aggregate fails verification and **the verifier cannot tell which signature was
responsible**. Every honest sensor in the group is denied service by one bad
member, and the verifier has no way to exclude it.

Nothing in the scheme detects this, because nothing is cryptographically wrong:
the aggregate is a faithful sum of what it was given.

Policies
--------
``BLIND``
    Aggregate whatever arrives. This is the paper's model. Cheapest, and
    fully exposed: one bad signature costs the batch.

``PREVERIFY``
    Check each signature before admitting it. The aggregator is a
    mains-powered gateway rather than a sensor, so it can afford this, and the
    cloud is then guaranteed a verifying aggregate. Costs a single verification
    per signature.

``RETAIN``
    Aggregate optimistically but keep the individual signatures. If the
    aggregate fails, locate the culprits by divide and conquer over the
    retained set. Pays nothing on the happy path and ``O(f log n)`` aggregate
    verifications when ``f`` signatures are bad.

Which is right depends on how often signatures are bad and on how much the
aggregator costs relative to the cloud; ``bench/dos.py`` measures the trade.

The aggregator still uses no secret material under any policy, so the security
argument is untouched -- these are availability measures, not security ones.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional, Sequence

from .optimized import PreparedSigner, agg_verify_prepared, prepare
from .scheme import AggregateSignature, PublicParams, Signature, Signer, agg_sign


class Policy(Enum):
    """How much the aggregator checks before it commits to an aggregate."""

    BLIND = "blind"
    PREVERIFY = "preverify"
    RETAIN = "retain"


@dataclass
class Submission:
    """One signature offered to the aggregator."""

    signer: Signer
    message: bytes
    signature: Signature


@dataclass
class AggregationResult:
    """What the aggregator produced, and what it excluded."""

    aggregate: Optional[AggregateSignature]
    accepted: list[int] = field(default_factory=list)
    rejected: list[int] = field(default_factory=list)
    signers: list[Signer] = field(default_factory=list)
    messages: list[bytes] = field(default_factory=list)
    #: Individual verifications performed (PREVERIFY).
    single_verifications: int = 0
    #: Aggregate verifications performed (RETAIN, during localisation).
    aggregate_verifications: int = 0

    @property
    def ok(self) -> bool:
        return self.aggregate is not None and not self.rejected

    @property
    def n(self) -> int:
        return len(self.accepted)


def locate_faults(
    params: PublicParams,
    prepared: Sequence[PreparedSigner],
    messages: Sequence[bytes],
    signatures: Sequence[Signature],
    _counter: Optional[list] = None,
) -> list[int]:
    """Return the indices of signatures that do not verify.

    Divide and conquer over the retained individual signatures: verify a range
    as an aggregate, and on failure split it. A clean range costs one aggregate
    verification regardless of its size, so with ``f`` bad signatures among
    ``n`` this costs ``O(f log n)`` verifications rather than ``n`` individual
    ones.

    The gain comes from aggregate verification being cheaper per signature than
    individual verification -- the fixed terms are paid once for the whole
    range.
    """
    counter = _counter if _counter is not None else [0]

    def verifies(lo: int, hi: int) -> bool:
        counter[0] += 1
        sub = AggregateSignature(
            T=tuple(s.T for s in signatures[lo:hi]),
            z=params.be.sum_scalars([s.z for s in signatures[lo:hi]]),
        )
        return agg_verify_prepared(params, prepared[lo:hi], messages[lo:hi], sub)

    bad: list[int] = []

    def descend(lo: int, hi: int) -> None:
        if lo >= hi or verifies(lo, hi):
            return
        if hi - lo == 1:
            bad.append(lo)
            return
        mid = (lo + hi) // 2
        descend(lo, mid)
        descend(mid, hi)

    descend(0, len(signatures))
    return bad


class Aggregator:
    """Collects signatures from a fixed roster and emits an aggregate.

    The roster is prepared once, which is what an industrial deployment would
    do: the set of enrolled sensors changes rarely, the readings constantly.
    """

    def __init__(self, params: PublicParams, signers: Sequence[Signer],
                 policy: Policy = Policy.PREVERIFY):
        self.params = params
        self.policy = policy
        self.signers = list(signers)
        self.prepared = prepare(params, self.signers)
        self._index = {s.identity: i for i, s in enumerate(self.signers)}
        self._pending: list[Submission] = []

    def submit(self, signer: Signer, message: bytes, signature: Signature) -> None:
        if signer.identity not in self._index:
            raise ValueError(f"{signer.identity!r} is not on this aggregator's roster")
        self._pending.append(Submission(signer, message, signature))

    def _verify_one(self, sub: Submission) -> bool:
        idx = self._index[sub.signer.identity]
        one = AggregateSignature(T=(sub.signature.T,), z=sub.signature.z)
        return agg_verify_prepared(self.params, [self.prepared[idx]], [sub.message], one)

    def aggregate(self) -> AggregationResult:
        pending, self._pending = self._pending, []
        if not pending:
            return AggregationResult(aggregate=None)

        result = AggregationResult(aggregate=None)

        if self.policy is Policy.PREVERIFY:
            admitted = []
            for i, sub in enumerate(pending):
                result.single_verifications += 1
                if self._verify_one(sub):
                    result.accepted.append(i)
                    admitted.append(sub)
                else:
                    result.rejected.append(i)
            pending = admitted
            if not pending:
                return result
        else:
            result.accepted = list(range(len(pending)))

        result.signers = [s.signer for s in pending]
        result.messages = [s.message for s in pending]
        result.aggregate = agg_sign(self.params, [s.signature for s in pending])

        if self.policy is Policy.RETAIN:
            counter = [0]
            prep = [self.prepared[self._index[s.signer.identity]] for s in pending]
            if not agg_verify_prepared(self.params, prep, result.messages, result.aggregate):
                bad = locate_faults(self.params, prep, result.messages,
                                    [s.signature for s in pending], counter)
                keep = [i for i in range(len(pending)) if i not in set(bad)]
                result.rejected = bad
                result.accepted = keep
                result.signers = [pending[i].signer for i in keep]
                result.messages = [pending[i].message for i in keep]
                result.aggregate = (
                    agg_sign(self.params, [pending[i].signature for i in keep])
                    if keep else None
                )
            result.aggregate_verifications = counter[0] or 1

        return result


def subbatch_plan(n: int, failure_rate: float, k: int,
                  cost_fixed: float = 1.0, cost_per_signature: float = 1.0) -> dict:
    """Expected outcome of splitting ``n`` submissions into batches of ``k``.

    Under BLIND aggregation a single bad signature destroys everything it is
    aggregated with, so the blast radius is the batch size. Splitting bounds the
    damage, at the cost of more aggregates for the cloud to verify. With
    independent failures at rate ``p``, a batch of ``k`` survives with
    probability ``(1-p)^k``.

    Delivery alone is not the objective: it is maximised trivially at ``k = 1``,
    which is aggregation abandoned. Verifying one aggregate of ``k`` signatures
    is modelled as ``cost_fixed + k * cost_per_signature``, so shrinking ``k``
    pays the fixed term more often. The figure to compare is therefore expected
    **cost per delivered signature**, which has an interior optimum.
    """
    if not 0.0 <= failure_rate < 1.0:
        raise ValueError("failure_rate must be in [0, 1)")
    if k < 1:
        raise ValueError("k must be at least 1")

    survive = (1.0 - failure_rate) ** k
    batches = -(-n // k)
    delivered = 0.0
    cost = 0.0
    for b in range(batches):
        size = min(k, n - b * k)
        cost += cost_fixed + size * cost_per_signature
        delivered += size * (1.0 - failure_rate) ** size

    return {
        "k": k,
        "batches": batches,
        "batch_survival_probability": survive,
        "expected_signatures_delivered": delivered,
        "expected_fraction_delivered": delivered / n if n else 0.0,
        "expected_cost": cost,
        "cost_per_delivered": cost / delivered if delivered else float("inf"),
    }


def best_subbatch_size(n: int, failure_rate: float,
                       candidates: Optional[Sequence[int]] = None,
                       cost_fixed: float = 1.0,
                       cost_per_signature: float = 1.0) -> dict:
    """The ``k`` minimising expected cost per delivered signature."""
    candidates = candidates or [k for k in (1, 2, 5, 10, 20, 25, 50, 100, 250, 500) if k <= n]
    plans = [subbatch_plan(n, failure_rate, k, cost_fixed, cost_per_signature)
             for k in candidates]
    return min(plans, key=lambda p: p["cost_per_delivered"])
