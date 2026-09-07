"""Operation-counting backend wrapper.

This exists to settle an empirical question about the reference paper.

Qiao et al.'s Table III gives the aggregate-verification cost of their own
scheme as ``(n+2)Te + (n+1)Ta + 2nTh`` -- an expression **identical** to the row
they give for Verma et al.'s scheme.  But their verification equation carries an
extra per-signer term ``u_i R_i`` and an extra hash ``H2`` that Verma's does not,
so the two cannot have the same cost.  Rather than argue this on paper, we route
every group operation and every hash through this wrapper and simply count.

See ``bench/`` for the experiment and ``tests/test_opcount.py`` for the assertion.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass

from .base import Backend, OpCount


@dataclass
class CountResult:
    """Filled in when its :meth:`CountingBackend.count` block exits."""

    ops: OpCount = OpCount()

    @property
    def Te(self) -> int:
        return self.ops.Te

    @property
    def Ta(self) -> int:
        return self.ops.Ta

    @property
    def Th(self) -> int:
        return self.ops.Th

    @property
    def Ts(self) -> int:
        return self.ops.Ts

    def formula(self, n: int) -> str:
        return self.ops.formula(n)

    def cost_ms(self, te: float, ta: float, th: float) -> float:
        return self.ops.cost_ms(te, ta, th)


class CountingBackend(Backend):
    """Delegates to an inner backend, tallying operations in the paper's units.

    Delegation is written out explicitly rather than via ``__getattr__`` so that
    it is obvious, on inspection, exactly which operations are counted and which
    are not.  Adding a group operation to :class:`~cbas.backend.base.Backend`
    without deciding its cost class will fail loudly here rather than silently
    going uncounted.
    """

    def __init__(self, inner: Backend):
        self._inner = inner
        self._te = 0
        self._ta = 0
        self._th = 0
        self._ts = 0

    # -- identity of the wrapper -----------------------------------------
    @property
    def name(self) -> str:  # type: ignore[override]
        return f"counting({self._inner.name})"

    @property
    def inner(self) -> Backend:
        return self._inner

    @property
    def order_bits(self) -> int:  # type: ignore[override]
        return self._inner.order_bits

    @property
    def point_bytes(self) -> int:  # type: ignore[override]
        return self._inner.point_bytes

    @property
    def scalar_bytes(self) -> int:  # type: ignore[override]
        return self._inner.scalar_bytes

    @property
    def order(self) -> int:
        return self._inner.order

    # -- counting ---------------------------------------------------------
    @property
    def ops(self) -> OpCount:
        """Cumulative counts since construction or the last :meth:`reset`."""
        return OpCount(Te=self._te, Ta=self._ta, Th=self._th, Ts=self._ts)

    def reset(self) -> None:
        self._te = self._ta = self._th = self._ts = 0

    @contextmanager
    def count(self):
        """Count operations performed inside the block.

        >>> with be.count() as c:
        ...     scheme.agg_verify(...)
        >>> c.formula(n)
        '(2n+2)Te + 3nTa + 3nTh'
        """
        start = self.ops
        result = CountResult()
        try:
            yield result
        finally:
            result.ops = self.ops - start

    # -- counted group operations (Te) ------------------------------------
    def point_mul(self, k, point):
        self._te += 1
        return self._inner.point_mul(k, point)

    def point_mul_base(self, k):
        self._te += 1
        return self._inner.point_mul_base(k)

    # -- counted group operations (Ta) ------------------------------------
    def point_add(self, a, b):
        self._ta += 1
        return self._inner.point_add(a, b)

    def point_sub(self, a, b):
        self._ta += 1
        return self._inner.point_sub(a, b)

    # -- counted hashes (Th) ----------------------------------------------
    def note_hash(self, count: int = 1) -> None:
        self._th += count

    # -- scalar field operations (Ts; not modelled by the paper) ----------
    def scalar_add(self, a, b):
        self._ts += 1
        return self._inner.scalar_add(a, b)

    def scalar_sub(self, a, b):
        self._ts += 1
        return self._inner.scalar_sub(a, b)

    def scalar_mul(self, a, b):
        self._ts += 1
        return self._inner.scalar_mul(a, b)

    def scalar_invert(self, a):
        self._ts += 1
        return self._inner.scalar_invert(a)

    def scalar_negate(self, a):
        self._ts += 1
        return self._inner.scalar_negate(a)

    # -- uncounted passthrough --------------------------------------------
    def scalar_random(self):
        return self._inner.scalar_random()

    def scalar_from_wide(self, data):
        return self._inner.scalar_from_wide(data)

    def scalar_from_int(self, value):
        return self._inner.scalar_from_int(value)

    def scalar_to_int(self, s):
        return self._inner.scalar_to_int(s)

    def scalar_is_zero(self, a) -> bool:
        return self._inner.scalar_is_zero(a)

    @property
    def generator(self):
        return self._inner.generator

    @property
    def identity(self):
        return self._inner.identity

    def point_eq(self, a, b) -> bool:
        return self._inner.point_eq(a, b)

    def point_is_identity(self, point) -> bool:
        return self._inner.point_is_identity(point)

    def point_to_bytes(self, point) -> bytes:
        return self._inner.point_to_bytes(point)

    def point_from_bytes(self, data):
        return self._inner.point_from_bytes(data)

    def scalar_to_bytes(self, s) -> bytes:
        return self._inner.scalar_to_bytes(s)

    def scalar_from_bytes(self, data):
        return self._inner.scalar_from_bytes(data)
