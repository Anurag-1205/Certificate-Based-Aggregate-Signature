"""Backend interface: a prime-order group with counted operations.

The CBAS scheme of Qiao et al. needs an additive cyclic group ``G`` of prime
order ``p`` with generator ``P``, and scalars in ``Z_p*``.  Everything above
this layer is written against this interface only, so that:

  * a second backend (OpenSSL / P-256) can be added without touching the
    scheme, giving a differential test and a two-curve robustness check; and
  * every group operation and hash flows through one chokepoint, which is what
    makes the operation counter (and hence the Table III experiment) possible.

Cost model follows the paper's Table IV:

    Te  scalar multiplication over the group   ("multiplication over group")
    Ta  point addition over the group          ("addition over group")
    Th  hash computation

We additionally track ``Ts``, scalar-field arithmetic in ``Z_p``.  The paper
ignores these entirely; they are genuinely cheap, but counting them keeps us
honest about what is being left out.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, replace


class BackendError(Exception):
    """Base class for backend failures."""


class InvalidPoint(BackendError):
    """A byte string did not decode to a valid group element."""


class InvalidScalar(BackendError):
    """A scalar was rejected (e.g. inverting zero)."""


@dataclass(frozen=True)
class OpCount:
    """Counted primitive operations, in the paper's units."""

    Te: int = 0  # scalar multiplications (group)
    Ta: int = 0  # point additions (group)
    Th: int = 0  # hash computations
    Ts: int = 0  # scalar-field operations (not modelled by the paper)

    def __sub__(self, other: "OpCount") -> "OpCount":
        return OpCount(
            Te=self.Te - other.Te,
            Ta=self.Ta - other.Ta,
            Th=self.Th - other.Th,
            Ts=self.Ts - other.Ts,
        )

    def __add__(self, other: "OpCount") -> "OpCount":
        return OpCount(
            Te=self.Te + other.Te,
            Ta=self.Ta + other.Ta,
            Th=self.Th + other.Th,
            Ts=self.Ts + other.Ts,
        )

    def cost_ms(self, te: float, ta: float, th: float) -> float:
        """Model cost in ms given per-operation costs (e.g. the paper's Table IV)."""
        return self.Te * te + self.Ta * ta + self.Th * th

    def formula(self, n: int) -> str:
        """Render as a Table III-style expression in terms of ``n``."""

        def coef(q: int) -> str:
            return "n" if q == 1 else f"{q}n"

        def term(v: int, sym: str) -> str:
            if v == 0:
                return ""
            q, r = divmod(v, n) if n else (0, v)
            if n and r == 0 and q:
                return f"{coef(q)}{sym}"
            if n and q:
                return f"({coef(q)}{r:+d}){sym}"
            return f"{v}{sym}"

        parts = [t for t in (term(self.Te, "Te"), term(self.Ta, "Ta"), term(self.Th, "Th")) if t]
        return " + ".join(parts) if parts else "0"

    def replace(self, **kw) -> "OpCount":
        return replace(self, **kw)


class Backend(ABC):
    """A prime-order group together with its scalar field."""

    name: str
    #: Bit length of the group order.
    order_bits: int
    #: Encoded size of a group element, in bytes.
    point_bytes: int
    #: Encoded size of a scalar, in bytes.
    scalar_bytes: int

    # -- group order ------------------------------------------------------
    @property
    @abstractmethod
    def order(self) -> int:
        """The prime order ``p`` of the group."""

    # -- scalars (field arithmetic in Z_p) --------------------------------
    @abstractmethod
    def scalar_random(self): ...

    @abstractmethod
    def scalar_from_wide(self, data: bytes):
        """Reduce a wide (2x) byte string to a scalar.  Unbiased."""

    @abstractmethod
    def scalar_from_int(self, value: int): ...

    @abstractmethod
    def scalar_to_int(self, s) -> int: ...

    @abstractmethod
    def scalar_add(self, a, b): ...

    @abstractmethod
    def scalar_sub(self, a, b): ...

    @abstractmethod
    def scalar_mul(self, a, b): ...

    @abstractmethod
    def scalar_invert(self, a): ...

    @abstractmethod
    def scalar_negate(self, a): ...

    @abstractmethod
    def scalar_is_zero(self, a) -> bool: ...

    # -- group ------------------------------------------------------------
    @property
    @abstractmethod
    def generator(self):
        """The generator ``P``."""

    @property
    @abstractmethod
    def identity(self):
        """The identity element."""

    @abstractmethod
    def point_mul(self, k, point):
        """``k * point``.  Counted as one Te."""

    @abstractmethod
    def point_mul_base(self, k):
        """``k * P``.  Counted as one Te."""

    @abstractmethod
    def point_add(self, a, b):
        """``a + b``.  Counted as one Ta."""

    @abstractmethod
    def point_sub(self, a, b):
        """``a - b``.  Counted as one Ta."""

    @abstractmethod
    def point_eq(self, a, b) -> bool: ...

    @abstractmethod
    def point_is_identity(self, point) -> bool: ...

    # -- encoding ---------------------------------------------------------
    @abstractmethod
    def point_to_bytes(self, point) -> bytes: ...

    @abstractmethod
    def point_from_bytes(self, data: bytes):
        """Decode and **validate**.  Raises :class:`InvalidPoint` if invalid."""

    @abstractmethod
    def scalar_to_bytes(self, s) -> bytes: ...

    @abstractmethod
    def scalar_from_bytes(self, data: bytes): ...

    # -- instrumentation --------------------------------------------------
    def note_hash(self, count: int = 1) -> None:
        """Record ``count`` hash computations.  No-op unless counting."""

    # -- convenience ------------------------------------------------------
    def sum_points(self, points):
        """Sum a sequence of points.  Costs ``len(points) - 1`` Ta."""
        it = iter(points)
        try:
            acc = next(it)
        except StopIteration:
            return self.identity
        for p in it:
            acc = self.point_add(acc, p)
        return acc

    def sum_scalars(self, scalars):
        it = iter(scalars)
        try:
            acc = next(it)
        except StopIteration:
            return self.scalar_from_int(0)
        for s in it:
            acc = self.scalar_add(acc, s)
        return acc
