"""Group backends for the CBAS scheme."""

from .base import Backend, BackendError, InvalidPoint, InvalidScalar, OpCount
from .counter import CountingBackend, CountResult
from .sodium import RISTRETTO255_ORDER, Point, Scalar, SodiumBackend


def default_backend(counting: bool = False) -> Backend:
    """The project's default group: Ristretto255 via native libsodium."""
    be = SodiumBackend()
    return CountingBackend(be) if counting else be


__all__ = [
    "Backend",
    "BackendError",
    "InvalidPoint",
    "InvalidScalar",
    "OpCount",
    "CountingBackend",
    "CountResult",
    "SodiumBackend",
    "Point",
    "Scalar",
    "RISTRETTO255_ORDER",
    "default_backend",
]
