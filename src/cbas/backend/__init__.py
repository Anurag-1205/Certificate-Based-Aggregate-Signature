"""Group backends for the CBAS scheme."""

from .base import Backend, BackendError, InvalidPoint, InvalidScalar, OpCount
from .counter import CountingBackend, CountResult
from .openssl import P256_ORDER, OpenSSLBackend
from .sodium import RISTRETTO255_ORDER, Point, Scalar, SodiumBackend


#: Every available group backend, by short name.
BACKENDS = {
    "ristretto255": SodiumBackend,
    "p256": OpenSSLBackend,
}


def default_backend(counting: bool = False, kind: str = "ristretto255") -> Backend:
    """A group backend; Ristretto255 via native libsodium by default."""
    try:
        be = BACKENDS[kind]()
    except KeyError:
        raise ValueError(f"unknown backend {kind!r}; choose from {sorted(BACKENDS)}") from None
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
    "OpenSSLBackend",
    "P256_ORDER",
    "BACKENDS",
    "default_backend",
]
