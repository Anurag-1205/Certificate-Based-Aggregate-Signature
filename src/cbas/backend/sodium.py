"""Ristretto255 backend: a ctypes wrapper over native libsodium.

Why Ristretto255
----------------
The scheme's algebra assumes a group of **prime** order (the security analysis
divides by hash scalars, and the forgery in Section IV inverts ``v_i``).  Raw
Curve25519/Ed25519 has cofactor 8 and is therefore *not* a prime-order group;
using it directly would invalidate that algebra.  Ristretto255 is a
prime-order quotient of Curve25519, so it gives us the required structure with
Curve25519's speed.

Two properties fall out for free and are relied upon elsewhere:

  * ``crypto_core_ristretto255_scalar_reduce`` performs a *wide* (64 -> 32 byte)
    reduction, which gives unbiased hash-to-scalar with no rejection sampling
    and no modular bias.
  * libsodium operates on canonical 32-byte encodings and rejects non-canonical
    ones at the library boundary, which removes a class of encoding
    malleability bugs before we write a line of our own.

A libsodium API hazard, verified empirically
--------------------------------------------
``crypto_scalarmult_ristretto255`` returns ``-1`` in *two different*
situations, and writes an all-zero output buffer in both:

  1. the input point was invalid; and
  2. the **result** is the identity element (e.g. ``0 * P``, or ``k * identity``)
     -- a perfectly legitimate outcome in general group arithmetic, which
     libsodium flags because it is a failure for Diffie-Hellman, its primary
     use case.

Conflating these would silently substitute the identity for a real value.  We
disambiguate structurally: every :class:`Point` in the system is validated
exactly once -- at :meth:`SodiumBackend.point_from_bytes`, the only place
untrusted bytes enter -- and is trusted thereafter.  For a trusted input,
``-1`` therefore means "the result is the identity", which we assert and
return.  Untrusted input never reaches the scalar multiplication.
"""

from __future__ import annotations

import ctypes
import ctypes.util
from typing import Optional

from .base import Backend, BackendError, InvalidPoint, InvalidScalar

# Order of the Ristretto255 group (= order of the Curve25519 prime-order subgroup).
RISTRETTO255_ORDER = (
    2**252 + 27742317777372353535851937790883648493
)

_POINT_BYTES = 32
_SCALAR_BYTES = 32
_WIDE_BYTES = 64


def _pynacl_sodium() -> Optional[str]:
    """PyNaCl ships a compiled libsodium; use it if no system copy exists.

    Lets the project run on hosts without libsodium installed (managed
    notebook images, for instance) without changing anything else.
    """
    try:
        import nacl._sodium as _s  # type: ignore
    except Exception:
        return None
    return getattr(_s, "__file__", None)


def _load_libsodium(path: Optional[str] = None) -> ctypes.CDLL:
    candidates = [path] if path else []
    found = ctypes.util.find_library("sodium")
    if found:
        candidates.append(found)
    candidates += ["libsodium.so.23", "libsodium.so.26", "libsodium.so",
                   "libsodium.dylib"]
    bundled = _pynacl_sodium()
    if bundled:
        candidates.append(bundled)
    errors = []
    for cand in candidates:
        if not cand:
            continue
        try:
            lib = ctypes.CDLL(cand)
        except OSError as exc:  # pragma: no cover - environment dependent
            errors.append(f"{cand}: {exc}")
            continue
        if not hasattr(lib, "crypto_core_ristretto255_add"):
            errors.append(f"{cand}: no Ristretto255 support")
            continue
        if lib.sodium_init() < 0:  # pragma: no cover
            raise BackendError(f"sodium_init() failed for {cand}")
        return lib
    raise BackendError(
        "could not load libsodium. Tried: " + "; ".join(errors or candidates)  # pragma: no cover
    )


class Scalar:
    """An element of ``Z_p``, held as 32 canonical little-endian bytes."""

    __slots__ = ("_b",)

    def __init__(self, raw: bytes):
        if len(raw) != _SCALAR_BYTES:
            raise InvalidScalar(f"scalar must be {_SCALAR_BYTES} bytes, got {len(raw)}")
        self._b = bytes(raw)

    @property
    def raw(self) -> bytes:
        return self._b

    def __eq__(self, other) -> bool:
        return isinstance(other, Scalar) and self._b == other._b

    def __hash__(self) -> int:
        return hash(self._b)

    def __repr__(self) -> str:
        return f"Scalar({self._b.hex()[:16]}...)"


class Point:
    """A Ristretto255 group element, held as its canonical 32-byte encoding.

    ``trusted`` records that this encoding has already passed validation (or
    was produced by libsodium itself).  See the module docstring for why this
    matters.
    """

    __slots__ = ("_b", "trusted")

    def __init__(self, raw: bytes, trusted: bool = False):
        if len(raw) != _POINT_BYTES:
            raise InvalidPoint(f"point must be {_POINT_BYTES} bytes, got {len(raw)}")
        self._b = bytes(raw)
        self.trusted = trusted

    @property
    def raw(self) -> bytes:
        return self._b

    def __eq__(self, other) -> bool:
        return isinstance(other, Point) and self._b == other._b

    def __hash__(self) -> int:
        return hash(self._b)

    def __repr__(self) -> str:
        return f"Point({self._b.hex()[:16]}...)"


class SodiumBackend(Backend):
    """Prime-order group backed by libsodium's Ristretto255 API."""

    name = "ristretto255/libsodium"
    order_bits = 253
    point_bytes = _POINT_BYTES
    scalar_bytes = _SCALAR_BYTES
    wide_bytes = _WIDE_BYTES

    IDENTITY_BYTES = b"\x00" * _POINT_BYTES

    def __init__(self, lib_path: Optional[str] = None):
        self._lib = _load_libsodium(lib_path)
        self._identity = Point(self.IDENTITY_BYTES, trusted=True)
        # Generator P = 1 * basepoint.
        one = self.scalar_from_int(1)
        self._generator = self._raw_mul_base(one)

    # -- internal helpers -------------------------------------------------
    @staticmethod
    def _buf(size: int = _POINT_BYTES):
        return (ctypes.c_ubyte * size)()

    @staticmethod
    def _arg(data: bytes):
        return (ctypes.c_ubyte * len(data))(*data)

    def _is_valid_point_bytes(self, data: bytes) -> bool:
        return bool(self._lib.crypto_core_ristretto255_is_valid_point(self._arg(data)))

    # -- version ----------------------------------------------------------
    @property
    def libsodium_version(self) -> str:
        self._lib.sodium_version_string.restype = ctypes.c_char_p
        return self._lib.sodium_version_string().decode()

    # -- group order ------------------------------------------------------
    @property
    def order(self) -> int:
        return RISTRETTO255_ORDER

    # -- scalars ----------------------------------------------------------
    def scalar_random(self) -> Scalar:
        out = self._buf(_SCALAR_BYTES)
        self._lib.crypto_core_ristretto255_scalar_random(out)
        return Scalar(bytes(out))

    def scalar_from_wide(self, data: bytes) -> Scalar:
        if len(data) != _WIDE_BYTES:
            raise InvalidScalar(f"wide reduction needs {_WIDE_BYTES} bytes, got {len(data)}")
        out = self._buf(_SCALAR_BYTES)
        self._lib.crypto_core_ristretto255_scalar_reduce(out, self._arg(data))
        return Scalar(bytes(out))

    def scalar_from_int(self, value: int) -> Scalar:
        value %= RISTRETTO255_ORDER
        return Scalar(value.to_bytes(_SCALAR_BYTES, "little"))

    def scalar_to_int(self, s: Scalar) -> int:
        return int.from_bytes(s.raw, "little")

    def scalar_add(self, a: Scalar, b: Scalar) -> Scalar:
        out = self._buf(_SCALAR_BYTES)
        self._lib.crypto_core_ristretto255_scalar_add(out, self._arg(a.raw), self._arg(b.raw))
        return Scalar(bytes(out))

    def scalar_sub(self, a: Scalar, b: Scalar) -> Scalar:
        out = self._buf(_SCALAR_BYTES)
        self._lib.crypto_core_ristretto255_scalar_sub(out, self._arg(a.raw), self._arg(b.raw))
        return Scalar(bytes(out))

    def scalar_mul(self, a: Scalar, b: Scalar) -> Scalar:
        out = self._buf(_SCALAR_BYTES)
        self._lib.crypto_core_ristretto255_scalar_mul(out, self._arg(a.raw), self._arg(b.raw))
        return Scalar(bytes(out))

    def scalar_invert(self, a: Scalar) -> Scalar:
        if self.scalar_is_zero(a):
            raise InvalidScalar("cannot invert zero")
        out = self._buf(_SCALAR_BYTES)
        rc = self._lib.crypto_core_ristretto255_scalar_invert(out, self._arg(a.raw))
        if rc != 0:  # pragma: no cover - guarded by the zero check above
            raise InvalidScalar("scalar_invert failed")
        return Scalar(bytes(out))

    def scalar_negate(self, a: Scalar) -> Scalar:
        out = self._buf(_SCALAR_BYTES)
        self._lib.crypto_core_ristretto255_scalar_negate(out, self._arg(a.raw))
        return Scalar(bytes(out))

    def scalar_is_zero(self, a: Scalar) -> bool:
        return a.raw == b"\x00" * _SCALAR_BYTES

    # -- group ------------------------------------------------------------
    @property
    def generator(self) -> Point:
        return self._generator

    @property
    def identity(self) -> Point:
        return self._identity

    def _raw_mul_base(self, k: Scalar) -> Point:
        out = self._buf()
        rc = self._lib.crypto_scalarmult_ristretto255_base(out, self._arg(k.raw))
        return self._interpret(rc, bytes(out), context="scalarmult_base")

    def _interpret(self, rc: int, out: bytes, context: str) -> Point:
        """Map a libsodium return code to a Point.

        ``rc == -1`` on a *trusted* input means the result is the identity;
        libsodium reports it as an error only because it is a failure for
        Diffie-Hellman.  We assert the buffer really is the identity encoding
        rather than trusting the return code alone.
        """
        if rc == 0:
            return Point(out, trusted=True)
        if out == self.IDENTITY_BYTES:
            return self._identity
        raise BackendError(  # pragma: no cover - would indicate libsodium misbehaviour
            f"{context}: rc={rc} with non-identity output {out.hex()}"
        )

    def point_mul(self, k: Scalar, point: Point) -> Point:
        if not point.trusted:  # pragma: no cover - defensive; see module docstring
            if not self._is_valid_point_bytes(point.raw):
                raise InvalidPoint("point_mul on an unvalidated, invalid point")
            point.trusted = True
        out = self._buf()
        rc = self._lib.crypto_scalarmult_ristretto255(out, self._arg(k.raw), self._arg(point.raw))
        return self._interpret(rc, bytes(out), context="scalarmult")

    def point_mul_base(self, k: Scalar) -> Point:
        return self._raw_mul_base(k)

    def point_add(self, a: Point, b: Point) -> Point:
        out = self._buf()
        rc = self._lib.crypto_core_ristretto255_add(out, self._arg(a.raw), self._arg(b.raw))
        if rc != 0:
            raise InvalidPoint("point_add: invalid operand")
        return Point(bytes(out), trusted=True)

    def point_sub(self, a: Point, b: Point) -> Point:
        out = self._buf()
        rc = self._lib.crypto_core_ristretto255_sub(out, self._arg(a.raw), self._arg(b.raw))
        if rc != 0:
            raise InvalidPoint("point_sub: invalid operand")
        return Point(bytes(out), trusted=True)

    def point_eq(self, a: Point, b: Point) -> bool:
        return a.raw == b.raw

    def point_is_identity(self, point: Point) -> bool:
        return point.raw == self.IDENTITY_BYTES

    # -- encoding ---------------------------------------------------------
    def point_to_bytes(self, point: Point) -> bytes:
        return point.raw

    def point_from_bytes(self, data: bytes) -> Point:
        """The single entry point for untrusted bytes.  Validates once."""
        if len(data) != _POINT_BYTES:
            raise InvalidPoint(f"point must be {_POINT_BYTES} bytes, got {len(data)}")
        if data == self.IDENTITY_BYTES:
            return self._identity
        if not self._is_valid_point_bytes(data):
            raise InvalidPoint("not a canonical Ristretto255 encoding")
        return Point(data, trusted=True)

    def scalar_to_bytes(self, s: Scalar) -> bytes:
        return s.raw

    def scalar_from_bytes(self, data: bytes) -> Scalar:
        if len(data) != _SCALAR_BYTES:
            raise InvalidScalar(f"scalar must be {_SCALAR_BYTES} bytes, got {len(data)}")
        if int.from_bytes(data, "little") >= RISTRETTO255_ORDER:
            raise InvalidScalar("scalar is not canonical (>= group order)")
        return Scalar(data)

    def point_from_hash(self, wide: bytes) -> Point:
        """Hash-to-group.  Not used by the scheme; useful for tests."""
        if len(wide) != _WIDE_BYTES:
            raise InvalidPoint(f"from_hash needs {_WIDE_BYTES} bytes, got {len(wide)}")
        out = self._buf()
        self._lib.crypto_core_ristretto255_from_hash(out, self._arg(wide))
        return Point(bytes(out), trusted=True)
