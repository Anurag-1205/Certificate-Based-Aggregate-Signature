"""NIST P-256 backend: a ctypes wrapper over OpenSSL libcrypto.

A second backend exists for three reasons, all of which bear on the evidence
this project reports.

1. **Curve independence.** Results obtained on one group could in principle be
   an artefact of that group's library. Running the whole suite on an unrelated
   curve, in an unrelated library, removes that possibility.
2. **A stronger test of the cost model.** P-256 through OpenSSL has a different
   balance between scalar multiplication, point addition and hashing than
   Ristretto255 through libsodium. The predicted slope ratio between the two
   schemes is a function of those costs, so it takes a different value here. If
   measurement tracks the prediction on both backends, with different constants,
   the model is confirmed far more strongly than by one agreement alone.
3. **Differential testing.** Two independent implementations of the same scheme
   must agree on every count; disagreement would indicate a bug in one of them.

P-256 is also the curve actually deployed in industrial IoT stacks, so the
timings here are the more representative of the two for that setting.

Implementation notes
--------------------
Every pointer-returning OpenSSL function has its ``restype`` set explicitly.
ctypes defaults to ``c_int``, which silently truncates 64-bit pointers; that is
the classic way to corrupt a libcrypto binding.

``EC_POINT`` and ``BIGNUM`` are owned by small wrapper objects that free the
underlying allocation on collection.
"""

from __future__ import annotations

import ctypes
import ctypes.util
from typing import Optional

from .base import Backend, BackendError, InvalidPoint, InvalidScalar

NID_X9_62_prime256v1 = 415
POINT_CONVERSION_COMPRESSED = 2

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _load_libcrypto(path: Optional[str] = None) -> ctypes.CDLL:
    candidates = [path] if path else []
    found = ctypes.util.find_library("crypto")
    if found:
        candidates.append(found)
    candidates += ["libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so", "libcrypto.dylib"]
    errors = []
    for cand in candidates:
        if not cand:
            continue
        try:
            lib = ctypes.CDLL(cand)
        except OSError as exc:
            errors.append(f"{cand}: {exc}")
            continue
        if not hasattr(lib, "EC_GROUP_new_by_curve_name"):
            errors.append(f"{cand}: no EC support")
            continue
        _declare(lib)
        return lib
    raise BackendError("could not load libcrypto. Tried: " + "; ".join(errors or candidates))


def _declare(l: ctypes.CDLL) -> None:
    """Set restype/argtypes.  Pointer returns MUST be declared, or they truncate."""
    P = ctypes.c_void_p
    l.EC_GROUP_new_by_curve_name.restype = P
    l.EC_GROUP_new_by_curve_name.argtypes = [ctypes.c_int]
    l.EC_GROUP_get0_order.restype = P
    l.EC_GROUP_get0_order.argtypes = [P]
    l.EC_GROUP_get0_generator.restype = P
    l.EC_GROUP_get0_generator.argtypes = [P]
    l.EC_POINT_new.restype = P
    l.EC_POINT_new.argtypes = [P]
    l.EC_POINT_free.argtypes = [P]
    l.EC_POINT_copy.argtypes = [P, P]
    l.EC_POINT_mul.argtypes = [P, P, P, P, P, P]
    l.EC_POINT_add.argtypes = [P, P, P, P, P]
    l.EC_POINT_invert.argtypes = [P, P, P]
    l.EC_POINT_cmp.argtypes = [P, P, P, P]
    l.EC_POINT_is_at_infinity.argtypes = [P, P]
    l.EC_POINT_set_to_infinity.argtypes = [P, P]
    l.EC_POINT_is_on_curve.argtypes = [P, P, P]
    l.EC_POINT_point2oct.restype = ctypes.c_size_t
    l.EC_POINT_point2oct.argtypes = [P, P, ctypes.c_int, ctypes.c_char_p,
                                     ctypes.c_size_t, P]
    l.EC_POINT_oct2point.argtypes = [P, P, ctypes.c_char_p, ctypes.c_size_t, P]

    l.BN_CTX_new.restype = P
    l.BN_CTX_free.argtypes = [P]
    l.BN_new.restype = P
    l.BN_free.argtypes = [P]
    l.BN_bin2bn.restype = P
    l.BN_bin2bn.argtypes = [ctypes.c_char_p, ctypes.c_int, P]
    l.BN_bn2binpad.argtypes = [P, ctypes.c_char_p, ctypes.c_int]
    l.BN_mod_add.argtypes = [P, P, P, P, P]
    l.BN_mod_sub.argtypes = [P, P, P, P, P]
    l.BN_mod_mul.argtypes = [P, P, P, P, P]
    l.BN_mod_inverse.restype = P
    l.BN_mod_inverse.argtypes = [P, P, P, P]
    l.BN_nnmod.argtypes = [P, P, P, P]
    l.BN_rand_range.argtypes = [P, P]
    l.BN_is_zero.argtypes = [P]
    l.BN_num_bits.argtypes = [P]
    l.BN_cmp.argtypes = [P, P]


class _BN:
    """An owned BIGNUM, compared by value.

    Value equality is not decoration: the scheme and its tests compare scalars
    and points routinely, and Python's default identity comparison would make
    every such check silently false.
    """

    __slots__ = ("ptr", "_lib")

    def __init__(self, lib, ptr):
        self._lib, self.ptr = lib, ptr

    def _bytes(self) -> bytes:
        buf = ctypes.create_string_buffer(32)
        self._lib.BN_bn2binpad(self.ptr, buf, 32)
        return buf.raw[:32]

    def __eq__(self, other) -> bool:
        if not isinstance(other, _BN):
            return NotImplemented
        return self._lib.BN_cmp(self.ptr, other.ptr) == 0

    def __hash__(self) -> int:
        return hash(self._bytes())

    def __repr__(self) -> str:
        return f"Scalar({self._bytes().hex()[:16]}...)"

    def __del__(self):
        try:
            self._lib.BN_free(self.ptr)
        except Exception:  # pragma: no cover
            pass


class _PT:
    """An owned EC_POINT, compared by value.

    Carries the group and BN_CTX pointers as plain integers rather than a
    reference to the backend, so that points do not form reference cycles with
    the object that owns the group.
    """

    __slots__ = ("ptr", "_lib", "_group", "_ctx", "trusted")

    def __init__(self, lib, ptr, group=None, ctx=None, trusted=True):
        self._lib, self.ptr = lib, ptr
        self._group, self._ctx = group, ctx
        self.trusted = trusted

    def _bytes(self) -> bytes:
        size = self._lib.EC_POINT_point2oct(
            self._group, self.ptr, POINT_CONVERSION_COMPRESSED, None, 0, self._ctx)
        buf = ctypes.create_string_buffer(size)
        self._lib.EC_POINT_point2oct(self._group, self.ptr,
                                     POINT_CONVERSION_COMPRESSED, buf, size, self._ctx)
        return buf.raw[:size]

    def __eq__(self, other) -> bool:
        if not isinstance(other, _PT):
            return NotImplemented
        return self._lib.EC_POINT_cmp(self._group, self.ptr, other.ptr, self._ctx) == 0

    def __hash__(self) -> int:
        return hash(self._bytes())

    def __repr__(self) -> str:
        return f"Point({self._bytes().hex()[:16]}...)"

    def __del__(self):
        try:
            self._lib.EC_POINT_free(self.ptr)
        except Exception:  # pragma: no cover
            pass


class OpenSSLBackend(Backend):
    """Prime-order group: NIST P-256 via OpenSSL libcrypto."""

    name = "p256/openssl"
    order_bits = 256
    point_bytes = 33      # compressed
    scalar_bytes = 32

    def __init__(self, lib_path: Optional[str] = None):
        self._lib = _load_libcrypto(lib_path)
        self._group = self._lib.EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)
        if not self._group:  # pragma: no cover
            raise BackendError("EC_GROUP_new_by_curve_name failed for P-256")
        self._ctx = self._lib.BN_CTX_new()
        self._order_ptr = self._lib.EC_GROUP_get0_order(self._group)

        gen = self._lib.EC_GROUP_get0_generator(self._group)
        g = self._lib.EC_POINT_new(self._group)
        self._lib.EC_POINT_copy(g, gen)
        self._generator = _PT(self._lib, g, self._group, self._ctx)

        inf = self._lib.EC_POINT_new(self._group)
        self._lib.EC_POINT_set_to_infinity(self._group, inf)
        self._identity = _PT(self._lib, inf, self._group, self._ctx)

    # -- helpers ----------------------------------------------------------
    def _new_bn(self) -> _BN:
        return _BN(self._lib, self._lib.BN_new())

    def _new_pt(self) -> _PT:
        return _PT(self._lib, self._lib.EC_POINT_new(self._group),
                   self._group, self._ctx)

    @property
    def openssl_version(self) -> str:
        self._lib.OpenSSL_version.restype = ctypes.c_char_p
        self._lib.OpenSSL_version.argtypes = [ctypes.c_int]
        return self._lib.OpenSSL_version(0).decode()

    @property
    def order(self) -> int:
        return P256_ORDER

    # -- scalars ----------------------------------------------------------
    def scalar_random(self) -> _BN:
        bn = self._new_bn()
        self._lib.BN_rand_range(bn.ptr, self._order_ptr)
        if self._lib.BN_is_zero(bn.ptr):  # pragma: no cover
            return self.scalar_from_int(1)
        return bn

    def scalar_from_wide(self, data: bytes) -> _BN:
        if len(data) != 64:
            raise InvalidScalar(f"wide reduction needs 64 bytes, got {len(data)}")
        tmp = self._lib.BN_bin2bn(data, len(data), None)
        out = self._new_bn()
        self._lib.BN_nnmod(out.ptr, tmp, self._order_ptr, self._ctx)
        self._lib.BN_free(tmp)
        return out

    def scalar_from_int(self, value: int) -> _BN:
        value %= P256_ORDER
        raw = value.to_bytes(32, "big")
        return _BN(self._lib, self._lib.BN_bin2bn(raw, 32, None))

    def scalar_to_int(self, s: _BN) -> int:
        buf = ctypes.create_string_buffer(32)
        self._lib.BN_bn2binpad(s.ptr, buf, 32)
        return int.from_bytes(buf.raw, "big")

    def _bn_binop(self, fn, a: _BN, b: _BN) -> _BN:
        out = self._new_bn()
        fn(out.ptr, a.ptr, b.ptr, self._order_ptr, self._ctx)
        return out

    def scalar_add(self, a, b):
        return self._bn_binop(self._lib.BN_mod_add, a, b)

    def scalar_sub(self, a, b):
        return self._bn_binop(self._lib.BN_mod_sub, a, b)

    def scalar_mul(self, a, b):
        return self._bn_binop(self._lib.BN_mod_mul, a, b)

    def scalar_invert(self, a: _BN) -> _BN:
        if self.scalar_is_zero(a):
            raise InvalidScalar("cannot invert zero")
        ptr = self._lib.BN_mod_inverse(None, a.ptr, self._order_ptr, self._ctx)
        if not ptr:  # pragma: no cover
            raise InvalidScalar("BN_mod_inverse failed")
        return _BN(self._lib, ptr)

    def scalar_negate(self, a: _BN) -> _BN:
        return self.scalar_sub(self.scalar_from_int(0), a)

    def scalar_is_zero(self, a: _BN) -> bool:
        return bool(self._lib.BN_is_zero(a.ptr))

    # -- group ------------------------------------------------------------
    @property
    def generator(self) -> _PT:
        return self._generator

    @property
    def identity(self) -> _PT:
        return self._identity

    def point_mul(self, k: _BN, point: _PT) -> _PT:
        out = self._new_pt()
        if self._lib.EC_POINT_mul(self._group, out.ptr, None, point.ptr,
                                  k.ptr, self._ctx) != 1:  # pragma: no cover
            raise BackendError("EC_POINT_mul failed")
        return out

    def point_mul_base(self, k: _BN) -> _PT:
        out = self._new_pt()
        if self._lib.EC_POINT_mul(self._group, out.ptr, k.ptr, None,
                                  None, self._ctx) != 1:  # pragma: no cover
            raise BackendError("EC_POINT_mul (base) failed")
        return out

    def point_add(self, a: _PT, b: _PT) -> _PT:
        out = self._new_pt()
        if self._lib.EC_POINT_add(self._group, out.ptr, a.ptr, b.ptr,
                                  self._ctx) != 1:  # pragma: no cover
            raise InvalidPoint("EC_POINT_add failed")
        return out

    def point_sub(self, a: _PT, b: _PT) -> _PT:
        neg = self._new_pt()
        self._lib.EC_POINT_copy(neg.ptr, b.ptr)
        if self._lib.EC_POINT_invert(self._group, neg.ptr, self._ctx) != 1:  # pragma: no cover
            raise InvalidPoint("EC_POINT_invert failed")
        return self.point_add(a, neg)

    def point_eq(self, a: _PT, b: _PT) -> bool:
        return self._lib.EC_POINT_cmp(self._group, a.ptr, b.ptr, self._ctx) == 0

    def point_is_identity(self, point: _PT) -> bool:
        return bool(self._lib.EC_POINT_is_at_infinity(self._group, point.ptr))

    # -- encoding ---------------------------------------------------------
    def point_to_bytes(self, point: _PT) -> bytes:
        size = self._lib.EC_POINT_point2oct(
            self._group, point.ptr, POINT_CONVERSION_COMPRESSED, None, 0, self._ctx)
        if size == 0:  # pragma: no cover
            raise InvalidPoint("point2oct sizing failed")
        buf = ctypes.create_string_buffer(size)
        if self._lib.EC_POINT_point2oct(self._group, point.ptr,
                                        POINT_CONVERSION_COMPRESSED, buf,
                                        size, self._ctx) != size:  # pragma: no cover
            raise InvalidPoint("point2oct failed")
        return buf.raw[:size]

    def point_from_bytes(self, data: bytes) -> _PT:
        """The single entry point for untrusted bytes.  Validates once."""
        if not data:
            raise InvalidPoint("empty point encoding")
        out = self._new_pt()
        if self._lib.EC_POINT_oct2point(self._group, out.ptr, data,
                                        len(data), self._ctx) != 1:
            raise InvalidPoint("not a valid P-256 point encoding")
        if not self.point_is_identity(out) and \
                self._lib.EC_POINT_is_on_curve(self._group, out.ptr, self._ctx) != 1:
            raise InvalidPoint("point is not on the curve")  # pragma: no cover
        return out

    def scalar_to_bytes(self, s: _BN) -> bytes:
        buf = ctypes.create_string_buffer(32)
        self._lib.BN_bn2binpad(s.ptr, buf, 32)
        return buf.raw[:32]

    def scalar_from_bytes(self, data: bytes) -> _BN:
        if len(data) != 32:
            raise InvalidScalar(f"scalar must be 32 bytes, got {len(data)}")
        if int.from_bytes(data, "big") >= P256_ORDER:
            raise InvalidScalar("scalar is not canonical (>= group order)")
        return _BN(self._lib, self._lib.BN_bin2bn(data, 32, None))
