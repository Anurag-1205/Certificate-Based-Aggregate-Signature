"""Ed25519 signatures as a reference point.

Neither scheme is competing with Ed25519 -- it does not aggregate, and it has no
certificate structure.  It is included because it is the signature scheme a
reader is most likely to have intuitions about, so plotting *n* independent
Ed25519 verifications next to one aggregate verification shows at a glance what
aggregation costs and what it buys.

Bound directly from the same libsodium already loaded by the backend.
"""

from __future__ import annotations

import ctypes

from cbas.backend import SodiumBackend

_PK, _SK, _SIG = 32, 64, 64


class Ed25519:
    def __init__(self, backend: SodiumBackend | None = None):
        self._lib = (backend or SodiumBackend())._lib

    def keypair(self) -> tuple[bytes, bytes]:
        pk, sk = (ctypes.c_ubyte * _PK)(), (ctypes.c_ubyte * _SK)()
        if self._lib.crypto_sign_keypair(pk, sk) != 0:  # pragma: no cover
            raise RuntimeError("crypto_sign_keypair failed")
        return bytes(pk), bytes(sk)

    def sign(self, message: bytes, sk: bytes) -> bytes:
        sig = (ctypes.c_ubyte * _SIG)()
        slen = ctypes.c_ulonglong(0)
        rc = self._lib.crypto_sign_detached(
            sig, ctypes.byref(slen),
            (ctypes.c_ubyte * len(message))(*message), ctypes.c_ulonglong(len(message)),
            (ctypes.c_ubyte * _SK)(*sk),
        )
        if rc != 0:  # pragma: no cover
            raise RuntimeError("crypto_sign_detached failed")
        return bytes(sig)

    def verify(self, sig: bytes, message: bytes, pk: bytes) -> bool:
        return self._lib.crypto_sign_verify_detached(
            (ctypes.c_ubyte * _SIG)(*sig),
            (ctypes.c_ubyte * len(message))(*message), ctypes.c_ulonglong(len(message)),
            (ctypes.c_ubyte * _PK)(*pk),
        ) == 0
