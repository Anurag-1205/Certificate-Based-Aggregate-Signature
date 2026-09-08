"""Length-prefixed TLV encoding for hash inputs.

The paper writes hash inputs as concatenations, e.g.
``H1(m_i || pk_i || R_i || id_i || T_i || D)``.  Plain concatenation of
**variable-length** fields is ambiguous: with ``m="ab", id="c"`` and
``m="a", id="bc"`` the concatenation is byte-identical, so the two distinct
inputs hash to the same value.  Given a signature on one, you have a signature
on the other.  That is a forgery vector introduced entirely by implementation
choices -- the scheme on paper is fine.

We therefore encode every hash input as length-prefixed TLV:

    count(4) || len(f_1)(4) || f_1 || len(f_2)(4) || f_2 || ...

Encoding the field *count* as well as each length means that inputs with
different arities cannot collide either, not just inputs with different field
splits.  The encoding is injective: distinct field tuples always produce
distinct byte strings.
"""

from __future__ import annotations

from typing import Iterator, Sequence

#: Width of the count and length prefixes, in bytes.
PREFIX = 4
_MAX = 2**(8 * PREFIX) - 1


class EncodingError(ValueError):
    """A value could not be encoded, or a buffer could not be decoded."""


def tlv_encode(*fields: bytes) -> bytes:
    """Encode a tuple of byte strings injectively."""
    if len(fields) > _MAX:
        raise EncodingError(f"too many fields: {len(fields)}")
    out = [len(fields).to_bytes(PREFIX, "big")]
    for i, f in enumerate(fields):
        if not isinstance(f, (bytes, bytearray, memoryview)):
            raise EncodingError(f"field {i} is {type(f).__name__}, expected bytes")
        f = bytes(f)
        if len(f) > _MAX:
            raise EncodingError(f"field {i} too long: {len(f)} bytes")
        out.append(len(f).to_bytes(PREFIX, "big"))
        out.append(f)
    return b"".join(out)


def tlv_decode(data: bytes) -> list[bytes]:
    """Inverse of :func:`tlv_encode`.  Used by tests to prove injectivity."""
    if len(data) < PREFIX:
        raise EncodingError("buffer too short for field count")
    count = int.from_bytes(data[:PREFIX], "big")
    pos = PREFIX
    fields: list[bytes] = []
    for i in range(count):
        if pos + PREFIX > len(data):
            raise EncodingError(f"truncated length prefix for field {i}")
        length = int.from_bytes(data[pos:pos + PREFIX], "big")
        pos += PREFIX
        if pos + length > len(data):
            raise EncodingError(f"truncated value for field {i}")
        fields.append(data[pos:pos + length])
        pos += length
    if pos != len(data):
        raise EncodingError(f"{len(data) - pos} trailing bytes")
    return fields


def enc_utf8(s: str) -> bytes:
    """Encode a text field (identity, state information)."""
    return s.encode("utf-8")


def enc_u64(v: int) -> bytes:
    """Encode an unsigned integer field in fixed width."""
    if not 0 <= v < 2**64:
        raise EncodingError(f"value out of range for u64: {v}")
    return v.to_bytes(8, "big")


def as_bytes(value) -> bytes:
    """Coerce str/bytes/int into a field encoding."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return enc_utf8(value)
    if isinstance(value, int):
        return enc_u64(value)
    raise EncodingError(f"cannot encode {type(value).__name__}")
