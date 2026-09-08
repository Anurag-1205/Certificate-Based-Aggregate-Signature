"""TLV encoding must be injective, or hash inputs are ambiguous."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cbas.encoding import EncodingError, tlv_decode, tlv_encode


def test_the_concatenation_ambiguity_is_closed():
    """The motivating attack: ("ab","c") and ("a","bc") must not collide.

    Under plain concatenation both are b"abc".  Under TLV they differ.
    """
    assert b"ab" + b"c" == b"a" + b"bc"           # the hazard is real
    assert tlv_encode(b"ab", b"c") != tlv_encode(b"a", b"bc")


def test_arity_does_not_collide():
    """Different field counts must not collide either."""
    assert tlv_encode(b"abc") != tlv_encode(b"abc", b"")
    assert tlv_encode(b"a", b"b", b"c") != tlv_encode(b"a", b"bc")


def test_empty_fields_are_distinguishable():
    assert tlv_encode(b"", b"") != tlv_encode(b"")
    assert tlv_encode(b"", b"a") != tlv_encode(b"a", b"")


def test_roundtrip():
    fields = [b"", b"a", b"hello world", bytes(range(256))]
    assert tlv_decode(tlv_encode(*fields)) == fields


def test_rejects_non_bytes():
    with pytest.raises(EncodingError):
        tlv_encode("a string")           # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [b"", b"\x00\x00\x00\x01", b"\x00\x00\x00\x01\x00\x00\x00\x05ab"])
def test_decode_rejects_malformed(bad):
    with pytest.raises(EncodingError):
        tlv_decode(bad)


def test_decode_rejects_trailing_bytes():
    with pytest.raises(EncodingError):
        tlv_decode(tlv_encode(b"a") + b"junk")


@given(st.lists(st.binary(max_size=64), max_size=8))
@settings(max_examples=200)
def test_roundtrip_property(fields):
    assert tlv_decode(tlv_encode(*fields)) == fields


@given(
    st.lists(st.binary(max_size=32), max_size=5),
    st.lists(st.binary(max_size=32), max_size=5),
)
@settings(max_examples=400)
def test_injective_property(a, b):
    """Distinct field tuples always produce distinct encodings."""
    if a == b:
        assert tlv_encode(*a) == tlv_encode(*b)
    else:
        assert tlv_encode(*a) != tlv_encode(*b)
