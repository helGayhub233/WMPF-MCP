"""Minimal protobuf wire-format helpers (varint + length-delimited only).

The WMPF remote-debug messages are simple protos; this module implements just
the wire primitives needed to read/write them without pulling in a protobuf
runtime or generated code. Field numbers and types used by the message layer
(``codec.py``) are protocol facts taken from the public ``wmpf_debug.proto``
descriptor shipped by the WeChat devtools protocol research.
"""

from __future__ import annotations

from typing import Iterator

WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_LENGTH = 2
WIRE_FIXED32 = 5


class ProtoError(ValueError):
    """Malformed protobuf wire data."""


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ProtoError("negative varint is not supported")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ProtoError("truncated varint")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ProtoError("varint too long")


def encode_tag(field_no: int, wire_type: int) -> bytes:
    return encode_varint((field_no << 3) | wire_type)


def encode_uint(field_no: int, value: int) -> bytes:
    """proto3 semantics: default (0) values are not serialized."""
    if not value:
        return b""
    return encode_tag(field_no, WIRE_VARINT) + encode_varint(value)


def encode_str(field_no: int, text: str) -> bytes:
    if not text:
        return b""
    return encode_bytes(field_no, text.encode("utf-8"))


def encode_bytes(field_no: int, payload: bytes) -> bytes:
    if not payload:
        return b""
    return encode_tag(field_no, WIRE_LENGTH) + encode_varint(len(payload)) + payload


def iter_fields(data: bytes) -> Iterator[tuple[int, int, int | bytes]]:
    """Yield ``(field_no, wire_type, value)`` for each field.

    Varint fields yield ints; length-delimited fields yield bytes; fixed32/64
    values are yielded as raw ints (rarely used by these protos).
    """
    pos = 0
    while pos < len(data):
        tag, pos = decode_varint(data, pos)
        field_no = tag >> 3
        wire_type = tag & 0x7
        if field_no == 0:
            raise ProtoError("field number 0 is invalid")
        if wire_type == WIRE_VARINT:
            value, pos = decode_varint(data, pos)
            yield field_no, wire_type, value
        elif wire_type == WIRE_LENGTH:
            length, pos = decode_varint(data, pos)
            if pos + length > len(data):
                raise ProtoError("truncated length-delimited field")
            yield field_no, wire_type, data[pos : pos + length]
            pos += length
        elif wire_type == WIRE_FIXED64:
            if pos + 8 > len(data):
                raise ProtoError("truncated fixed64 field")
            yield field_no, wire_type, int.from_bytes(data[pos : pos + 8], "little")
            pos += 8
        elif wire_type == WIRE_FIXED32:
            if pos + 4 > len(data):
                raise ProtoError("truncated fixed32 field")
            yield field_no, wire_type, int.from_bytes(data[pos : pos + 4], "little")
            pos += 4
        else:
            raise ProtoError(f"unsupported wire type {wire_type}")


def first_uint(data: bytes, field_no: int) -> int:
    for number, wire_type, value in iter_fields(data):
        if number == field_no and wire_type == WIRE_VARINT and isinstance(value, int):
            return value
    return 0


def first_bytes(data: bytes, field_no: int) -> bytes:
    for number, wire_type, value in iter_fields(data):
        if number == field_no and wire_type == WIRE_LENGTH and isinstance(value, bytes):
            return value
    return b""


def first_str(data: bytes, field_no: int) -> str:
    return first_bytes(data, field_no).decode("utf-8", errors="replace")
