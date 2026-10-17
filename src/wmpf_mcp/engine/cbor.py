"""Decoder for native WeChat devtools filter messages.

Observed framing on 25800: values are wrapped as ``d8 18`` (tag 24) around a
byte string whose payload is a nested CBOR item; maps/arrays/text/int/float
follow CBOR encoding. CRDTP uses untagged byte strings for UTF-16LE text
and tag 22 for binary data rendered as base64 in CDP JSON.

The same filter also receives UTF-8 JSON, notably Inspector.detached during
runtime shutdown. Identify JSON objects before CBOR decoding, without retrying
malformed CBOR as another encoding. ``decode_message`` consumes one full message.
"""

from __future__ import annotations

import base64
import json
import struct
from typing import Any

MAX_CONTAINER_DEPTH = 300
MAX_TAG_DEPTH = 16


class CborError(ValueError):
    """Native message decode failure (legacy exception name)."""


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant {value}")


def _read_uint(data: memoryview, pos: int, info: int) -> tuple[int, int]:
    if info < 24:
        return info, pos
    width = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if width is None:
        raise CborError(f"reserved additional info {info}")
    if pos + width > len(data):
        raise CborError("truncated integer/length")
    return int.from_bytes(data[pos : pos + width], "big"), pos + width


def _decode_item(data: memoryview, pos: int, depth: int = 0,
                 raw_bytes: bool = False, tag_depth: int = 0) -> tuple[Any, int]:
    # CRDTP counts objects/arrays, not their tag-24 byte-string envelopes.
    # 300 matches its container stack limit; tag recursion is bounded separately.
    if depth > MAX_CONTAINER_DEPTH:
        raise CborError(f"container nesting exceeds {MAX_CONTAINER_DEPTH}")
    if pos >= len(data):
        raise CborError("truncated item")
    initial = data[pos]
    pos += 1
    major = initial >> 5
    info = initial & 0x1F

    if major == 0:  # unsigned int
        value, pos = _read_uint(data, pos, info)
        return value, pos
    if major == 1:  # negative int
        value, pos = _read_uint(data, pos, info)
        return -1 - value, pos
    if major == 2:  # byte string
        length, pos = _read_uint(data, pos, info)
        chunk = data[pos : pos + length]
        if len(chunk) != length:
            raise CborError("truncated byte string")
        if raw_bytes:
            return chunk, pos + length
        # CRDTP uses untagged byte strings for UTF-16LE (including lone
        # surrogates). Only tag-24 envelopes and tag-22 binary keep raw bytes.
        if length % 2:
            raise CborError("odd-length UTF-16 string")
        return bytes(chunk).decode("utf-16-le", errors="surrogatepass"), pos + length
    if major == 3:  # text string
        length, pos = _read_uint(data, pos, info)
        chunk = data[pos : pos + length]
        if len(chunk) != length:
            raise CborError("truncated text string")
        try:
            return bytes(chunk).decode("utf-8"), pos + length
        except UnicodeDecodeError as error:
            raise CborError("invalid UTF-8 string") from error
    if major == 4:  # array
        if info == 31:  # indefinite
            items: list[Any] = []
            while True:
                if pos >= len(data):
                    raise CborError("unterminated array")
                if data[pos] == 0xFF:
                    return items, pos + 1
                item, pos = _decode_item(data, pos, depth + 1)
                items.append(item)
        length, pos = _read_uint(data, pos, info)
        items = []
        for _ in range(length):
            item, pos = _decode_item(data, pos, depth + 1)
            items.append(item)
        return items, pos
    if major == 5:  # map
        result: dict[Any, Any] = {}
        if info == 31:  # indefinite
            while True:
                if pos >= len(data):
                    raise CborError("unterminated map")
                if data[pos] == 0xFF:
                    return result, pos + 1
                key, pos = _decode_item(data, pos, depth + 1)
                value, pos = _decode_item(data, pos, depth + 1)
                result[key if isinstance(key, (str, int)) else str(key)] = value
        length, pos = _read_uint(data, pos, info)
        for _ in range(length):
            key, pos = _decode_item(data, pos, depth + 1)
            value, pos = _decode_item(data, pos, depth + 1)
            result[key if isinstance(key, (str, int)) else str(key)] = value
        return result, pos
    if major == 6:  # tag
        if tag_depth >= MAX_TAG_DEPTH:
            raise CborError(f"tag nesting exceeds {MAX_TAG_DEPTH}")
        tag, pos = _read_uint(data, pos, info)
        item, pos = _decode_item(data, pos, depth, raw_bytes=tag in (22, 24), tag_depth=tag_depth + 1)
        if tag == 24:
            if not isinstance(item, memoryview):
                raise CborError("envelope must wrap a byte string")
            # Views avoid copying the whole remaining subtree at every envelope.
            inner, used = _decode_item(item, 0, depth, tag_depth=tag_depth + 1)
            if used != len(item):
                raise CborError("trailing bytes inside envelope")
            return inner, pos
        if tag == 22:
            if not isinstance(item, memoryview):
                raise CborError("binary tag must wrap a byte string")
            return base64.b64encode(item).decode("ascii"), pos
        return item, pos
    if major == 7:
        if info == 20:
            return False, pos
        if info == 21:
            return True, pos
        if info == 22:
            return None, pos
        if info == 25:  # half float
            value, pos = _read_uint(data, pos, 25)
            return struct.unpack(">e", value.to_bytes(2, "big"))[0], pos
        if info == 26:
            value, pos = _read_uint(data, pos, 26)
            return struct.unpack(">f", value.to_bytes(4, "big"))[0], pos
        if info == 27:
            value, pos = _read_uint(data, pos, 27)
            return struct.unpack(">d", value.to_bytes(8, "big"))[0], pos
        raise CborError(f"unsupported simple value {info}")
    raise CborError(f"unsupported major type {major}")


def decode_message(buf: bytes) -> Any:
    """Decode one native message: an identified JSON object or full CBOR item.

    CDP JSON begins with ``{`` (optionally after JSON whitespace), whereas a
    CRDTP message begins with its tag-24 envelope. No parse-error fallback or
    lossy text replacement is used; invalid JSON and CBOR remain failures.
    """
    if buf.lstrip(b" \t\r\n").startswith(b"{"):
        try:
            return json.loads(buf.decode("utf-8"), parse_constant=_reject_json_constant)
        except (UnicodeDecodeError, ValueError) as error:
            raise CborError("invalid native JSON message") from error
    value, pos = _decode_item(memoryview(buf), 0)
    if pos != len(buf):
        raise CborError("trailing bytes after message")
    return value


__all__ = ["CborError", "decode_message"]
