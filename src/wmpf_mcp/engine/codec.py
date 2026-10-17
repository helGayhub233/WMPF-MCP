"""Message codec for the WMPF remote-debug protocol (docs/02 §3.5).

Two layers, matching the runtime's structure:

- Outer envelope ``WARemoteDebug_DebugMessage``:
  ``seq(1,u32) after(2,u32) category(3,str) data(4,bytes)
  compressAlgo(5,u32) originalSize(6,u32)``
- Inner payloads by category; the CDP bridge uses
  ``chromeDevtools`` / ``chromeDevtoolsResult``:
  ``opId(1,u64) payload(2,str) jscontextId(3,str)``

Field numbers are protocol facts (public descriptor); the wire primitives are
our own (``proto.py``). CDP JSON travels verbatim in ``payload``.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass

from .proto import (
    ProtoError,
    encode_bytes,
    encode_str,
    encode_uint,
    first_str,
    first_uint,
    iter_fields,
)

# -- categories (DebugMessageCategory) ---------------------------------------
CAT_SETUP_CONTEXT = "setupContext"
CAT_CHROME_DEVTOOLS = "chromeDevtools"
CAT_CHROME_DEVTOOLS_RESULT = "chromeDevtoolsResult"
CAT_PING = "ping"
CAT_PONG = "pong"
CAT_ADD_JS_CONTEXT = "addJsContext"
CAT_REMOVE_JS_CONTEXT = "removeJsContext"
CAT_CALL_INTERFACE = "callInterface"
CAT_CALL_INTERFACE_RESULT = "callInterfaceResult"
CAT_EVALUATE_JS = "evaluateJavascript"
CAT_EVALUATE_JS_RESULT = "evaluateJavascriptResult"
CAT_BREAKPOINT = "breakpoint"
CAT_DOM_OP = "domOp"
CAT_DOM_EVENT = "domEvent"
CAT_NETWORK_DEBUG_API = "networkDebugAPI"
CAT_CUSTOM = "customMessage"

COMPRESS_ZLIB = 1


class CodecError(ValueError):
    """Undecodable remote-debug message."""


@dataclass
class DebugMessage:
    """Outer envelope (WARemoteDebug_DebugMessage)."""

    seq: int = 0
    after: int = 0
    category: str = ""
    data: bytes = b""
    compress_algo: int = 0
    original_size: int = 0

    @classmethod
    def parse(cls, buf: bytes) -> "DebugMessage":
        msg = cls()
        for number, wire_type, value in iter_fields(buf):
            if number == 1 and isinstance(value, int):
                msg.seq = value
            elif number == 2 and isinstance(value, int):
                msg.after = value
            elif number == 3 and isinstance(value, bytes):
                msg.category = value.decode("utf-8", errors="replace")
            elif number == 4 and isinstance(value, bytes):
                msg.data = value
            elif number == 5 and isinstance(value, int):
                msg.compress_algo = value
            elif number == 6 and isinstance(value, int):
                msg.original_size = value
        return msg

    def serialize(self) -> bytes:
        return (
            encode_uint(1, self.seq)
            + encode_uint(2, self.after)
            + encode_str(3, self.category)
            + encode_bytes(4, self.data)
            + encode_uint(5, self.compress_algo)
            + encode_uint(6, self.original_size)
        )

    def payload_bytes(self) -> bytes:
        """``data`` after undoing the declared compression (zlib bit flag)."""
        if self.data and self.compress_algo and (self.compress_algo & COMPRESS_ZLIB):
            try:
                return zlib.decompress(self.data)
            except zlib.error as error:
                raise CodecError(f"zlib payload decompression failed: {error}") from error
        return self.data


@dataclass
class ChromeDevtools:
    """CDP bridge payload (ChromeDevtools / ChromeDevtoolsResult)."""

    op_id: int = 0
    payload: str = ""
    jscontext_id: str = ""

    @classmethod
    def parse(cls, buf: bytes) -> "ChromeDevtools":
        return cls(
            op_id=first_uint(buf, 1),
            payload=first_str(buf, 2),
            jscontext_id=first_str(buf, 3),
        )

    def serialize(self) -> bytes:
        return (
            encode_uint(1, self.op_id)
            + encode_str(2, self.payload)
            + encode_str(3, self.jscontext_id)
        )


def build_chrome_devtools(
    cdp_json: str,
    *,
    seq: int,
    op_id: int = 0,
    jscontext_id: str = "",
) -> bytes:
    """Wrap one CDP JSON string into a serialized DebugMessage (uncompressed)."""
    inner = ChromeDevtools(op_id=op_id, payload=cdp_json, jscontext_id=jscontext_id)
    outer = DebugMessage(seq=seq, category=CAT_CHROME_DEVTOOLS, data=inner.serialize())
    return outer.serialize()


def parse_chrome_devtools_result(message: DebugMessage) -> ChromeDevtools | None:
    """Decode a ``chromeDevtoolsResult`` envelope into its CDP payload."""
    if message.category != CAT_CHROME_DEVTOOLS_RESULT:
        return None
    try:
        return ChromeDevtools.parse(message.payload_bytes())
    except (CodecError, ProtoError):
        return None


def parse_ping_id(message: DebugMessage) -> int:
    """pingId from a ``ping`` envelope (0 when absent)."""
    if message.category != CAT_PING:
        return 0
    try:
        payload = message.payload_bytes()
    except CodecError:
        return 0
    return first_uint(payload, 1)
