"""Bounded per-hop Network ledger, observed before virtual-session fan-out.

ExtraInfo is paired in protocol order after hasExtraInfo/redirectHasExtraInfo
identifies the emitting hop. Runtime bodies are retrieved lazily.
"""
from __future__ import annotations

import json
import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

MAX_TRANSACTIONS = 1000
MAX_WS_FRAMES = 200
MAX_PENDING_EXTRA = 128
HEADER_CAP = 64 * 1024
POST_CAP = 256 * 1024


def number(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None


def byte_count(value: Any) -> int | None:
    value = number(value)
    return int(value) if value is not None and value >= 0 and value.is_integer() else None


def bounded_text(value: Any, cap: int) -> tuple[str, bool]:
    raw = str(value).encode("utf-8")
    return raw[:cap].decode("utf-8", "ignore"), len(raw) > cap


def headers(value: Any) -> tuple[dict[str, str], bool]:
    result: dict[str, str] = {}
    remaining = HEADER_CAP
    if not isinstance(value, dict):
        return result, False
    for name, item in value.items():
        cost = len(str(name).encode()) + len(str(item).encode())
        if cost > remaining:
            return result, True
        result[str(name)] = str(item)
        remaining -= cost
    return result, False


@dataclass
class Transaction:
    request_id: str  # public per-hop ID; Network commands need runtime_request_id
    runtime_request_id: str = ""
    hop: int = 0
    method: str = ""
    url: str = ""
    status: int | None = None
    status_text: str = ""
    mime: str | None = None
    protocol: str = ""
    resource_type: str | None = None
    size: int | None = None  # transferred bytes, including response headers
    started_at: float = 0.0
    wall_time: float = 0.0
    finished_at: float | None = None
    response_at: float | None = None
    failed: bool = False
    failure: str | None = None
    redirected: bool = False
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    request_headers_text: str | None = None
    response_headers_text: str | None = None
    request_post: str | None = None
    has_post_data: bool = False
    request_post_truncated: bool = False
    metadata_truncated: bool = False
    extra_expected: bool | None = None
    request_extra: bool = False
    response_extra: bool = False
    extra_unreliable: bool = False
    timing: dict[str, float] = field(default_factory=dict)
    decoded_length: int = 0
    encoded_length: int = 0
    data_seen: bool = False
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.request_id, "runtime_request_id": self.runtime_request_id,
            "redirect_hop": self.hop, "redirected": self.redirected,
            "method": self.method, "url": self.url, "status": self.status,
            "mime": self.mime, "resource_type": self.resource_type, "size": self.size,
            "size_scope": "transferred bytes including response headers",
            "started_at": round(self.started_at, 3),
            "duration_ms": round(max(0, self.finished_at - self.started_at) * 1000, 3) if self.finished_at is not None else None,
            "failed": self.failed, "failure": self.failure,
            "request_headers": self.request_headers, "response_headers": self.response_headers,
            "request_extra_info": self.request_extra, "response_extra_info": self.response_extra,
            "metadata_truncated": self.metadata_truncated, "extra_info_ambiguous": self.extra_unreliable,
        }


@dataclass
class TrafficLedger:
    active: bool = False
    transactions: deque[Transaction] = field(default_factory=lambda: deque(maxlen=MAX_TRANSACTIONS))
    ws_frames: deque[dict] = field(default_factory=lambda: deque(maxlen=MAX_WS_FRAMES))
    _by_id: dict[str, Transaction] = field(default_factory=dict)
    _current: dict[str, Transaction] = field(default_factory=dict)
    _extra: deque[tuple[str, str, dict]] = field(default_factory=lambda: deque(maxlen=MAX_PENDING_EXTRA))
    counts: dict[str, int] = field(default_factory=dict)
    generation: int = 0
    _serial: int = 0
    dropped_extra: int = 0
    extra_overflow: bool = False

    def activate(self) -> None:
        self.active = True

    def deactivate(self) -> None:
        self.active = False
        self.clear()

    def clear(self) -> None:
        self.transactions.clear()
        self._by_id.clear()
        self._current.clear()
        self._extra.clear()
        self.ws_frames.clear()
        self.counts.clear()
        self.dropped_extra = 0
        self.extra_overflow = False
        self.generation += 1

    def _append(self, entry: Transaction) -> None:
        if len(self.transactions) == self.transactions.maxlen:
            old = self.transactions[0]
            self._by_id.pop(old.request_id, None)
            if old.extra_expected is not False and not (old.request_extra and old.response_extra):
                # A late ExtraInfo for an evicted hop must not be assigned to
                # its retained successor. Once pairing is ambiguous, say so.
                for retained in self.transactions:
                    if retained.runtime_request_id == old.runtime_request_id:
                        retained.extra_unreliable = True
                if entry.runtime_request_id == old.runtime_request_id:
                    entry.extra_unreliable = True
            if self._current.get(old.runtime_request_id) is old:
                self._current.pop(old.runtime_request_id, None)
        self.transactions.append(entry)
        self._by_id[entry.request_id] = entry
        self._current[entry.runtime_request_id] = entry

    def _response(self, entry: Transaction, response: dict) -> None:
        if not entry.response_extra:
            entry.status = byte_count(response.get("status"))
        entry.status_text = str(response.get("statusText") or "")
        entry.mime = response.get("mimeType")
        entry.protocol = str(response.get("protocol") or "")
        if not entry.response_extra:
            entry.response_headers, cut = headers(response.get("headers"))
            entry.metadata_truncated |= cut
        if not entry.request_extra and isinstance(response.get("requestHeaders"), dict):
            entry.request_headers, cut = headers(response["requestHeaders"])
            entry.metadata_truncated |= cut
        entry.size = byte_count(response.get("encodedDataLength"))
        entry.cached = bool(response.get("fromDiskCache") or response.get("fromServiceWorker") or entry.cached)
        entry.timing = {k: n for k, v in (response.get("timing") or {}).items() if (n := number(v)) is not None}

    def _reconcile(self, request_id: str) -> None:
        if self.extra_overflow:
            return  # After loss, pairing order is unknown; do not guess.
        hops = [e for e in self.transactions if e.runtime_request_id == request_id]
        if any(e.extra_unreliable for e in hops):
            return
        for kind in ("request", "response"):
            for entry in hops:
                if entry.extra_expected is None:
                    break
                if not entry.extra_expected or getattr(entry, f"{kind}_extra"):
                    continue
                pending = next((e for e in self._extra if e[0] == request_id and e[1] == kind), None)
                if pending is None:
                    break
                self._extra.remove(pending)
                extra = pending[2]
                setattr(entry, f"{kind}_headers", extra["headers"])
                setattr(entry, f"{kind}_extra", True)
                setattr(entry, f"{kind}_headers_text", extra.get("headersText"))
                entry.metadata_truncated |= extra["truncated"]
                if kind == "response" and extra.get("statusCode") is not None:
                    entry.status = extra["statusCode"]

    def observe(self, payload: str, method: str) -> None:
        if not self.active or not method.startswith("Network."):
            return
        try:
            params = json.loads(payload).get("params") or {}
            if not isinstance(params, dict):
                return
        except (json.JSONDecodeError, TypeError, AttributeError):
            return
        self.counts[method] = self.counts.get(method, 0) + 1
        rid = str(params.get("requestId") or "")
        entry = self._current.get(rid)
        timestamp = number(params.get("timestamp"))
        now = timestamp if timestamp is not None else time.monotonic()
        if method == "Network.requestWillBeSent" and rid:
            request = params.get("request") or {}
            if entry and isinstance(params.get("redirectResponse"), dict):
                self._response(entry, params["redirectResponse"])
                entry.finished_at = now
                entry.response_at = now
                entry.redirected = True
                entry.extra_expected = params.get("redirectHasExtraInfo")
                self._reconcile(rid)
            self._serial += 1
            hop = entry.hop + 1 if entry and entry.redirected else 0
            public_id = rid if rid not in self._by_id else f"{rid}:hop:{self._serial}"
            while public_id in self._by_id:
                self._serial += 1
                public_id = f"{rid}:hop:{self._serial}"
            entry = Transaction(request_id=public_id, runtime_request_id=rid, hop=hop,
                                method=str(request.get("method") or ""), url=str(request.get("url") or ""),
                                resource_type=params.get("type"), started_at=now,
                                wall_time=number(params.get("wallTime")) or time.time(),
                                has_post_data=bool(request.get("hasPostData") or "postData" in request))
            entry.request_headers, entry.metadata_truncated = headers(request.get("headers"))
            if "postData" in request:
                entry.request_post, entry.request_post_truncated = bounded_text(request["postData"], POST_CAP)
            self._append(entry)
            self._reconcile(rid)
        elif method in ("Network.requestWillBeSentExtraInfo", "Network.responseReceivedExtraInfo") and rid:
            kind = "request" if method == "Network.requestWillBeSentExtraInfo" else "response"
            fields, cut = headers(params.get("headers"))
            text, text_cut = bounded_text(params["headersText"], HEADER_CAP) if "headersText" in params else (None, False)
            if self.extra_overflow or len(self._extra) == self._extra.maxlen:
                self.dropped_extra += len(self._extra) + 1
                self.extra_overflow = True
                self._extra.clear()
                return
            self._extra.append((rid, kind, {"headers": fields, "headersText": None if text_cut else text,
                "statusCode": byte_count(params.get("statusCode")), "truncated": cut or text_cut}))
            self._reconcile(rid)
        elif method == "Network.responseReceived" and entry:
            self._response(entry, params.get("response") or {})
            entry.response_at = now
            entry.extra_expected = params.get("hasExtraInfo")
            entry.resource_type = params.get("type") or entry.resource_type
            self._reconcile(rid)
        elif method == "Network.requestServedFromCache" and entry:
            entry.cached = True
        elif method == "Network.dataReceived" and entry:
            entry.data_seen = True
            entry.decoded_length += byte_count(params.get("dataLength")) or 0
            entry.encoded_length += byte_count(params.get("encodedDataLength")) or 0
        elif method == "Network.loadingFinished" and entry:
            entry.size = byte_count(params.get("encodedDataLength"))
            entry.finished_at = now
        elif method == "Network.loadingFailed" and entry:
            entry.failed = True
            entry.failure = str(params.get("errorText") or "Network loading failed")
            entry.finished_at = now
        elif method in ("Network.webSocketFrameSent", "Network.webSocketFrameReceived"):
            frame = params.get("response") or {}
            self.ws_frames.append({"direction": "sent" if method.endswith("Sent") else "received",
                "opcode": frame.get("opcode"), "payload_len": len(str(frame.get("payloadData") or "")),
                "at": round(time.monotonic(), 3)})

    def get(self, request_id: str) -> Transaction | None:
        return self._by_id.get(request_id)

    def can_fetch(self, entry: Transaction) -> bool:
        return self.get(entry.request_id) is entry and self._current.get(entry.runtime_request_id) is entry

    def select(self, filter_text: str | None = None, method: str | None = None, max_items: int = 50) -> list[Transaction]:
        selected = [e for e in reversed(self.transactions)
                    if (not filter_text or filter_text.lower() in e.url.lower())
                    and (not method or e.method.upper() == method.upper())]
        return selected[:max_items]

    def list(self, filter_text: str | None = None, method: str | None = None, max_items: int = 50) -> list[dict]:
        return [entry.to_dict() for entry in self.select(filter_text, method, max_items)]

    def summary(self) -> dict:
        return {"active": self.active, "transactions": len(self.transactions), "ws_frames": len(self.ws_frames),
                "recent_ws_frames": list(self.ws_frames)[-5:], "event_counts": dict(self.counts),
                "pending_extra_info": len(self._extra), "dropped_extra_info": self.dropped_extra}


__all__ = ["TrafficLedger", "Transaction"]
