"""Read-only HAR 1.2 export with explicit omissions and separate byte scopes."""
from __future__ import annotations

import asyncio
import base64
import copy
from datetime import datetime, timezone
import json
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .. import __version__
from .ledger import TrafficLedger, Transaction, byte_count

BODY_CAP_BYTES = 256 * 1024
EXPORT_BODY_BUDGET = 2 * 1024 * 1024
EXPORT_SIZE_CAP = 4 * 1024 * 1024
EXPORT_TIMEOUT = 20.0


def _header(fields: dict[str, str], name: str) -> str:
    return next((v for k, v in fields.items() if k.lower() == name.lower()), "")


def _headers(fields: dict[str, str]) -> list[dict[str, str]]:
    return [{"name": name, "value": value} for name, values in fields.items() for value in values.split("\n")]


def _http_version(protocol: str) -> str:
    return {"h2": "HTTP/2.0", "h3": "HTTP/3.0"}.get(protocol, protocol.upper())


def _header_size(text: str | None) -> int:
    return len(text.encode("utf-8")) if text is not None else -1


def _sizes(e: Transaction) -> tuple[int, int]:
    if e.method.upper() == "HEAD" or e.status in (204, 304):
        return 0, 0
    # loadingFinished is the entire transfer; never call it entity size.
    encoded = decoded = -1
    if e.finished_at is not None:
        if e.cached and e.size == 0:
            encoded = 0
        elif e.data_seen and e.encoded_length > 0:
            encoded = e.encoded_length
        elif e.size is not None and e.response_headers_text is not None and e.size >= _header_size(e.response_headers_text):
            encoded = e.size - _header_size(e.response_headers_text)
        elif not e.cached:
            length = _header(e.response_headers, "content-length")
            encoded = int(length) if length.isascii() and length.isdecimal() else -1
        if e.data_seen:
            decoded = e.decoded_length
        elif not _header(e.response_headers, "content-encoding") and encoded >= 0 and not e.cached:
            decoded = encoded
    return encoded, decoded


def _timings(e: Transaction) -> tuple[float, dict[str, float]]:
    total = max(0, (e.finished_at or e.response_at or e.started_at) - e.started_at) * 1000
    t = e.timing
    def duration(start: str, end: str) -> float:
        a, b = t.get(start, -1), t.get(end, -1)
        return round(b - a, 3) if b >= a >= 0 else -1
    timings = {"blocked": -1, "dns": duration("dnsStart", "dnsEnd"),
               "connect": duration("connectStart", "connectEnd"), "ssl": duration("sslStart", "sslEnd"),
               "send": duration("sendStart", "sendEnd"), "wait": duration("sendEnd", "receiveHeadersEnd"), "receive": -1}
    if "requestTime" in t:
        timings["blocked"] = round(max(0, (t["requestTime"] - e.started_at) * 1000), 3)
        if e.finished_at is not None and t.get("receiveHeadersEnd", -1) >= 0:
            receive = (e.finished_at - t["requestTime"]) * 1000 - t["receiveHeadersEnd"]
            if receive >= 0:
                timings["receive"] = round(receive, 3)
    return round(total, 3), timings


def _metadata(e: Transaction) -> dict[str, Any]:
    body_size, decoded_size = _sizes(e)
    content: dict[str, Any] = {"size": decoded_size, "mimeType": e.mime or _header(e.response_headers, "content-type")}
    post_size = len(e.request_post.encode()) if e.request_post is not None and not e.request_post_truncated else -1 if e.has_post_data else 0
    total, timings = _timings(e)
    result = {
        "startedDateTime": datetime.fromtimestamp(e.wall_time, timezone.utc).isoformat(timespec="milliseconds"),
        "time": total,
        "request": {"method": e.method, "url": e.url, "httpVersion": _http_version(e.protocol),
                    "cookies": [], "headers": _headers(e.request_headers),
                    "queryString": [{"name": k, "value": v} for k, v in parse_qsl(urlsplit(e.url).query, keep_blank_values=True)],
                    "headersSize": _header_size(e.request_headers_text), "bodySize": post_size},
        "response": {"status": e.status or 0, "statusText": e.status_text, "httpVersion": _http_version(e.protocol),
                     "cookies": [], "headers": _headers(e.response_headers), "content": content,
                     "redirectURL": _header(e.response_headers, "location"),
                     "headersSize": _header_size(e.response_headers_text), "bodySize": body_size,
                     "_transferSize": e.size if e.size is not None else -1},
        "cache": {}, "timings": timings,
        "_wmpf": {"id": e.request_id, "runtimeRequestId": e.runtime_request_id, "redirectHop": e.hop,
                  "redirected": e.redirected, "finished": e.finished_at is not None, "failed": e.failed,
                  "failure": e.failure, "requestExtraInfo": e.request_extra, "responseExtraInfo": e.response_extra,
                  "metadataTruncated": e.metadata_truncated,
                  "extraInfoAmbiguous": e.extra_unreliable,
                  "requestBodyTruncated": e.request_post_truncated,
                  "headerCompleteness": "ExtraInfo observed" if e.request_extra and e.response_extra else "base fields only or ExtraInfo pending/unavailable",
                  "cookies": "Cookie/Set-Cookie headers retained; cookie arrays are not parsed"},
    }
    return result


def _text_mime(mime: str) -> bool:
    return mime.startswith("text/") or any(v in mime for v in ("json", "javascript", "xml", "x-www-form-urlencoded"))


async def export_har(ledger: TrafficLedger, engine: Any, *, filter_text: str | None = None,
                     method: str | None = None, limit: int = 50, content: str = "all", live: bool = False) -> dict:
    generation = ledger.generation
    originals = list(reversed(ledger.select(filter_text, method, limit)))
    original_by_id = {e.request_id: e for e in originals}
    entries = copy.deepcopy(originals)  # a stable metadata snapshot, not an environment inventory
    result = [_metadata(e) for e in entries]
    used = 0
    semaphore = asyncio.Semaphore(4)
    deadline = asyncio.get_running_loop().time() + EXPORT_TIMEOUT

    async def fetch(e: Transaction, command: str, field: str) -> dict:
        async with semaphore:
            original = original_by_id[e.request_id]
            if generation != ledger.generation or not ledger.can_fetch(original):
                raise ValueError("Transaction expired or runtime changed during export")
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("HAR export deadline exceeded")
            async with asyncio.timeout(min(8.0, remaining)):
                raw = await engine.send_cdp_command(command, {"requestId": e.runtime_request_id}, timeout=min(8.0, remaining))
            if generation != ledger.generation or not ledger.can_fetch(original):
                raise ValueError("Runtime changed during body retrieval")
            if raw.get("error"):
                raise ValueError(str(raw["error"]))
            value = raw.get("result") or {}
            if field not in value:
                raise ValueError(f"{command} returned no {field} field")
            if not isinstance(value[field], str):
                raise ValueError(f"{command} returned a non-string {field} field")
            return value

    def reserve(raw: bytes, *, text: bool = False) -> tuple[bytes, bool]:
        nonlocal used
        available = min(BODY_CAP_BYTES, max(0, EXPORT_BODY_BUDGET - used))
        kept = raw[:available]
        if text:
            kept = kept.decode("utf-8", "ignore").encode("utf-8")
        used += len(kept)
        return kept, len(kept) < len(raw)

    async def fill(e: Transaction, row: dict) -> None:
        meta = row["_wmpf"]
        response = row["response"]["content"]
        if content == "none":
            meta["bodyOmission"] = "content=none"
            return
        if e.has_post_data and content == "text" and not _text_mime(_header(e.request_headers, "content-type")):
            meta["requestBodyOmission"] = "Non-text MIME with content=text"
        elif e.has_post_data:
            post = e.request_post
            try:
                if post is None:
                    if e.redirected:
                        raise ValueError("Redirect hop request body unavailable; runtime ID now refers to the final hop")
                    if not live:
                        raise ValueError("No live Portal/runtime for request body")
                    post = str((await fetch(e, "Network.getRequestPostData", "postData"))["postData"])
                raw = post.encode("utf-8")
                kept, cut = reserve(raw, text=True)
                row["request"]["postData"] = {"mimeType": _header(e.request_headers, "content-type"), "text": kept.decode("utf-8", "ignore")}
                if not e.request_post_truncated:
                    row["request"]["bodySize"] = len(raw)
                meta["requestBodyTruncated"] = cut or e.request_post_truncated
            except Exception as error:  # one failed body must not discard the ledger
                meta["requestBodyError"] = str(error) or type(error).__name__
        if e.method.upper() == "HEAD" or e.status in (204, 304):
            response.update(size=0, text="")
            return
        if content == "text" and not _text_mime(response["mimeType"]):
            meta["responseBodyOmission"] = "Non-text MIME with content=text"
            return
        try:
            if e.redirected:
                raise ValueError("Redirect response body unavailable; runtime ID now refers to the final hop")
            if e.failed:
                raise ValueError(e.failure or "Request failed")
            if e.finished_at is None:
                raise ValueError("Request still in flight; export after loadingFinished")
            if not live:
                raise ValueError("No live Portal/runtime for response body")
            value = await fetch(e, "Network.getResponseBody", "body")
            encoded = bool(value.get("base64Encoded"))
            raw = base64.b64decode(value["body"], validate=True) if encoded else str(value["body"]).encode("utf-8")
            response["size"] = len(raw)
            kept, cut = reserve(raw, text=not encoded)
            if encoded:
                response.update(text=base64.b64encode(kept).decode("ascii"), encoding="base64")
            else:
                response["text"] = kept.decode("utf-8", "ignore")
            meta["responseBodyTruncated"] = cut
            body_size = row["response"]["bodySize"]
            if body_size >= 0 and body_size <= len(raw) and not e.cached:
                response["compression"] = len(raw) - body_size
        except Exception as error:
            meta["responseBodyError"] = str(error) or type(error).__name__

    await asyncio.gather(*(fill(e, row) for e, row in zip(entries, result)))
    selected_count = len(result)
    while result and len(json.dumps(result, ensure_ascii=False).encode()) > EXPORT_SIZE_CAP:
        result.pop(0)
    retained = 0
    for row in result:
        retained += len(row["request"].get("postData", {}).get("text", "").encode("utf-8"))
        body = row["response"]["content"]
        text = body.get("text", "")
        retained += len(base64.b64decode(text)) if body.get("encoding") == "base64" else len(text.encode("utf-8"))
    return {"har": {"log": {"version": "1.2", "creator": {"name": "WMPF-MCP", "version": __version__},
                            "entries": result, "comment": "Observed CDP Network events; _wmpf records omissions. Not a byte-for-byte HTTP wire capture."}},
            "export": {"selected": selected_count, "exported": len(result), "omitted_by_size_cap": selected_count - len(result),
                       "body_bytes_retained": retained, "body_cap_bytes": BODY_CAP_BYTES,
                       "body_budget_bytes": EXPORT_BODY_BUDGET, "output_cap_bytes": EXPORT_SIZE_CAP,
                       "output_cap_scope": "entries serialized as UTF-8 JSON without indentation",
                       "deadline_seconds": EXPORT_TIMEOUT, "content": content,
                       "pending_extra_info": ledger.summary()["pending_extra_info"],
                       "dropped_extra_info": ledger.dropped_extra},
            "capture_scope": "Observed CDP Network only. ExtraInfo may be absent; redirects retain distinct hops. Native wx.request depends on runtime emission; mmtls/ilink unverified."}
