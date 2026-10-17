"""Protocol-order and byte-accurate HAR tests; no external traffic or sleeps."""
import asyncio
import base64
from collections import deque
import gzip
import json
from types import SimpleNamespace

import pytest

from wmpf_mcp.portal import har
from wmpf_mcp.portal.ledger import MAX_PENDING_EXTRA, TrafficLedger
from wmpf_mcp.server import build_server


def emit(ledger, event, rid="r", **params):
    name = "Network." + event
    ledger.observe(json.dumps({"method": name, "params": {"requestId": rid, **params}}), name)


def ledger():
    result = TrafficLedger()
    result.activate()
    return result


def request(book, rid="r", *, method="GET", url="http://fixture/echo?a=&a=2", **fields):
    emit(book, "requestWillBeSent", rid, timestamp=1, wallTime=1710000000,
         request={"url": url, "method": method, "headers": {"X-Base": "base"}, **fields})


def response(book, rid="r", *, status=200, extra=False, **fields):
    emit(book, "responseReceived", rid, timestamp=2, hasExtraInfo=extra,
         response={"status": status, "statusText": "OK", "protocol": "http/1.1", "mimeType": "application/json",
                   "headers": {"Content-Type": "application/json"}, **fields})


def finish(book, rid="r", *, decoded=5, encoded=5, total=100.0):
    emit(book, "dataReceived", rid, dataLength=decoded, encodedDataLength=encoded)
    emit(book, "loadingFinished", rid, timestamp=3, encodedDataLength=total)


class Engine:
    running = True
    miniapp_clients = [object()]

    def __init__(self, bodies=None):
        self.bodies = bodies or {"r": {"body": "hello"}}
        self.calls = []

    async def send_cdp_command(self, command, params, timeout):
        self.calls.append((command, params))
        return {"result": self.bodies[params["requestId"]]}


@pytest.mark.anyio
async def test_redirect_extra_info_out_of_order_keeps_hop_identity_and_body():
    book = ledger()
    # ExtraInfo may precede the corresponding base request/response.
    emit(book, "requestWillBeSentExtraInfo", headers={"Host": "first", "Cookie": "a=1"})
    request(book, method="POST", postData="中文", hasPostData=True)
    emit(book, "requestWillBeSent", timestamp=2, wallTime=1710000001,
         redirectResponse={"status": 302, "headers": {"Location": "/final"}, "protocol": "http/1.1"},
         redirectHasExtraInfo=True,
         request={"method": "GET", "url": "http://fixture/final", "headers": {}})
    # Late first-hop response ExtraInfo must not overwrite the final hop.
    emit(book, "responseReceivedExtraInfo", statusCode=302, headers={"Location": "/final", "X-Hop": "first"})
    emit(book, "requestWillBeSentExtraInfo", headers={"Host": "final"})
    emit(book, "responseReceivedExtraInfo", statusCode=200, headers={"X-Hop": "final"})
    response(book, extra=True)
    finish(book)
    first, final = book.transactions
    assert first.request_id != final.request_id
    assert first.runtime_request_id == final.runtime_request_id == "r"
    assert first.status == 302 and first.finished_at == 2 and first.redirected
    assert final.status == 200 and final.hop == 1 and not final.redirected
    assert first.request_headers["Host"] == "first" and final.request_headers["Host"] == "final"
    assert first.response_headers["X-Hop"] == "first" and final.response_headers["X-Hop"] == "final"
    engine = Engine()
    exported = await har.export_har(book, engine, live=True)
    rows = exported["har"]["log"]["entries"]
    assert [r["response"]["status"] for r in rows] == [302, 200]
    assert rows[0]["response"]["redirectURL"] == "/final"
    assert "text" not in rows[0]["response"]["content"]
    assert "Redirect" in rows[0]["_wmpf"]["responseBodyError"]
    assert rows[0]["request"]["postData"]["text"] == "中文"
    assert rows[0]["request"]["bodySize"] == 6
    assert rows[1]["response"]["content"]["text"] == "hello"
    assert engine.calls == [("Network.getResponseBody", {"requestId": "r"})]


@pytest.mark.anyio
@pytest.mark.parametrize("method", ["POST", "HEAD"])
@pytest.mark.parametrize("evidence", ["headers_only_transfer", "content_length", "partial_chunk"])
async def test_redirect_entity_sizes_require_independent_body_completion(method, evidence):
    book = ledger()
    request(book, method=method)
    fields = {"Content-Length": "104", "Location": "/final"}
    header_text = "HTTP/1.1 307 Temporary Redirect\r\nContent-Length: 104\r\nLocation: /final\r\n\r\n"
    if evidence == "headers_only_transfer":
        emit(book, "responseReceivedExtraInfo", statusCode=307, headers=fields, headersText=header_text)
    if evidence == "partial_chunk":
        emit(book, "dataReceived", dataLength=23, encodedDataLength=17)
    emit(book, "requestWillBeSent", timestamp=2, wallTime=1710000001,
         redirectResponse={"status": 307, "statusText": "Temporary Redirect", "headers": fields,
                           "encodedDataLength": len(header_text) if evidence == "headers_only_transfer" else 0},
         redirectHasExtraInfo=evidence == "headers_only_transfer",
         request={"method": method, "url": "http://fixture/final", "headers": {}})
    response(book)
    finish(book)
    engine = Engine()
    rows = (await har.export_har(book, engine, live=True))["har"]["log"]["entries"]
    first, final = rows
    expected = 0 if method == "HEAD" else -1
    assert first["response"]["bodySize"] == first["response"]["content"]["size"] == expected
    assert {h["name"]: h["value"] for h in first["response"]["headers"]}["Content-Length"] == "104"
    if method == "HEAD":
        assert first["response"]["content"]["text"] == ""
        assert not engine.calls
    else:
        assert "text" not in first["response"]["content"]
        assert "Redirect" in first["_wmpf"]["responseBodyError"]
        assert final["response"]["content"]["text"] == "hello"
        assert engine.calls == [("Network.getResponseBody", {"requestId": "r"})]


def test_extra_info_skips_hops_that_explicitly_emit_none():
    book = ledger()
    request(book)
    emit(book, "requestWillBeSent", timestamp=2, redirectResponse={"status": 302}, redirectHasExtraInfo=False,
         request={"method": "GET", "url": "http://fixture/final"})
    emit(book, "requestWillBeSentExtraInfo", headers={"Host": "final"})
    response(book, extra=True)
    first, final = book.transactions
    assert not first.request_extra and final.request_headers == {"Host": "final"}


@pytest.mark.anyio
@pytest.mark.parametrize("method,status", [("HEAD", 200), ("GET", 204), ("GET", 304)])
async def test_empty_entity_is_zero_even_when_transfer_has_headers(method, status):
    book = ledger()
    request(book, method=method)
    response(book, status=status, headers={"Content-Length": "256"})
    emit(book, "loadingFinished", timestamp=3, encodedDataLength=357.0)
    engine = Engine()
    row = (await har.export_har(book, engine, live=True))["har"]["log"]["entries"][0]
    assert row["response"]["bodySize"] == row["response"]["content"]["size"] == 0
    assert row["response"]["content"]["text"] == ""
    assert row["response"]["_transferSize"] == 357
    assert not engine.calls


@pytest.mark.anyio
async def test_binary_base64_and_compressed_entity_sizes_are_separate():
    book = ledger()
    binary = bytes(range(256))
    zipped = gzip.compress(binary)
    request(book)
    response(book, mimeType="application/octet-stream", headers={"Content-Encoding": "gzip"})
    finish(book, decoded=256, encoded=len(zipped), total=float(len(zipped) + 150))
    engine = Engine({"r": {"body": base64.b64encode(binary).decode(), "base64Encoded": True}})
    row = (await har.export_har(book, engine, live=True))["har"]["log"]["entries"][0]
    assert row["response"]["bodySize"] == len(zipped)
    assert row["response"]["_transferSize"] == len(zipped) + 150
    assert row["response"]["content"]["size"] == 256
    assert base64.b64decode(row["response"]["content"]["text"]) == binary
    assert row["response"]["content"]["encoding"] == "base64"


@pytest.mark.anyio
async def test_extra_response_304_and_duplicate_headers_remain_wire_truth():
    book = ledger()
    request(book)
    emit(book, "responseReceivedExtraInfo", statusCode=304,
         headers={"Set-Cookie": "a=1\nb=2"}, headersText="HTTP/1.1 304 Not Modified\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n")
    response(book, extra=True)  # base event may report 200 for a revalidated cache.
    finish(book)
    row = (await har.export_har(book, Engine(), live=True))["har"]["log"]["entries"][0]
    assert row["response"]["status"] == 304
    assert row["response"]["headers"] == [{"name": "Set-Cookie", "value": "a=1"}, {"name": "Set-Cookie", "value": "b=2"}]
    assert row["response"]["headersSize"] > 0


@pytest.mark.anyio
async def test_missing_expired_inflight_and_failed_bodies_are_not_empty_success():
    book = ledger()
    for rid in ("missing", "inflight", "failed"):
        request(book, rid)
        response(book, rid)
    finish(book, "missing")
    emit(book, "loadingFailed", "failed", timestamp=3, errorText="net::ERR_EMPTY_RESPONSE")
    rows = (await har.export_har(book, Engine({"missing": {}}), live=True))["har"]["log"]["entries"]
    assert all("text" not in r["response"]["content"] for r in rows)
    assert "no body field" in rows[0]["_wmpf"]["responseBodyError"]
    assert "in flight" in rows[1]["_wmpf"]["responseBodyError"]
    assert "ERR_EMPTY_RESPONSE" in rows[2]["_wmpf"]["responseBodyError"]


@pytest.mark.anyio
async def test_har_caps_bodies_and_reports_omitted_entries(monkeypatch):
    book = ledger()
    for rid in ("a", "b"):
        request(book, rid)
        response(book, rid)
        finish(book, rid, decoded=40, encoded=40)
    monkeypatch.setattr(har, "BODY_CAP_BYTES", 16)
    monkeypatch.setattr(har, "EXPORT_BODY_BUDGET", 24)
    result = await har.export_har(book, Engine({r: {"body": "x" * 40} for r in ("a", "b")}), live=True)
    rows = result["har"]["log"]["entries"]
    assert result["export"]["body_bytes_retained"] == 24
    assert all(r["_wmpf"]["responseBodyTruncated"] for r in rows)
    assert all(r["response"]["content"]["size"] == 40 for r in rows)
    # Retained byte accounting must exclude an incomplete UTF-8 character.
    monkeypatch.setattr(har, "BODY_CAP_BYTES", 5)
    result = await har.export_har(book, Engine({r: {"body": "中文"} for r in ("a", "b")}), live=True)
    assert result["export"]["body_bytes_retained"] == 6
    assert all(r["response"]["content"]["text"] == "中" for r in result["har"]["log"]["entries"])
    monkeypatch.setattr(har, "EXPORT_SIZE_CAP", 10)
    result = await har.export_har(book, Engine(), content="none")
    assert result["har"]["log"]["entries"] == []
    assert result["export"]["omitted_by_size_cap"] == 2
    result = await har.export_har(book, Engine({r: {"body": "中文"} for r in ("a", "b")}), live=True)
    assert result["export"]["body_bytes_retained"] == 0


@pytest.mark.anyio
async def test_runtime_change_during_body_retrieval_discards_body():
    book = ledger()
    request(book)
    response(book)
    finish(book)
    class Changed(Engine):
        async def send_cdp_command(self, *args, **kwargs):
            book.clear()
            return {"result": {"body": "wrong runtime"}}
    row = (await har.export_har(book, Changed(), live=True))["har"]["log"]["entries"][0]
    assert "text" not in row["response"]["content"]
    assert "Runtime changed" in row["_wmpf"]["responseBodyError"]


@pytest.mark.anyio
async def test_export_deadline_and_cancellation_are_bounded(monkeypatch):
    book = ledger()
    request(book)
    response(book)
    finish(book)
    entered = asyncio.Event()
    class Hanging(Engine):
        async def send_cdp_command(self, *args, **kwargs):
            entered.set()
            await asyncio.Event().wait()
    monkeypatch.setattr(har, "EXPORT_TIMEOUT", 0.02)
    row = (await har.export_har(book, Hanging(), live=True))["har"]["log"]["entries"][0]
    assert "responseBodyError" in row["_wmpf"]
    task = asyncio.create_task(har.export_har(book, Hanging(), live=True))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_all_ledger_indexes_are_bounded_and_clear_expires_them():
    book = ledger()
    book.transactions = deque(maxlen=3)
    for i in range(20):
        request(book, str(i))
    assert len(book._by_id) == len(book._current) == len(book.transactions) == 3
    assert book.get("0") is None
    generation = book.generation
    book.clear()
    assert book.generation > generation and not book._current and not book._by_id


def test_extra_info_overflow_never_assigns_later_headers_to_missing_hop():
    book = ledger()
    for i in range(MAX_PENDING_EXTRA + 1):
        emit(book, "requestWillBeSentExtraInfo", str(i), headers={"Host": str(i)})
    request(book)
    response(book, extra=True)
    emit(book, "requestWillBeSentExtraInfo", headers={"Host": "must not guess"})
    assert not book.get("r").request_extra and book.dropped_extra > 0
    assert len(book._extra) == 0


def test_late_extra_for_evicted_redirect_is_not_assigned_to_retained_hop():
    book = ledger()
    book.transactions = deque(maxlen=1)
    request(book)
    emit(book, "requestWillBeSent", timestamp=2, redirectResponse={"status": 302}, redirectHasExtraInfo=True,
         request={"method": "GET", "url": "http://fixture/final"})
    response(book, extra=True)
    emit(book, "requestWillBeSentExtraInfo", headers={"Host": "evicted first hop"})
    assert book.transactions[0].extra_unreliable
    assert not book.transactions[0].request_extra


@pytest.mark.anyio
async def test_public_har_tool_is_read_only_and_keeps_ledger(monkeypatch):
    from wmpf_mcp.tools import _traffic
    book = ledger()
    request(book)
    response(book)
    finish(book)
    monkeypatch.setattr(_traffic, "get_portal", lambda: SimpleNamespace(running=True, ledger=book))
    monkeypatch.setattr(_traffic, "get_engine", lambda: Engine())
    server = build_server()
    result = await server.call_tool("query_traffic", {"view": "har", "content": "all"})
    assert not result.is_error
    data = result.structured_content["data"]
    assert data["har"]["log"]["entries"][0]["response"]["content"]["text"] == "hello"
    assert len(book.transactions) == 1
