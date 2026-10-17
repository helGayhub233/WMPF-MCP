"""Cross-transport numeric representations must not duplicate Network events."""
import json
from types import SimpleNamespace

import pytest

from wmpf_mcp.engine import core
from wmpf_mcp.portal.ledger import TrafficLedger


def test_integral_float_transport_copy_keeps_one_redirect_and_original_payload(monkeypatch):
    monkeypatch.setattr(core, "time", SimpleNamespace(monotonic=lambda: 1.0))
    engine = core.DebugEngine()
    book = TrafficLedger()
    book.activate()
    engine.on_cdp_upstream(book.observe)
    received = []
    engine.on_cdp_upstream(lambda raw, _: received.append(raw))
    name = "Network.requestWillBeSent"
    events = []
    engine.on_cdp_event(name, events.append)
    first = {"method": name, "params": {"requestId": "r", "timestamp": 1,
        "request": {"method": "POST", "url": "http://fixture/first", "headers": {}}}}
    redirect = {"method": name, "params": {"requestId": "r", "timestamp": 2.0,
        "redirectResponse": {"status": 307.0, "statusText": "Temporary Redirect",
            "headers": {"Location": "/final"}, "encodedDataLength": 639.0,
            "timing": {"requestTime": 1.25, "dnsStart": -1.0}},
        "request": {"method": "POST", "url": "http://fixture/final", "headers": {}},
        "nested": [{"values": [0.0, 11286.0]}]}}
    integer_copy = json.loads(json.dumps(redirect))
    integer_copy["params"]["timestamp"] = 2
    response = integer_copy["params"]["redirectResponse"]
    response.update(status=307, encodedDataLength=639)
    response["timing"]["dnsStart"] = -1
    integer_copy["params"]["nested"][0]["values"] = [0, 11286]
    first_raw, float_raw = json.dumps(first), json.dumps(redirect)
    engine._dispatch_miniapp_payload(first_raw, "runtime")
    engine._dispatch_miniapp_payload(float_raw, "frida:7")
    engine._dispatch_miniapp_payload(json.dumps(integer_copy), "runtime")
    assert len(book.transactions) == 2
    assert [row.hop for row in book.transactions] == [0, 1]
    assert [row.status for row in book.transactions] == [307, None]
    assert engine.duplicate_payloads_dropped == 1
    assert received == [first_raw, float_raw]
    delivered = json.loads(received[-1])["params"]
    assert type(delivered["redirectResponse"]["status"]) is float
    assert type(delivered["nested"][0]["values"][0]) is float
    assert type(events[-1]["params"]["redirectResponse"]["status"]) is float
    assert type(events[-1]["params"]["nested"][0]["values"][0]) is float


@pytest.mark.parametrize("first,second,duplicate", [
    (0.0, 0, True), (-1.0, -1, True), (639.0, 639, True), (1e20, 10**20, True),
    (True, 1, False), (False, 0, False), ("639", 639, False), (1.25, 1, False),
    (-0.0, 0, False), (10**20 + 1, 1e20, False),
    (9007199254740993, 9007199254740993.0, False),
    (10**400, 10**400 + 1, False),
    (1.25, 1.25, True), (float("inf"), float("inf"), True),
    (float("nan"), float("nan"), True), (float("inf"), -float("inf"), False),
])
def test_fingerprint_numeric_and_type_boundaries(first, second, duplicate):
    engine = core.DebugEngine()
    received = []
    engine.on_cdp_upstream(lambda raw, _: received.append(raw))
    for value, source in ((first, "frida:7"), (second, "runtime")):
        engine._dispatch_miniapp_payload(json.dumps({"method": "Network.dataReceived",
            "params": {"requestId": "r", "nested": [{"value": value}]}}), source)
    assert len(received) == (1 if duplicate else 2)
    assert engine.duplicate_payloads_dropped == int(duplicate)


def test_same_source_repetitions_and_one_second_boundary_remain_distinct(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(core, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    engine = core.DebugEngine()
    received = []
    engine.on_cdp_upstream(lambda raw, _: received.append(raw))
    for at, value, source in ((0.0, 639.0, "frida:7"), (0.25, 639, "frida:7"),
                              (0.75, 639.0, "runtime"), (1.25, 639, "runtime")):
        clock[0] = at
        engine._dispatch_miniapp_payload(json.dumps({"method": "Network.dataReceived",
            "params": {"requestId": "r", "value": value}}), source)
    assert len(received) == 3
    assert engine.duplicate_payloads_dropped == 1


def test_fingerprint_cache_still_evicts_after_512_distinct_envelopes():
    engine = core.DebugEngine()
    engine._dispatch_miniapp_payload(json.dumps({"id": 0, "result": {}}))
    first = next(iter(engine._recent_payloads))
    for value in range(1, 513):
        engine._dispatch_miniapp_payload(json.dumps({"id": value, "result": {}}))
    assert len(engine._recent_payloads) == 512
    assert first not in engine._recent_payloads
