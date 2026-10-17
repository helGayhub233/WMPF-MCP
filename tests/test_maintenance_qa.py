"""Login Q&A follows completed maintenance and never repeats its side effects."""
import asyncio

from jsonschema import Draft202012Validator
from mcp.types import ElicitResult, InputRequiredResult
import pytest

from test_elicitation import context
from test_maintenance import installation
from wmpf_mcp.core import envelope
from wmpf_mcp.core.notifications import get_login_prompt
from wmpf_mcp.platform.maintenance import tree_digest
from wmpf_mcp.server import build_server
from wmpf_mcp.tools import maintenance as tool, runtime

LOGIN = "已登录，继续"
CANCEL = "取消"
ARGS = {"action": "prepare", "force_resign": True}


@pytest.fixture
def login_maintenance(installation, monkeypatch):
    f = installation
    monkeypatch.setattr(tool, "get_adapter", lambda: f.adapter)
    monkeypatch.setattr(tool, "Maintenance", f.Worker)
    async def stop(*args, **kwargs):
        await get_login_prompt().stop()
        return envelope.ok({"components": {}}, stage="INIT")
    monkeypatch.setattr(runtime, "stop_owned", stop)
    return f


@pytest.mark.anyio
@pytest.mark.parametrize("protocol", ["2025-11-25", "2026-07-28"])
@pytest.mark.parametrize("answer,status", [
    (ElicitResult(action="accept", content={"choice": LOGIN}), "accepted"),
    (ElicitResult(action="accept", content={"choice": CANCEL}), "cancelled"),
    (ElicitResult(action="decline"), "declined"),
    (ElicitResult(action="cancel"), "cancelled"),
])
async def test_login_q_and_a_after_maintenance_preserves_completed_work(login_maintenance, protocol, answer, status):
    f, server = login_maintenance, build_server()
    async def choose(**_):
        assert not runtime._LIFECYCLE_LOCK.locked()
        assert [event for event in f.events if event[0] == "sign"]
        return answer
    ctx, calls = context(protocol, callback=choose)
    result = await server.call_tool("manage_wechat", ARGS, ctx)
    completed = list(f.events)
    prepared = tree_digest(f.root)
    if protocol == "2026-07-28":
        assert isinstance(result, InputRequiredResult) and not calls
        request = result.input_requests["login_wechat"]
        schema = request.params.requested_schema
        assert "进入微信" in request.params.message
        resumed, _ = context(protocol, state=result.request_state, responses={"login_wechat": answer})
        result = await server.call_tool("manage_wechat", ARGS, resumed)
    else:
        assert len(calls) == 1 and "进入微信" in calls[0]["message"]
        schema = calls[0]["requested_schema"]
    assert schema["properties"]["choice"]["enum"] == [LOGIN, CANCEL]
    assert f.events == completed and tree_digest(f.root) == prepared
    data = result.structured_content["data"]
    assert data["executed"] and not data["awaiting_login"]
    assert len(data["signed_binaries"]) == 2 and data["notification"]["status"] == status
    assert bool(result.structured_content["next_actions"]) is (status == "accepted")
    if status == "accepted":
        assert result.structured_content["next_actions"][0]["tool"] == "check_environment"
    schema = next(t.output_schema for t in await server.list_tools() if t.name == "manage_wechat")
    Draft202012Validator(schema).validate(result.structured_content)


@pytest.mark.anyio
async def test_unsupported_client_gets_login_hint_without_automatic_followup(login_maintenance):
    ctx, calls = context(capability=False)
    reply = await build_server().call_tool("manage_wechat", ARGS, ctx)
    assert not calls
    assert reply.structured_content["data"]["awaiting_login"]
    assert reply.structured_content["data"]["notification"]["status"] == "unsupported"
    assert not reply.structured_content["next_actions"]
    assert "log in" in reply.structured_content["next_hint"]


@pytest.mark.anyio
async def test_login_continuation_rejects_changed_invalid_or_stale_answers_without_writes(login_maintenance):
    f, server = login_maintenance, build_server()
    ctx, _ = context("2026-07-28")
    pending = await server.call_tool("manage_wechat", ARGS, ctx)
    completed = list(f.events)
    response = {"login_wechat": ElicitResult(action="accept", content={"choice": LOGIN})}
    resumed, _ = context("2026-07-28", state=pending.request_state, responses=response)
    changed = await server.call_tool("manage_wechat", {"action": "restart"}, resumed)
    assert changed.is_error and f.events == completed
    invalid, _ = context("2026-07-28", state=pending.request_state,
                         responses={"login_wechat": ElicitResult(action="accept", content={"choice": "invented"})})
    result = await server.call_tool("manage_wechat", ARGS, invalid)
    assert result.is_error and f.events == completed
    await server.call_tool("stop_runtime", {})
    result = await server.call_tool("manage_wechat", ARGS, resumed)
    assert result.is_error and f.events == completed


@pytest.mark.anyio
@pytest.mark.parametrize("ending", ["stop", "cancel_request", "timeout"])
async def test_login_wait_ends_without_undoing_or_repeating_maintenance(login_maintenance, ending):
    f, server = login_maintenance, build_server()
    entered = asyncio.Event()
    async def wait(**_):
        entered.set()
        await asyncio.Event().wait()
    ctx, _ = context(callback=wait)
    if ending == "timeout": get_login_prompt().ANSWER_TIMEOUT_S = 0.01
    task = asyncio.create_task(server.call_tool("manage_wechat", ARGS, ctx))
    await asyncio.wait_for(entered.wait(), 1)
    assert not runtime._LIFECYCLE_LOCK.locked()
    completed, prepared = list(f.events), tree_digest(f.root)
    if ending == "cancel_request":
        task.cancel()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 1)
    else:
        if ending == "stop": await server.call_tool("stop_runtime", {})
        reply = await asyncio.wait_for(task, 1)
        assert reply.structured_content["data"]["notification"]["status"] == ("closed" if ending == "stop" else "timeout")
        assert not reply.structured_content["next_actions"]
    assert f.events == completed and tree_digest(f.root) == prepared
    assert get_login_prompt().task is None and not runtime._LIFECYCLE_LOCK.locked()


@pytest.mark.anyio
async def test_dry_run_never_asks_for_login(login_maintenance):
    ctx, calls = context()
    result = await build_server().call_tool("manage_wechat", {**ARGS, "dry_run": True}, ctx)
    assert not calls and not result.structured_content["data"]["executed"] and not login_maintenance.events
