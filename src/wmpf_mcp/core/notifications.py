"""In-band login/miniapp Q&A, bound to the completed tool preparation."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import secrets
from typing import Literal

from mcp.server.elicitation import render_elicitation_schema
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, ElicitRequest, ElicitRequestFormParams, ElicitResult, InputRequiredResult
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import envelope
from .asyncio_utils import drain_task
from .errors import ErrorCode, ToolError
from .state import get_state

_MESSAGE = "调试监听和 Hook 已就绪。请先关闭目标小程序，再在微信中重新打开，然后选择下一步。"
_CONTINUE = "打开后继续"
_CANCEL = "取消"
_INPUT_KEY = "open_miniapp"
_LOGIN_MESSAGE = "微信已启动。若停在“进入微信”界面，请手动登录；登录完成后选择“已登录，继续”。选择取消将结束后续流程，已完成的备份、签名或还原不会重复执行或撤销。"
_LOGIN_CONTINUE = "已登录，继续"
_LOGIN_INPUT_KEY = "login_wechat"


def _supports_form(ctx):
    if ctx is None or ctx.protocol_version is None:
        return False
    capabilities = ctx.client_capabilities
    elicitation = capabilities.elicitation if capabilities else None
    return elicitation is not None and not (elicitation.form is None and elicitation.url is not None)


def _form_request(message, schema, input_key):
    return InputRequiredResult(input_requests={input_key: ElicitRequest(params=ElicitRequestFormParams(
        message=message, requested_schema=render_elicitation_schema(schema)))},
        request_state=secrets.token_urlsafe(24))


class LoginChoice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    choice: Literal[_LOGIN_CONTINUE, _CANCEL] = Field(title="微信登录确认",
        description="手动登录后继续体检；取消结束后续流程，保留已经完成的应用维护。")


class MiniappChoice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    choice: Literal[_CONTINUE, _CANCEL] = Field(
        title="小程序操作确认",
        description="确认已重新打开后继续验证连接；取消则结束流程，停止本 MCP 的监听、Hook 及依赖的 Portal，清理完成后返回结果。")


@dataclass
class _Pending:
    tool: str
    arguments: dict
    reply: CallToolResult
    request: InputRequiredResult


class MiniappPrompt:
    ANSWER_TIMEOUT_S = 120

    def __init__(self):
        self.key = None
        self.engine = None
        self.task = None
        self.pending = None
        self.status = {"status": "not_requested"}

    @staticmethod
    def _key(engine):
        # Opening the miniapp advances epoch: that is the requested action, not
        # a new preparation. A stop/restart invalidates the outstanding answer.
        return (id(engine), getattr(engine, "_stop_generation", 0))

    def _detach(self):
        if self.engine is not None:
            self.engine.off_lifecycle(self.lifecycle)
        self.engine = None

    def lifecycle(self, event):
        engine = self.engine
        if engine is not None and (not engine.running or (
                engine.miniapp_clients and engine.setup_context_at is not None)):
            self.status = {"status": "not_needed" if engine.running else "closed"}
            if self.task and not self.task.done():
                self.task.cancel()
            self._detach()

    def attach_reply(self, reply, status):
        payload = reply.structured_content
        next_actions = payload.get("next_actions", [])
        hint = payload.get("next_hint")
        if status["status"] not in {"accepted", "not_needed"}:
            next_actions = []
            hint = {
                "unsupported": "Use the client's Q&A to ask the user to reopen the miniapp; probe_runtime(layer=reconnect) only after confirmation.",
                "disabled": "Manually reopen the miniapp before probe_runtime(layer=reconnect); MCP Q&A is disabled.",
                "pending": "Answer the existing miniapp Q&A before continuing.",
                "declined": "User declined. Stop owned listeners, hooks and the dependent Portal before returning; do not continue checks.",
                "cancelled": "User cancelled. Stop owned listeners, hooks and the dependent Portal before returning; do not continue checks.",
                "closed": "Runtime preparation was stopped. Inspect current resources before continuing.",
            }.get(status["status"], "No valid user confirmation was received. Wait for user action before probing reconnect.")
        if self.task is None and self.pending is None:
            self.status = dict(status)
        return envelope.ok({**payload["data"], "notification": dict(status)}, stage=get_state().stage.value,
                           warnings=payload.get("warnings", []), next_actions=next_actions, next_hint=hint)

    def _answer(self, action, content):
        if action != "accept":
            self.status = {"status": "declined" if action == "decline" else "cancelled"}
        else:
            choice = MiniappChoice.model_validate(content).choice
            self.status = {"status": {_CONTINUE: "accepted", _CANCEL: "cancelled"}[choice],
                           "choice": choice}

    def resume(self, ctx, engine, tool, arguments):
        """Resume only the stored preparation; never repeat startup on a retry."""
        if ctx is None or (ctx.request_state is None and ctx.input_responses is None):
            return None
        pending = self.pending
        if (pending is None or ctx.request_state != pending.request.request_state
                or pending.tool != tool or pending.arguments != arguments):
            return envelope.fail(ToolError(ErrorCode.PARAM, "Unknown or mismatched miniapp Q&A continuation.",
                remedy="Inspect the current runtime; resume with the original tool, arguments and request_state."), stage=get_state().stage.value)
        if not engine.running or self._key(engine) != self.key:
            self.pending = None
            self._detach()
            self.status = {"status": "closed"}
            return envelope.fail(ToolError(ErrorCode.ORDER_VIOLATION, "Runtime changed while awaiting miniapp Q&A.",
                remedy="Inspect the current runtime before preparing it again."), stage=get_state().stage.value)
        if not ctx.input_responses:
            return pending.request
        answer = ctx.input_responses.get(_INPUT_KEY)
        if not isinstance(answer, ElicitResult):
            return envelope.fail(ToolError(ErrorCode.PARAM, "Missing miniapp Q&A response."), stage=get_state().stage.value)
        try:
            self._answer(answer.action, answer.content)
        except ValidationError:
            return envelope.fail(ToolError(ErrorCode.PARAM, "Invalid miniapp Q&A choice."), stage=get_state().stage.value)
        self.pending = None
        self._detach()
        return self.attach_reply(pending.reply, self.status)

    async def request(self, engine, ctx, reply, tool, arguments):
        if not engine.running or (engine.miniapp_clients and engine.setup_context_at is not None):
            return self.attach_reply(reply, {"status": "not_needed" if engine.running else "closed"})
        if ctx is None or ctx.protocol_version is None:
            return self.attach_reply(reply, {"status": "unsupported", "message": "An active MCP client with form elicitation is required."})
        # The original empty capability means form support; URL-only clients do not.
        if not _supports_form(ctx):
            return self.attach_reply(reply, {"status": "unsupported", "message": "Client does not support form elicitation; ask the user through its Q&A."})
        key = self._key(engine)
        if self.key == key:
            if self.pending is not None:
                if self.pending.tool == tool and self.pending.arguments == arguments:
                    return self.pending.request
                return self.attach_reply(reply, {"status": "pending", "message": "Answer the existing miniapp Q&A first."})
            return self.attach_reply(reply, self.status)
        await self.stop()
        self.key = key
        self.engine = engine
        engine.on_lifecycle(self.lifecycle)
        self.status = {"status": "pending"}
        if ctx.protocol_version >= "2026-07-28":
            request = _form_request(_MESSAGE, MiniappChoice, _INPUT_KEY)
            self.pending = _Pending(tool, dict(arguments), reply, request)
            return request
        task = self.task = asyncio.create_task(ctx.elicit(_MESSAGE, schema=MiniappChoice))
        try:
            async with asyncio.timeout(self.ANSWER_TIMEOUT_S):
                answer = await asyncio.shield(task)
            self._answer(answer.action, answer.data.model_dump() if answer.action == "accept" else None)
        except TimeoutError:
            self.status = {"status": "timeout", "message": "Miniapp Q&A timed out; no confirmation was received."}
        except (MCPError, ValueError) as error:
            self.status = {"status": "failed", "message": str(error)}
        except asyncio.CancelledError:
            if asyncio.current_task().cancelling() or self.status["status"] not in {"closed", "not_needed"}:
                self.status = {"status": "cancelled"}
                self.key = None
                raise
        finally:
            if not task.done():
                task.cancel()
            try:
                try:
                    await drain_task(task)
                except (asyncio.CancelledError, MCPError, ValueError):
                    pass
            finally:
                if self.task is task:
                    self.task = None
                    self._detach()
        return self.attach_reply(reply, self.status)

    async def stop(self):
        task = self.task
        self.status = {"status": "closed"}
        self._detach()
        self.pending = None
        self.key = None
        self.task = None
        if task and not task.done():
            task.cancel()
            try:
                await drain_task(task)
            except (asyncio.CancelledError, MCPError, ValueError):
                pass


_PROMPT = MiniappPrompt()


def get_prompt():
    return _PROMPT


class LoginPrompt:
    """Reuse form Q&A after maintenance; keep login in the user's control."""
    ANSWER_TIMEOUT_S = MiniappPrompt.ANSWER_TIMEOUT_S

    def __init__(self):
        self.generation = 0
        self.pending = None
        self.task = None
        self.status = {"status": "not_requested"}

    def prepare(self):
        # Called under the lifecycle lock after maintenance; no OS identity cache.
        self.generation += 1
        self.status = {"status": "pending"}
        return self.generation

    @staticmethod
    def attach_reply(reply, status):
        payload = reply.structured_content
        accepted = status["status"] == "accepted"
        cancelled = status["status"] in {"cancelled", "declined"}
        closed = status["status"] == "closed"
        hint = ("Login was reported complete. Recheck the actual environment before hooks or miniapp reopening." if accepted
                else "User cancelled login confirmation. Completed maintenance remains; wait for a new instruction." if cancelled
                else "This login Q&A was closed by a stop or newer preparation. Inspect current resources before continuing." if closed
                else "Please log in at WeChat's Enter WeChat screen. Use the client's Q&A; only after confirmation continue check_environment.")
        return envelope.ok({**payload["data"], "awaiting_login": not (accepted or cancelled or closed),
                            "notification": dict(status)}, stage=payload["stage"],
                           warnings=payload.get("warnings", []), next_hint=hint,
                           next_actions=payload.get("next_actions", []) if accepted else [])

    @staticmethod
    def answer(action, content):
        if action != "accept":
            return {"status": "declined" if action == "decline" else "cancelled"}
        choice = LoginChoice.model_validate(content).choice
        return {"status": "accepted" if choice == _LOGIN_CONTINUE else "cancelled", "choice": choice}

    def resume(self, ctx, tool, arguments):
        if ctx is None or (ctx.request_state is None and ctx.input_responses is None):
            return None
        pending = self.pending
        if (pending is None or ctx.request_state != pending.request.request_state
                or pending.tool != tool or pending.arguments != arguments):
            return envelope.fail(ToolError(ErrorCode.PARAM, "Unknown or mismatched login Q&A continuation.",
                remedy="Resume with the original arguments and request_state; do not repeat maintenance."), stage=get_state().stage.value)
        if not ctx.input_responses:
            return pending.request
        answer = ctx.input_responses.get(_LOGIN_INPUT_KEY)
        if not isinstance(answer, ElicitResult):
            return envelope.fail(ToolError(ErrorCode.PARAM, "Missing login Q&A response."), stage=get_state().stage.value)
        try:
            status = self.answer(answer.action, answer.content)
        except ValidationError:
            return envelope.fail(ToolError(ErrorCode.PARAM, "Invalid login Q&A choice."), stage=get_state().stage.value)
        self.pending = None
        self.status = status
        return self.attach_reply(pending.reply, status)

    async def request(self, ctx, reply, tool, arguments, generation):
        if generation != self.generation:
            return self.attach_reply(reply, {"status": "closed"})
        if not _supports_form(ctx):
            self.status = {"status": "unsupported", "message": "Client form Q&A unavailable; ask the user to log in manually."}
            return self.attach_reply(reply, self.status)
        if ctx.protocol_version >= "2026-07-28":
            request = _form_request(_LOGIN_MESSAGE, LoginChoice, _LOGIN_INPUT_KEY)
            self.pending = _Pending(tool, dict(arguments), reply, request)
            return request
        task = self.task = asyncio.create_task(ctx.elicit(_LOGIN_MESSAGE, schema=LoginChoice))
        status = {"status": "closed"}
        try:
            async with asyncio.timeout(self.ANSWER_TIMEOUT_S):
                answer = await asyncio.shield(task)
            if generation == self.generation:
                status = self.answer(answer.action, answer.data.model_dump() if answer.action == "accept" else None)
        except TimeoutError:
            status = {"status": "timeout", "message": "Login Q&A timed out; no login confirmation received."}
        except (MCPError, ValueError) as error:
            status = {"status": "failed", "message": str(error)}
        except asyncio.CancelledError:
            if asyncio.current_task().cancelling():
                status = {"status": "cancelled"}
                raise
        finally:
            if not task.done():
                task.cancel()
            try:
                await drain_task(task)
            except (asyncio.CancelledError, MCPError, ValueError):
                pass
            if self.task is task:
                self.task = None
            if generation == self.generation:
                self.status = status
        return self.attach_reply(reply, status)

    async def stop(self):
        self.generation += 1
        self.pending = None
        self.status = {"status": "closed"}
        task, self.task = self.task, None
        if task and not task.done():
            task.cancel()
            try:
                await drain_task(task)
            except (asyncio.CancelledError, MCPError, ValueError):
                pass


_LOGIN_PROMPT = LoginPrompt()


def get_login_prompt():
    return _LOGIN_PROMPT
