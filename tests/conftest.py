"""Shared pytest fixtures for the WMPF-MCP test suite."""

from __future__ import annotations

import pytest

from wmpf_mcp.core.state import get_state


@pytest.fixture()
def anyio_backend() -> str:
    """Run anyio-marked tests on asyncio only."""
    return "asyncio"


@pytest.fixture
def fake_cancellable():
    class Cancellable:
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False
        def cancel(self):
            pass
    return Cancellable


@pytest.fixture(autouse=True)
def _fresh_session_state(monkeypatch, tmp_path):
    """Isolate derived files and process bookkeeping around every test."""
    from wmpf_mcp.core import notifications
    prompt = notifications.MiniappPrompt()
    monkeypatch.setattr(notifications, "_PROMPT", prompt)
    monkeypatch.setattr(notifications, "_LOGIN_PROMPT", notifications.LoginPrompt())
    home_dir = tmp_path / "mcp-home"
    monkeypatch.setenv("WMPF_MCP_HOME", str(home_dir))
    monkeypatch.setenv("WMPF_MCP_WORKSPACE", str(tmp_path / "workspace"))
    get_state().reset()
    yield
    get_state().reset()
