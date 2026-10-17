"""Global session state machine (docs/03-流程编排.md §2).

One process, one session. Stage records historical progress; live resources
choose the next investigation. No identity or evidence archive is persisted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Stage(str, Enum):
    INIT = "INIT"
    ENV_READY = "ENV_READY"
    LOCATED = "LOCATED"
    OFFSETS_READY = "OFFSETS_READY"
    INJECTED = "INJECTED"
    ENGINE_UP = "ENGINE_UP"
    MINIAPP_CONNECTED = "MINIAPP_CONNECTED"
    PORTAL_UP = "PORTAL_UP"


_ORDER: list[Stage] = list(Stage)


@dataclass
class SessionState:
    stage: Stage = Stage.INIT
    # version / runtime dimension
    platform: str | None = None
    arch: str | None = None
    wechat_path: str | None = None
    runtime_path: str | None = None
    wmpf_version: int | None = None
    running_pids: list[int] = field(default_factory=list)
    # offsets dimension
    offsets_source: str | None = None  # cache | none
    config_path: str | None = None
    # inject / engine / miniapp / portal dimensions
    injected_pids: list[int] = field(default_factory=list)
    engine_ports: dict[str, int] = field(default_factory=dict)
    miniapp_epoch: int = 0
    portal_port: int | None = None
    wechat_prepared: bool = False
    prompt_user: bool = True

    # -- transitions ---------------------------------------------------------
    def advance(self, stage: Stage) -> None:
        """Move the stage forward; never regress on a stale call."""
        if _ORDER.index(stage) >= _ORDER.index(self.stage):
            self.stage = stage

    @property
    def next_hint(self) -> str | None:
        # Stage records progress; current resources choose the next investigation.
        from ..engine import get_engine
        from ..injector import get_injector
        from ..portal import get_portal

        engine, portal = get_engine(), get_portal()
        if engine.running:
            if not engine.miniapp_clients or engine.setup_context_at is None:
                return 'probe_runtime(layer="reconnect")'
            if portal.running:
                return 'probe_runtime(layer="portal")'
            return 'probe_runtime(layer="raw")'
        if get_injector().status()["active"]:
            return 'start_runtime(component="engine")'
        if self.config_path:
            return 'start_runtime()'
        if self.runtime_path:
            return 'check_offsets()'
        return 'check_environment()'

    def snapshot(self) -> dict[str, Any]:
        return {
            "stage": self.stage.value,
            "version": {
                "platform": self.platform,
                "arch": self.arch,
                "wechat_path": self.wechat_path,
                "runtime_path": self.runtime_path,
                "wmpf_version": self.wmpf_version,
                "running_pids": self.running_pids,
            },
            "offsets": {"source": self.offsets_source, "config_path": self.config_path},
            "inject": {"injected_pids": self.injected_pids},
            "engine": {"ports": self.engine_ports},
            "miniapp": {"epoch": self.miniapp_epoch},
            "portal": {"port": self.portal_port},
        }

    def reset(self) -> None:
        self.__dict__.update(SessionState().__dict__)


_STATE: SessionState | None = None


def get_state() -> SessionState:
    """Return the process-wide session state singleton."""
    global _STATE
    if _STATE is None:
        _STATE = SessionState()
    return _STATE
