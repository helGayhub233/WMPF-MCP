"""Frida injection: render the hook template and attach per-process sessions."""

from .manager import InjectorManager, get_injector

__all__ = ["InjectorManager", "get_injector"]
