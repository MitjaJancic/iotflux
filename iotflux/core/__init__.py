"""
core package - CLI engine, session management, and logging for IoTFlux

`FluxConsole` and `main` are resolved lazily so that importing a submodule
(`iotflux.core.logger`, `iotflux.core.creds_store`, ...) does not drag in the CLI,
which itself imports `iotflux.modules` and would otherwise form an import cycle.
"""

from __future__ import annotations

from typing import Any

from .logger import FluxLogger, logger
from .session import FluxSession, session
from .specification import SPEC_CATALOG, SpecReference, get_spec, list_specs

__all__ = [
    "FluxConsole",
    "main",
    "FluxLogger",
    "logger",
    "FluxSession",
    "session",
    "SPEC_CATALOG",
    "SpecReference",
    "get_spec",
    "list_specs",
]


def __getattr__(name: str) -> Any:
    if name in ("FluxConsole", "main"):
        from . import cli

        return getattr(cli, name)
    raise AttributeError(f"module 'iotflux.core' has no attribute '{name}'")
