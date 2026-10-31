"""
logger.py - Color-coded defensive logging engine for IoTFlux
Authorized Defensive Security Validation Lab
"""

from __future__ import annotations

import os
import sys
import time
from typing import Optional


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"


class FluxLogger:
    """Color-coded console logger with structured log output."""

    def __init__(self, use_color: Optional[bool] = None) -> None:
        if use_color is None:
            # Enable colors if running in terminal or if forced via env
            self.use_color = sys.stdout.isatty() or os.environ.get("FLUX_COLOR", "1") == "1"
        else:
            self.use_color = use_color

    def _format(self, prefix: str, color: str, msg: str) -> str:
        t_str = time.strftime("%H:%M:%S", time.localtime())
        if self.use_color:
            return f"{Colors.GRAY}[{t_str}]{Colors.RESET} {color}{prefix}{Colors.RESET} {msg}"
        return f"[{t_str}] {prefix} {msg}"

    def info(self, msg: str) -> None:
        print(self._format("[*]", Colors.CYAN, msg))

    def debug(self, msg: str) -> None:
        if os.environ.get("FLUX_DEBUG", "0") == "1":
            print(self._format("[D]", Colors.GRAY, msg))

    def success(self, msg: str) -> None:
        print(self._format("[+]", Colors.GREEN, msg))

    def warning(self, msg: str) -> None:
        print(self._format("[!]", Colors.YELLOW, msg))

    def failure(self, msg: str) -> None:
        print(self._format("[-]", Colors.RED, msg))

    def error(self, msg: str) -> None:
        self.failure(msg)

    def audit(self, msg: str) -> None:
        print(self._format("[#]", Colors.MAGENTA, f"{Colors.BOLD}{msg}{Colors.RESET}"))

    def header(self, title: str) -> None:
        line = "=" * 76
        if self.use_color:
            print(f"\n{Colors.BLUE}{line}\n  {Colors.BOLD}{title}{Colors.RESET}\n{Colors.BLUE}{line}{Colors.RESET}")
        else:
            print(f"\n{line}\n  {title}\n{line}")


logger = FluxLogger()
