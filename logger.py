# -*- coding: utf-8 -*-
"""日志系统和彩色输出模块。"""

import ctypes
import datetime
from pathlib import Path
from typing import Optional

from constants import LogLevel


# ── 彩色输出 ──────────────────────────────────────────────────────────────────

def _ansi(code: int) -> str:
    """生成 ANSI 转义码。"""
    return f"\033[{code}m"


RESET = _ansi(0)
GREEN = _ansi(32)
YELLOW = _ansi(33)
RED = _ansi(31)
CYAN = _ansi(36)
GRAY = _ansi(90)


def enable_ansi():
    """启用 Windows 控制台 ANSI 转义序列支持。"""
    try:
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except OSError:
        pass


def ok(msg: str):
    """输出成功消息。"""
    print(f"  {GREEN}-->{RESET} {msg}")


def warn(msg: str):
    """输出警告消息。"""
    print(f"  {YELLOW}[!]{RESET} {msg}")


def err(msg: str):
    """输出错误消息。"""
    print(f"  {RED}[X]{RESET} {msg}")


def step(msg: str):
    """输出步骤标题。"""
    print(f"\n{YELLOW}{msg}{RESET}")


def info(msg: str):
    """输出信息消息。"""
    print(f"  {GRAY}{msg}{RESET}")


# ── 日志系统 ──────────────────────────────────────────────────────────────────

class Logger:
    """日志记录器，支持控制台和文件输出。"""

    def __init__(self, log_file: Optional[Path] = None,
                 level: LogLevel = LogLevel.INFO):
        """初始化日志记录器。

        Args:
            log_file: 日志文件路径，可选。
            level: 日志级别，默认 INFO。
        """
        self.log_file = log_file
        self.level = level
        self._log_entries: list[str] = []

    def _write(self, level: LogLevel, msg: str):
        """写入日志条目。"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] [{level.name}] {msg}"
        self._log_entries.append(entry)

        if self.log_file:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(entry + "\n")

        if level.value >= self.level.value:
            print(entry)

    def debug(self, msg: str):
        """记录 DEBUG 级别日志。"""
        self._write(LogLevel.DEBUG, msg)

    def info(self, msg: str):
        """记录 INFO 级别日志。"""
        self._write(LogLevel.INFO, msg)

    def warning(self, msg: str):
        """记录 WARNING 级别日志。"""
        self._write(LogLevel.WARNING, msg)

    def error(self, msg: str):
        """记录 ERROR 级别日志。"""
        self._write(LogLevel.ERROR, msg)

    def get_entries(self) -> list[str]:
        """获取所有日志条目的副本。"""
        return self._log_entries.copy()
