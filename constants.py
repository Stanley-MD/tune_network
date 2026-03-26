# -*- coding: utf-8 -*-
"""常量定义模块。"""

import re
from enum import Enum
from pathlib import Path
import os


class LogLevel(Enum):
    """日志级别枚举。"""
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3


# 协议开销数据库 (字节)
# 格式: "协议名": 基础开销
# 注意: 实际开销可能因传输层封装而增加
OVERHEAD_MAP: dict[str, int] = {
    "VLESS":            50,   # VLESS + TLS
    "VLESS_Reality":    90,   # VLESS + Reality (推荐)
    "VLESS_WS":         70,   # VLESS + WebSocket
    "VLESS_gRPC":       60,   # VLESS + gRPC
    "VMess":            80,   # VMess + TLS
    "VMess_WS":         100,  # VMess + WebSocket
    "VMess_QUIC":       120,  # VMess + QUIC
    "Trojan":           100,  # Trojan
    "Trojan_gRPC":      60,   # Trojan + gRPC
    "Trojan_WS":        80,   # Trojan + WebSocket
    "Shadowsocks":      70,   # SS 原始
    "Shadowsocks_AEAD": 70,   # SS AEAD
    "Hysteria2":        80,   # Hysteria2 (FEC时建议100~120)
    "TUIC":             80,   # TUIC
    "WireGuard":        60,   # WireGuard
    "NaiveProxy":       90,   # NaiveProxy
    "SOCKS5":           20,   # SOCKS5 无加密
    "HTTP_Proxy":       60,   # HTTP Proxy
}

# UDP 协议集合
UDP_PROTOCOLS: set[str] = {"WireGuard", "Hysteria2", "TUIC", "VMess_QUIC"}

# 默认探测目标
DEFAULT_PROBE_TARGETS: list[tuple[str, str]] = [
    ("223.5.5.5",      "阿里云 DNS"),
    ("119.29.29.29",   "腾讯 DNS"),
    ("1.1.1.1",        "Cloudflare"),
    ("8.8.8.8",        "Google"),
]

# 隧道网卡识别正则（扩展版）
TUNNEL_RE = re.compile(
    r"(?i)tun|tap|sing|v2ray|wireguard|wg|proxy|vnet|utun|"
    r"clash|shadowsocks|ss-local|outline|ssr|trojan-go|"
    r"nekoray|v2raya|xray|sing-box|hysteria|tuic"
)

# 安全余量（字节）
MTU_SAFETY_MARGIN = 20

# 命令执行超时（秒）
COMMAND_TIMEOUT = 30

# 注册表路径
REG_BASE = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"

# ── Ping 命令参数 ─────────────────────────────────────────────────────────────
PING_COUNT = 1  # ping 命令的 -n 参数（发送次数）
PING_TIMEOUT_MS = 2000  # ping 命令的 -w 参数（超时时间，毫秒）
PROBE_TIMEOUT_MS = 1000  # MTU 探测时的 ping 超时时间（毫秒）

# ── MTU 探测参数 ─────────────────────────────────────────────────────────────
MTU_PROBE_LOW = 500  # 二分探测下限
MTU_PROBE_HIGH = 1472  # 二分探测上限（基于标准以太网）
MTU_TEMP = 9000  # 临时设置隧道网卡 MTU 以消除 TUN 干扰
MTU_SLEEP_SECONDS = 0.3  # 设置 MTU 后的等待时间

# ── 手动输入范围 ─────────────────────────────────────────────────────────────
MANUAL_MTU_MIN = 576  # 手动输入 MTU 的最小值
MANUAL_MTU_MAX = 9000  # 手动输入 MTU 的最大值
MANUAL_OVERHEAD_MIN = 10  # 手动输入 Overhead 的最小值
MANUAL_OVERHEAD_MAX = 200  # 手动输入 Overhead 的最大值

# ── TCP 参数默认值 ───────────────────────────────────────────────────────────
TCP_INITIAL_RTO_MS = 3000  # 初始重传超时（毫秒），还原时使用
TCP_INITIAL_RTO_OPTIMIZED_MS = 2000  # 优化后的初始重传超时（毫秒）

# ── GUI 限制 ─────────────────────────────────────────────────────────────────
V2RAYN_GUI_MTU_MIN = 1280  # v2rayN GUI 允许手动输入的最小 MTU


def get_state_file_path() -> Path:
    """获取状态文件路径，存储到 APPDATA 目录。"""
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        state_dir = Path(appdata) / "mtutune"
        state_dir.mkdir(parents=True, exist_ok=True)
        return state_dir / "mtutune_state.json"
    return Path(__file__).parent / "mtutune_state.json"


STATE_PATH = get_state_file_path()
