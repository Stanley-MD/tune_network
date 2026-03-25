# -*- coding: utf-8 -*-
"""
v2rayN 网络自适应优化脚本 v1.0
专为 v2rayN（sing-box 内核）设计，需以管理员身份运行。
依赖：Python 3.8+，无第三方库。
用法：
  python tune_network.py          # 正常优化
  python tune_network.py --restore # 还原上次的设置
"""

import sys
import os
import ctypes
import subprocess
import socket
import time
import json
import winreg
import re
import argparse
from pathlib import Path

# ── 颜色输出 ──────────────────────────────────────────────────────────────────
def _ansi(code): return f"\033[{code}m"
RESET  = _ansi(0);  GREEN  = _ansi(32); YELLOW = _ansi(33)
RED    = _ansi(31); CYAN   = _ansi(36); GRAY   = _ansi(90)

def enable_ansi():
    try:
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

def ok(msg):   print(f"  {GREEN}-->{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}[!]{RESET} {msg}")
def err(msg):  print(f"  {RED}[X]{RESET} {msg}")
def step(msg): print(f"\n{YELLOW}{msg}{RESET}")
def info(msg): print(f"  {GRAY}{msg}{RESET}")

# ── 管理员权限 ────────────────────────────────────────────────────────────────
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def elevate():
    script = os.path.abspath(sys.argv[0])
    args   = " ".join(f'"{a}"' for a in sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}" {args}', None, 1)
    sys.exit(0)

# ── subprocess 统一编码 ───────────────────────────────────────────────────────
def run(cmd: str | list, **kwargs) -> subprocess.CompletedProcess:
    """统一使用 UTF-8 + errors=replace，避免 GBK 解码错误"""
    defaults = dict(capture_output=True, text=True,
                    encoding="utf-8", errors="replace")
    defaults.update(kwargs)
    if isinstance(cmd, str):
        defaults["shell"] = True
    return subprocess.run(cmd, **defaults)

# ── 状态文件（记录上次修改，用于还原） ────────────────────────────────────────
STATE_FILE = Path(__file__).parent / "tune_network_state.json"

def save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2),
                          encoding="utf-8")

def load_state() -> dict | None:
    if not STATE_FILE.exists():
        return None
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None

# ── 协议数据库 ────────────────────────────────────────────────────────────────
OVERHEAD_MAP = {
    "VLESS":             50,
    "VLESS_Reality":     90,
    "VMess":             80,
    "VMess_QUIC":       120,
    "Trojan":           100,
    "Trojan_gRPC":       60,
    "Shadowsocks":       70,
    "Shadowsocks_AEAD":  70,
    "Hysteria2":         80,
    "TUIC":              80,
    "WireGuard":         60,
    "NaiveProxy":        90,
    "SOCKS5":            20,
    "HTTP_Proxy":        60,
}
UDP_PROTOCOLS   = {"WireGuard", "Hysteria2", "TUIC", "VMess_QUIC"}
PROBE_TARGETS   = [
    ("223.5.5.5",    "阿里云 DNS"),
    ("119.29.29.29", "腾讯 DNS"),
    ("1.1.1.1",      "Cloudflare"),
    ("8.8.8.8",      "Google"),
]

# ── v2rayN 目录自动检测 ───────────────────────────────────────────────────────
def find_v2rayn_candidates() -> list[Path]:
    """
    按优先级收集候选目录：
    1. 注册表（如果有安装记录）
    2. 常见安装位置（各盘符根目录 + Program Files）
    3. AppData 漫游目录
    """
    candidates = []

    # 注册表查找
    for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for sub in (r"SOFTWARE\v2rayN", r"SOFTWARE\WOW6432Node\v2rayN"):
            try:
                key = winreg.OpenKey(root, sub)
                path, _ = winreg.QueryValueEx(key, "InstallPath")
                candidates.append(Path(path))
                winreg.CloseKey(key)
            except OSError:
                pass

    # 常见路径
    drives = [Path(f"{c}:\\") for c in "CDEFGHIJ"
              if Path(f"{c}:\\").exists()]
    common_names = [
        "v2rayN", "v2rayN-windows-64", "v2rayN-windows-32",
        "v2rayN-Core", "v2ray",
    ]
    for drive in drives:
        for name in common_names:
            candidates.append(drive / name)
        for name in common_names:
            candidates.append(drive / "Program Files" / name)
            candidates.append(drive / "Programs" / name)
            candidates.append(drive / "Tools" / name)
            candidates.append(drive / "Portable" / name)

    # AppData
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        candidates.append(Path(appdata) / "v2rayN")

    # 过滤：目录存在且含 guiNConfig.json
    seen  = set()
    valid = []
    for p in candidates:
        config = p / "guiConfigs" / "guiNConfig.json"
        if config.exists() and str(p) not in seen:
            seen.add(str(p))
            valid.append(p)
    return valid

def select_v2rayn_dir() -> Path | None:
    candidates = find_v2rayn_candidates()

    print()
    print(f"  {CYAN}v2rayN 安装目录：{RESET}")

    if candidates:
        for i, p in enumerate(candidates, 1):
            print(f"   [{i}] {p}")
        print(f"   [{len(candidates)+1}] 手动输入路径")
        print(f"   [0] 跳过（不自动更新 v2rayN 配置）")
        print()
        while True:
            sel = input(f"  请选择 [0-{len(candidates)+1}]: ").strip()
            if sel == "0":
                warn("已跳过，请优化完成后手动修改 v2rayN TUN 设置中的 MTU。")
                return None
            if sel.isdigit() and 1 <= int(sel) <= len(candidates):
                chosen = candidates[int(sel)-1]
                ok(f"已选择：{chosen}")
                return chosen / "guiConfigs" / "guiNConfig.json"
            if sel == str(len(candidates)+1):
                break
            warn(f"请输入 0~{len(candidates)+1} 之间的数字。")

    # 手动输入（未找到候选时直接进入）
    if not candidates:
        info("未自动检测到 v2rayN，请手动输入安装目录。")
        info("直接回车跳过。")
    while True:
        user_input = input("  目录路径: ").strip().rstrip("\\/")
        if not user_input:
            warn("已跳过，请优化完成后手动修改 v2rayN TUN 设置中的 MTU。")
            return None
        config = Path(user_input) / "guiConfigs" / "guiNConfig.json"
        if config.exists():
            ok(f"找到配置文件：{config}")
            return config
        warn(f"未找到配置文件：{config}")
        warn("请确认目录是否正确，或直接回车跳过。")

def is_v2rayn_running() -> bool:
    """检测 v2rayN.exe 进程是否正在运行"""
    r = run(["tasklist", "/FI", "IMAGENAME eq v2rayN.exe", "/NH"])
    return "v2rayN.exe" in r.stdout


def wait_v2rayn_closed() -> bool:
    """
    如果 v2rayN 正在运行，提示用户关闭它，并循环等待。
    用户也可以输入 's' 跳过（此时 json 写入可能被覆盖，给出警告）。
    返回 True = 已确认关闭或本来就没运行；False = 用户选择跳过。
    """
    if not is_v2rayn_running():
        return True  # 没在跑，直接写

    print()
    warn("检测到 v2rayN 正在运行。")
    warn("v2rayN 退出时会把 GUI 中的 MTU 值写回 json，覆盖脚本的修改。")
    warn(f"MTU 目标值 {_PENDING_MTU} < 1280，GUI 无法手动输入，必须由脚本写入 json。")
    print()
    print(f"  {CYAN}请在 v2rayN 托盘图标右键 → 退出，然后按 Enter 继续。{RESET}")
    print(f"  {GRAY}（输入 s 跳过，但 json 修改可能被 v2rayN 下次退出覆盖）{RESET}")
    print()

    while True:
        ans = input("  已关闭 v2rayN？[Enter=继续 / s=跳过]: ").strip().lower()
        if ans == "s":
            warn("已跳过等待。json 已写入，但若 v2rayN 之后正常退出会被覆盖。")
            warn(f"请在下次启动 v2rayN 前确认 json 中 Mtu={_PENDING_MTU}。")
            return False
        if not is_v2rayn_running():
            ok("v2rayN 已关闭，继续写入配置。")
            return True
        warn("v2rayN 仍在运行，请先退出再按 Enter。")


_PENDING_MTU: int = 0  # 写入前暂存目标 MTU，供提示用


def set_v2rayn_mtu(config_path: Path, mtu: int) -> None:
    global _PENDING_MTU
    _PENDING_MTU = mtu

    # 等待 v2rayN 关闭（若在运行）
    wait_v2rayn_closed()

    # 写入 json
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        data["TunModeItem"]["Mtu"] = mtu
        config_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        ok(f"已写入 v2rayN 配置：TunModeItem.Mtu = {mtu}")
        ok("请重新启动 v2rayN，新 MTU 将在启动时生效。")
    except Exception as e:
        err(f"写入 v2rayN 配置文件失败：{e}")
        warn(f"请手动编辑 {config_path}，将 TunModeItem.Mtu 改为 {mtu}。")

# ── 协议选择 ──────────────────────────────────────────────────────────────────
def select_protocol() -> tuple[str, int]:
    print()
    print(f"  {CYAN}请选择你的代理协议（输入编号）：{RESET}")
    print("  ── TCP 协议 ─────────────────────────────────────────────")
    print("   [1] VLESS + TLS            Overhead = 50")
    print("   [2] VLESS + Reality        Overhead = 90  （推荐）")
    print("   [3] VMess + TLS            Overhead = 80")
    print("   [4] VMess + QUIC           Overhead = 120")
    print("   [5] Trojan                 Overhead = 100")
    print("   [6] Trojan + gRPC          Overhead = 60")
    print("   [7] Shadowsocks AEAD       Overhead = 70")
    print("   [8] NaiveProxy             Overhead = 90")
    print("   [9] SOCKS5（无加密）       Overhead = 20")
    print("  [10] HTTP Proxy（无加密）   Overhead = 60")
    print("  ── UDP 协议 ─────────────────────────────────────────────")
    print("  [11] WireGuard              Overhead = 60")
    print("  [12] Hysteria2              Overhead = 80  (* FEC时建议100~120)")
    print("  [13] TUIC                   Overhead = 80")
    print("  ── 其他 ─────────────────────────────────────────────────")
    print("  [14] 手动输入 Overhead 值")
    print()
    menu = {
        "1":"VLESS",      "2":"VLESS_Reality", "3":"VMess",    "4":"VMess_QUIC",
        "5":"Trojan",     "6":"Trojan_gRPC",   "7":"Shadowsocks_AEAD",
        "8":"NaiveProxy", "9":"SOCKS5",        "10":"HTTP_Proxy",
        "11":"WireGuard", "12":"Hysteria2",    "13":"TUIC",
    }
    while True:
        sel = input("  请输入编号 [1-14]: ").strip()
        if sel == "14":
            while True:
                raw = input("  请输入 Overhead 字节数（10~200）: ").strip()
                if raw.isdigit() and 10 <= int(raw) <= 200:
                    return "Custom", int(raw)
                warn("请输入 10~200 之间的整数。")
        if sel in menu:
            proto = menu[sel]
            return proto, OVERHEAD_MAP[proto]
        warn("无效输入，请输入 1~14 之间的数字。")

# ── 网卡工具 ──────────────────────────────────────────────────────────────────
def get_adapters() -> list[dict]:
    cmd = (
        "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | "
        "Select-Object Name,InterfaceDescription,InterfaceGuid,"
        "ifIndex,MediaType | ConvertTo-Json -Depth 2"
    )
    r = run(["powershell", "-NoProfile", "-Command", cmd])
    if r.returncode != 0 or not r.stdout.strip():
        return []
    data = json.loads(r.stdout)
    return [data] if isinstance(data, dict) else data

def is_tunnel(a: dict) -> bool:
    pat = r"(?i)tun|tap|sing|v2ray|wireguard|wg|proxy|vnet|utun"
    if re.search(pat, a.get("Name","")) or re.search(pat, a.get("InterfaceDescription","")):
        return True
    if not a.get("MediaType"):
        return True
    return False

def get_physical_source_ip(adapters: list[dict]) -> str | None:
    for a in adapters:
        if is_tunnel(a):
            continue
        idx = a.get("ifIndex")
        if not idx:
            continue
        cmd = (
            f"Get-NetIPAddress -InterfaceIndex {idx} -AddressFamily IPv4 "
            f"-ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.IPAddress -notmatch '^169\\.' }} | "
            f"Select-Object -First 1 -ExpandProperty IPAddress"
        )
        r = run(["powershell", "-NoProfile", "-Command", cmd])
        ip = r.stdout.strip()
        if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            return ip
    return None

def set_tun_mtu_all(adapters: list[dict], mtu: int):
    """临时设置所有隧道网卡 MTU（探测前用于消除 TUN 干扰）"""
    for a in adapters:
        if is_tunnel(a):
            run(f'netsh interface ipv4 set subinterface {a["ifIndex"]} '
                f'mtu={mtu} store=active')

# ── MTU 探测 ──────────────────────────────────────────────────────────────────
def find_reachable_target(source_ip: str | None) -> str | None:
    for ip, desc in PROBE_TARGETS:
        print(f"    测试 {ip} ({desc})...", end="", flush=True)
        cmd = ["ping", "-n", "1", "-w", "2000"]
        if source_ip:
            cmd += ["-S", source_ip]
        cmd.append(ip)
        r = run(cmd)
        if r.returncode == 0:
            print(f" {GREEN}可达{RESET}")
            return ip
        print(f" {GRAY}不可达{RESET}")
    return None

def probe_mtu_icmp(target_ip: str, source_ip: str | None) -> tuple[int, str]:
    """
    用 ICMP ping -f（DF位）二分探测物理 MTU。

    判断逻辑：
    - ping 返回 0（有回复）          → 这个尺寸能通过，best = mid
    - ping 返回非0 且含"分拆/frag"   → 包太大，收到了 ICMP type=3 code=4
    - ping 返回非0 且纯超时           → 中间设备静默丢包（不返回ICMP错误），
                                        同样说明包太大，high = mid - 1
                                        （与"分拆"处理方式相同，无需区分）

    说明：纯超时 和 收到"需要分拆"报文，对二分法而言结果一致，
    都意味着"这个尺寸过不去"。不需要也不应该区分两者。

    ICMP 被完全屏蔽的判定：
    - best 从未更新（停在初始值）且 探测过程中始终超时
    → 说明连小包（500字节）的回复都收不到，ICMP 被完全屏蔽
    → 返回 method="blocked"，由调用方提示用户手动输入
    """
    # ICMP 载荷搜索范围：500~1472 字节
    # 最终 MTU = best_payload + IP头(20) + ICMP头(8) = best_payload + 28
    low, high, best = 500, 1472, -1
    total_steps = 0

    while low <= high:
        mid = (low + high) // 2
        total_steps += 1
        cmd = ["ping", "-f", "-l", str(mid), "-n", "1", "-w", "1000"]
        if source_ip:
            cmd += ["-S", source_ip]
        cmd.append(target_ip)
        r   = run(cmd)
        out = r.stdout + r.stderr

        info(f"  ping -f -l {mid} {target_ip} → {'成功' if r.returncode == 0 else '失败'}")

        if r.returncode == 0:
            # 包通过了，尝试更大
            best = mid
            low  = mid + 1
        else:
            # 包过不去（无论是收到分拆报文还是纯超时），尝试更小
            high = mid - 1

    if best == -1:
        # 连 500 字节的小包都没有回复，ICMP 被完全屏蔽
        return -1, "blocked"

    return best + 28, "ICMP"


def get_physical_mtu(target_ip: str, source_ip: str | None,
                     adapters: list[dict]) -> tuple[int, str]:
    """
    探测物理 MTU。
    关键：探测前将隧道网卡 MTU 临时设为 9000，消除 TUN 拦截干扰。
    探测完成后再恢复（由调用方负责设回真正的 safe_mtu）。
    """
    # 临时解除 TUN MTU 限制，防止探测包被隧道截断
    info("临时设置隧道网卡 MTU=9000，消除 TUN 干扰...")
    set_tun_mtu_all(adapters, 9000)
    time.sleep(0.3)  # 等待内核生效

    print("    使用 ICMP ping -f 二分探测...")
    mtu, method = probe_mtu_icmp(target_ip, source_ip)

    if method == "blocked":
        print()
        warn("ICMP ping 完全无响应（防火墙/运营商屏蔽了 ICMP）。")
        warn("无法自动探测，请手动执行以下命令二分测试：")
        print()
        src_opt = f"-S {source_ip} " if source_ip else ""
        print(f"  {CYAN}ping -f -l 1464 {src_opt}{target_ip}{RESET}   ← 先试这个")
        print(f"  {CYAN}ping -f -l 1200 {src_opt}{target_ip}{RESET}")
        print(f"  {CYAN}ping -f -l 1000 {src_opt}{target_ip}{RESET}")
        print(f"  {CYAN}ping -f -l 800  {src_opt}{target_ip}{RESET}")
        print(f"  {CYAN}ping -f -l 500  {src_opt}{target_ip}{RESET}")
        print()
        print(f"  {GRAY}找到「成功」的最大值，加 28 即为物理 MTU。{RESET}")
        print(f"  {GRAY}例如 -l 996 成功、-l 997 超时 → MTU = 996+28 = 1024{RESET}")
        print()
        while True:
            raw = input("  请输入你测得的物理 MTU 值（576~9000）: ").strip()
            if raw.isdigit() and 576 <= int(raw) <= 9000:
                return int(raw), "手动"
            warn("请输入 576~9000 之间的整数。")

    return mtu, method

# ── 注册表 ────────────────────────────────────────────────────────────────────
REG_BASE = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"

def get_reg_value(guid: str, name: str) -> int | None:
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             rf"{REG_BASE}\{{{guid}}}")
        val, _ = winreg.QueryValueEx(key, name)
        winreg.CloseKey(key)
        return val
    except OSError:
        return None

def set_reg_tcp_opts(guid: str) -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             rf"{REG_BASE}\{{{guid}}}",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "TcpAckFrequency", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "TCPNoDelay",      0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        return True
    except Exception as e:
        err(f"注册表写入失败：{e}")
        return False

def delete_reg_value(guid: str, name: str):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             rf"{REG_BASE}\{{{guid}}}",
                             0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, name)
        winreg.CloseKey(key)
    except OSError:
        pass  # 键不存在，无需处理

# ── MTU 验证 ──────────────────────────────────────────────────────────────────
def confirm_mtu(adapter: dict, expected: int):
    idx = adapter["ifIndex"]
    cmd = (
        f"(Get-NetIPInterface -InterfaceIndex {idx} "
        f"-AddressFamily IPv4 -ErrorAction SilentlyContinue).NlMtu"
    )
    r = run(["powershell", "-NoProfile", "-Command", cmd])
    actual = r.stdout.strip()
    if actual == str(expected):
        ok(f"验证通过：[{adapter['Name']}] 当前MTU = {actual}")
    else:
        warn(f"验证：[{adapter['Name']}] 期望={expected}，实际={actual}（可能需重启生效）")

# ── netsh 调用 ────────────────────────────────────────────────────────────────
def netsh(cmd: str, desc: str):
    r = run(f"netsh {cmd}")
    if r.returncode == 0:
        ok(desc)
    else:
        err(f"{desc} 失败：{(r.stdout + r.stderr).strip()}")

# ── 还原模式 ──────────────────────────────────────────────────────────────────
def do_restore():
    print(f"\n{CYAN}{'='*54}{RESET}")
    print(f"{CYAN}  还原模式{RESET}")
    print(f"{CYAN}{'='*54}{RESET}")

    state = load_state()
    if not state:
        err(f"未找到状态文件：{STATE_FILE}")
        err("请先运行一次正常优化，生成状态记录后再还原。")
        input("\n按 Enter 退出...")
        sys.exit(1)

    print(f"  上次优化时间：{state.get('timestamp', '未知')}")
    print()

    # 还原隧道网卡 MTU
    step("还原隧道网卡 MTU...")
    for entry in state.get("tunnel_mtus", []):
        idx  = entry["ifIndex"]
        orig = entry["originalMtu"]
        name = entry["name"]
        r = run(f'netsh interface ipv4 set subinterface {idx} mtu={orig} store=active')
        if r.returncode == 0:
            ok(f"[{name}] MTU → {orig}")
        else:
            err(f"[{name}] 还原失败")

    # 还原注册表
    step("还原注册表 TCP 参数...")
    for entry in state.get("reg_entries", []):
        guid = entry["guid"]
        name = entry["adapterName"]
        for prop in ("TcpAckFrequency", "TCPNoDelay"):
            orig_val = entry.get(prop)
            if orig_val is None:
                delete_reg_value(guid, prop)
                ok(f"已删除 {prop} @ {name}（原本不存在）")
            else:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                         rf"{REG_BASE}\{{{guid}}}",
                                         0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, prop, 0, winreg.REG_DWORD, orig_val)
                    winreg.CloseKey(key)
                    ok(f"已还原 {prop} = {orig_val} @ {name}")
                except Exception as e:
                    err(f"还原 {prop} 失败：{e}")

    # 还原全局 TCP
    step("还原全局 TCP 参数...")
    netsh("int tcp set global autotuninglevel=normal", "autotuninglevel → normal")
    netsh("int tcp set global timestamps=disabled",    "timestamps → disabled")
    netsh("int tcp set global initialrto=3000",        "initialrto → 3000ms")
    netsh("int tcp set global pacingprofile=off",      "pacingprofile → off")

    # 还原 v2rayN 配置
    v2rayn_path = state.get("v2raynConfigPath")
    orig_mtu    = state.get("v2raynOriginalMtu")
    if v2rayn_path and orig_mtu is not None:
        step("还原 v2rayN 配置...")
        try:
            p    = Path(v2rayn_path)
            data = json.loads(p.read_text(encoding="utf-8"))
            data["TunModeItem"]["Mtu"] = orig_mtu
            p.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                         encoding="utf-8")
            ok(f"v2rayN TunModeItem.Mtu → {orig_mtu}")
            warn("请重启 v2rayN 使还原生效。")
        except Exception as e:
            err(f"还原 v2rayN 配置失败：{e}")

    print(f"\n{CYAN}还原完成！建议重启电脑使所有更改完全生效。{RESET}")
    input("\n按 Enter 退出...")

# ── 主流程 ────────────────────────────────────────────────────────────────────
def main():
    enable_ansi()

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--restore", action="store_true")
    args, _ = parser.parse_known_args()

    if not is_admin():
        warn("权限不足，正在请求管理员权限...")
        elevate()
        return

    if args.restore:
        do_restore()
        return

    print(f"\n{CYAN}{'='*54}{RESET}")
    print(f"{CYAN}  v2rayN 网络自适应优化脚本 v1.0{RESET}")
    print(f"{CYAN}{'='*54}{RESET}")

    # 上次状态检查
    state = load_state()
    if state:
        print()
        warn(f"检测到上次优化记录（{state.get('timestamp','未知')}）。")
        print(f"   [1] 继续本次优化（将覆盖上次记录）")
        print(f"   [2] 先还原上次设置，再退出")
        print(f"   [3] 先还原上次设置，再进行本次优化")
        print()
        while True:
            c = input("  请选择 [1-3]: ").strip()
            if c == "1":
                break
            elif c == "2":
                do_restore(); return
            elif c == "3":
                do_restore()
                print(f"\n{CYAN}{'='*54}{RESET}")
                print(f"{CYAN}  继续本次优化...{RESET}")
                print(f"{CYAN}{'='*54}{RESET}")
                break
            else:
                warn("请输入 1、2 或 3。")

    # v2rayN 目录
    v2rayn_config = select_v2rayn_dir()

    # 协议选择
    protocol, overhead = select_protocol()
    ok(f"已选择：{protocol}，Overhead = {overhead} 字节")
    if protocol in UDP_PROTOCOLS:
        warn("UDP协议在高丢包/QoS环境下可能不稳定，探测结果仅供参考。")
        if protocol == "Hysteria2":
            warn("Hysteria2 启用FEC时建议将 Overhead 调高至 100~120。")

    # 步骤1：获取物理网卡源IP
    step("[1/4] 获取物理网卡源IP...")
    adapters  = get_adapters()
    source_ip = get_physical_source_ip(adapters)
    if source_ip:
        ok(f"将使用源IP {source_ip} 进行探测")
    else:
        warn("未找到物理网卡IP，不绑定源IP")

    # 步骤2：寻找可达探测目标
    step("[2/4] 寻找可达的MTU探测目标...")
    target_ip = find_reachable_target(source_ip)
    if not target_ip:
        err("所有候选探测目标均不可达。")
        input("\n按 Enter 退出..."); sys.exit(1)

    # 步骤3：探测物理MTU（临时解除TUN限制）
    step(f"[3/4] 探测物理链路极限MTU（目标：{target_ip}）...")
    physical_mtu, method = get_physical_mtu(target_ip, source_ip, adapters)
    safe_mtu = max(500, physical_mtu - overhead)
    ok(f"物理极限MTU：{physical_mtu} 字节（探测方式：{method}）")
    ok(f"隧道安全MTU：{safe_mtu} 字节（{physical_mtu} - {overhead}）")

    # 步骤4：下发配置 + 记录状态
    step("[4/4] 下发配置...")
    wlan_guid   = None
    reg_entries = []
    tunnel_mtus = []

    for a in adapters:
        name = a["Name"]
        desc = a.get("InterfaceDescription", "")
        idx  = a["ifIndex"]
        guid = a.get("InterfaceGuid", "").strip("{}")

        if is_tunnel(a):
            print(f"    {CYAN}[隧道]{RESET} {name} | {desc}")
            # 记录原始 MTU（探测前已临时设为9000，用1500作为还原目标）
            tunnel_mtus.append({"name": name, "ifIndex": idx, "originalMtu": 1500})
            r = run(f'netsh interface ipv4 set subinterface {idx} '
                    f'mtu={safe_mtu} store=active')
            if r.returncode == 0:
                ok(f"MTU 已设置为 {safe_mtu}")
                confirm_mtu(a, safe_mtu)
            else:
                err(f"设置 [{name}] MTU 失败")
        else:
            print(f"    {CYAN}[物理]{RESET} {name} | {desc}")
            if guid:
                wlan_guid = guid
                # 记录原始注册表值（用于还原）
                reg_entries.append({
                    "guid":            guid,
                    "adapterName":     name,
                    "TcpAckFrequency": get_reg_value(guid, "TcpAckFrequency"),
                    "TCPNoDelay":      get_reg_value(guid, "TCPNoDelay"),
                })
                if set_reg_tcp_opts(guid):
                    ok("已写入 TcpAckFrequency=1, TCPNoDelay=1")

    # 写回 v2rayN
    v2rayn_orig_mtu = None
    if v2rayn_config:
        try:
            v2rayn_orig_mtu = json.loads(
                v2rayn_config.read_text(encoding="utf-8")
            )["TunModeItem"]["Mtu"]
        except Exception:
            pass
        set_v2rayn_mtu(v2rayn_config, safe_mtu)

    # 全局 TCP 调优
    netsh("int tcp set global autotuninglevel=normal", "TCP自动调优窗口：normal")
    netsh("int tcp set global timestamps=enabled",     "TCP时间戳：enabled")
    netsh("int tcp set global initialrto=2000",        "初始重传超时：2000ms")
    ver = sys.getwindowsversion()
    if ver.major >= 10:
        netsh("int tcp set global pacingprofile=initialwindow",
              "发包节奏控制：initialwindow")
    else:
        warn("系统版本 < Win10，跳过 pacingprofile。")

    # 保存状态文件（供 --restore 使用）
    import datetime
    save_state({
        "timestamp":         datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "protocol":          protocol,
        "overhead":          overhead,
        "physicalMtu":       physical_mtu,
        "safeMtu":           safe_mtu,
        "tunnel_mtus":       tunnel_mtus,
        "reg_entries":       reg_entries,
        "v2raynConfigPath":  str(v2rayn_config) if v2rayn_config else None,
        "v2raynOriginalMtu": v2rayn_orig_mtu,
    })
    ok(f"状态已保存至 {STATE_FILE}")

    # 完成
    print(f"\n{CYAN}{'='*54}{RESET}")
    print(f"{CYAN}  优化完成！{RESET}")
    print(f"{CYAN}{'='*54}{RESET}")
    print("【摘要】")
    print(f"  物理MTU     : {physical_mtu}（探测方式：{method}）")
    print(f"  隧道安全MTU : {safe_mtu}（协议={protocol}, Overhead={overhead}）")
    print()
    print("【后续操作】")
    print("  1. 重新启动 v2rayN（脚本已等待其关闭后写入 json，启动时将读取新 MTU）。")
    print("  2. 确认 v2rayN TUN 设置中协议栈为 system（不是 gvisor）。")
    print("  3. 建议重启电脑，使注册表TCP参数完全挂载。")
    print(f"  4. 如需还原：python tune_network.py --restore")
    print()
    print(f"{YELLOW}【如需手动还原，执行以下命令】{RESET}")
    print("  netsh int tcp set global autotuninglevel=normal")
    print("  netsh int tcp set global timestamps=disabled")
    print("  netsh int tcp set global initialrto=3000")
    print("  netsh int tcp set global pacingprofile=off")
    print(f"  netsh interface ipv4 set subinterface singbox_tun mtu=1500 store=active")
    if wlan_guid:
        base = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        print(f'  reg delete "{base}\\{{{wlan_guid}}}" /v TcpAckFrequency /f')
        print(f'  reg delete "{base}\\{{{wlan_guid}}}" /v TCPNoDelay /f')
    print(f"{CYAN}{'='*54}{RESET}")
    input("\n按 Enter 退出...")

if __name__ == "__main__":
    main()
