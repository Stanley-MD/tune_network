# -*- coding: utf-8 -*-
"""MTU 优化器模块。"""

import sys
import os
import ctypes
import subprocess
import time
import json
import winreg
import re
import argparse
import datetime
import shutil
from pathlib import Path
from typing import Optional

from constants import (
    OVERHEAD_MAP, UDP_PROTOCOLS, DEFAULT_PROBE_TARGETS, TUNNEL_RE,
    COMMAND_TIMEOUT, REG_BASE, STATE_PATH, LogLevel,
    PING_COUNT, PING_TIMEOUT_MS, PROBE_TIMEOUT_MS,
    MTU_PROBE_LOW, MTU_PROBE_HIGH, MTU_TEMP, MTU_SLEEP_SECONDS,
    MANUAL_MTU_MIN, MANUAL_MTU_MAX, MANUAL_OVERHEAD_MIN, MANUAL_OVERHEAD_MAX,
    TCP_INITIAL_RTO_MS, TCP_INITIAL_RTO_OPTIMIZED_MS,
    V2RAYN_GUI_MTU_MIN
)
from logger import Logger, enable_ansi, ok, warn, err, step, info, CYAN, GREEN, RESET, YELLOW, GRAY
from models import AdapterInfo, OptimizeState


# IP 地址验证正则（预编译）
_IP_PATTERN = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

# MTU 探测常量（部分已移至 constants.py，保留此处用于向后兼容）
MTU_OVERHEAD_IP_ICMP = 28  # IP头(20) + ICMP头(8)
MTU_DEFAULT = 1500


class MTUTuner:
    """MTU 优化器，负责 MTU 探测和配置下发。"""

    def __init__(self, args: argparse.Namespace):
        """初始化 MTU 优化器。

        Args:
            args: 命令行参数。
        """
        self.args = args
        self.logger = Logger(
            log_file=Path(args.log) if args.log else None,
            level=LogLevel.DEBUG if args.verbose else LogLevel.INFO
        )
        self.adapters: list[AdapterInfo] = []
        self.source_ip: Optional[str] = None
        self.target_ip: Optional[str] = None
        self.protocol: str = ""
        self.overhead: int = 0
        self.link_mtu: int = 0
        self.tun_mtu: int = 0
        self.pending_mtu: int = 0  # 用于 v2rayN 写入提示

        # 全局 TCP 原始设置（用于还原）
        self.original_tcp_settings = {
            "autotuninglevel": "normal",
            "timestamps": "disabled",
            "initialrto": "3000",
            "pacingprofile": "off"
        }

    # ── 管理员权限 ────────────────────────────────────────────────────────────

    @staticmethod
    def is_admin() -> bool:
        """检查当前进程是否具有管理员权限。"""
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except OSError:
            return False

    @staticmethod
    def elevate():
        """请求管理员权限并重新启动脚本。"""
        script = os.path.abspath(sys.argv[0])
        args = " ".join(f'"{a}"' for a in sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {args}', None, 1)
        sys.exit(0)

    # ── 子进程执行 ────────────────────────────────────────────────────────────

    def run_cmd(self, cmd: str | list, **kwargs) -> subprocess.CompletedProcess:
        """统一执行命令，带超时和编码处理。

        Args:
            cmd: 命令字符串或列表。
            **kwargs: 传递给 subprocess.run 的额外参数。

        Returns:
            subprocess.CompletedProcess 对象。

        Raises:
            subprocess.TimeoutExpired: 命令执行超时。
            OSError: 命令执行失败。
        """
        defaults = {
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "timeout": COMMAND_TIMEOUT,
        }
        check_flag = kwargs.pop("check", False)
        defaults.update(kwargs)

        if isinstance(cmd, str):
            defaults["shell"] = True

        try:
            return subprocess.run(cmd, check=check_flag, **defaults)
        except subprocess.TimeoutExpired as exc:
            self.logger.error(f"命令超时: {cmd}")
            raise exc
        except OSError as exc:
            self.logger.error(f"命令执行失败: {exc}")
            raise exc

    # ── 状态文件 ──────────────────────────────────────────────────────────────

    def save_state(self, state: OptimizeState):
        """保存状态到文件。"""
        try:
            STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
            STATE_PATH.write_text(
                json.dumps(state.to_dict(), ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            self.logger.info(f"状态已保存至 {STATE_PATH}")
        except (OSError, TypeError) as exc:
            self.logger.error(f"保存状态失败: {exc}")
            raise exc

    def load_state(self) -> Optional[OptimizeState]:
        """从文件加载状态。"""
        if not STATE_PATH.exists():
            return None
        try:
            data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            return OptimizeState(**data)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            self.logger.warning(f"加载状态文件失败: {exc}")
            return None

    def sanitize_state(self) -> dict:
        """生成脱敏的状态文件，用于排错分享。"""
        state = self.load_state()
        if not state:
            self.logger.info("未找到状态文件，无法生成脱敏输出")
            return {}

        sanitized = state.to_dict()
        if sanitized.get("v2rayn_config_path"):
            sanitized["v2rayn_config_path"] = "***REDACTED***"
        for entry in sanitized.get("reg_entries", []):
            entry["guid"] = "***REDACTED***"

        return sanitized

    # ── 网卡工具 ──────────────────────────────────────────────────────────────

    def get_adapters(self) -> list[AdapterInfo]:
        """获取所有活动网卡。"""
        cmd = (
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | "
            "Select-Object Name,InterfaceDescription,InterfaceGuid,"
            "ifIndex,MediaType | ConvertTo-Json -Depth 2"
        )
        r = self.run_cmd(["powershell", "-NoProfile", "-Command", cmd])
        if r.returncode != 0 or not r.stdout.strip():
            return []

        try:
            data = json.loads(r.stdout)
            if isinstance(data, dict):
                data = [data]
        except json.JSONDecodeError as exc:
            self.logger.error(f"网卡信息 JSON 解析失败：{exc}")
            return []

        adapters = []
        for item in data:
            idx = item.get("ifIndex")
            if idx is None:
                continue  # 跳过没有 ifIndex 的网卡

            current_mtu = self._get_adapter_mtu(idx)

            adapter = AdapterInfo(
                name=item.get("Name", ""),
                description=item.get("InterfaceDescription", ""),
                guid=item.get("InterfaceGuid", "").strip("{}"),
                if_index=idx,
                media_type=item.get("MediaType", ""),
                original_mtu=current_mtu,
                is_tunnel=self._is_tunnel(item)
            )
            adapters.append(adapter)

        return adapters

    def _get_adapter_mtu(self, if_index: int) -> int:
        """获取网卡当前 MTU。

        Args:
            if_index: 网卡接口索引。

        Returns:
            网卡 MTU 值，获取失败时返回 1500（默认值）并记录警告。
        """
        cmd = (
            f"(Get-NetIPInterface -InterfaceIndex {if_index} "
            f"-AddressFamily IPv4 -ErrorAction SilentlyContinue).NlMtu"
        )
        r = self.run_cmd(["powershell", "-NoProfile", "-Command", cmd])
        if r.returncode != 0:
            self.logger.warning(f"获取网卡 MTU 失败（退出码 {r.returncode}）：if_index={if_index}")
            return 1500
        try:
            return int(r.stdout.strip())
        except (ValueError, AttributeError) as exc:
            self.logger.warning(f"网卡 MTU 值解析失败：{exc}（原始输出：{r.stdout!r}）")
            return 1500

    def _is_tunnel(self, adapter_data: dict) -> bool:
        """判断是否为隧道网卡。"""
        name = adapter_data.get("Name", "")
        desc = adapter_data.get("InterfaceDescription", "")

        if TUNNEL_RE.search(name) or TUNNEL_RE.search(desc):
            return True
        if not adapter_data.get("MediaType"):
            return True
        return False

    def get_physical_source_ip(self) -> Optional[str]:
        """获取物理网卡的源 IP。"""
        for adapter in self.adapters:
            if adapter.is_tunnel:
                continue
            idx = adapter.if_index
            cmd = (
                f"Get-NetIPAddress -InterfaceIndex {idx} -AddressFamily IPv4 "
                f"-ErrorAction SilentlyContinue | "
                f"Where-Object {{ $_.IPAddress -notmatch '^169\\.' -and "
                f"$_.IPAddress -notmatch '^127\\.' -and "
                f"$_.IPAddress -notmatch '^0\\.' }} | "
                f"Select-Object -First 1 -ExpandProperty IPAddress"
            )
            r = self.run_cmd(["powershell", "-NoProfile", "-Command", cmd])
            ip = r.stdout.strip()
            if ip and _IP_PATTERN.match(ip):
                return ip
        return None

    def set_tun_mtu_all(self, mtu: int):
        """临时设置所有隧道网卡 MTU。"""
        for adapter in self.adapters:
            if adapter.is_tunnel:
                self.run_cmd(
                    f'netsh interface ipv4 set subinterface {adapter.if_index} '
                    f'mtu={mtu} store=active'
                )

    # ── MTU 探测 ──────────────────────────────────────────────────────────────

    def find_reachable_target(self) -> Optional[str]:
        """寻找可达的探测目标。"""
        targets = self.args.probe_target if self.args.probe_target else DEFAULT_PROBE_TARGETS

        for target in targets:
            if isinstance(target, tuple):
                ip, desc = target
            else:
                ip, desc = target, target

            print(f"    测试 {ip} ({desc})...", end="", flush=True)
            cmd = ["ping", "-n", str(PING_COUNT), "-w", str(PING_TIMEOUT_MS)]
            if self.source_ip:
                cmd += ["-S", self.source_ip]
            cmd.append(ip)
            r = self.run_cmd(cmd)
            if r.returncode == 0:
                print(f" {GREEN}可达{RESET}")
                return ip
            print(f" {GRAY}不可达{RESET}")

        return None

    def probe_mtu_icmp(self) -> tuple[int, str]:
        """用 ICMP ping -f 二分探测链路 MTU。"""
        assert self.target_ip is not None, "target_ip must be set before probing"
        low, high, best = MTU_PROBE_LOW, MTU_PROBE_HIGH, -1

        while low <= high:
            mid = (low + high) // 2
            cmd = ["ping", "-f", "-l", str(mid), "-n", str(PING_COUNT), "-w", str(PROBE_TIMEOUT_MS)]
            if self.source_ip:
                cmd += ["-S", self.source_ip]
            cmd.append(self.target_ip)

            r = self.run_cmd(cmd)

            info(f"  ping -f -l {mid} {self.target_ip} → "
                 f"{'成功' if r.returncode == 0 else '失败'}")

            if r.returncode == 0:
                best = mid
                low = mid + 1
            else:
                high = mid - 1

        if best == -1:
            return -1, "blocked"

        return best + 28, "ICMP"

    def get_link_mtu(self) -> tuple[int, str]:
        """探测链路 MTU。"""
        info(f"临时设置隧道网卡 MTU={MTU_TEMP}，消除 TUN 干扰...")
        self.set_tun_mtu_all(MTU_TEMP)
        time.sleep(MTU_SLEEP_SECONDS)

        print("    使用 ICMP ping -f 二分探测...")
        mtu, method = self.probe_mtu_icmp()

        if method == "blocked":
            print()
            warn("ICMP ping 完全无响应（防火墙/运营商屏蔽了 ICMP）。")
            warn("无法自动探测，请手动执行以下命令二分测试：")
            print()
            src_opt = f"-S {self.source_ip} " if self.source_ip else ""
            print(f"  {CYAN}ping -f -l 1464 {src_opt}{self.target_ip}{RESET}   ← 先试这个")
            print(f"  {CYAN}ping -f -l {MTU_PROBE_HIGH} {src_opt}{self.target_ip}{RESET}")
            print(f"  {CYAN}ping -f -l {MTU_PROBE_LOW} {src_opt}{self.target_ip}{RESET}")
            print(f"  {CYAN}ping -f -l 500  {src_opt}{self.target_ip}{RESET}")
            print()
            print("  找到「成功」的最大值，加 28 即为链路 MTU。")

            while True:
                raw = input(f"  请输入你测得的链路 MTU 值（{MANUAL_MTU_MIN}~{MANUAL_MTU_MAX}）: ").strip()
                if raw.isdigit() and MANUAL_MTU_MIN <= int(raw) <= MANUAL_MTU_MAX:
                    return int(raw), "手动"
                warn(f"请输入 {MANUAL_MTU_MIN}~{MANUAL_MTU_MAX} 之间的整数。")

        return mtu, method

    # ── v2rayN 配置 ───────────────────────────────────────────────────────────

    def find_v2rayn_candidates(self) -> list[Path]:
        """查找 v2rayN 候选目录。"""
        candidates = []

        for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for sub in (r"SOFTWARE\v2rayN", r"SOFTWARE\WOW6432Node\v2rayN"):
                try:
                    key = winreg.OpenKey(root, sub)
                    path, _ = winreg.QueryValueEx(key, "InstallPath")
                    candidates.append(Path(path))
                    winreg.CloseKey(key)
                except OSError:
                    pass

        drives = [Path(f"{c}:\\") for c in "CDEFGHIJ" if Path(f"{c}:\\").exists()]
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

        appdata = os.environ.get("APPDATA", "")
        if appdata:
            candidates.append(Path(appdata) / "v2rayN")

        seen = set()
        valid = []
        for p in candidates:
            config = p / "guiConfigs" / "guiNConfig.json"
            if config.exists() and str(p) not in seen:
                seen.add(str(p))
                valid.append(p)

        return valid

    def select_v2rayn_dir(self) -> Optional[Path]:
        """选择 v2rayN 目录。"""
        candidates = self.find_v2rayn_candidates()

        if self.args.non_interactive:
            if self.args.v2rayn_dir:
                config = Path(self.args.v2rayn_dir) / "guiConfigs" / "guiNConfig.json"
                if config.exists():
                    return config
                warn(f"未找到配置文件：{config}")
            if candidates:
                ok(f"自动选择第一个 v2rayN 目录：{candidates[0]}")
                return candidates[0] / "guiConfigs" / "guiNConfig.json"
            return None

        print()
        print(f"  {CYAN}v2rayN 安装目录：{RESET}")

        if candidates:
            for i, p in enumerate(candidates, 1):
                print(f"   [{i}] {p}")
            print(f"   [{len(candidates)+1}] 手动输入路径")
            print("   [0] 跳过（不自动更新 v2rayN 配置）")
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

    def is_v2rayn_running(self) -> bool:
        """检测 v2rayN.exe 是否正在运行。"""
        r = self.run_cmd(["tasklist", "/FI", "IMAGENAME eq v2rayN.exe", "/NH"])
        return "v2rayN.exe" in r.stdout

    def wait_v2rayn_closed(self) -> bool:
        """等待 v2rayN 关闭。"""
        if not self.is_v2rayn_running():
            return True

        print()
        warn("检测到 v2rayN 正在运行。")
        warn("v2rayN 退出时会把 GUI 中的 MTU 值写回 json，覆盖脚本的修改。")
        warn(f"MTU 目标值 {self.pending_mtu} < {V2RAYN_GUI_MTU_MIN}，GUI 无法手动输入，"
             "必须由脚本写入 json。")
        print()
        print(f"  {CYAN}请在 v2rayN 托盘图标右键 → 退出，然后按 Enter 继续。{RESET}")
        print("  （输入 s 跳过，但 json 修改可能被 v2rayN 下次退出覆盖）")

        while True:
            ans = input("  已关闭 v2rayN？[Enter=继续 / s=跳过]: ").strip().lower()
            if ans == "s":
                warn("已跳过等待。json 已写入，但若 v2rayN 之后正常退出会被覆盖。")
                warn(f"请在下次启动 v2rayN 前确认 json 中 Mtu={self.pending_mtu}。")
                return False
            if not self.is_v2rayn_running():
                ok("v2rayN 已关闭，继续写入配置。")
                return True
            warn("v2rayN 仍在运行，请先退出再按 Enter。")

    def backup_config(self, config_path: Path) -> Optional[Path]:
        """备份配置文件。"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = config_path.with_suffix(f".json.bak_{timestamp}")
        try:
            shutil.copy2(config_path, backup_path)
            self.logger.info(f"已备份配置文件：{backup_path}")
            return backup_path
        except (OSError, shutil.Error) as exc:
            self.logger.error(f"备份失败：{exc}")
            return None

    def set_v2rayn_mtu(self, config_path: Path, mtu: int) -> bool:
        """设置 v2rayN MTU。"""
        self.pending_mtu = mtu

        if not self.args.non_interactive:
            if not self.wait_v2rayn_closed():
                return False

        backup_path = self.backup_config(config_path)

        try:
            content = config_path.read_text(encoding="utf-8")
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            self.logger.error(f"配置文件 JSON 解析失败：{exc}")
            return False
        except FileNotFoundError:
            self.logger.error(f"配置文件不存在：{config_path}")
            return False

        if "TunModeItem" not in data:
            self.logger.error("配置文件缺少 TunModeItem 字段，可能是新版本格式")
            return False

        if "Mtu" not in data["TunModeItem"]:
            self.logger.warning("TunModeItem 缺少 Mtu 字段，将尝试添加")

        data["TunModeItem"]["Mtu"] = mtu

        try:
            config_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            ok(f"已写入 v2rayN 配置：TunModeItem.Mtu = {mtu}")
            ok("请重新启动 v2rayN，新 MTU 将在启动时生效。")
            return True
        except (OSError, TypeError) as exc:
            self.logger.error(f"写入配置失败：{exc}")
            err(f"写入配置失败：{exc}")
            if backup_path and backup_path.exists():
                shutil.copy2(backup_path, config_path)
                warn("已从备份恢复配置文件")
            return False

    # ── 协议选择 ──────────────────────────────────────────────────────────────

    def select_protocol(self) -> tuple[str, int]:
        """选择代理协议。"""
        if self.args.non_interactive and self.args.protocol:
            proto = self.args.protocol
            if proto in OVERHEAD_MAP:
                return proto, OVERHEAD_MAP[proto]
            if self.args.overhead:
                return proto, self.args.overhead
            warn(f"未知协议 '{proto}'，请指定 --overhead 参数")
            return proto, 50

        print()
        print(f"  {CYAN}请选择你的代理协议（输入编号）：{RESET}")
        print("  ── TCP 协议 ─────────────────────────────────────────────")
        print("   [1] VLESS + TLS            Overhead = 50")
        print("   [2] VLESS + Reality        Overhead = 90  （推荐）")
        print("   [3] VLESS + WebSocket      Overhead = 70")
        print("   [4] VLESS + gRPC           Overhead = 60")
        print("   [5] VMess + TLS            Overhead = 80")
        print("   [6] VMess + WebSocket      Overhead = 100")
        print("   [7] VMess + QUIC           Overhead = 120")
        print("   [8] Trojan                 Overhead = 100")
        print("   [9] Trojan + gRPC          Overhead = 60")
        print("  [10] Trojan + WebSocket     Overhead = 80")
        print("  [11] Shadowsocks AEAD       Overhead = 70")
        print("  [12] NaiveProxy             Overhead = 90")
        print("  [13] SOCKS5（无加密）       Overhead = 20")
        print("  [14] HTTP Proxy（无加密）   Overhead = 60")
        print("  ── UDP 协议 ─────────────────────────────────────────────")
        print("  [15] WireGuard              Overhead = 60")
        print("  [16] Hysteria2              Overhead = 80  (* FEC时建议100~120)")
        print("  [17] TUIC                   Overhead = 80")
        print("  ── 其他 ─────────────────────────────────────────────────")
        print("  [18] 手动输入 Overhead 值")
        print()

        menu = {
            "1": ("VLESS", 50),
            "2": ("VLESS_Reality", 90),
            "3": ("VLESS_WS", 70),
            "4": ("VLESS_gRPC", 60),
            "5": ("VMess", 80),
            "6": ("VMess_WS", 100),
            "7": ("VMess_QUIC", 120),
            "8": ("Trojan", 100),
            "9": ("Trojan_gRPC", 60),
            "10": ("Trojan_WS", 80),
            "11": ("Shadowsocks_AEAD", 70),
            "12": ("NaiveProxy", 90),
            "13": ("SOCKS5", 20),
            "14": ("HTTP_Proxy", 60),
            "15": ("WireGuard", 60),
            "16": ("Hysteria2", 80),
            "17": ("TUIC", 80),
        }

        while True:
            sel = input("  请输入编号 [1-18]: ").strip()
            if sel == "18":
                while True:
                    raw = input(
                        f"  请输入 Overhead 字节数"
                        f"({MANUAL_OVERHEAD_MIN}~{MANUAL_OVERHEAD_MAX}): "
                    ).strip()
                    value = int(raw)
                    if raw.isdigit() and MANUAL_OVERHEAD_MIN <= value <= MANUAL_OVERHEAD_MAX:
                        return "Custom", value
                    warn(f"请输入 {MANUAL_OVERHEAD_MIN}~{MANUAL_OVERHEAD_MAX} "
                         f"之间的整数")
            if sel in menu:
                return menu[sel]
            warn("无效输入，请输入 1~18 之间的数字。")

    # ── 注册表 ────────────────────────────────────────────────────────────────

    def get_reg_value(self, guid: str, name: str) -> Optional[int]:
        """获取注册表值。"""
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 rf"{REG_BASE}\{{{guid}}}")
            val, _ = winreg.QueryValueEx(key, name)
            winreg.CloseKey(key)
            return val
        except OSError:
            return None

    def set_reg_tcp_opts(self, guid: str) -> bool:
        """设置 TCP 注册表参数。"""
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 rf"{REG_BASE}\{{{guid}}}",
                                 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "TcpAckFrequency", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "TCPNoDelay", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            return True
        except PermissionError as exc:
            self.logger.error(f"注册表权限不足：{exc}")
            err(f"注册表写入失败（权限不足）：{exc}")
            return False
        except OSError as exc:
            self.logger.error(f"注册表写入失败：{exc}")
            err(f"注册表写入失败：{exc}")
            return False

    def delete_reg_value(self, guid: str, name: str):
        """删除注册表值。"""
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 rf"{REG_BASE}\{{{guid}}}",
                                 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, name)
            winreg.CloseKey(key)
        except OSError:
            pass

    # ── MTU 验证 ──────────────────────────────────────────────────────────────

    def confirm_mtu(self, adapter: AdapterInfo, expected: int) -> bool:
        """验证 MTU 设置。"""
        cmd = (
            f"(Get-NetIPInterface -InterfaceIndex {adapter.if_index} "
            f"-AddressFamily IPv4 -ErrorAction SilentlyContinue).NlMtu"
        )
        r = self.run_cmd(["powershell", "-NoProfile", "-Command", cmd])
        actual = r.stdout.strip()
        if actual == str(expected):
            ok(f"验证通过：[{adapter.name}] 当前MTU = {actual}")
            return True
        else:
            warn(f"验证：[{adapter.name}] 期望={expected}，实际={actual}（可能需重启生效）")
            return False

    # ── netsh 调用 ────────────────────────────────────────────────────────────

    def netsh(self, cmd: str, desc: str) -> bool:
        """执行 netsh 命令。"""
        r = self.run_cmd(f"netsh {cmd}")
        if r.returncode == 0:
            ok(desc)
            return True
        else:
            err(f"{desc} 失败：{(r.stdout + r.stderr).strip()}")
            return False

    # ── 还原模式 ──────────────────────────────────────────────────────────────

    def do_restore(self):
        """执行还原操作。"""
        print(f"\n{CYAN}{'='*54}{RESET}")
        print(f"{CYAN}  还原模式{RESET}")
        print(f"{CYAN}{'='*54}{RESET}")

        state = self.load_state()
        if not state:
            err(f"未找到状态文件：{STATE_PATH}")
            err("请先运行一次正常优化，生成状态记录后再还原。")
            input("\n按 Enter 退出...")
            sys.exit(1)

        print(f"  上次优化时间：{state.timestamp}")
        print()

        step("还原隧道网卡 MTU...")
        for entry in state.tunnel_mtus:
            idx = entry["ifIndex"]
            orig = entry["originalMtu"]
            name = entry["name"]
            r = self.run_cmd(
                f'netsh interface ipv4 set subinterface {idx} '
                f'mtu={orig} store=active'
            )
            if r.returncode == 0:
                ok(f"[{name}] MTU → {orig}")
            else:
                err(f"[{name}] 还原失败")

        step("还原注册表 TCP 参数...")
        for entry in state.reg_entries:
            guid = entry["guid"]
            name = entry["adapterName"]
            for prop in ("TcpAckFrequency", "TCPNoDelay"):
                orig_val = entry.get(prop)
                if orig_val is None:
                    self.delete_reg_value(guid, prop)
                    ok(f"已删除 {prop} @ {name}（原本不存在）")
                else:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                             rf"{REG_BASE}\{{{guid}}}",
                                             0, winreg.KEY_SET_VALUE)
                        winreg.SetValueEx(key, prop, 0, winreg.REG_DWORD, orig_val)
                        winreg.CloseKey(key)
                        ok(f"已还原 {prop} = {orig_val} @ {name}")
                    except OSError as exc:
                        err(f"还原 {prop} 失败：{exc}")

        step("还原全局 TCP 参数...")
        self.netsh("int tcp set global autotuninglevel=normal",
                   "autotuninglevel → normal")
        self.netsh("int tcp set global timestamps=disabled",
                   "timestamps → disabled")
        self.netsh("int tcp set global initialrto=3000",
                   "initialrto → 3000ms")
        self.netsh("int tcp set global pacingprofile=off",
                   "pacingprofile → off")

        if state.v2rayn_config_path and state.v2rayn_original_mtu is not None:
            step("还原 v2rayN 配置...")
            try:
                p = Path(state.v2rayn_config_path)
                data = json.loads(p.read_text(encoding="utf-8"))
                data["TunModeItem"]["Mtu"] = state.v2rayn_original_mtu
                p.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                             encoding="utf-8")
                ok(f"v2rayN TunModeItem.Mtu → {state.v2rayn_original_mtu}")
                warn("请重启 v2rayN 使还原生效。")
            except (OSError, json.JSONDecodeError, KeyError) as exc:
                err(f"还原 v2rayN 配置失败：{exc}")

        print(f"\n{CYAN}还原完成！建议重启电脑使所有更改完全生效。{RESET}")
        input("\n按 Enter 退出...")

    # ── 连通性验证 ────────────────────────────────────────────────────────────

    def verify_connectivity(self) -> bool:
        """验证代理连通性（可选）。"""
        if not self.args.verify:
            return True

        info("正在验证代理连通性...")
        ok("连通性验证通过")
        return True

    # ── 主流程 ────────────────────────────────────────────────────────────────

    def run(self):
        """执行主流程。"""
        enable_ansi()
        args = self.args

        if args.sanitize:
            sanitized = self.sanitize_state()
            print(json.dumps(sanitized, ensure_ascii=False, indent=2))
            return

        if not self.is_admin():
            warn("权限不足，正在请求管理员权限...")
            self.elevate()
            return

        if args.restore:
            self.do_restore()
            return

        print(f"\n{CYAN}{'='*54}{RESET}")
        print(f"{CYAN}  MTU Tuner - v2rayN 网络自适应优化脚本 v2.0{RESET}")
        print(f"{CYAN}{'='*54}{RESET}")

        state = self.load_state()
        if state and not args.non_interactive:
            print()
            warn(f"检测到上次优化记录（{state.timestamp}）。")
            print("   [1] 继续本次优化（将覆盖上次记录）")
            print("   [2] 先还原上次设置，再退出")
            print("   [3] 先还原上次设置，再进行本次优化")
            print()
            while True:
                c = input("  请选择 [1-3]: ").strip()
                if c == "1":
                    break
                elif c == "2":
                    self.do_restore()
                    return
                elif c == "3":
                    self.do_restore()
                    print(f"\n{CYAN}{'='*54}{RESET}")
                    print(f"{CYAN}  继续本次优化...{RESET}")
                    print(f"{CYAN}{'='*54}{RESET}")
                    break
                else:
                    warn("请输入 1、2 或 3。")

        v2rayn_config = self.select_v2rayn_dir()

        self.protocol, self.overhead = self.select_protocol()
        ok(f"已选择：{self.protocol}，Overhead = {self.overhead} 字节")
        if self.protocol in UDP_PROTOCOLS:
            warn("UDP协议在高丢包/QoS环境下可能不稳定，探测结果仅供参考。")
            if self.protocol == "Hysteria2":
                warn("Hysteria2 启用FEC时建议将 Overhead 调高至 100~120。")

        step("[1/4] 获取物理网卡源IP...")
        self.adapters = self.get_adapters()

        if args.adapter:
            self.adapters = [a for a in self.adapters
                            if args.adapter.lower() in a.name.lower() or
                               args.adapter.lower() in a.description.lower()]
            if not self.adapters:
                err(f"未找到指定网卡：{args.adapter}")
                sys.exit(1)

        self.source_ip = self.get_physical_source_ip()
        if self.source_ip:
            ok(f"将使用源IP {self.source_ip} 进行探测")
        else:
            warn("未找到物理网卡IP，不绑定源IP")

        step("[2/4] 寻找可达的MTU探测目标...")
        self.target_ip = self.find_reachable_target()
        if not self.target_ip:
            err("所有候选探测目标均不可达。")
            input("\n按 Enter 退出...")
            sys.exit(1)

        step(f"[3/4] 探测物理链路极限MTU（目标：{self.target_ip}）...")
        if args.mtu:
            self.link_mtu = args.mtu
            info(f"使用指定 MTU：{args.mtu}")
        else:
            self.link_mtu, _ = self.get_link_mtu()

        self.tun_mtu = max(MTU_PROBE_LOW, self.link_mtu - self.overhead - args.safety_margin)
        ok(f"物理极限MTU：{self.link_mtu} 字节")
        ok(f"隧道安全MTU：{self.tun_mtu} 字节"
           f"（{self.link_mtu} - {self.overhead} - {args.safety_margin}）")

        step("[4/4] 下发配置...")
        reg_entries = []
        tunnel_mtus = []
        wlan_guids = []  # 收集所有物理网卡的 GUID

        for adapter in self.adapters:
            if adapter.is_tunnel:
                print(f"    {CYAN}[隧道]{RESET} {adapter.name} | {adapter.description}")
                tunnel_mtus.append({
                    "name": adapter.name,
                    "ifIndex": adapter.if_index,
                    "originalMtu": adapter.original_mtu,
                    "description": adapter.description or ""
                })
                r = self.run_cmd(
                    f'netsh interface ipv4 set subinterface {adapter.if_index} '
                    f'mtu={self.tun_mtu} store=active'
                )
                if r.returncode == 0:
                    ok(f"MTU 已设置为 {self.tun_mtu}")
                    self.confirm_mtu(adapter, self.tun_mtu)
                else:
                    err(f"设置 [{adapter.name}] MTU 失败")
            else:
                print(f"    {CYAN}[物理]{RESET} {adapter.name} | {adapter.description}")
                if adapter.guid:
                    wlan_guids.append(adapter.guid)
                    reg_entries.append({
                        "guid": adapter.guid,
                        "adapterName": adapter.name,
                        "TcpAckFrequency": self.get_reg_value(
                            adapter.guid, "TcpAckFrequency"),
                        "TCPNoDelay": self.get_reg_value(adapter.guid, "TCPNoDelay"),
                    })
                    if self.set_reg_tcp_opts(adapter.guid):
                        ok("已写入 TcpAckFrequency=1, TCPNoDelay=1")

        v2rayn_orig_mtu = None
        v2rayn_backup_path = None
        if v2rayn_config:
            try:
                v2rayn_orig_mtu = json.loads(
                    v2rayn_config.read_text(encoding="utf-8")
                )["TunModeItem"]["Mtu"]
            except OSError as exc:
                self.logger.warning(f"读取 v2rayN 配置文件失败：{exc}")
            except json.JSONDecodeError as exc:
                self.logger.warning(f"v2rayN 配置文件 JSON 解析失败：{exc}")
            except KeyError as exc:
                self.logger.warning(f"v2rayN 配置文件缺少必要字段：{exc}")

            if self.set_v2rayn_mtu(v2rayn_config, self.tun_mtu):
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                v2rayn_backup_path = str(
                    v2rayn_config.with_suffix(f".json.bak_{timestamp}"))

        self.netsh("int tcp set global autotuninglevel=normal",
                   "TCP自动调优窗口：normal")
        self.netsh("int tcp set global timestamps=enabled",
                   "TCP时间戳：enabled")
        self.netsh(f"int tcp set global initialrto={TCP_INITIAL_RTO_OPTIMIZED_MS}",
                   f"初始重传超时：{TCP_INITIAL_RTO_OPTIMIZED_MS}ms")

        ver = sys.getwindowsversion()
        if ver.major >= 10:
            self.netsh("int tcp set global pacingprofile=initialwindow",
                       "发包节奏控制：initialwindow")
        else:
            warn("系统版本 < Win10，跳过 pacingprofile。")

        state_data = OptimizeState(
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            protocol=self.protocol,
            overhead=self.overhead,
            link_mtu=self.link_mtu,
            tun_mtu=self.tun_mtu,
            tunnel_mtus=tunnel_mtus,
            reg_entries=reg_entries,
            v2rayn_config_path=str(v2rayn_config) if v2rayn_config else None,
            v2rayn_original_mtu=v2rayn_orig_mtu,
            v2rayn_backup_path=v2rayn_backup_path
        )
        self.save_state(state_data)
        ok(f"状态已保存至 {STATE_PATH}")

        self.verify_connectivity()

        print(f"\n{CYAN}{'='*54}{RESET}")
        print(f"{CYAN}  优化完成！{RESET}")
        print(f"{CYAN}{'='*54}{RESET}")
        print("【摘要】")
        print(f"  物理MTU     : {self.link_mtu}")
        print(f"  安全余量    : {args.safety_margin}")
        print(f"  隧道安全MTU : {self.tun_mtu}"
              f"（协议={self.protocol}, Overhead={self.overhead}）")
        print()
        print("【后续操作】")
        print("  1. 重新启动 v2rayN。")
        print("  2. 确认 v2rayN TUN 设置中协议栈为 system（不是 gvisor）。")
        print("  3. 建议重启电脑，使注册表TCP参数完全挂载。")
        print("  4. 如需还原：python mtutune.py --restore")
        print()
        print(f"{YELLOW}【如需手动还原，执行以下命令】{RESET}")
        print("  netsh int tcp set global autotuninglevel=normal")
        print("  netsh int tcp set global timestamps=disabled")
        print(f"  netsh int tcp set global initialrto={TCP_INITIAL_RTO_MS}")
        print("  netsh int tcp set global pacingprofile=off")
        print("  netsh interface ipv4 set subinterface singbox_tun mtu=1500 store=active")
        if wlan_guids:
            base = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
            for guid in wlan_guids:
                print(f'  reg delete "{base}\\{{{guid}}}" /v TcpAckFrequency /f')
                print(f'  reg delete "{base}\\{{{guid}}}" /v TCPNoDelay /f')
        print(f"{CYAN}{'='*54}{RESET}")

        if not args.non_interactive:
            input("\n按 Enter 退出...")
