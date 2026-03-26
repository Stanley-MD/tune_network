# -*- coding: utf-8 -*-
"""数据类定义模块。"""

from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class AdapterInfo:
    """网卡信息数据类。"""
    name: str
    description: str
    guid: str
    if_index: int
    media_type: str
    original_mtu: int = 1500  # 探测前读取的真实 MTU
    is_tunnel: bool = False


@dataclass
class OptimizeState:
    """优化状态数据类，用于保存和还原设置。"""
    timestamp: str
    protocol: str
    overhead: int
    link_mtu: int
    tun_mtu: int
    tunnel_mtus: list[dict]
    reg_entries: list[dict]
    v2rayn_config_path: Optional[str]
    v2rayn_original_mtu: Optional[int]
    v2rayn_backup_path: Optional[str] = None
    global_tcp_settings: Optional[dict] = None

    def to_dict(self) -> dict:
        """转换为字典。"""
        return asdict(self)
