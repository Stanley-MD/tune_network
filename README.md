# v2rayN 网络自适应优化脚本

专为 **v2rayN（sing-box 内核）TUN 模式**设计的 MTU 自动探测与 TCP 参数调优脚本。

## 解决的问题

v2rayN 的 TUN 模式 MTU 默认值为 1500，但实际物理链路（尤其是 WiFi、PPPoE、VPN 嵌套等场景）的真实 MTU 往往远低于此，导致：

- 大包被静默丢弃，连接反复重传
- 视频卡顿、大文件传输慢、网页加载不完整
- GUI 最小只能输入 1280，无法覆盖低 MTU 场景

本脚本自动探测物理链路极限 MTU，计算适合当前代理协议的隧道安全 MTU，并绕过 GUI 限制直接写入配置文件。

## 功能

- **ICMP 二分探测**：用 `ping -f` 精确定位物理链路 MTU 上限
- **多协议 Overhead 数据库**：内置 14 种代理协议的封装开销，自动计算隧道安全 MTU
- **v2rayN 进程守护写入**：检测 v2rayN 是否运行，确保在其退出后写入 json，防止被 GUI 覆盖
- **TCP 参数调优**：写入 `TcpAckFrequency`、`TCPNoDelay` 注册表项，调整 TCP 自动调优、时间戳、初始重传超时
- **一键还原**：所有改动均记录状态文件，`--restore` 可完整还原

## 环境要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Windows 10 / 11 |
| Python | 3.8 或以上 |
| 第三方库 | 无（纯标准库） |
| 运行权限 | 管理员（脚本会自动请求） |
| v2rayN | sing-box 内核，TUN 模式已启用 |

## 使用方法

### 正常优化

```
python tune_network.py
```

脚本将引导你完成以下步骤：

1. 自动检测 v2rayN 安装目录（或手动输入）
2. 选择代理协议
3. 探测物理链路 MTU
4. 提示关闭 v2rayN，写入配置，提示重启

### 还原上次修改

```
python tune_network.py --restore
```

### 完整交互流程示意

```
[1/4] 获取物理网卡源IP...
  --> 将使用源IP 192.168.1.5 进行探测

[2/4] 寻找可达的MTU探测目标...
    测试 223.5.5.5 (阿里云 DNS)... 可达

[3/4] 探测物理链路极限MTU（目标：223.5.5.5）...
    使用 ICMP ping -f 二分探测...
  --> 物理极限MTU：1024 字节（探测方式：ICMP）
  --> 隧道安全MTU：934 字节（1024 - 90）

[4/4] 下发配置...
  [!] 检测到 v2rayN 正在运行。
  请在 v2rayN 托盘图标右键 → 退出，然后按 Enter 继续。

  已关闭 v2rayN？[Enter=继续 / s=跳过]:
  --> 已写入 v2rayN 配置：TunModeItem.Mtu = 934
  --> 请重新启动 v2rayN，新 MTU 将在启动时生效。
```

## 支持的代理协议

| 编号 | 协议 | Overhead（字节） |
|------|------|----------------|
| 1 | VLESS + TLS | 50 |
| 2 | VLESS + Reality | 90 |
| 3 | VMess + TLS | 80 |
| 4 | VMess + QUIC | 120 |
| 5 | Trojan | 100 |
| 6 | Trojan + gRPC | 60 |
| 7 | Shadowsocks AEAD | 70 |
| 8 | NaiveProxy | 90 |
| 9 | SOCKS5 | 20 |
| 10 | HTTP Proxy | 60 |
| 11 | WireGuard | 60 |
| 12 | Hysteria2 | 80 |
| 13 | TUIC | 80 |
| 14 | 自定义 | 手动输入 |

> Overhead 值包含外层 IP 头（20）+ TCP/UDP 头 + 协议加密封装，直接用于 `物理MTU - Overhead = 隧道MTU`。

## MTU 计算原理

```
物理链路 MTU（ping -f 探测）
    └─ 减去协议封装 Overhead
        = TUN 虚拟网卡对上层呈现的 MTU（写入 TunModeItem.Mtu）
```

示例（VLESS Reality，WiFi 链路 MTU = 1024）：

```
隧道 MTU = 1024 - 90 = 934
```

## ICMP 被屏蔽时的处理

部分网络环境（运营商、企业防火墙）会屏蔽 ICMP，脚本将自动检测并提示手动测试：

```
ping -f -l 996 223.5.5.5   ← 成功
ping -f -l 997 223.5.5.5   ← 超时
→ 物理 MTU = 996 + 28 = 1024
```

测得后输入数值即可继续。

## 文件说明

```
tune_network.py           主脚本
tune_network_state.json   自动生成，记录上次修改内容（用于还原）
```

## 注意事项

- 注册表 TCP 参数修改后**建议重启电脑**完全生效
- `tune_network_state.json` 不要手动删除，否则 `--restore` 将无法还原
- Hysteria2 启用 FEC 时建议将 Overhead 手动调高至 100～120（选编号 14 自定义）
- 脚本只修改 `TunModeItem.Mtu`，不会改动服务器配置或其他 v2rayN 设置

## License

MIT
