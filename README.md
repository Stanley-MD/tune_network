# MTU Tuner - v2rayN 网络优化工具

自动探测并优化 v2rayN TUN 模式的 MTU 设置。

## 这适合我吗？

如果你使用 v2rayN TUN 模式时遇到：

- 视频/网页加载卡顿或失败
- 大文件传输慢
- 网络 MTU 低于 1280（GUI 无法设置）

## 使用方法

```bash
python main.py           # 运行优化
python main.py --restore # 还原设置
```

脚本会引导你选择协议、探测 MTU、自动配置。

## 支持的协议

VLESS、VMess、Trojan、Shadowsocks、WireGuard、Hysteria2、TUIC 等主流协议。

## 环境要求

- Windows 10/11
- Python 3.8+
- 管理员权限（脚本会自动请求）

## 注意事项

- 运行后建议重启 v2rayN
- TCP 参数修改后建议重启电脑
- 如 v2rayN 正在运行，脚本会提示你先退出

## License

MIT
