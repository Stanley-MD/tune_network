# -*- coding: utf-8 -*-
"""程序入口点。"""

import argparse
import sys
import traceback

from constants import MTU_SAFETY_MARGIN
from tuner import MTUTuner


def main():
    """程序入口点。"""
    try:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--restore", action="store_true")
        parser.add_argument("--protocol", type=str)
        parser.add_argument("--overhead", type=int)
        parser.add_argument("--mtu", type=int)
        parser.add_argument("--non-interactive", action="store_true")
        parser.add_argument("--log", type=str)
        parser.add_argument("--verbose", action="store_true")
        parser.add_argument("--sanitize", action="store_true")
        parser.add_argument("--adapter", type=str)
        parser.add_argument("--probe-target", type=str, action="append")
        parser.add_argument("--verify", action="store_true")
        parser.add_argument("--v2rayn-dir", type=str)
        parser.add_argument("--safety-margin", type=int, default=MTU_SAFETY_MARGIN)

        args, _ = parser.parse_known_args()

        tuner = MTUTuner(args)
        tuner.run()
    except KeyboardInterrupt:
        print("\n\n操作已取消。")
        print("如需还原设置，请重新运行脚本并选择还原模式。")
        input("\n按 Enter 退出...")
        sys.exit(0)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"\n{'='*54}")
        print("  发生错误！程序意外退出")
        print(f"{'='*54}")
        print(f"\n错误类型：{type(exc).__name__}")
        print(f"错误信息：{exc}")
        print("\n完整堆栈跟踪：")
        traceback.print_exc()
        print(f"{'='*54}")
        print("\n请尝试以下解决方法：")
        print("  1. 以管理员身份运行脚本")
        print("  2. 检查网络连接是否正常")
        print("  3. 暂时关闭杀毒软件/防火墙")
        print("  4. 检查 v2rayN 是否正在运行")
        print(f"{'='*54}")
        input("\n按 Enter 退出...")
        sys.exit(1)


main()
