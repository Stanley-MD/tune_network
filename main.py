# -*- coding: utf-8 -*-
"""程序入口点。"""

import argparse

from constants import MTU_SAFETY_MARGIN
from tuner import MTUTuner


def main():
    """程序入口点。"""
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


main()
