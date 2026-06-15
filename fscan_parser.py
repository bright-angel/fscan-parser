"""Fscan结果解析工具 — 顶层兼容入口（python fscan_parser.py）"""
import sys

if __name__ == "__main__":
    if len(sys.argv) > 1:
        from fscan_parser.cli import main as cli_main
        cli_main()
    else:
        from fscan_parser.gui import main as gui_main
        gui_main()
