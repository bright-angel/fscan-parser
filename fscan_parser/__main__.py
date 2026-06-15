"""python -m fscan_parser 入口：无参数时启动GUI，有参数时走CLI"""
import sys


def main():
    if len(sys.argv) > 1:
        try:
            from .cli import main as cli_main
        except ImportError:
            import os
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from fscan_parser.cli import main as cli_main
        cli_main()
    else:
        try:
            from .gui import main as gui_main
        except ImportError:
            import os
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from fscan_parser.gui import main as gui_main
        gui_main()


if __name__ == "__main__":
    main()
