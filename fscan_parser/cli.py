"""CLI命令行模式 — python -m fscan_parser.cli 或 python fscan_parser/cli.py"""
import argparse

try:
    from .parser import parse_fscan_files
    from .excel import save_excel
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from fscan_parser.parser import parse_fscan_files
    from fscan_parser.excel import save_excel


def main():
    parser = argparse.ArgumentParser(
        description="Fscan结果解析工具 | 自动补充IP列 | 导出三Sheet Excel"
    )
    parser.add_argument("-i", "--input", required=True, help="txt文件/扫描结果目录")
    parser.add_argument("-o", "--output", required=True, help="输出.xlsx路径")
    args = parser.parse_args()

    p, t, pc = parse_fscan_files(args.input)
    save_excel(p, t, pc, args.output)


if __name__ == "__main__":
    main()
