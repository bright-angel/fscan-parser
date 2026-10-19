"""命令行入口：python -m fscan_parser ..."""

from __future__ import annotations

import argparse
import glob
import os
import sys
from typing import List

from . import __version__
from .excel import export_workbook
from .merge import dedupe, merge_web_records
from .models import ParseStats, Record
from .parsers import parse_file


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fscan-parser",
        description="解析 fscan 扫描结果（txt / csv / json），导出为结构化 Excel（xlsx）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  fscan-parser result.txt\n"
            "  fscan-parser result.txt -o report.xlsx\n"
            "  fscan-parser results/ -o report.xlsx --recursive\n"
            "  fscan-parser result.json result.csv --no-dedupe\n"
        ),
    )
    p.add_argument("inputs", nargs="+", help="结果文件或目录（支持通配符）")
    p.add_argument("-o", "--output", default="fscan-report.xlsx", help="输出 xlsx 路径（默认 fscan-report.xlsx）")
    p.add_argument("-f", "--format", default="auto", choices=["auto", "txt", "csv", "json"], help="强制指定输入格式")
    p.add_argument(
        "--version-spec",
        default="",
        metavar="VER",
        help="强制指定 fscan 版本（1.8.0/1.8.2/1.8.3/1.8.4/2.0.0/2.1 等），自动识别不准时用",
    )
    p.add_argument("--no-dedupe", action="store_true", help="关闭跨文件去重")
    p.add_argument("--keep-web-only", action="store_true", help="保留 TXT 末尾独立的 Web 服务记录（默认合并进服务表）")
    p.add_argument("-r", "--recursive", action="store_true", help="目录输入时递归查找")
    p.add_argument("-q", "--quiet", action="store_true", help="只输出错误")
    p.add_argument("-V", "--version", action="version", version=f"fscan-parser {__version__}")
    return p


def collect_files(inputs: List[str], recursive: bool) -> List[str]:
    exts = {".txt", ".csv", ".json", ".tmp", ".log"}
    files: List[str] = []
    for item in inputs:
        if os.path.isdir(item):
            pattern = "**/*" if recursive else "*"
            for path in sorted(glob.glob(os.path.join(item, pattern), recursive=recursive)):
                if os.path.isfile(path) and _is_candidate(path, exts):
                    files.append(path)
        elif any(ch in item for ch in "*?["):
            for path in sorted(glob.glob(item, recursive=recursive)):
                if os.path.isfile(path):
                    files.append(path)
        elif os.path.isfile(item):
            files.append(item)
        else:
            raise FileNotFoundError(f"找不到文件或目录: {item}")
    # 去重且保持顺序
    seen = set()
    ordered = []
    for f in files:
        real = os.path.abspath(f)
        if real not in seen:
            seen.add(real)
            ordered.append(f)
    return ordered


def _is_candidate(path: str, exts: set[str]) -> bool:
    name = os.path.basename(path)
    if name.startswith("~$"):
        return False
    if name.endswith(".realtime.tmp") or name.endswith(".tmp"):
        return True
    if os.path.splitext(name)[1].lower() in exts:
        return True
    if "." not in name and "result" in name.lower():
        return True
    return False


def main(argv: List[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        files = collect_files(args.inputs, args.recursive)
    except FileNotFoundError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if not files:
        print("[!] 没有找到可解析的文件", file=sys.stderr)
        return 2

    all_records: List[Record] = []
    total = ParseStats()
    for path in files:
        try:
            records, stats = parse_file(path, fmt=args.format, version_spec=args.version_spec)
        except Exception as exc:  # 单文件失败不中断整体流程
            print(f"[!] 解析失败 {path}: {exc}", file=sys.stderr)
            total.failed += 1
            continue
        total.merge(stats)
        all_records.extend(records)
        if not args.quiet:
            fmt = next(iter(stats.formats), "-")
            era = stats.versions and next(iter(stats.versions), "")
            suffix = f", fscan {era}" if era and era != "unknown" else ""
            print(f"[+] {path}  ({fmt}{suffix}, {len(records)} 条)")

    if not args.keep_web_only:
        all_records = merge_web_records(all_records)

    if not args.no_dedupe:
        before = len(all_records)
        all_records, dropped = dedupe(all_records)
        if not args.quiet and dropped:
            print(f"[*] 去重：移除 {dropped} 条重复记录（{before} -> {len(all_records)}）")

    if not all_records:
        print("[!] 未解析出任何记录，请检查文件格式（可用 -f 指定）", file=sys.stderr)
        return 1

    out_path = args.output
    parent = os.path.dirname(os.path.abspath(out_path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)

    export_workbook(all_records, out_path, stats=total, source_files=files)
    if not args.quiet:
        print(f"[✓] 已导出 {len(all_records)} 条记录 -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
