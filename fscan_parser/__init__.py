"""fscan-parser: 把 fscan 的扫描结果（txt/csv/json）转换成结构化 Excel。"""

from .excel import export_workbook
from .merge import build_assets, dedupe, merge_web_records
from .models import ParseStats, Record, RecordType, Severity, Target
from .parsers import parse_file, parse_text, sniff_format
from .targets import normalize_target
from .version import (
    FscanEra,
    FormatDetection,
    detect_format_and_version,
    detect_from_records,
    resolve_version_spec,
)

__version__ = "1.1.0"

__all__ = [
    "export_workbook",
    "build_assets",
    "dedupe",
    "merge_web_records",
    "ParseStats",
    "Record",
    "RecordType",
    "Severity",
    "Target",
    "parse_file",
    "parse_text",
    "sniff_format",
    "normalize_target",
    "FscanEra",
    "FormatDetection",
    "detect_format_and_version",
    "detect_from_records",
    "resolve_version_spec",
    "__version__",
]
