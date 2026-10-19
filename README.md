# fscan-parser

把 [fscan](https://github.com/shadow1ng/fscan) 的扫描结果（`result.txt` / `result.csv` / `result.json`）解析成一份结构化的 Excel 报告：多张工作表、可筛选、带风险等级和资产视图。

## 为什么需要它

fscan 的输出文件是"给人看"的，不是"给表格用"的：

- TXT 按段落罗列，端口、服务、漏洞分散在三段，一台主机要来回翻；
- 服务段用 `http://1.2.3.4:80 [标题] 200 server [指纹]` 这种紧凑格式，靠空格分隔；
- 漏洞段里弱口令写成 `1.2.3.4:80 mysql root/123456`，与 POC 漏洞 `1.2.3.4:445 MS17-010` 混在一起；
- CSV 的漏洞段 `Details` 列写的是 `result.Status`，弱口令账号密码直接丢失；
- 不同版本格式还不一样（v1.x 行式 `[+]` 前缀 vs v2.x 分段）。

本项目按 fscan 源码里 `common/output/writers.go`、`common/output/types.go` 的真实序列化逻辑逐个字段还原，不是猜格式。

## 安装

从 wheel 安装（会自动拉取 `openpyxl` 依赖）：

```bash
pip install dist/fscan_parser-1.0.0-py3-none-any.whl
fscan-parser result.txt
```

从源码安装（开发用）：

```bash
pip install -e .
# 或不安装，直接在项目目录内运行
pip install openpyxl && python -m fscan_parser result.txt
```

重新打包：

```bash
pip install build
python -m build --wheel --no-isolation   # 产物在 dist/
```

Python ≥ 3.9，唯一依赖 `openpyxl`；测试用 `pytest`。

## 使用

```bash
# 单个文件，输出到默认 fscan-report.xlsx
fscan-parser result.txt

# 指定输出
fscan-parser result.txt -o 内网报告.xlsx

# 多文件 / 整个目录（自动识别格式、跨文件去重）
fscan-parser results/ -o report.xlsx --recursive
fscan-parser a.txt b.csv c.json

# 关闭去重、保留原始 Web 汇总段
fscan-parser result.txt --no-dedupe
```

| 参数 | 说明 |
| --- | --- |
| `inputs` | 文件、目录或通配符，可多个 |
| `-o, --output` | 输出 xlsx 路径，默认 `fscan-report.xlsx` |
| `-f, --format` | 强制格式 `txt`/`csv`/`json`，默认 `auto` |
| `--version-spec` | 强制指定 fscan 版本（`1.8.0`/`1.8.3`/`2.0.0`/`2.1` 等），自动识别不准时用 |
| `--no-dedupe` | 关闭跨文件去重 |
| `--keep-web-only` | 保留 TXT 末尾"Web服务"汇总段为独立记录 |
| `-r, --recursive` | 目录递归查找 |
| `-q, --quiet` | 只输出错误 |

作为库调用：

```python
from fscan_parser import parse_file, export_workbook, build_assets

records, stats = parse_file("result.txt")
export_workbook(records, "report.xlsx", stats=stats, source_files=["result.txt"])

for asset in build_assets(records):
    print(asset.host, asset.port_list, asset.highest_severity)
```

## 输出结构

| 工作表 | 内容 |
| --- | --- |
| **概览** | 扫描统计、解析信息、服务/漏洞 TOP、端口与网段分布 |
| **资产视图** | 一台主机一行：开放端口、服务、Web 地址、漏洞数、最高风险等级 |
| **存活主机** | IP、状态、来源文件、行号 |
| **开放端口** | IP、端口、状态 |
| **服务信息** | 服务、版本、HTTP 状态、Server 头、标题、指纹、Banner、产品、OS |
| **Web服务** | 可直接复制的 URL、协议、标题、指纹 |
| **WebTitle** | 旧版 `[*] WebTitle` / `[*] 网站标题` 行：URL、状态码、长度、标题、跳转 |
| **漏洞信息** | 等级（高危/中危）、漏洞名、服务、账号、密码、描述 |
| **未知记录** | 无法归类但保留的原始内容，便于人工复核 |

所有明细表都冻结首行、开启自动筛选，并保留**来源文件 + 行号**，可以随时回到原始记录核对。
漏洞表的等级列按高/中风险着色（红/黄），便于快速定位。

性能参考：3.2 万条记录（5000 主机 / 2 万端口 / 6000 服务 / 1600 漏洞）解析 + 导出约 **4 秒**，输出的 xlsx 约 1.5 MB。

## 解析规则要点

| 场景 | 处理方式 |
| --- | --- |
| TXT 段落标题 | 中英文均识别（`# ===== 存活主机 =====` / `# ===== Alive Hosts =====`），按最长关键词匹配，避免"Web服务"被"服务"抢占 |
| TXT Web 汇总段 | 内容与服务段重复，默认并入服务记录，不重复计数 |
| 服务行 banner | `1.2.3.4:22 ssh SSH-2.0-OpenSSH_7.4` → 服务 `ssh`，版本 `SSH-2.0-OpenSSH 7.4` |
| 弱口令 | `1.2.3.4:80 mysql root/123456` 与旧版 `[+] SSH 1.2.3.4:22:root:123456` 都拆成账号/密码，等级判为高危 |
| 旧版多行输出 | `[+] FCGI ...` + 后续堆栈行合并为一条记录，原文完整保留 |
| 统计行 | `[*] LiveTop ... 段存活数量为: N` 等直接忽略，不产生记录 |
| IPv6 | `[2001:db8::1]:22` 正确拆分 host/port |
| `.realtime.tmp` | fscan 崩溃时的 NDJSON 实时备份，可直接解析 |
| 去重 | 同类型+同主机+同端口+同服务/漏洞名视为重复，多份报告合并时不刷屏 |
| 安全 | 以 `=` `+` `-` `@` 开头的文本会前置单引号，防止 Excel 公式注入 |

## 兼容性说明

fscan 的 `-o` 输出文件里**不写版本号**，只能靠内容特征反推。本项目内置版本识别（`fscan_parser/version.py`），逐版本对照源码模板归纳：

| 版本区间 | 识别特征 | 典型行 |
| --- | --- | --- |
| 1.8.0 – 1.8.2 | 冒号分隔 | `[+] InfoScan:1.2.3.4:80 [Apache]`、`[+] SSH:1.2.3.4:22:root:pwd`、`[*] WebTitle:http://x len:8 code:200` |
| 1.8.3 – 1.8.4 | 空格分隔 + `PocScan` | `[+] InfoScan 1.2.3.4:80 [Apache] 200 Server [fp]`、`[+] PocScan http://x poc-name`、`[*] OsInfo 1.2.3.4 (Win 2008)` |
| 2.0.0 | 全中文 + `[✓]` | `[+] 端口开放 1.2.3.4:22`、`[✓] SMB认证成功 1.2.3.4:445 User:a Pass:b`、`[+] Redis 1.2.3.4:6379 发现未授权访问` |
| 2.1.0+ | 分段标题 | `# ===== 存活主机 =====`、JSON 带 `summary`/`hosts` |

识别结果会写进报告「概览」页（版本区间 / 置信度 / 命中特征）。识别不准时用 `--version-spec` 覆盖，例如：

```bash
fscan-parser result.txt --version-spec 1.8.0
```

各版本的行为差异都已兼容：

- **旧版 `[+] URL poc名 结果名`**（1.8.0–1.8.2 的 WebScan 没有 `PocScan` 标识）靠 `poc-yaml-`、`cve-` 等前缀识别为 POC 漏洞；
- **`[*] WebTitle` 行**不再被误判为漏洞，统一解析为 `WEBTITLE` 类型、单独成表（字段 `len`/`code`/`title` 拆分）；
- **2.0.0 的 `[+] 端口开放 X`** 解析为开放端口，不再变成名为「端口开放」的漏洞；
- **`[✓]` 前缀**已纳入前缀识别，`User:`/`Pass:`/`Domain:` 拆分出账号密码；
- **`InfoScan:` 冒号紧贴目标**的写法不会把冒号吃进主机名。

已知限制：

- CSV 的漏洞段没有账号密码列（fscan 源码把 `Details` 写成 `result.Status`），弱口令只能还原出类型；需要完整凭据请用 TXT 或 JSON。
- 旧版行式没有"存活主机"行，`存活主机` 表可能为空，但「资产视图」仍会按主机聚合。

## 开发

```bash
python -m pytest tests -q
```

```
fscan_parser/
├── models.py        # Record / Target / 风险等级
├── targets.py       # 目标拆解（URL、ip:port、IPv6）
├── version.py       # fscan 版本识别（1.8.0 / 1.8.3 / 2.0.0 / 2.1+）
├── parsers/
│   ├── txt.py       # v2 分段 + 1.8.x/2.0.0 行式
│   └── csvjson.py   # CSV / JSON / NDJSON
├── merge.py         # 去重、Web 段合并、按主机聚合
├── excel.py         # xlsx 渲染
└── cli.py           # 命令行
```

测试夹具 `tests/fixtures/` 里每个版本一份样本（`v180.txt` / `v183.txt` / `v200.txt` / `v210.txt`），
`tests/test_versions.py` 逐版本断言模板解析结果，改解析规则时会立刻发现回归。
