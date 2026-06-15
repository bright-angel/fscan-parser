# Fscan Parser

Fscan 扫描结果解析工具，将 fscan 输出解析为结构化的三 Sheet Excel 文件，自动为 WebTitle 和 PocScan 补充 IP 列。

## 安装

```bash
pip install .
```

或使用 pipx 全局安装：

```bash
pipx install .
```

## 使用方式

### CLI 命令行

```bash
# pip 安装后
fscan-parser -i result.txt -o output.xlsx
fscan-parser -i ./scan_results/ -o output.xlsx

# 或直接运行
python -m fscan_parser.cli -i result.txt -o output.xlsx
python fscan_parser/cli.py -i result.txt -o output.xlsx
```

### GUI 图形界面

```bash
# pip 安装后
fscan-parser-gui

# 或直接运行
python -m fscan_parser
```

### PyInstaller 打包

```bash
# CLI 版本
pyinstaller --onefile run_cli.py

# GUI 版本（无控制台窗口）
pyinstaller --onefile --windowed run_gui.py
```

## 输出说明

生成的 Excel 包含三个 Sheet：

| Sheet | 内容 |
|-------|------|
| PortScan | 文件名、IP地址、开放端口 |
| WebTitle | 文件名、IP地址（自动提取）、URL、状态码、响应长度、站点标题、跳转URL |
| PocScan | 文件名、IP地址（自动提取）、URL、漏洞/POC详情 |

## 依赖

- Python >= 3.8
- openpyxl >= 3.0
- customtkinter >= 5.2
