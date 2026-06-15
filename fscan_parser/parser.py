import os
import re

from .logger import logger

# 端口扫描匹配
PORT_PATTERN = re.compile(r'^(\d+\.\d+\.\d+\.\d+):(\d+)\s+open$')
# WebTitle匹配
TITLE_PATTERN = re.compile(
    r'\[\*\]\s+WebTitle\s+(https?://\S+)\s+code:(\d+)\s+len:(\d+)\s+title:(.*?)(\s+跳转url:\s+\S+)?$'
)
# PocScan匹配
POC_PATTERN = re.compile(r'\[\+\]\s+PocScan\s+(https?://\S+)\s+(.*)$')
# URL提取IP正则
IP_FROM_URL_PATTERN = re.compile(r'https?://(\d+\.\d+\.\d+\.\d+):?\d*')


def extract_ip_from_url(url: str) -> str:
    try:
        match = IP_FROM_URL_PATTERN.search(url)
        if match:
            return match.group(1)
        return ""
    except Exception:
        return ""


def parse_fscan_file(file_path: str):
    """解析单个fscan结果文件，返回 (port_data, title_data, poc_data)"""
    file_name = os.path.basename(file_path)
    port_data, title_data, poc_data = [], [], []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            logger.log(f"[INFO] 正在解析: {file_name}")

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                pm = PORT_PATTERN.match(line)
                if pm:
                    ip, port = pm.groups()
                    port_data.append([file_name, ip, port])
                    continue

                tm = TITLE_PATTERN.search(line)
                if tm:
                    url, code, length, title, redirect = tm.groups()
                    redirect = redirect.strip() if redirect else ""
                    title_data.append([file_name, url, code, length, title, redirect])
                    continue

                pocm = POC_PATTERN.search(line)
                if pocm:
                    url, info = pocm.groups()
                    poc_data.append([file_name, url, info])
                    continue

        logger.log(f"[SUCC] {file_name} | 端口:{len(port_data)} Web:{len(title_data)} Poc:{len(poc_data)}")

    except Exception as e:
        logger.log(f"[ERR] {file_name} 解析异常: {str(e)}")

    return port_data, title_data, poc_data


def parse_fscan_files(path: str):
    """批量解析fscan结果（单个文件或目录），返回汇总数据"""
    all_port, all_title, all_poc = [], [], []
    file_cnt = 0

    logger.log("=" * 58)
    logger.log("[START] 开始批量解析Fscan扫描结果")
    logger.log("=" * 58)

    if os.path.isfile(path):
        file_cnt = 1
        p, t, pc = parse_fscan_file(path)
        all_port.extend(p)
        all_title.extend(t)
        all_poc.extend(pc)
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for fname in files:
                fullpath = os.path.join(root, fname)
                p, t, pc = parse_fscan_file(fullpath)
                all_port.extend(p)
                all_title.extend(t)
                all_poc.extend(pc)
                file_cnt += 1
    else:
        logger.log(f"[ERR] 输入路径不存在：{path}")

    logger.log("=" * 58)
    logger.log(f"[FINISH] 全部解析完成 | 共扫描文件：{file_cnt}")
    logger.log(f"[统计] 开放端口：{len(all_port)} | Web站点：{len(all_title)} | Poc漏洞：{len(all_poc)}")
    logger.log("=" * 58)

    return all_port, all_title, all_poc
