import openpyxl

from .logger import logger
from .parser import extract_ip_from_url


def save_excel(port_list: list, title_list: list, poc_list: list, out_file: str) -> bool:
    """生成三Sheet Excel，自动为WebTitle和PocScan补充IP列"""
    try:
        wb = openpyxl.Workbook()
        wb.remove(wb.active)

        sheet_configs = [
            {
                "name": "PortScan",
                "base_headers": ["文件名", "IP地址", "开放端口"],
                "raw_data": port_list,
                "ip_col_index": None,
            },
            {
                "name": "WebTitle",
                "base_headers": ["文件名", "URL", "状态码", "响应长度", "站点标题", "跳转URL"],
                "raw_data": title_list,
                "ip_col_index": 1,
            },
            {
                "name": "PocScan",
                "base_headers": ["文件名", "URL", "漏洞/POC详情"],
                "raw_data": poc_list,
                "ip_col_index": 1,
            },
        ]

        for config in sheet_configs:
            sheet_name = config["name"]
            base_headers = config["base_headers"].copy()
            raw_data = config["raw_data"]
            ip_col_index = config["ip_col_index"]

            final_headers = base_headers
            final_data = raw_data

            if ip_col_index is not None and "IP地址" not in base_headers:
                final_headers.insert(1, "IP地址")
                final_data = []
                for row in raw_data:
                    new_row = row.copy()
                    source_url = row[ip_col_index] if len(row) > ip_col_index else ""
                    ip = extract_ip_from_url(source_url)
                    new_row.insert(1, ip)
                    final_data.append(new_row)
                logger.log(f"[INFO] {sheet_name} 已自动补充IP列")

            ws = wb.create_sheet(sheet_name)
            ws.append(final_headers)
            for row in final_data:
                ws.append(row)

            for col in ws.columns:
                max_w = max(len(str(cell.value or "")) for cell in col)
                col_let = openpyxl.utils.get_column_letter(col[0].column)
                ws.column_dimensions[col_let].width = min(max_w + 3, 65)

        wb.save(out_file)
        logger.log(f"[SAVE] Excel结果已保存至：{out_file}\n")
        return True
    except Exception as e:
        logger.log(f"[ERR] Excel保存失败：{str(e)}")
        return False
