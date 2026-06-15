"""GUI图形界面模式 — 基于customtkinter美化"""
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox

try:
    from .parser import parse_fscan_files
    from .excel import save_excel
    from .logger import Logger
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from fscan_parser.parser import parse_fscan_files
    from fscan_parser.excel import save_excel
    from fscan_parser.logger import Logger

logger = Logger()

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class FscanParserGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Fscan 扫描结果解析工具")
        self.geometry("780x660")
        self.resizable(False, False)

        self._build_ui()

    # ---------- UI构建 ----------
    def _build_ui(self):
        # 顶部标题
        ctk.CTkLabel(
            self, text="Fscan 批量解析工具",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).pack(pady=(18, 12))

        # 输入区域
        self._build_input_section()

        # 输出区域
        self._build_output_section()

        # 开始按钮
        self.btn_start = ctk.CTkButton(
            self, text="开始解析导出", width=200, height=42,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._thread_run,
        )
        self.btn_start.pack(pady=(12, 12))

        # 进度条
        self.progress = ctk.CTkProgressBar(self, width=500)
        self.progress.pack(pady=(0, 8))
        self.progress.set(0)

        # 日志区域
        self._build_log_section()

    def _build_input_section(self):
        frm = ctk.CTkFrame(self)
        frm.pack(fill="x", padx=28, pady=(0, 10))

        ctk.CTkLabel(
            frm, text="输入（txt文件 / 文件夹）",
            font=ctk.CTkFont(size=13),
        ).pack(anchor="w", padx=14, pady=(10, 4))

        row = ctk.CTkFrame(frm, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(0, 10))

        self.var_in = ctk.StringVar()
        ctk.CTkEntry(row, textvariable=self.var_in, width=420).pack(side="left", padx=(0, 8))
        ctk.CTkButton(row, text="选文件", width=80,
                       command=lambda: self._pick_file()).pack(side="left", padx=3)
        ctk.CTkButton(row, text="选目录", width=80,
                       command=lambda: self._pick_dir()).pack(side="left", padx=3)

    def _build_output_section(self):
        frm = ctk.CTkFrame(self)
        frm.pack(fill="x", padx=28, pady=(0, 10))

        ctk.CTkLabel(
            frm, text="输出（Excel保存位置）",
            font=ctk.CTkFont(size=13),
        ).pack(anchor="w", padx=14, pady=(10, 4))

        row = ctk.CTkFrame(frm, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(0, 10))

        self.var_out = ctk.StringVar()
        ctk.CTkEntry(row, textvariable=self.var_out, width=420).pack(side="left", padx=(0, 8))
        ctk.CTkButton(row, text="保存路径", width=80,
                       command=lambda: self._pick_save()).pack(side="left", padx=3)

    def _build_log_section(self):
        frm = ctk.CTkFrame(self)
        frm.pack(fill="both", expand=True, padx=28, pady=(0, 18))

        ctk.CTkLabel(
            frm, text="运行日志",
            font=ctk.CTkFont(size=13),
        ).pack(anchor="w", padx=14, pady=(10, 4))

        self.log_text = ctk.CTkTextbox(frm, font=ctk.CTkFont(family="Consolas", size=11))
        self.log_text.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        logger.text_widget = self.log_text

    # ---------- 文件选取 ----------
    def _pick_file(self):
        path = filedialog.askopenfilename(filetypes=[("文本文件", "*.txt")])
        if path:
            self.var_in.set(path)

    def _pick_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.var_in.set(path)

    def _pick_save(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel文件", "*.xlsx")],
        )
        if path:
            self.var_out.set(path)

    # ---------- 后台任务 ----------
    def _thread_run(self):
        in_path = self.var_in.get().strip()
        out_path = self.var_out.get().strip()

        if not in_path or not out_path:
            messagebox.showerror("错误", "请先指定输入和输出路径！")
            return

        self.btn_start.configure(state="disabled", text="解析运行中...")
        self.progress.set(0.3)

        def task():
            self._clear_log()
            data_port, data_web, data_poc = parse_fscan_files(in_path)
            self.progress.set(0.7)
            ok = save_excel(data_port, data_web, data_poc, out_path)
            self.progress.set(1.0)
            self.after(0, lambda: self._on_done(ok))

        threading.Thread(target=task, daemon=True).start()

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _on_done(self, ok: bool):
        if ok:
            messagebox.showinfo("完成", "解析结束，Excel已生成！\n已自动为无IP列的Sheet补充IP列")
        else:
            messagebox.showerror("失败", "文件生成异常，请检查权限！")
        self.btn_start.configure(state="normal", text="开始解析导出")


def main():
    app = FscanParserGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
