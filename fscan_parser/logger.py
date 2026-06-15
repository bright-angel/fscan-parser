class Logger:
    """线程安全的日志记录器，同时输出到控制台和GUI文本框"""

    def __init__(self, text_widget=None):
        self.text_widget = text_widget

    def log(self, msg: str):
        print(msg)
        if self.text_widget:
            self.text_widget.after(0, self._gui_write, msg)

    def _gui_write(self, msg: str):
        self.text_widget.configure(state="normal")
        self.text_widget.insert("end", msg + "\n")
        self.text_widget.see("end")
        self.text_widget.configure(state="disabled")


logger = Logger()
