"""
Graphical user interface for LLM Injection Detector.

Launch with:
    python gui.py
or, after installation:
    llm-injection-detector-gui
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from llm_injection_detector import LLMInjectionDetector, Label

# Label colour scheme
_LABEL_FG = {
    Label.SAFE:       "#27ae60",
    Label.SUSPICIOUS: "#e67e22",
    Label.INJECTION:  "#c0392b",
}
_LABEL_BAR = {
    Label.SAFE:       "#2ecc71",
    Label.SUSPICIOUS: "#f39c12",
    Label.INJECTION:  "#e74c3c",
}
_LABEL_BG = {
    Label.SAFE:       "#eafaf1",
    Label.SUSPICIOUS: "#fef9e7",
    Label.INJECTION:  "#fdedec",
}


class _ScoreBar(tk.Canvas):
    """Horizontal progress bar that fills left-to-right based on a 0-100 score."""

    def __init__(self, parent, **kw):
        super().__init__(parent, height=18, bg="#ecf0f1",
                         highlightthickness=1, highlightbackground="#bdc3c7", **kw)
        self._score = 0
        self._color = "#bdc3c7"
        self.bind("<Configure>", self._draw)

    def set(self, score: int, color: str):
        self._score = score
        self._color = color
        self._draw()

    def _draw(self, _event=None):
        self.update_idletasks()
        w = self.winfo_width()
        if w <= 1:
            return
        self.delete("all")
        fill_w = int(w * self._score / 100)
        if fill_w > 0:
            self.create_rectangle(0, 0, fill_w, 18, fill=self._color, outline="")


class DetectorApp:
    """Main application window."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("LLM Injection Detector")
        self.root.geometry("820x700")
        self.root.minsize(640, 520)

        self._detector: LLMInjectionDetector = LLMInjectionDetector()
        self._last_results = None

        self._setup_style()
        self._build_header()
        self._build_body()
        self._build_statusbar()

        self.root.bind("<Control-Return>", lambda _e: self._analyze())
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

    # ------------------------------------------------------------------
    # Style
    # ------------------------------------------------------------------

    def _setup_style(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("TLabelframe.Label", font=("Helvetica", 10, "bold"))
        s.configure("Accent.TButton", font=("Helvetica", 10, "bold"))

    # ------------------------------------------------------------------
    # Layout builders
    # ------------------------------------------------------------------

    def _build_header(self):
        bar = tk.Frame(self.root, bg="#2c3e50")
        bar.grid(row=0, column=0, sticky="ew")
        tk.Label(
            bar, text="  LLM Injection Detector",
            bg="#2c3e50", fg="white",
            font=("Helvetica", 14, "bold"),
            pady=8,
        ).pack(side="left")
        tk.Label(
            bar, text="Ctrl+Enter to analyse  ",
            bg="#2c3e50", fg="#95a5a6",
            font=("Helvetica", 9),
        ).pack(side="right")

    def _build_body(self):
        paned = ttk.PanedWindow(self.root, orient="vertical")
        paned.grid(row=1, column=0, sticky="nsew", padx=8, pady=6)

        # ---- Input panel ----
        inp = ttk.LabelFrame(paned, text="Input text", padding=6)
        paned.add(inp, weight=2)
        inp.columnconfigure(0, weight=1)
        inp.rowconfigure(0, weight=1)

        self._text_input = tk.Text(
            inp, wrap="word", height=8,
            font=("Courier", 11), relief="flat",
            bg="#ffffff", fg="#2c3e50",
            insertbackground="#2c3e50",
            padx=4, pady=4,
        )
        inp_scroll = ttk.Scrollbar(inp, orient="vertical",
                                   command=self._text_input.yview)
        self._text_input.configure(yscrollcommand=inp_scroll.set)
        inp_scroll.grid(row=0, column=1, sticky="ns")
        self._text_input.grid(row=0, column=0, sticky="nsew")

        ctrl = ttk.Frame(inp)
        ctrl.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 0))

        ttk.Button(ctrl, text="Analyse", style="Accent.TButton",
                   command=self._analyze).pack(side="left", padx=(0, 4))
        ttk.Button(ctrl, text="Clear",
                   command=self._clear).pack(side="left", padx=4)
        ttk.Button(ctrl, text="Open file…",
                   command=self._open_file).pack(side="left", padx=4)

        ttk.Separator(ctrl, orient="vertical").pack(
            side="left", padx=10, fill="y", pady=2)

        ttk.Label(ctrl, text="Suspicious ≥").pack(side="left")
        self._sus_var = tk.IntVar(value=30)
        ttk.Spinbox(ctrl, from_=5, to=80, width=5,
                    textvariable=self._sus_var,
                    command=self._update_detector).pack(side="left")

        ttk.Label(ctrl, text="  Injection ≥").pack(side="left")
        self._inj_var = tk.IntVar(value=60)
        ttk.Spinbox(ctrl, from_=10, to=99, width=5,
                    textvariable=self._inj_var,
                    command=self._update_detector).pack(side="left")

        # ---- Results panel ----
        res = ttk.LabelFrame(paned, text="Results", padding=6)
        paned.add(res, weight=3)
        res.columnconfigure(0, weight=1)
        res.rowconfigure(1, weight=1)

        # Score / label header
        hdr = ttk.Frame(res)
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 6))

        self._score_lbl = tk.Label(
            hdr, text="—", width=5, anchor="e",
            font=("Helvetica", 36, "bold"), fg="#95a5a6",
        )
        self._score_lbl.pack(side="left", padx=(0, 12))

        score_right = ttk.Frame(hdr)
        score_right.pack(side="left", fill="x", expand=True)

        self._label_lbl = tk.Label(
            score_right, text="", anchor="w",
            font=("Helvetica", 14, "bold"), fg="#95a5a6",
        )
        self._label_lbl.pack(fill="x")

        self._bar = _ScoreBar(score_right)
        self._bar.pack(fill="x", pady=(2, 0))

        # Rules treeview
        tree_frame = ttk.LabelFrame(res, text="Rules triggered", padding=4)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        self._tree = ttk.Treeview(
            tree_frame,
            columns=("category", "weight", "pattern"),
            show="headings",
            height=8,
        )
        self._tree.heading("category", text="Category")
        self._tree.heading("weight",   text="Weight")
        self._tree.heading("pattern",  text="Pattern (truncated)")
        self._tree.column("category", width=180, minwidth=120)
        self._tree.column("weight",   width=70,  minwidth=55, anchor="center")
        self._tree.column("pattern",  width=400, minwidth=200)

        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical",
                                    command=self._tree.yview)
        self._tree.configure(yscrollcommand=tree_scroll.set)
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self._tree.grid(row=0, column=0, sticky="nsew")

        # Export button row
        btn_row = ttk.Frame(res)
        btn_row.grid(row=2, column=0, sticky="ew", pady=(4, 0))
        ttk.Button(btn_row, text="Export JSON…",
                   command=self._export_json).pack(side="right")

    def _build_statusbar(self):
        self._status_var = tk.StringVar(
            value="Ready — enter text above and press Analyse (or Ctrl+Enter).")
        tk.Label(
            self.root, textvariable=self._status_var,
            anchor="w", fg="#7f8c8d",
            font=("Helvetica", 9), pady=3,
        ).grid(row=2, column=0, sticky="ew", padx=8)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _update_detector(self):
        try:
            sus = self._sus_var.get()
            inj = self._inj_var.get()
            if sus < inj:
                self._detector = LLMInjectionDetector(
                    safe_threshold=sus, suspicious_threshold=inj)
        except Exception:
            self._detector = LLMInjectionDetector()

    def _analyze(self):
        text = self._text_input.get("1.0", "end-1c").strip()
        if not text:
            messagebox.showwarning("No input", "Please enter some text to analyse.")
            return
        self._update_detector()
        result = self._detector.detect(text)
        self._last_results = [result]
        self._show_result(result)
        n = len(result.rules_triggered)
        self._status_var.set(
            f"Done — score {result.score}/100 · {result.label.value}"
            f" · {n} rule{'s' if n != 1 else ''} triggered.")

    def _show_result(self, result):
        color = _LABEL_FG.get(result.label, "#95a5a6")
        bar_color = _LABEL_BAR.get(result.label, "#bdc3c7")

        self._score_lbl.configure(text=str(result.score), fg=color)
        self._label_lbl.configure(text=result.label.value, fg=color)
        self._bar.set(result.score, bar_color)

        for row in self._tree.get_children():
            self._tree.delete(row)

        if result.rules_triggered:
            for rule in result.rules_triggered:
                self._tree.insert("", "end", values=(
                    rule.get("category", ""),
                    rule.get("weight", ""),
                    rule.get("pattern", "")[:80],
                ))
        else:
            self._tree.insert("", "end",
                              values=("No rules triggered — text appears safe.", "", ""))

    def _clear(self):
        self._text_input.delete("1.0", "end")
        self._score_lbl.configure(text="—", fg="#95a5a6")
        self._label_lbl.configure(text="", fg="#95a5a6")
        self._bar.set(0, "#bdc3c7")
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._last_results = None
        self._status_var.set(
            "Ready — enter text above and press Analyse (or Ctrl+Enter).")

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="Open text file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                lines = [ln.strip() for ln in fh if ln.strip()]
        except OSError as exc:
            messagebox.showerror("File error", str(exc))
            return
        if not lines:
            messagebox.showinfo("Empty file", "The file contains no text lines.")
            return

        self._update_detector()
        results = self._detector.detect_batch(lines)
        self._last_results = results

        counts = {Label.SAFE: 0, Label.SUSPICIOUS: 0, Label.INJECTION: 0}
        for r in results:
            counts[r.label] += 1

        # Show the highest-severity result in the detail panel
        worst = max(results, key=lambda r: r.score)
        self._show_result(worst)
        self._text_input.delete("1.0", "end")
        preview = "\n".join(lines[:5]) + ("\n…" if len(lines) > 5 else "")
        self._text_input.insert("1.0", preview)

        messagebox.showinfo(
            "Batch results",
            f"Analysed {len(lines)} lines from file:\n\n"
            f"  SAFE:       {counts[Label.SAFE]}\n"
            f"  SUSPICIOUS: {counts[Label.SUSPICIOUS]}\n"
            f"  INJECTION:  {counts[Label.INJECTION]}\n\n"
            f"Showing worst-case result above.",
        )
        self._status_var.set(
            f"Batch: {len(lines)} lines — "
            f"{counts[Label.INJECTION]} injection, "
            f"{counts[Label.SUSPICIOUS]} suspicious, "
            f"{counts[Label.SAFE]} safe.")

    def _export_json(self):
        if not self._last_results:
            messagebox.showinfo("No results", "Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(
            title="Export results",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            data = [r.to_dict() for r in self._last_results]
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            self._status_var.set(f"Exported {len(data)} result(s) to {path}")
        except OSError as exc:
            messagebox.showerror("Export error", str(exc))


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def main():
    root = tk.Tk()
    DetectorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
