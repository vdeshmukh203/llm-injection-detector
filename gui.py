"""
LLM Injection Detector – Graphical User Interface

Launch with:
    python gui.py
    llm-injection-detector-gui   (after pip install)

Requires only the Python standard library (tkinter is included with CPython).
"""

from __future__ import annotations

import json
import sys
import tkinter as tk
from tkinter import filedialog, font, messagebox, scrolledtext, ttk
from typing import List

# ---------------------------------------------------------------------------
# Inline import so the GUI works both from the project root and after install
# ---------------------------------------------------------------------------
try:
    from llm_injection_detector import (
        LLMInjectionDetector,
        DetectionResult,
        Label,
        __version__,
    )
except ImportError:
    import pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).parent))
    from llm_injection_detector import (
        LLMInjectionDetector,
        DetectionResult,
        Label,
        __version__,
    )


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
_PALETTE = {
    "bg": "#1e1e2e",          # dark background
    "surface": "#2a2a3e",     # card / panel
    "border": "#3d3d5c",
    "text": "#cdd6f4",
    "muted": "#7f849c",
    "green": "#a6e3a1",       # SAFE
    "yellow": "#f9e2af",      # SUSPICIOUS
    "red": "#f38ba8",         # INJECTION
    "accent": "#89b4fa",
    "button_bg": "#313244",
    "button_fg": "#cdd6f4",
    "input_bg": "#181825",
}

_LABEL_COLOUR = {
    Label.SAFE: _PALETTE["green"],
    Label.SUSPICIOUS: _PALETTE["yellow"],
    Label.INJECTION: _PALETTE["red"],
}

_LABEL_EMOJI = {
    Label.SAFE: "SAFE",
    Label.SUSPICIOUS: "SUSPICIOUS",
    Label.INJECTION: "INJECTION",
}


# ---------------------------------------------------------------------------
# Helper widgets
# ---------------------------------------------------------------------------

class ScoreBar(tk.Canvas):
    """Colour-coded progress bar that visualises the 0–100 score."""

    _HEIGHT = 22

    def __init__(self, parent: tk.Widget, **kwargs) -> None:
        super().__init__(
            parent,
            height=self._HEIGHT,
            bg=_PALETTE["surface"],
            highlightthickness=0,
            **kwargs,
        )
        self._score = 0
        self._colour = _PALETTE["green"]
        self.bind("<Configure>", lambda _: self._redraw())

    def set(self, score: int, label: Label) -> None:
        self._score = max(0, min(100, score))
        self._colour = _LABEL_COLOUR[label]
        self._redraw()

    def _redraw(self) -> None:
        self.delete("all")
        w = self.winfo_width() or 300
        h = self._HEIGHT
        # Background track
        self.create_rectangle(0, 0, w, h, fill=_PALETTE["border"], outline="")
        # Filled portion
        filled = int(w * self._score / 100)
        if filled > 0:
            self.create_rectangle(0, 0, filled, h, fill=self._colour, outline="")
        # Score text centred on bar
        self.create_text(
            w // 2, h // 2,
            text=f"{self._score}/100",
            fill=_PALETTE["bg"],
            font=("Segoe UI", 9, "bold"),
        )


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"LLM Injection Detector  v{__version__}")
        self.configure(bg=_PALETTE["bg"])
        self.minsize(760, 560)
        self.resizable(True, True)

        self._detector = LLMInjectionDetector()
        self._last_results: List[DetectionResult] = []

        self._build_fonts()
        self._build_menu()
        self._build_ui()

        # Trigger analysis on any keypress after a short idle delay
        self._after_id: str | None = None
        self._input_var.trace_add("write", self._on_text_change)

    # ------------------------------------------------------------------
    # Font setup
    # ------------------------------------------------------------------
    def _build_fonts(self) -> None:
        self.f_mono = font.Font(family="Courier New", size=10)
        self.f_label = font.Font(family="Segoe UI", size=11, weight="bold")
        self.f_small = font.Font(family="Segoe UI", size=9)
        self.f_score = font.Font(family="Segoe UI", size=28, weight="bold")
        self.f_heading = font.Font(family="Segoe UI", size=10, weight="bold")

    # ------------------------------------------------------------------
    # Menu bar
    # ------------------------------------------------------------------
    def _build_menu(self) -> None:
        menubar = tk.Menu(self, bg=_PALETTE["surface"], fg=_PALETTE["text"],
                          activebackground=_PALETTE["accent"],
                          activeforeground=_PALETTE["bg"])

        file_menu = tk.Menu(menubar, tearoff=False,
                            bg=_PALETTE["surface"], fg=_PALETTE["text"])
        file_menu.add_command(label="Open file…", command=self._open_file,
                              accelerator="Ctrl+O")
        file_menu.add_command(label="Export JSON…", command=self._export_json,
                              accelerator="Ctrl+S")
        file_menu.add_separator()
        file_menu.add_command(label="Quit", command=self.quit,
                              accelerator="Ctrl+Q")
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=False,
                            bg=_PALETTE["surface"], fg=_PALETTE["text"])
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)
        self.bind("<Control-o>", lambda _: self._open_file())
        self.bind("<Control-s>", lambda _: self._export_json())
        self.bind("<Control-q>", lambda _: self.quit())

    # ------------------------------------------------------------------
    # Main layout
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Configure ttk styles for dark theme
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background=_PALETTE["bg"],
                         borderwidth=0)
        style.configure("TNotebook.Tab", background=_PALETTE["button_bg"],
                         foreground=_PALETTE["text"], padding=[12, 4])
        style.map("TNotebook.Tab",
                  background=[("selected", _PALETTE["accent"])],
                  foreground=[("selected", _PALETTE["bg"])])

        # Tab 1 – single-text analysis
        single_frame = tk.Frame(notebook, bg=_PALETTE["bg"])
        notebook.add(single_frame, text="  Analyse  ")
        self._build_single_tab(single_frame)

        # Tab 2 – batch analysis
        batch_frame = tk.Frame(notebook, bg=_PALETTE["bg"])
        notebook.add(batch_frame, text="  Batch  ")
        self._build_batch_tab(batch_frame)

        # Tab 3 – settings
        settings_frame = tk.Frame(notebook, bg=_PALETTE["bg"])
        notebook.add(settings_frame, text="  Settings  ")
        self._build_settings_tab(settings_frame)

    # ------------------------------------------------------------------
    # Tab 1: Single-text analysis
    # ------------------------------------------------------------------
    def _build_single_tab(self, parent: tk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)

        # ---- Input panel ----
        in_frame = self._card(parent, "Input text", row=0, sticky="ew")
        in_frame.columnconfigure(0, weight=1)

        self._input_var = tk.StringVar()
        self._input_text = scrolledtext.ScrolledText(
            in_frame,
            height=7,
            wrap=tk.WORD,
            font=self.f_mono,
            bg=_PALETTE["input_bg"],
            fg=_PALETTE["text"],
            insertbackground=_PALETTE["text"],
            relief=tk.FLAT,
            borderwidth=4,
        )
        self._input_text.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        # Sync ScrolledText content to StringVar via trace
        self._input_text.bind("<KeyRelease>", self._sync_input_var)

        btn_row = tk.Frame(in_frame, bg=_PALETTE["surface"])
        btn_row.grid(row=1, column=0, sticky="e", padx=4, pady=(0, 4))
        self._btn(btn_row, "Clear", self._clear_input).pack(side=tk.RIGHT, padx=4)
        self._btn(btn_row, "Analyse", self._run_single).pack(side=tk.RIGHT, padx=4)

        # ---- Results panel ----
        res_frame = self._card(parent, "Result", row=1, sticky="nsew")
        res_frame.columnconfigure(1, weight=1)

        # Score number
        self._score_label = tk.Label(
            res_frame, text="—", font=self.f_score,
            bg=_PALETTE["surface"], fg=_PALETTE["muted"],
        )
        self._score_label.grid(row=0, column=0, rowspan=2, padx=16, pady=8)

        # Label + bar
        right = tk.Frame(res_frame, bg=_PALETTE["surface"])
        right.grid(row=0, column=1, sticky="ew", padx=(0, 12), pady=(8, 0))
        right.columnconfigure(0, weight=1)

        self._label_var = tk.StringVar(value="—")
        lbl = tk.Label(right, textvariable=self._label_var,
                       font=self.f_label, bg=_PALETTE["surface"],
                       fg=_PALETTE["muted"])
        lbl.grid(row=0, column=0, sticky="w")
        self._label_widget = lbl

        self._bar = ScoreBar(right)
        self._bar.grid(row=1, column=0, sticky="ew", pady=(4, 0))

        # Timestamp
        self._ts_var = tk.StringVar(value="")
        tk.Label(res_frame, textvariable=self._ts_var,
                 font=self.f_small, bg=_PALETTE["surface"],
                 fg=_PALETTE["muted"]).grid(row=1, column=1, sticky="w",
                                            padx=(0, 12), pady=(2, 8))

        # ---- Rules panel ----
        rules_frame = self._card(parent, "Rules triggered", row=2, sticky="nsew")
        parent.rowconfigure(2, weight=2)
        rules_frame.columnconfigure(0, weight=1)
        rules_frame.rowconfigure(0, weight=1)

        cols = ("category", "weight", "pattern")
        self._tree = ttk.Treeview(
            rules_frame, columns=cols, show="headings",
            selectmode="browse", height=8,
        )
        style = ttk.Style()
        style.configure("Treeview",
                         background=_PALETTE["input_bg"],
                         foreground=_PALETTE["text"],
                         fieldbackground=_PALETTE["input_bg"],
                         rowheight=22)
        style.configure("Treeview.Heading",
                         background=_PALETTE["button_bg"],
                         foreground=_PALETTE["accent"],
                         relief="flat")
        style.map("Treeview", background=[("selected", _PALETTE["accent"])],
                  foreground=[("selected", _PALETTE["bg"])])

        self._tree.heading("category", text="Category")
        self._tree.heading("weight",   text="Weight")
        self._tree.heading("pattern",  text="Pattern (truncated)")
        self._tree.column("category", width=160, anchor="w")
        self._tree.column("weight",   width=55,  anchor="center")
        self._tree.column("pattern",  width=380, anchor="w")

        vsb = ttk.Scrollbar(rules_frame, orient="vertical",
                            command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew", padx=(4, 0), pady=4)
        vsb.grid(row=0, column=1, sticky="ns", pady=4)

    # ------------------------------------------------------------------
    # Tab 2: Batch analysis
    # ------------------------------------------------------------------
    def _build_batch_tab(self, parent: tk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)

        in_frame = self._card(parent, "Input (one prompt per line)", row=0, sticky="ew")
        in_frame.columnconfigure(0, weight=1)

        self._batch_input = scrolledtext.ScrolledText(
            in_frame, height=6, wrap=tk.WORD, font=self.f_mono,
            bg=_PALETTE["input_bg"], fg=_PALETTE["text"],
            insertbackground=_PALETTE["text"], relief=tk.FLAT, borderwidth=4,
        )
        self._batch_input.grid(row=0, column=0, sticky="ew", padx=4, pady=4)

        btn_row = tk.Frame(in_frame, bg=_PALETTE["surface"])
        btn_row.grid(row=1, column=0, sticky="e", padx=4, pady=(0, 4))
        self._btn(btn_row, "Export JSON", self._batch_export).pack(side=tk.RIGHT, padx=4)
        self._btn(btn_row, "Analyse all", self._run_batch).pack(side=tk.RIGHT, padx=4)

        res_frame = self._card(parent, "Results", row=1, sticky="nsew")
        res_frame.columnconfigure(0, weight=1)
        res_frame.rowconfigure(0, weight=1)

        cols = ("text", "score", "label", "rules")
        self._batch_tree = ttk.Treeview(
            res_frame, columns=cols, show="headings", height=12,
        )
        self._batch_tree.heading("text",  text="Text (truncated)")
        self._batch_tree.heading("score", text="Score")
        self._batch_tree.heading("label", text="Label")
        self._batch_tree.heading("rules", text="# Rules")
        self._batch_tree.column("text",  width=380, anchor="w")
        self._batch_tree.column("score", width=55,  anchor="center")
        self._batch_tree.column("label", width=100, anchor="center")
        self._batch_tree.column("rules", width=60,  anchor="center")

        vsb2 = ttk.Scrollbar(res_frame, orient="vertical",
                              command=self._batch_tree.yview)
        self._batch_tree.configure(yscrollcommand=vsb2.set)
        self._batch_tree.grid(row=0, column=0, sticky="nsew", padx=(4, 0), pady=4)
        vsb2.grid(row=0, column=1, sticky="ns", pady=4)

        # Tag colours
        self._batch_tree.tag_configure("SAFE",       foreground=_PALETTE["green"])
        self._batch_tree.tag_configure("SUSPICIOUS", foreground=_PALETTE["yellow"])
        self._batch_tree.tag_configure("INJECTION",  foreground=_PALETTE["red"])

    # ------------------------------------------------------------------
    # Tab 3: Settings
    # ------------------------------------------------------------------
    def _build_settings_tab(self, parent: tk.Frame) -> None:
        frame = self._card(parent, "Detection thresholds", row=0, sticky="nsew")
        frame.columnconfigure(1, weight=1)

        def _row(label: str, row: int, default: int, lo: int = 0, hi: int = 100):
            tk.Label(frame, text=label, bg=_PALETTE["surface"],
                     fg=_PALETTE["text"], font=self.f_small
                     ).grid(row=row, column=0, sticky="w", padx=8, pady=6)
            var = tk.IntVar(value=default)
            scale = tk.Scale(frame, from_=lo, to=hi, orient=tk.HORIZONTAL,
                             variable=var, bg=_PALETTE["surface"],
                             fg=_PALETTE["text"],
                             troughcolor=_PALETTE["border"],
                             highlightthickness=0,
                             activebackground=_PALETTE["accent"])
            scale.grid(row=row, column=1, sticky="ew", padx=8, pady=6)
            return var

        self._suspicious_var = _row(
            "Suspicious threshold (score ≥ X → SUSPICIOUS)",
            row=0,
            default=LLMInjectionDetector.DEFAULT_SUSPICIOUS_THRESHOLD,
        )
        self._injection_var = _row(
            "Injection threshold  (score ≥ X → INJECTION)",
            row=1,
            default=LLMInjectionDetector.DEFAULT_INJECTION_THRESHOLD,
        )

        self._btn(frame, "Apply", self._apply_settings).grid(
            row=2, column=1, sticky="e", padx=8, pady=8,
        )

        # Info
        info = (
            "Scores are computed with a logarithmic saturation curve.\n"
            "A single strong signal scores ~46; two together score ~63."
        )
        tk.Label(frame, text=info, bg=_PALETTE["surface"],
                 fg=_PALETTE["muted"], font=self.f_small,
                 justify=tk.LEFT
                 ).grid(row=3, column=0, columnspan=2, sticky="w",
                        padx=8, pady=(0, 8))

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _sync_input_var(self, _event=None) -> None:
        self._input_var.set(self._input_text.get("1.0", tk.END))

    def _on_text_change(self, *_) -> None:
        if self._after_id:
            self.after_cancel(self._after_id)
        self._after_id = self.after(350, self._run_single)

    def _run_single(self, _event=None) -> None:
        text = self._input_text.get("1.0", tk.END).strip()
        if not text:
            self._reset_result()
            return
        result = self._detector.detect(text)
        self._last_results = [result]
        self._show_result(result)

    def _show_result(self, result: DetectionResult) -> None:
        colour = _LABEL_COLOUR[result.label]
        self._score_label.config(text=str(result.score), fg=colour)
        self._label_var.set(_LABEL_EMOJI[result.label])
        self._label_widget.config(fg=colour)
        self._bar.set(result.score, result.label)
        self._ts_var.set(result.timestamp)

        for row in self._tree.get_children():
            self._tree.delete(row)
        for rule in result.rules_triggered:
            self._tree.insert("", tk.END, values=(
                rule["category"],
                rule["weight"],
                rule["pattern"],
            ))

    def _reset_result(self) -> None:
        self._score_label.config(text="—", fg=_PALETTE["muted"])
        self._label_var.set("—")
        self._label_widget.config(fg=_PALETTE["muted"])
        self._bar.set(0, Label.SAFE)
        self._ts_var.set("")
        for row in self._tree.get_children():
            self._tree.delete(row)

    def _clear_input(self) -> None:
        self._input_text.delete("1.0", tk.END)
        self._reset_result()

    def _run_batch(self) -> None:
        raw = self._batch_input.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showinfo("No input", "Enter at least one line to analyse.")
            return
        lines = [l for l in raw.splitlines() if l.strip()]
        results = self._detector.detect_batch(lines)
        self._last_results = results

        for row in self._batch_tree.get_children():
            self._batch_tree.delete(row)
        for r in results:
            self._batch_tree.insert(
                "", tk.END,
                values=(r.text[:60], r.score, r.label.value, len(r.rules_triggered)),
                tags=(r.label.value,),
            )

    def _apply_settings(self) -> None:
        st = self._suspicious_var.get()
        it = self._injection_var.get()
        if st >= it:
            messagebox.showerror(
                "Invalid thresholds",
                "Suspicious threshold must be less than injection threshold.",
            )
            return
        self._detector = LLMInjectionDetector(
            suspicious_threshold=st,
            injection_threshold=it,
        )
        messagebox.showinfo("Applied",
                            f"Thresholds updated:\n"
                            f"  SUSPICIOUS ≥ {st}\n"
                            f"  INJECTION  ≥ {it}")

    def _open_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Open text file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            try:
                with open(path, encoding="utf-8") as fh:
                    content = fh.read()
                self._input_text.delete("1.0", tk.END)
                self._input_text.insert("1.0", content)
                self._sync_input_var()
            except OSError as exc:
                messagebox.showerror("Error", str(exc))

    def _export_json(self) -> None:
        if not self._last_results:
            messagebox.showinfo("Nothing to export", "Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
        )
        if path:
            data = [r.to_dict() for r in self._last_results]
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2)
                messagebox.showinfo("Exported", f"Results saved to:\n{path}")
            except OSError as exc:
                messagebox.showerror("Error", str(exc))

    def _show_about(self) -> None:
        messagebox.showinfo(
            "About",
            f"LLM Injection Detector  v{__version__}\n\n"
            "Static and heuristic prompt injection detector.\n"
            "Detects 11 attack categories with 40+ patterns.\n\n"
            "Author: Vaibhav Deshmukh\n"
            "License: MIT",
        )

    # ------------------------------------------------------------------
    # Widget factories
    # ------------------------------------------------------------------
    def _card(self, parent: tk.Widget, title: str, row: int,
              sticky: str = "ew") -> tk.Frame:
        """Return a labelled frame with consistent styling."""
        lf = tk.LabelFrame(
            parent,
            text=f"  {title}  ",
            font=self.f_heading,
            bg=_PALETTE["surface"],
            fg=_PALETTE["accent"],
            bd=1,
            relief=tk.SOLID,
            labelanchor="nw",
        )
        lf.grid(row=row, column=0, sticky=sticky, padx=6, pady=4)
        lf.columnconfigure(0, weight=1)
        return lf

    def _btn(self, parent: tk.Widget, text: str, command) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=_PALETTE["button_bg"],
            fg=_PALETTE["button_fg"],
            activebackground=_PALETTE["accent"],
            activeforeground=_PALETTE["bg"],
            relief=tk.FLAT,
            padx=12,
            pady=4,
            cursor="hand2",
            font=self.f_small,
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
