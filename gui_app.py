"""
LLM Injection Detector – Graphical User Interface

Provides a Tkinter desktop application for interactive detection of prompt
injection attacks.  Requires only the Python standard library (tkinter is
bundled with CPython).

Entry point::

    python gui_app.py
    # or, after installation:
    llm-injection-detector-gui
"""

import json
import sys
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    _TKINTER_AVAILABLE = True
except ImportError:
    _TKINTER_AVAILABLE = False

try:
    import llm_injection_detector as lid
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent))
    import llm_injection_detector as lid


# ---------------------------------------------------------------------------
# Colour scheme
# ---------------------------------------------------------------------------

COLOURS = {
    "bg": "#1e1e2e",
    "surface": "#2a2a3e",
    "border": "#3a3a5e",
    "text": "#cdd6f4",
    "subtext": "#a6adc8",
    "safe": "#a6e3a1",
    "suspicious": "#f9e2af",
    "injection": "#f38ba8",
    "safe_bg": "#1e3a2e",
    "suspicious_bg": "#3a3000",
    "injection_bg": "#3a0000",
    "button": "#89b4fa",
    "button_text": "#1e1e2e",
    "accent": "#cba6f7",
}

LABEL_COLOURS = {
    "SAFE": (COLOURS["safe"], COLOURS["safe_bg"]),
    "SUSPICIOUS": (COLOURS["suspicious"], COLOURS["suspicious_bg"]),
    "INJECTION": (COLOURS["injection"], COLOURS["injection_bg"]),
}


if _TKINTER_AVAILABLE:
    _TkBase = tk.Tk
else:
    _TkBase = object


class DetectorApp(_TkBase):
    """Main application window for the LLM Injection Detector GUI."""

    def __init__(self):
        super().__init__()
        self.title("LLM Injection Detector")
        self.geometry("900x700")
        self.minsize(700, 550)
        self.configure(bg=COLOURS["bg"])

        self._detector = lid.LLMInjectionDetector()
        self._results: list = []

        self._build_menu()
        self._build_ui()
        self._apply_styles()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_menu(self):
        menu = tk.Menu(self, bg=COLOURS["surface"], fg=COLOURS["text"],
                       activebackground=COLOURS["accent"],
                       activeforeground=COLOURS["button_text"],
                       relief="flat")
        self.config(menu=menu)

        file_menu = tk.Menu(menu, tearoff=0, bg=COLOURS["surface"],
                            fg=COLOURS["text"],
                            activebackground=COLOURS["accent"],
                            activeforeground=COLOURS["button_text"])
        file_menu.add_command(label="Open File…", command=self._open_file,
                              accelerator="Ctrl+O")
        file_menu.add_command(label="Save Results…", command=self._save_results,
                              accelerator="Ctrl+S")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menu.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menu, tearoff=0, bg=COLOURS["surface"],
                            fg=COLOURS["text"],
                            activebackground=COLOURS["accent"],
                            activeforeground=COLOURS["button_text"])
        help_menu.add_command(label="About", command=self._show_about)
        menu.add_cascade(label="Help", menu=help_menu)

        self.bind_all("<Control-o>", lambda _e: self._open_file())
        self.bind_all("<Control-s>", lambda _e: self._save_results())

    def _build_ui(self):
        # ---- top: input ----
        input_frame = tk.Frame(self, bg=COLOURS["bg"])
        input_frame.pack(fill="both", expand=True, padx=12, pady=(12, 0))

        tk.Label(input_frame, text="Input Text", bg=COLOURS["bg"],
                 fg=COLOURS["accent"], font=("Segoe UI", 10, "bold")
                 ).pack(anchor="w")

        self._input_text = tk.Text(
            input_frame,
            height=8,
            wrap="word",
            bg=COLOURS["surface"],
            fg=COLOURS["text"],
            insertbackground=COLOURS["text"],
            relief="flat",
            font=("Consolas", 11),
            padx=8, pady=8,
        )
        self._input_text.pack(fill="both", expand=True, pady=(4, 0))

        sb = tk.Scrollbar(input_frame, command=self._input_text.yview,
                          bg=COLOURS["border"], troughcolor=COLOURS["surface"])
        sb.pack(side="right", fill="y")
        self._input_text.config(yscrollcommand=sb.set)

        # ---- middle: controls ----
        ctrl_frame = tk.Frame(self, bg=COLOURS["bg"])
        ctrl_frame.pack(fill="x", padx=12, pady=8)

        btn_analyse = tk.Button(
            ctrl_frame,
            text="Analyse  (Ctrl+Return)",
            command=self._analyse,
            bg=COLOURS["button"],
            fg=COLOURS["button_text"],
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padx=14, pady=6,
            cursor="hand2",
        )
        btn_analyse.pack(side="left")

        btn_clear = tk.Button(
            ctrl_frame,
            text="Clear",
            command=self._clear,
            bg=COLOURS["surface"],
            fg=COLOURS["text"],
            relief="flat",
            font=("Segoe UI", 10),
            padx=14, pady=6,
            cursor="hand2",
        )
        btn_clear.pack(side="left", padx=(8, 0))

        btn_file = tk.Button(
            ctrl_frame,
            text="Open File…",
            command=self._open_file,
            bg=COLOURS["surface"],
            fg=COLOURS["text"],
            relief="flat",
            font=("Segoe UI", 10),
            padx=14, pady=6,
            cursor="hand2",
        )
        btn_file.pack(side="left", padx=(8, 0))

        # Threshold sliders
        thresh_frame = tk.Frame(ctrl_frame, bg=COLOURS["bg"])
        thresh_frame.pack(side="right")

        self._safe_thresh_var = tk.IntVar(value=20)
        self._inj_thresh_var = tk.IntVar(value=50)

        self._add_slider(thresh_frame, "Safe ≤", self._safe_thresh_var, 0, 49, 0)
        self._add_slider(thresh_frame, "Inject ≥", self._inj_thresh_var, 10, 100, 1)

        self.bind_all("<Control-Return>", lambda _e: self._analyse())

        # ---- bottom: results ----
        results_outer = tk.Frame(self, bg=COLOURS["bg"])
        results_outer.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        tk.Label(results_outer, text="Results", bg=COLOURS["bg"],
                 fg=COLOURS["accent"], font=("Segoe UI", 10, "bold")
                 ).pack(anchor="w")

        results_frame = tk.Frame(results_outer, bg=COLOURS["surface"],
                                 relief="flat")
        results_frame.pack(fill="both", expand=True, pady=(4, 0))

        # Score / label summary row
        summary = tk.Frame(results_frame, bg=COLOURS["surface"])
        summary.pack(fill="x", padx=10, pady=(10, 4))

        self._label_var = tk.StringVar(value="—")
        self._label_display = tk.Label(
            summary, textvariable=self._label_var,
            bg=COLOURS["surface"], fg=COLOURS["subtext"],
            font=("Segoe UI", 18, "bold"), width=14, anchor="w",
        )
        self._label_display.pack(side="left")

        self._score_var = tk.StringVar(value="")
        tk.Label(summary, textvariable=self._score_var,
                 bg=COLOURS["surface"], fg=COLOURS["subtext"],
                 font=("Segoe UI", 14)).pack(side="left", padx=(0, 12))

        # Score bar
        bar_frame = tk.Frame(results_frame, bg=COLOURS["surface"])
        bar_frame.pack(fill="x", padx=10, pady=(0, 8))
        self._canvas = tk.Canvas(bar_frame, height=16,
                                 bg=COLOURS["border"], highlightthickness=0)
        self._canvas.pack(fill="x")

        # Rules tree
        cols = ("category", "weight", "pattern")
        self._tree = ttk.Treeview(results_frame, columns=cols,
                                   show="headings", height=7)
        self._tree.heading("category", text="Category")
        self._tree.heading("weight", text="Weight")
        self._tree.heading("pattern", text="Pattern")
        self._tree.column("category", width=160, anchor="w")
        self._tree.column("weight", width=70, anchor="center")
        self._tree.column("pattern", width=500, anchor="w")
        self._tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        vsb = ttk.Scrollbar(results_frame, orient="vertical",
                             command=self._tree.yview)
        vsb.pack(side="right", fill="y")
        self._tree.configure(yscrollcommand=vsb.set)

    @staticmethod
    def _add_slider(parent, label: str, var,
                    from_: int, to: int, col: int):
        tk.Label(parent, text=label, bg=COLOURS["bg"],
                 fg=COLOURS["subtext"], font=("Segoe UI", 9)
                 ).grid(row=0, column=col * 2, padx=(8, 2), sticky="e")
        tk.Scale(parent, variable=var, from_=from_, to=to,
                 orient="horizontal", length=110,
                 bg=COLOURS["bg"], fg=COLOURS["text"],
                 troughcolor=COLOURS["border"], highlightthickness=0,
                 relief="flat", showvalue=True, font=("Segoe UI", 8)
                 ).grid(row=0, column=col * 2 + 1, padx=(0, 4))

    def _apply_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview",
                         background=COLOURS["surface"],
                         foreground=COLOURS["text"],
                         fieldbackground=COLOURS["surface"],
                         rowheight=22,
                         font=("Consolas", 10))
        style.configure("Treeview.Heading",
                         background=COLOURS["border"],
                         foreground=COLOURS["text"],
                         font=("Segoe UI", 9, "bold"),
                         relief="flat")
        style.map("Treeview",
                  background=[("selected", COLOURS["accent"])],
                  foreground=[("selected", COLOURS["button_text"])])

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _analyse(self):
        text = self._input_text.get("1.0", "end").strip()
        if not text:
            return

        safe_t = self._safe_thresh_var.get()
        inj_t = self._inj_thresh_var.get()
        if safe_t >= inj_t:
            messagebox.showwarning(
                "Invalid thresholds",
                "Safe threshold must be strictly less than injection threshold."
            )
            return

        self._detector = lid.LLMInjectionDetector(
            safe_threshold=safe_t,
            injection_threshold=inj_t,
        )
        result = self._detector.detect(text)
        self._results = [result]
        self._display_result(result)

    def _display_result(self, result: lid.DetectionResult):
        fg, bg = LABEL_COLOURS.get(result.label.value,
                                    (COLOURS["text"], COLOURS["surface"]))
        self._label_var.set(result.label.value)
        self._label_display.config(fg=fg)
        self._score_var.set(f"Score: {result.score}/100   |   {result.timestamp[:19]} UTC")

        # Redraw score bar
        self._canvas.update_idletasks()
        w = self._canvas.winfo_width()
        self._canvas.delete("all")
        if w > 0:
            fill_w = int(w * result.score / 100)
            self._canvas.create_rectangle(0, 0, fill_w, 16, fill=fg, outline="")

        # Populate rules tree
        for row in self._tree.get_children():
            self._tree.delete(row)

        if result.rules_triggered:
            for rule in result.rules_triggered:
                self._tree.insert(
                    "", "end",
                    values=(rule["category"], rule["weight"], rule["pattern"]),
                )
        else:
            self._tree.insert("", "end",
                               values=("No rules triggered", "", ""))

    def _clear(self):
        self._input_text.delete("1.0", "end")
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._label_var.set("—")
        self._score_var.set("")
        self._canvas.delete("all")
        self._results = []

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="Open text file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return

        safe_t = self._safe_thresh_var.get()
        inj_t = self._inj_thresh_var.get()
        self._detector = lid.LLMInjectionDetector(
            safe_threshold=safe_t, injection_threshold=inj_t
        )

        lines = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    lines.append(line)

        if not lines:
            messagebox.showinfo("Empty file", "The selected file contains no text.")
            return

        self._results = self._detector.detect_batch(lines)

        # Show summary in input pane and display last result
        self._input_text.delete("1.0", "end")
        self._input_text.insert(
            "end",
            f"[Batch: {len(lines)} lines from {Path(path).name}]\n\n"
            + "\n".join(lines[:20])
            + ("\n…" if len(lines) > 20 else ""),
        )

        # Display worst result
        worst = max(self._results, key=lambda r: r.score)
        self._display_result(worst)

        summary = (
            f"Processed {len(self._results)} lines.\n"
            f"SAFE: {sum(1 for r in self._results if r.label == lid.Label.SAFE)}\n"
            f"SUSPICIOUS: {sum(1 for r in self._results if r.label == lid.Label.SUSPICIOUS)}\n"
            f"INJECTION: {sum(1 for r in self._results if r.label == lid.Label.INJECTION)}\n"
            f"\nHighest score: {worst.score}/100  ({worst.label.value})"
        )
        messagebox.showinfo("Batch complete", summary)

    def _save_results(self):
        if not self._results:
            messagebox.showinfo("Nothing to save", "Run an analysis first.")
            return

        path = filedialog.asksaveasfilename(
            title="Save results",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return

        data = [r.to_dict() for r in self._results]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        messagebox.showinfo("Saved", f"Results written to {path}")

    def _show_about(self):
        messagebox.showinfo(
            "About",
            f"LLM Injection Detector  v{lid.__version__}\n\n"
            "Heuristic detector for prompt injection, jailbreak,\n"
            "and system-extraction attacks on LLM applications.\n\n"
            f"Author: {lid.__author__}\n"
            f"Licence: {lid.__license__}",
        )


def main():
    """Launch the GUI application."""
    if not _TKINTER_AVAILABLE:
        print(
            "Error: tkinter is not available in this Python installation.\n"
            "On Debian/Ubuntu:  sudo apt install python3-tk\n"
            "On macOS (Homebrew): brew install python-tk\n"
            "On Windows: tkinter is bundled with the official Python installer.",
            file=sys.stderr,
        )
        sys.exit(1)
    app = DetectorApp()
    app.mainloop()


if __name__ == "__main__":
    main()
