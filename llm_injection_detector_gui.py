"""
Graphical user interface for the LLM Injection Detector.

Requires only the Python standard library (tkinter).  Launch via::

    python llm_injection_detector_gui.py
    # or
    llm-injection-detector --gui
"""

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError as _tk_err:  # pragma: no cover
    raise ImportError(
        "The GUI requires tkinter, which is part of the Python standard library "
        "but may need to be installed separately on some systems.\n"
        "  • Debian/Ubuntu: sudo apt-get install python3-tk\n"
        "  • Fedora/RHEL:   sudo dnf install python3-tkinter\n"
        "  • macOS/Windows: tkinter ships with the official Python installer.\n"
        f"Original error: {_tk_err}"
    ) from _tk_err

import json
from pathlib import Path

from llm_injection_detector import (
    LLMInjectionDetector,
    Label,
)

# ---------------------------------------------------------------------------
# Colour scheme
# ---------------------------------------------------------------------------
COLOURS = {
    Label.SAFE:       {"bg": "#d4edda", "fg": "#155724", "badge": "#28a745"},
    Label.SUSPICIOUS: {"bg": "#fff3cd", "fg": "#856404", "badge": "#ffc107"},
    Label.INJECTION:  {"bg": "#f8d7da", "fg": "#721c24", "badge": "#dc3545"},
}
FONT_MONO  = ("Courier New", 10)
FONT_LABEL = ("Helvetica", 11)
FONT_TITLE = ("Helvetica", 14, "bold")
BG_APP     = "#f5f5f5"
BG_PANEL   = "#ffffff"
FG_MUTED   = "#6c757d"


class InjectionDetectorApp(tk.Tk):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.title("LLM Injection Detector")
        self.minsize(780, 560)
        self.configure(bg=BG_APP)
        self._detector = LLMInjectionDetector()
        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        self._build_header()
        self._build_settings_bar()
        self._build_body()
        self._build_status_bar()
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

    def _build_header(self):
        hdr = tk.Frame(self, bg="#343a40", pady=10)
        hdr.grid(row=0, column=0, sticky="ew")
        tk.Label(
            hdr, text="LLM Injection Detector",
            font=FONT_TITLE, bg="#343a40", fg="white",
        ).pack(side="left", padx=16)
        tk.Label(
            hdr, text="Heuristic prompt-injection analysis",
            font=FONT_LABEL, bg="#343a40", fg="#adb5bd",
        ).pack(side="left")

    def _build_settings_bar(self):
        bar = tk.Frame(self, bg=BG_APP, pady=6)
        bar.grid(row=1, column=0, sticky="ew", padx=12)

        tk.Label(bar, text="Safe threshold:", bg=BG_APP, font=FONT_LABEL).pack(side="left")
        self._safe_var = tk.IntVar(value=20)
        tk.Spinbox(bar, from_=0, to=99, textvariable=self._safe_var,
                   width=5, font=FONT_MONO).pack(side="left", padx=(2, 12))

        tk.Label(bar, text="Injection threshold:", bg=BG_APP, font=FONT_LABEL).pack(side="left")
        self._inj_var = tk.IntVar(value=50)
        tk.Spinbox(bar, from_=1, to=100, textvariable=self._inj_var,
                   width=5, font=FONT_MONO).pack(side="left", padx=(2, 12))

        self._verbose_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            bar, text="Verbose", variable=self._verbose_var,
            bg=BG_APP, font=FONT_LABEL,
        ).pack(side="left", padx=4)

        ttk.Button(bar, text="Load file…", command=self._load_file).pack(side="right")
        ttk.Button(bar, text="Export JSON", command=self._export_json).pack(side="right", padx=4)
        ttk.Button(bar, text="Clear", command=self._clear).pack(side="right")

    def _build_body(self):
        body = tk.PanedWindow(self, orient="horizontal", bg=BG_APP,
                              sashrelief="groove", sashwidth=5)
        body.grid(row=2, column=0, sticky="nsew", padx=8, pady=8)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        # ---- Left pane: input ----
        left = tk.Frame(body, bg=BG_PANEL, relief="flat", bd=1)
        body.add(left, minsize=320)
        left.columnconfigure(0, weight=1)
        left.rowconfigure(1, weight=1)

        tk.Label(left, text="Input text", font=FONT_LABEL,
                 bg=BG_PANEL, anchor="w").grid(row=0, column=0, sticky="ew", padx=8, pady=(6, 2))
        self._input_text = tk.Text(left, wrap="word", font=FONT_MONO,
                                   relief="flat", bg="#fafafa", insertbackground="#000")
        self._input_text.grid(row=1, column=0, sticky="nsew", padx=6, pady=4)
        self._input_text.bind("<Control-Return>", lambda _: self._analyse())

        sb_in = ttk.Scrollbar(left, command=self._input_text.yview)
        sb_in.grid(row=1, column=1, sticky="ns")
        self._input_text["yscrollcommand"] = sb_in.set

        btn_frame = tk.Frame(left, bg=BG_PANEL)
        btn_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=6, pady=4)
        ttk.Button(btn_frame, text="Analyse (Ctrl+Enter)",
                   command=self._analyse).pack(side="right")

        # ---- Right pane: results ----
        right = tk.Frame(body, bg=BG_PANEL, relief="flat", bd=1)
        body.add(right, minsize=320)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        tk.Label(right, text="Results", font=FONT_LABEL,
                 bg=BG_PANEL, anchor="w").grid(row=0, column=0, sticky="ew", padx=8, pady=(6, 2))
        self._result_text = tk.Text(right, wrap="word", font=FONT_MONO,
                                    relief="flat", bg="#fafafa", state="disabled")
        self._result_text.grid(row=1, column=0, sticky="nsew", padx=6, pady=4)

        sb_out = ttk.Scrollbar(right, command=self._result_text.yview)
        sb_out.grid(row=1, column=1, sticky="ns")
        self._result_text["yscrollcommand"] = sb_out.set

        # Score / label badge
        self._badge_frame = tk.Frame(right, bg=BG_PANEL)
        self._badge_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=6, pady=4)
        self._score_label = tk.Label(self._badge_frame, text="", font=FONT_LABEL, bg=BG_PANEL)
        self._score_label.pack(side="left")
        self._badge_label = tk.Label(self._badge_frame, text="", font=FONT_LABEL,
                                     width=12, relief="flat", padx=8, pady=2)
        self._badge_label.pack(side="right")

        self._last_results = []

    def _build_status_bar(self):
        self._status_var = tk.StringVar(value="Ready — enter text and press Analyse.")
        bar = tk.Label(self, textvariable=self._status_var, anchor="w",
                       font=("Helvetica", 9), fg=FG_MUTED, bg="#dee2e6", pady=3)
        bar.grid(row=3, column=0, sticky="ew")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _analyse(self):
        text = self._input_text.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo("No input", "Please enter some text to analyse.")
            return
        self._status_var.set("Analysing…")
        self.after(10, lambda: self._run_analysis(text))

    def _run_analysis(self, text: str):
        detector = LLMInjectionDetector(
            verbose=self._verbose_var.get(),
            safe_threshold=self._safe_var.get(),
            suspicious_threshold=self._inj_var.get(),
        )
        lines = [l for l in text.splitlines() if l.strip()]
        if len(lines) > 1:
            results = detector.detect_batch(lines)
        else:
            results = [detector.detect(text)]
        self._last_results = results
        self._render_results(results)

    def _render_results(self, results):
        colours = COLOURS[results[0].label] if results else None

        self._result_text.configure(state="normal")
        self._result_text.delete("1.0", "end")

        for i, r in enumerate(results, 1):
            c = COLOURS[r.label]
            header = f"{'─'*60}\nAnalysis {i}\n{'─'*60}\n"
            self._result_text.insert("end", header)
            self._result_text.insert("end", f"Score : {r.score}/100\n")
            self._result_text.insert("end", f"Label : {r.label.value}\n")
            self._result_text.insert("end", f"Text  : {r.text[:80]}\n")

            if r.rules_triggered:
                self._result_text.insert("end", f"\nRules triggered ({len(r.rules_triggered)}):\n")
                for rule in r.rules_triggered:
                    self._result_text.insert(
                        "end",
                        f"  [{rule['category']}]  weight={rule['weight']}\n"
                    )
            else:
                self._result_text.insert("end", "\nNo rules triggered.\n")
            self._result_text.insert("end", "\n")

        self._result_text.configure(state="disabled")

        # Update badge
        if results:
            worst = max(results, key=lambda r: r.score)
            c = COLOURS[worst.label]
            self._score_label.configure(
                text=f"Score: {worst.score}/100",
                fg=c["fg"], bg=BG_PANEL,
            )
            self._badge_label.configure(
                text=worst.label.value,
                bg=c["badge"], fg="white",
            )

        self._status_var.set(
            f"Done — {len(results)} input(s) analysed. "
            f"SAFE: {sum(r.label==Label.SAFE for r in results)}  "
            f"SUSPICIOUS: {sum(r.label==Label.SUSPICIOUS for r in results)}  "
            f"INJECTION: {sum(r.label==Label.INJECTION for r in results)}"
        )

    def _load_file(self):
        path = filedialog.askopenfilename(
            title="Open text file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8")
            self._input_text.delete("1.0", "end")
            self._input_text.insert("1.0", content)
            self._status_var.set(f"Loaded: {path}")
        except Exception as exc:
            messagebox.showerror("Error", f"Could not read file:\n{exc}")

    def _export_json(self):
        if not self._last_results:
            messagebox.showinfo("No results", "Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save JSON report",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            data = [r.to_dict() for r in self._last_results]
            Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
            self._status_var.set(f"Exported: {path}")
        except Exception as exc:
            messagebox.showerror("Error", f"Could not save file:\n{exc}")

    def _clear(self):
        self._input_text.delete("1.0", "end")
        self._result_text.configure(state="normal")
        self._result_text.delete("1.0", "end")
        self._result_text.configure(state="disabled")
        self._score_label.configure(text="")
        self._badge_label.configure(text="", bg=BG_PANEL)
        self._last_results = []
        self._status_var.set("Ready — enter text and press Analyse.")


def launch_gui():
    """Start the Tk main loop."""
    app = InjectionDetectorApp()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
