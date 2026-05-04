"""
LLM Injection Detector – Graphical User Interface

A Tkinter-based desktop frontend for the LLM injection detector.

Launch
------
    python llm_injection_detector_gui.py
    llm-injection-detector-gui          # when installed as a package

Features
--------
- Paste or load any text and analyse it with one click
- Colour-coded result: green (SAFE), amber (SUSPICIOUS), red (INJECTION)
- Score bar and numeric score display
- Per-rule breakdown table
- Configurable suspicious / injection thresholds
- Full analysis history with one-click JSON export
- Thread-safe: analysis runs off the GUI thread so the UI stays responsive
"""

import json
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from llm_injection_detector import Label, LLMInjectionDetector


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

_PALETTE = {
    Label.SAFE: {
        "badge_fg": "#155724",
        "badge_bg": "#d4edda",
        "accent":   "#28a745",
    },
    Label.SUSPICIOUS: {
        "badge_fg": "#856404",
        "badge_bg": "#fff3cd",
        "accent":   "#e0a800",
    },
    Label.INJECTION: {
        "badge_fg": "#721c24",
        "badge_bg": "#f8d7da",
        "accent":   "#dc3545",
    },
}

_BADGE_TEXT = {
    Label.SAFE:       "✓  SAFE",
    Label.SUSPICIOUS: "⚠  SUSPICIOUS",
    Label.INJECTION:  "✗  INJECTION",
}

_BG = "#f8f9fa"


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class App(tk.Tk):
    """Root window for the LLM Injection Detector GUI."""

    def __init__(self) -> None:
        super().__init__()
        self.title("LLM Injection Detector")
        self.geometry("960x700")
        self.minsize(760, 520)
        self.configure(bg=_BG)

        self._history: list = []
        self._build_styles()
        self._build_ui()

    # ------------------------------------------------------------------
    # Styles
    # ------------------------------------------------------------------

    def _build_styles(self) -> None:
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".",            background=_BG, font=("Segoe UI", 10))
        s.configure("TFrame",       background=_BG)
        s.configure("TLabelframe",  background=_BG)
        s.configure("TLabelframe.Label", background=_BG, font=("Segoe UI", 10, "bold"))
        s.configure("TLabel",       background=_BG)
        s.configure("TButton",      font=("Segoe UI", 10), padding=6)
        s.configure("TSpinbox",     font=("Segoe UI", 10))
        s.configure("Heading.TLabel",
                    font=("Segoe UI", 13, "bold"), background=_BG)
        s.configure("Score.TLabel",
                    font=("Segoe UI", 32, "bold"), background=_BG)
        s.configure("Badge.TLabel",
                    font=("Segoe UI", 14, "bold"), padding=(8, 4))

        # Progress-bar sub-styles for each label
        for label, pal in _PALETTE.items():
            style_name = f"{label.value}.Horizontal.TProgressbar"
            s.configure(style_name,
                        troughcolor="#dee2e6",
                        background=pal["accent"],
                        thickness=14)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        # Title bar
        title_row = ttk.Frame(self, padding=(12, 6))
        title_row.pack(fill=tk.X)
        ttk.Label(title_row, text="LLM Injection Detector",
                  style="Heading.TLabel").pack(side=tk.LEFT)
        ttk.Label(title_row, text="v0.1.0",
                  foreground="#6c757d").pack(side=tk.LEFT, padx=(8, 0))

        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X)

        # Two-pane layout
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        left = ttk.Frame(paned, padding=4)
        right = ttk.Frame(paned, padding=4)
        paned.add(left,  weight=55)
        paned.add(right, weight=45)

        self._build_left(left)
        self._build_right(right)

        # Status bar
        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X)
        self._status_var = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self._status_var,
                  foreground="#6c757d", padding=(10, 3)).pack(side=tk.LEFT)

    # --- Left pane: input + settings + result ---------------------------

    def _build_left(self, parent: ttk.Frame) -> None:
        # Input header row
        hdr = ttk.Frame(parent)
        hdr.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(hdr, text="Input Text",
                  style="Heading.TLabel").pack(side=tk.LEFT)
        ttk.Button(hdr, text="Load File…",
                   command=self._load_file).pack(side=tk.RIGHT)
        ttk.Button(hdr, text="Clear",
                   command=self._clear_input).pack(side=tk.RIGHT, padx=(0, 6))

        # Text area
        self._input = scrolledtext.ScrolledText(
            parent, height=11, font=("Consolas", 10), wrap=tk.WORD,
            relief=tk.FLAT, borderwidth=1,
            highlightthickness=1, highlightbackground="#ced4da",
        )
        self._input.pack(fill=tk.BOTH, expand=True)

        # Threshold controls
        thresh = ttk.LabelFrame(parent, text="Detection Thresholds", padding=8)
        thresh.pack(fill=tk.X, pady=(8, 0))

        ttk.Label(thresh, text="Suspicious ≥").grid(
            row=0, column=0, sticky=tk.W)
        self._susp_var = tk.IntVar(value=30)
        ttk.Spinbox(thresh, from_=1, to=98, width=6,
                    textvariable=self._susp_var).grid(
            row=0, column=1, padx=(4, 20))

        ttk.Label(thresh, text="Injection ≥").grid(
            row=0, column=2, sticky=tk.W)
        self._inj_var = tk.IntVar(value=60)
        ttk.Spinbox(thresh, from_=2, to=100, width=6,
                    textvariable=self._inj_var).grid(
            row=0, column=3, padx=(4, 0))

        # Analyse button
        self._btn = ttk.Button(
            parent, text="  Analyse Text  ", command=self._on_analyse)
        self._btn.pack(fill=tk.X, pady=(8, 0))

        # Result panel
        result_frame = ttk.LabelFrame(parent, text="Result", padding=10)
        result_frame.pack(fill=tk.X, pady=(8, 0))

        top = ttk.Frame(result_frame)
        top.pack(fill=tk.X)

        self._badge = ttk.Label(top, text="—", style="Badge.TLabel", width=17)
        self._badge.pack(side=tk.LEFT)

        self._score_lbl = ttk.Label(top, text="—", style="Score.TLabel")
        self._score_lbl.pack(side=tk.RIGHT, padx=(0, 4))

        ttk.Label(result_frame, text="/100", foreground="#6c757d").pack(
            side=tk.RIGHT, pady=(0, 4))

        self._bar = ttk.Progressbar(result_frame, maximum=100, length=300)
        self._bar.pack(fill=tk.X, pady=(6, 0))

    # --- Right pane: rules + history ------------------------------------

    def _build_right(self, parent: ttk.Frame) -> None:
        # Rules triggered
        ttk.Label(parent, text="Rules Triggered",
                  style="Heading.TLabel").pack(anchor=tk.W, pady=(0, 4))

        rule_cols = ("Category", "Weight", "Rule ID")
        self._rules_tree = ttk.Treeview(
            parent, columns=rule_cols, show="headings", height=9)
        self._rules_tree.heading("Category", text="Category")
        self._rules_tree.heading("Weight",   text="Wt")
        self._rules_tree.heading("Rule ID",  text="Rule ID")
        self._rules_tree.column("Category", width=150)
        self._rules_tree.column("Weight",   width=40, anchor=tk.CENTER)
        self._rules_tree.column("Rule ID",  width=150)

        rules_sb = ttk.Scrollbar(parent, orient=tk.VERTICAL,
                                 command=self._rules_tree.yview)
        self._rules_tree.configure(yscrollcommand=rules_sb.set)
        self._rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        rules_sb.pack(side=tk.LEFT, fill=tk.Y)

        # History
        sep_frame = ttk.Frame(parent)
        sep_frame.pack(fill=tk.BOTH, expand=True, side=tk.TOP)

        ttk.Separator(parent, orient=tk.HORIZONTAL).pack(
            fill=tk.X, pady=6)

        hist_hdr = ttk.Frame(parent)
        hist_hdr.pack(fill=tk.X)
        ttk.Label(hist_hdr, text="History",
                  style="Heading.TLabel").pack(side=tk.LEFT)
        ttk.Button(hist_hdr, text="Export JSON",
                   command=self._export_history).pack(side=tk.RIGHT)
        ttk.Button(hist_hdr, text="Clear",
                   command=self._clear_history).pack(
            side=tk.RIGHT, padx=(0, 6))

        hist_cols = ("Time", "Label", "Score", "Preview")
        self._hist_tree = ttk.Treeview(
            parent, columns=hist_cols, show="headings", height=6)
        self._hist_tree.heading("Time",    text="Time")
        self._hist_tree.heading("Label",   text="Label")
        self._hist_tree.heading("Score",   text="Score")
        self._hist_tree.heading("Preview", text="Preview")
        self._hist_tree.column("Time",    width=70)
        self._hist_tree.column("Label",   width=90)
        self._hist_tree.column("Score",   width=42, anchor=tk.CENTER)
        self._hist_tree.column("Preview", width=170)

        hist_sb = ttk.Scrollbar(parent, orient=tk.VERTICAL,
                                command=self._hist_tree.yview)
        self._hist_tree.configure(yscrollcommand=hist_sb.set)
        self._hist_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hist_sb.pack(side=tk.LEFT, fill=tk.Y)

        # Colour tags for history rows
        self._hist_tree.tag_configure("SAFE",       foreground="#28a745")
        self._hist_tree.tag_configure("SUSPICIOUS", foreground="#856404")
        self._hist_tree.tag_configure("INJECTION",  foreground="#dc3545")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_analyse(self) -> None:
        text = self._input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning(
                "No Input", "Please enter or load some text to analyse.")
            return

        susp = self._susp_var.get()
        inj  = self._inj_var.get()
        if susp >= inj:
            messagebox.showerror(
                "Invalid Thresholds",
                "Suspicious threshold must be strictly less than the "
                "injection threshold.",
            )
            return

        self._btn.configure(state=tk.DISABLED)
        self._status_var.set("Analysing…")
        threading.Thread(
            target=self._worker, args=(text, susp, inj), daemon=True
        ).start()

    def _worker(self, text: str, susp: int, inj: int) -> None:
        try:
            detector = LLMInjectionDetector(
                suspicious_threshold=susp,
                injection_threshold=inj,
            )
            result = detector.detect(text)
            self.after(0, self._show_result, result)
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror("Error", str(exc)))
        finally:
            self.after(0, lambda: self._btn.configure(state=tk.NORMAL))

    def _show_result(self, result) -> None:
        pal = _PALETTE[result.label]

        # Badge
        self._badge.configure(
            text=_BADGE_TEXT[result.label],
            foreground=pal["badge_fg"],
            background=pal["badge_bg"],
        )

        # Score label
        self._score_lbl.configure(
            text=str(result.score),
            foreground=pal["accent"],
        )

        # Progress bar
        bar_style = f"{result.label.value}.Horizontal.TProgressbar"
        self._bar.configure(style=bar_style, value=result.score)

        # Rules table
        for row in self._rules_tree.get_children():
            self._rules_tree.delete(row)
        for rule in result.rules_triggered:
            self._rules_tree.insert(
                "", tk.END,
                values=(rule["category"], rule["weight"], rule["rule_id"]),
            )

        # History row
        ts      = datetime.now().strftime("%H:%M:%S")
        preview = result.text[:35].replace("\n", " ")
        self._hist_tree.insert(
            "", 0,
            values=(ts, result.label.value, result.score, preview),
            tags=(result.label.value,),
        )
        self._history.insert(0, result.to_dict())

        self._status_var.set(
            f"Done — {result.label.value}  "
            f"score={result.score}/100  "
            f"rules triggered={len(result.rules_triggered)}"
        )

    def _load_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Open text file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("File Error", str(exc))
            return
        self._input.delete("1.0", tk.END)
        self._input.insert("1.0", content)
        self._status_var.set(f"Loaded: {Path(path).name}")

    def _clear_input(self) -> None:
        self._input.delete("1.0", tk.END)
        for row in self._rules_tree.get_children():
            self._rules_tree.delete(row)
        self._badge.configure(
            text="—", foreground="#343a40", background=_BG)
        self._score_lbl.configure(text="—", foreground="#343a40")
        self._bar["value"] = 0
        self._status_var.set("Ready.")

    def _clear_history(self) -> None:
        for row in self._hist_tree.get_children():
            self._hist_tree.delete(row)
        self._history.clear()

    def _export_history(self) -> None:
        if not self._history:
            messagebox.showinfo("No History", "No analyses to export yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
            title="Export history as JSON",
        )
        if not path:
            return
        try:
            Path(path).write_text(
                json.dumps(self._history, indent=2), encoding="utf-8")
            messagebox.showinfo("Exported", f"History saved to:\n{path}")
        except OSError as exc:
            messagebox.showerror("Export Error", str(exc))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Launch the GUI application."""
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
