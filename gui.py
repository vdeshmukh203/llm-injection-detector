"""
Interactive Tkinter GUI for the LLM Injection Detector.

Launch with:
    python gui.py
or (after pip install):
    llm-injection-detector-gui
"""

import json
import sys
import os
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from llm_injection_detector import LLMInjectionDetector, Label, __version__

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
_C = {
    "bg":           "#2c3e50",
    "panel":        "#34495e",
    "input_bg":     "#1a252f",
    "text":         "#ecf0f1",
    "muted":        "#7f8c8d",
    "accent":       "#3498db",
    "btn_primary":  "#2980b9",
    "btn_primary_a":"#1abc9c",
    "btn_clear":    "#7f8c8d",
    "btn_clear_a":  "#95a5a6",
    "btn_file":     "#27ae60",
    "btn_file_a":   "#2ecc71",
    "btn_export":   "#8e44ad",
    "btn_export_a": "#9b59b6",
    Label.SAFE:       "#27ae60",
    Label.SUSPICIOUS: "#f39c12",
    Label.INJECTION:  "#e74c3c",
}


def _make_button(parent, text, bg, active_bg, command, **kw):
    """Helper to build a flat, coloured button with hover feedback."""
    btn = tk.Button(
        parent,
        text=text,
        bg=bg, fg="white",
        activebackground=active_bg, activeforeground="white",
        font=("Segoe UI", 10, "bold"),
        relief="flat", bd=0,
        cursor="hand2",
        command=command,
        **kw,
    )
    return btn


class InjectionDetectorGUI:
    """Main application window."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"LLM Injection Detector  v{__version__}")
        self.root.geometry("1080x700")
        self.root.minsize(860, 580)
        self.root.configure(bg=_C["bg"])

        self._detector = LLMInjectionDetector()
        self._history: list = []
        self._last_result = None

        self._build_styles()
        self._build_ui()

    # ------------------------------------------------------------------
    # Style configuration
    # ------------------------------------------------------------------

    def _build_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame",      background=_C["bg"])
        style.configure("Panel.TFrame", background=_C["panel"])
        style.configure("TLabel",      background=_C["bg"],    foreground=_C["text"],
                        font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=_C["panel"], foreground=_C["muted"],
                        font=("Segoe UI", 9))
        style.configure("Score.TLabel", background=_C["panel"], foreground=_C["text"],
                        font=("Segoe UI", 24, "bold"))
        style.configure("TScale",       background=_C["bg"])
        style.configure("Horizontal.TProgressbar",
                        troughcolor=_C["input_bg"],
                        background=_C["accent"],
                        thickness=22)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        # ── title row ─────────────────────────────────────────────────
        hdr = tk.Frame(self.root, bg=_C["bg"])
        hdr.pack(fill="x", padx=20, pady=(12, 4))

        tk.Label(hdr, text="LLM Injection Detector", bg=_C["bg"], fg=_C["text"],
                 font=("Segoe UI", 17, "bold")).pack(side="left")
        tk.Label(hdr, text=f"v{__version__}", bg=_C["bg"], fg=_C["muted"],
                 font=("Segoe UI", 10)).pack(side="left", padx=(8, 0), pady=(5, 0))

        # ── two-column content ─────────────────────────────────────────
        body = tk.Frame(self.root, bg=_C["bg"])
        body.pack(fill="both", expand=True, padx=20, pady=(4, 6))
        body.columnconfigure(0, weight=1, uniform="col")
        body.columnconfigure(1, weight=1, uniform="col")
        body.rowconfigure(0, weight=1)

        self._build_input_panel(body)
        self._build_results_panel(body)

        # ── status bar ────────────────────────────────────────────────
        self._build_status_bar()

    # ── left panel (input) ─────────────────────────────────────────────

    def _build_input_panel(self, parent: tk.Frame) -> None:
        left = tk.Frame(parent, bg=_C["panel"])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))

        tk.Label(left, text="Input Text", bg=_C["panel"], fg=_C["text"],
                 font=("Segoe UI", 12, "bold"), pady=8).pack(padx=14, anchor="w")

        # Text input area
        self._text_input = scrolledtext.ScrolledText(
            left, height=14, wrap=tk.WORD,
            bg=_C["input_bg"], fg=_C["text"],
            insertbackground=_C["text"],
            font=("Consolas", 11),
            relief="flat", borderwidth=0,
            padx=8, pady=8,
        )
        self._text_input.pack(fill="both", expand=True, padx=14)

        # ── threshold sliders ─────────────────────────────────────────
        thr_frame = tk.Frame(left, bg=_C["panel"])
        thr_frame.pack(fill="x", padx=14, pady=(10, 6))

        tk.Label(thr_frame, text="Thresholds", bg=_C["panel"], fg=_C["text"],
                 font=("Segoe UI", 9, "bold")).grid(
                     row=0, column=0, columnspan=6, sticky="w", pady=(0, 4))

        self._safe_var = tk.IntVar(value=30)
        self._susp_var = tk.IntVar(value=60)

        self._add_slider(thr_frame, "Safe ≤", self._safe_var, row=1, col=0,
                         from_=0, to=80)
        self._add_slider(thr_frame, "Injection ≥", self._susp_var, row=1, col=3,
                         from_=20, to=100)

        # ── action buttons ────────────────────────────────────────────
        btn_frame = tk.Frame(left, bg=_C["panel"])
        btn_frame.pack(fill="x", padx=14, pady=(2, 14))

        _make_button(btn_frame, "Analyze", _C["btn_primary"], _C["btn_primary_a"],
                     self._analyze, padx=22, pady=8).pack(side="left", padx=(0, 6))
        _make_button(btn_frame, "Clear", _C["btn_clear"], _C["btn_clear_a"],
                     self._clear, padx=16, pady=8).pack(side="left", padx=(0, 6))
        _make_button(btn_frame, "Load File", _C["btn_file"], _C["btn_file_a"],
                     self._load_file, padx=16, pady=8).pack(side="left")

    def _add_slider(self, parent, label, var, row, col, from_, to):
        """Attach a labelled scale widget to *parent* at the given grid position."""
        tk.Label(parent, text=label, bg=_C["panel"], fg=_C["muted"],
                 font=("Segoe UI", 9)).grid(row=row, column=col, sticky="w")
        val_lbl = tk.Label(parent, textvariable=var, bg=_C["panel"], fg=_C["accent"],
                           font=("Segoe UI", 9, "bold"), width=3)
        val_lbl.grid(row=row, column=col + 1, padx=(2, 6))
        ttk.Scale(parent, from_=from_, to=to, variable=var, orient="horizontal",
                  length=130, command=self._on_threshold_change).grid(
                      row=row, column=col + 2, padx=(0, 10))

    # ── right panel (results) ──────────────────────────────────────────

    def _build_results_panel(self, parent: tk.Frame) -> None:
        right = tk.Frame(parent, bg=_C["panel"])
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))

        tk.Label(right, text="Analysis Results", bg=_C["panel"], fg=_C["text"],
                 font=("Segoe UI", 12, "bold"), pady=8).pack(padx=14, anchor="w")

        # ── score row ─────────────────────────────────────────────────
        score_row = tk.Frame(right, bg=_C["panel"])
        score_row.pack(fill="x", padx=14)

        tk.Label(score_row, text="Score:", bg=_C["panel"], fg=_C["muted"],
                 font=("Segoe UI", 10)).pack(side="left")

        self._score_lbl = tk.Label(score_row, text="—", bg=_C["panel"], fg=_C["text"],
                                    font=("Segoe UI", 24, "bold"))
        self._score_lbl.pack(side="left", padx=(6, 0))

        tk.Label(score_row, text="/ 100", bg=_C["panel"], fg=_C["muted"],
                 font=("Segoe UI", 11)).pack(side="left", pady=(6, 0))

        # score bar
        self._score_var = tk.DoubleVar(value=0)
        self._score_bar = ttk.Progressbar(
            right, variable=self._score_var,
            maximum=100, mode="determinate",
        )
        self._score_bar.pack(fill="x", padx=14, pady=(6, 0))

        # ── label badge ───────────────────────────────────────────────
        badge_row = tk.Frame(right, bg=_C["panel"])
        badge_row.pack(fill="x", padx=14, pady=(8, 0))

        tk.Label(badge_row, text="Label:", bg=_C["panel"], fg=_C["muted"],
                 font=("Segoe UI", 10)).pack(side="left")

        self._label_badge = tk.Label(
            badge_row, text="—",
            bg=_C["muted"], fg="white",
            font=("Segoe UI", 11, "bold"),
            padx=14, pady=4,
        )
        self._label_badge.pack(side="left", padx=(8, 0))

        # ── separator ─────────────────────────────────────────────────
        ttk.Separator(right, orient="horizontal").pack(fill="x", padx=14, pady=10)

        # ── triggered rules list ──────────────────────────────────────
        tk.Label(right, text="Rules Triggered", bg=_C["panel"], fg=_C["text"],
                 font=("Segoe UI", 10, "bold")).pack(padx=14, anchor="w")

        self._rules_box = scrolledtext.ScrolledText(
            right, height=9, wrap=tk.WORD,
            bg=_C["input_bg"], fg=_C["text"],
            font=("Consolas", 10),
            relief="flat", borderwidth=0,
            padx=8, pady=6,
            state="disabled",
        )
        self._rules_box.pack(fill="both", expand=True, padx=14, pady=(4, 8))

        # ── export button + timestamp ─────────────────────────────────
        foot = tk.Frame(right, bg=_C["panel"])
        foot.pack(fill="x", padx=14, pady=(0, 12))

        _make_button(foot, "Export JSON", _C["btn_export"], _C["btn_export_a"],
                     self._export_json, padx=14, pady=6).pack(side="left")

        self._ts_lbl = tk.Label(foot, text="", bg=_C["panel"], fg=_C["muted"],
                                 font=("Segoe UI", 8))
        self._ts_lbl.pack(side="right")

    # ── status bar ─────────────────────────────────────────────────────

    def _build_status_bar(self) -> None:
        bar = tk.Frame(self.root, bg="#1a252f", height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self._status_var = tk.StringVar(value="Ready — enter text and click Analyze.")
        tk.Label(bar, textvariable=self._status_var,
                 bg="#1a252f", fg=_C["muted"],
                 font=("Segoe UI", 9), anchor="w").pack(
                     side="left", padx=12, pady=4)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_threshold_change(self, _=None) -> None:
        safe = self._safe_var.get()
        susp = self._susp_var.get()
        if safe >= susp:
            # Prevent the sliders from crossing
            susp = safe + 1
            self._susp_var.set(susp)
        try:
            self._detector = LLMInjectionDetector(
                safe_threshold=safe, suspicious_threshold=susp
            )
        except ValueError:
            pass

    def _analyze(self) -> None:
        text = self._text_input.get("1.0", tk.END).strip()
        if not text:
            self._status("Please enter text to analyze.")
            return

        self._status("Analyzing…")
        self.root.update_idletasks()

        result = self._detector.detect(text)
        self._last_result = result
        self._history.append(result)
        self._render_result(result)

        self._status(
            f"Score: {result.score}/100  ·  Label: {result.label.value}  ·  "
            f"Rules triggered: {len(result.rules_triggered)}"
        )

    def _render_result(self, result) -> None:
        colour = _C[result.label]

        # Score number + bar
        self._score_lbl.config(text=str(result.score))
        self._score_var.set(result.score)
        ttk.Style().configure("Horizontal.TProgressbar", background=colour)

        # Label badge
        self._label_badge.config(text=result.label.value, bg=colour)

        # Rules list
        self._rules_box.config(state="normal")
        self._rules_box.delete("1.0", tk.END)
        if result.rules_triggered:
            for rule in result.rules_triggered:
                self._rules_box.insert(
                    tk.END,
                    f"[{rule['category']}]  weight={rule['weight']}\n",
                )
        else:
            self._rules_box.insert(tk.END, "No rules triggered — text appears safe.")
        self._rules_box.config(state="disabled")

        # Timestamp
        self._ts_lbl.config(text=f"Analyzed: {result.timestamp}")

    def _clear(self) -> None:
        self._text_input.delete("1.0", tk.END)
        self._score_lbl.config(text="—")
        self._score_var.set(0)
        self._label_badge.config(text="—", bg=_C["muted"])
        self._rules_box.config(state="normal")
        self._rules_box.delete("1.0", tk.END)
        self._rules_box.config(state="disabled")
        self._ts_lbl.config(text="")
        self._last_result = None
        self._status("Ready — enter text and click Analyze.")

    def _load_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Open text file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as fh:
                self._text_input.delete("1.0", tk.END)
                self._text_input.insert("1.0", fh.read())
            self._status(f"Loaded: {path}")
        except OSError as exc:
            messagebox.showerror("File Error", str(exc))

    def _export_json(self) -> None:
        if not self._history:
            messagebox.showinfo("Export", "No results to export yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Save JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump([r.to_dict() for r in self._history], fh, indent=2)
            self._status(f"Exported {len(self._history)} result(s) → {path}")
        except OSError as exc:
            messagebox.showerror("Export Error", str(exc))

    def _status(self, msg: str) -> None:
        self._status_var.set(msg)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Launch the GUI."""
    root = tk.Tk()
    InjectionDetectorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
