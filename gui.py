"""
Graphical user interface for llm-injection-detector.

Launch with::

    python gui.py

or, after installation::

    llm-injection-detector-gui
"""

from __future__ import annotations

import json
import sys
import tkinter as tk
import tkinter.filedialog as fd
import tkinter.messagebox as mb
import tkinter.ttk as ttk
from pathlib import Path
from typing import List, Optional

# Ensure the package root is importable when running the script directly.
sys.path.insert(0, str(Path(__file__).parent))

from llm_injection_detector import (
    __version__,
    DetectionResult,
    Label,
    LLMInjectionDetector,
)

# ---------------------------------------------------------------------------
# Colour palette (Catppuccin Mocha-inspired)
# ---------------------------------------------------------------------------
_C = {
    "bg": "#1e1e2e",
    "surface": "#313244",
    "surface1": "#45475a",
    "overlay": "#585b70",
    "text": "#cdd6f4",
    "subtext": "#a6adc8",
    "blue": "#89b4fa",
    "green": "#a6e3a1",
    "yellow": "#f9e2af",
    "red": "#f38ba8",
    "peach": "#fab387",
    "mauve": "#cba6f7",
    "btn_bg": "#45475a",
    "btn_active": "#585b70",
}

_LABEL_COLOURS = {
    Label.SAFE: _C["green"],
    Label.SUSPICIOUS: _C["yellow"],
    Label.INJECTION: _C["red"],
}

_FONT_MONO = ("Courier", 11)
_FONT_UI = ("Helvetica", 11)
_FONT_TITLE = ("Helvetica", 18, "bold")
_FONT_SCORE = ("Helvetica", 36, "bold")
_FONT_LABEL = ("Helvetica", 16, "bold")
_FONT_SMALL = ("Helvetica", 9)

_WINDOW_MIN_W = 940
_WINDOW_MIN_H = 680


# ---------------------------------------------------------------------------
# Main application class
# ---------------------------------------------------------------------------


class DetectorApp:
    """Tkinter GUI for :class:`~llm_injection_detector.LLMInjectionDetector`.

    Parameters
    ----------
    root:
        The root ``Tk`` window.
    """

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.detector = LLMInjectionDetector()
        self._last_result: Optional[DetectionResult] = None
        self._batch_results: List[DetectionResult] = []

        self._configure_root()
        self._apply_theme()
        self._build_ui()

    # ------------------------------------------------------------------
    # Setup helpers
    # ------------------------------------------------------------------

    def _configure_root(self) -> None:
        self.root.title(f"LLM Injection Detector  v{__version__}")
        self.root.geometry("1060x720")
        self.root.minsize(_WINDOW_MIN_W, _WINDOW_MIN_H)
        self.root.configure(bg=_C["bg"])
        self.root.option_add("*tearOff", False)

    def _apply_theme(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(".", background=_C["bg"], foreground=_C["text"],
                        font=_FONT_UI, borderwidth=0)
        style.configure("TFrame", background=_C["bg"])
        style.configure("Surface.TFrame", background=_C["surface"])
        style.configure("TLabel", background=_C["bg"], foreground=_C["text"],
                        font=_FONT_UI)
        style.configure("Surface.TLabel", background=_C["surface"],
                        foreground=_C["text"])
        style.configure("Title.TLabel", background=_C["bg"],
                        foreground=_C["blue"], font=_FONT_TITLE)
        style.configure("Score.TLabel", background=_C["surface"],
                        font=_FONT_SCORE)
        style.configure("ResultLabel.TLabel", background=_C["surface"],
                        font=_FONT_LABEL)
        style.configure("Subtext.TLabel", background=_C["surface"],
                        foreground=_C["subtext"], font=_FONT_UI)
        style.configure("TButton", background=_C["btn_bg"],
                        foreground=_C["text"], font=_FONT_UI, padding=(8, 4),
                        relief="flat")
        style.map("TButton",
                  background=[("active", _C["btn_active"]),
                               ("pressed", _C["overlay"])])
        style.configure("Accent.TButton", background=_C["blue"],
                        foreground=_C["bg"], font=("Helvetica", 11, "bold"),
                        padding=(10, 5))
        style.map("Accent.TButton",
                  background=[("active", _C["mauve"]),
                               ("pressed", _C["mauve"])])
        style.configure("TScale", background=_C["bg"],
                        troughcolor=_C["surface1"])
        style.configure("TScrollbar", background=_C["surface1"],
                        troughcolor=_C["surface"], arrowcolor=_C["subtext"],
                        borderwidth=0)
        style.configure("Horizontal.TProgressbar",
                        troughcolor=_C["surface1"],
                        background=_C["blue"],
                        thickness=16)
        style.configure("TSeparator", background=_C["surface1"])

    def _build_ui(self) -> None:
        self._build_menu()
        self._build_header()
        self._build_main_panes()
        self._build_status_bar()

    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root, bg=_C["surface"], fg=_C["text"],
                          activebackground=_C["overlay"],
                          activeforeground=_C["text"], bd=0)

        file_menu = tk.Menu(menubar)
        file_menu.add_command(label="Open File…", command=self._open_file,
                              accelerator="Ctrl+O")
        file_menu.add_command(label="Export JSON…", command=self._export_json,
                              accelerator="Ctrl+S")
        file_menu.add_separator()
        file_menu.add_command(label="Quit", command=self.root.quit,
                              accelerator="Ctrl+Q")
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.configure(menu=menubar)
        self.root.bind("<Control-o>", lambda _: self._open_file())
        self.root.bind("<Control-s>", lambda _: self._export_json())
        self.root.bind("<Control-q>", lambda _: self.root.quit())

    def _build_header(self) -> None:
        header = ttk.Frame(self.root, padding=(16, 10, 16, 6))
        header.pack(fill="x")
        ttk.Label(header, text="LLM Injection Detector",
                  style="Title.TLabel").pack(side="left")
        ttk.Label(header, text=f"v{__version__}",
                  foreground=_C["subtext"], font=_FONT_SMALL,
                  background=_C["bg"]).pack(side="left", padx=(8, 0),
                                            anchor="s", pady=(0, 3))
        ttk.Separator(self.root, orient="horizontal").pack(fill="x",
                                                           padx=16, pady=0)

    def _build_main_panes(self) -> None:
        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=12, pady=8)

        left = ttk.Frame(paned, padding=4)
        right = ttk.Frame(paned, padding=4)
        paned.add(left, weight=55)
        paned.add(right, weight=45)

        self._build_input_panel(left)
        self._build_results_panel(right)

    def _build_input_panel(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Input Text", foreground=_C["blue"],
                  font=("Helvetica", 12, "bold"),
                  background=_C["bg"]).pack(anchor="w", pady=(0, 4))

        text_frame = ttk.Frame(parent, style="Surface.TFrame", padding=2)
        text_frame.pack(fill="both", expand=True)

        self.input_text = tk.Text(
            text_frame,
            wrap="word",
            font=_FONT_MONO,
            bg=_C["surface"],
            fg=_C["text"],
            insertbackground=_C["text"],
            selectbackground=_C["overlay"],
            selectforeground=_C["text"],
            relief="flat",
            padx=8,
            pady=8,
            undo=True,
        )
        sb = ttk.Scrollbar(text_frame, orient="vertical",
                           command=self.input_text.yview)
        self.input_text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.input_text.pack(side="left", fill="both", expand=True)
        self.input_text.bind("<Control-Return>", lambda _: self._analyse())

        # Controls
        ctrl_frame = ttk.Frame(parent, padding=(0, 8, 0, 0))
        ctrl_frame.pack(fill="x")

        # Threshold row
        thresh_row = ttk.Frame(ctrl_frame)
        thresh_row.pack(fill="x", pady=(0, 6))
        ttk.Label(thresh_row, text="Safe threshold:").pack(side="left")
        self.threshold_var = tk.IntVar(value=30)
        self.thresh_display = ttk.Label(thresh_row, text=" 30 ",
                                        foreground=_C["blue"],
                                        background=_C["bg"])
        self.thresh_display.pack(side="right")
        thresh_scale = ttk.Scale(
            thresh_row,
            from_=5,
            to=70,
            orient="horizontal",
            variable=self.threshold_var,
            command=self._on_threshold_change,
        )
        thresh_scale.pack(side="right", fill="x", expand=True, padx=(8, 4))

        # Button row
        btn_row = ttk.Frame(ctrl_frame)
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="Analyse  (Ctrl+↵)",
                   style="Accent.TButton",
                   command=self._analyse).pack(side="left", padx=(0, 6))
        ttk.Button(btn_row, text="Open File…",
                   command=self._open_file).pack(side="left", padx=(0, 6))
        ttk.Button(btn_row, text="Clear",
                   command=self._clear).pack(side="left")
        ttk.Button(btn_row, text="Export JSON",
                   command=self._export_json).pack(side="right")

        ttk.Label(ctrl_frame,
                  text="Ctrl+Enter to analyse  •  batch: open a file",
                  foreground=_C["subtext"], font=_FONT_SMALL,
                  background=_C["bg"]).pack(anchor="w", pady=(6, 0))

    def _build_results_panel(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Analysis Results", foreground=_C["blue"],
                  font=("Helvetica", 12, "bold"),
                  background=_C["bg"]).pack(anchor="w", pady=(0, 4))

        card = ttk.Frame(parent, style="Surface.TFrame", padding=14)
        card.pack(fill="x")

        # Score + label row
        top_row = ttk.Frame(card, style="Surface.TFrame")
        top_row.pack(fill="x")

        self.score_label = ttk.Label(top_row, text="—", style="Score.TLabel",
                                     foreground=_C["subtext"])
        self.score_label.pack(side="left", padx=(0, 16))

        badge_col = ttk.Frame(top_row, style="Surface.TFrame")
        badge_col.pack(side="left")
        self.result_label = ttk.Label(badge_col, text="NOT ANALYSED",
                                      style="ResultLabel.TLabel",
                                      foreground=_C["subtext"])
        self.result_label.pack(anchor="w")
        self.ts_label = ttk.Label(badge_col, text="",
                                  style="Subtext.TLabel", font=_FONT_SMALL)
        self.ts_label.pack(anchor="w", pady=(4, 0))

        # Score bar
        ttk.Label(card, text="Score", style="Subtext.TLabel",
                  font=_FONT_SMALL).pack(anchor="w", pady=(12, 2))
        self.progress = ttk.Progressbar(card, orient="horizontal",
                                        length=200, maximum=100,
                                        style="Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(0, 4))

        ttk.Separator(card, orient="horizontal").pack(fill="x", pady=8)

        # Rules list
        ttk.Label(card, text="Triggered Rules",
                  style="Subtext.TLabel").pack(anchor="w", pady=(0, 4))

        rules_frame = ttk.Frame(card, style="Surface.TFrame")
        rules_frame.pack(fill="both", expand=True)

        rules_sb = ttk.Scrollbar(rules_frame, orient="vertical")
        self.rules_list = tk.Listbox(
            rules_frame,
            font=_FONT_MONO,
            bg=_C["surface1"],
            fg=_C["text"],
            selectbackground=_C["overlay"],
            selectforeground=_C["text"],
            relief="flat",
            borderwidth=0,
            activestyle="none",
            yscrollcommand=rules_sb.set,
            height=8,
        )
        rules_sb.configure(command=self.rules_list.yview)
        rules_sb.pack(side="right", fill="y")
        self.rules_list.pack(side="left", fill="both", expand=True)

        # JSON preview
        ttk.Separator(card, orient="horizontal").pack(fill="x", pady=8)
        json_header = ttk.Frame(card, style="Surface.TFrame")
        json_header.pack(fill="x")
        ttk.Label(json_header, text="JSON Output",
                  style="Subtext.TLabel").pack(side="left")
        ttk.Button(json_header, text="Copy",
                   command=self._copy_json).pack(side="right")

        json_frame = ttk.Frame(card, style="Surface.TFrame", padding=1)
        json_frame.pack(fill="both", expand=True, pady=(4, 0))

        json_sb = ttk.Scrollbar(json_frame, orient="vertical")
        self.json_text = tk.Text(
            json_frame,
            font=("Courier", 9),
            bg=_C["bg"],
            fg=_C["subtext"],
            insertbackground=_C["text"],
            relief="flat",
            padx=6,
            pady=4,
            state="disabled",
            height=7,
            yscrollcommand=json_sb.set,
        )
        json_sb.configure(command=self.json_text.yview)
        json_sb.pack(side="right", fill="y")
        self.json_text.pack(side="left", fill="both", expand=True)

    def _build_status_bar(self) -> None:
        ttk.Separator(self.root, orient="horizontal").pack(fill="x", padx=0)
        status_bar = ttk.Frame(self.root, padding=(12, 3))
        status_bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(status_bar, textvariable=self.status_var,
                  foreground=_C["subtext"], font=_FONT_SMALL,
                  background=_C["bg"]).pack(side="left")
        ttk.Label(status_bar,
                  text="LLM Injection Detector  •  MIT Licence",
                  foreground=_C["overlay"], font=_FONT_SMALL,
                  background=_C["bg"]).pack(side="right")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_threshold_change(self, _: str) -> None:
        val = self.threshold_var.get()
        self.thresh_display.configure(text=f" {val} ")
        self.detector = LLMInjectionDetector(
            safe_threshold=val,
            suspicious_threshold=val + 30,
        )

    def _analyse(self) -> None:
        text = self.input_text.get("1.0", "end-1c").strip()
        if not text:
            self.status_var.set("Enter text to analyse.")
            return
        result = self.detector.detect(text)
        self._last_result = result
        self._batch_results = [result]
        self._display_result(result)
        self.status_var.set(
            f"Analysed 1 text — label: {result.label.value}  "
            f"score: {result.score}/100"
        )

    def _display_result(self, result: DetectionResult) -> None:
        colour = _LABEL_COLOURS[result.label]

        self.score_label.configure(text=str(result.score),
                                   foreground=colour)
        self.result_label.configure(text=result.label.value, foreground=colour)
        self.ts_label.configure(text=result.timestamp)

        self.progress["value"] = result.score
        # Tint the progress bar
        style = ttk.Style()
        bar_colour = colour
        style.configure("Horizontal.TProgressbar", background=bar_colour)

        self.rules_list.delete(0, "end")
        if result.rules_triggered:
            for rule in result.rules_triggered:
                entry = (
                    f"  [{rule['category']}]"
                    f"  weight={rule['weight']}"
                    f"  {rule['pattern'][:42]}"
                )
                self.rules_list.insert("end", entry)
        else:
            self.rules_list.insert("end", "  No rules triggered — input appears safe.")

        self._update_json(result.to_json())

    def _display_batch(self, results: List[DetectionResult]) -> None:
        if not results:
            return
        worst = max(results, key=lambda r: r.score)
        self._display_result(worst)
        combined = json.dumps([r.to_dict() for r in results], indent=2)
        self._update_json(combined)

    def _update_json(self, content: str) -> None:
        self.json_text.configure(state="normal")
        self.json_text.delete("1.0", "end")
        self.json_text.insert("end", content)
        self.json_text.configure(state="disabled")

    def _clear(self) -> None:
        self.input_text.delete("1.0", "end")
        self.rules_list.delete(0, "end")
        self.json_text.configure(state="normal")
        self.json_text.delete("1.0", "end")
        self.json_text.configure(state="disabled")
        self.score_label.configure(text="—", foreground=_C["subtext"])
        self.result_label.configure(text="NOT ANALYSED",
                                    foreground=_C["subtext"])
        self.ts_label.configure(text="")
        self.progress["value"] = 0
        self._last_result = None
        self._batch_results = []
        self.status_var.set("Cleared.")

    def _open_file(self) -> None:
        path = fd.askopenfilename(
            title="Open text file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
            texts = [ln for ln in lines if ln.strip()]
        except OSError as exc:
            mb.showerror("File Error", str(exc))
            return

        if not texts:
            mb.showinfo("Empty File", "The selected file contains no text.")
            return

        results = self.detector.detect_batch(texts)
        self._batch_results = results
        injection = sum(1 for r in results if r.label == Label.INJECTION)
        suspicious = sum(1 for r in results if r.label == Label.SUSPICIOUS)

        self.input_text.delete("1.0", "end")
        self.input_text.insert("end", "\n".join(texts))

        self._display_batch(results)
        self.status_var.set(
            f"Analysed {len(results)} lines from {Path(path).name} — "
            f"injection: {injection}  suspicious: {suspicious}"
        )

    def _export_json(self) -> None:
        if not self._batch_results:
            mb.showinfo("Nothing to Export", "Run an analysis first.")
            return
        path = fd.asksaveasfilename(
            title="Export JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        data = [r.to_dict() for r in self._batch_results]
        try:
            Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
            self.status_var.set(f"Exported to {Path(path).name}")
        except OSError as exc:
            mb.showerror("Export Error", str(exc))

    def _copy_json(self) -> None:
        content = self.json_text.get("1.0", "end-1c")
        if content.strip():
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self.status_var.set("JSON copied to clipboard.")

    def _show_about(self) -> None:
        mb.showinfo(
            "About LLM Injection Detector",
            f"LLM Injection Detector  v{__version__}\n\n"
            "Rule-based detection of prompt injection, jailbreak, "
            "system-extraction, and data-exfiltration attacks.\n\n"
            "36 patterns across 11 threat categories.\n\n"
            "Author: Vaibhav Deshmukh\n"
            "Licence: MIT",
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def launch_gui() -> None:
    """Launch the GUI application."""
    root = tk.Tk()
    DetectorApp(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
