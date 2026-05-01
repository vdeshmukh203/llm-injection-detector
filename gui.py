"""
Tkinter desktop GUI for llm-injection-detector.

Launch:
    python gui.py
    llm-injection-detector --gui
    llm-injection-detector-gui
"""

import sys
import pathlib
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from llm_injection_detector import LLMInjectionDetector, Label

# Colour palette for each verdict
_FG = {
    Label.SAFE.value:       "#1a7f37",
    Label.SUSPICIOUS.value: "#b5500b",
    Label.INJECTION.value:  "#c0392b",
}
_BG = {
    Label.SAFE.value:       "#d1f0db",
    Label.SUSPICIOUS.value: "#fde9d3",
    Label.INJECTION.value:  "#fcd4d4",
}

_PLACEHOLDER = "Enter or paste text to analyse here…"
_PLACEHOLDER_FG = "#999999"


class App(tk.Tk):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.title("LLM Injection Detector")
        self.geometry("980x680")
        self.minsize(720, 520)
        self.configure(bg="#f0f0f0")
        self._build()

    # ------------------------------------------------------------------
    # Layout construction
    # ------------------------------------------------------------------

    def _build(self):
        self._build_header()
        body = self._build_body()
        self._build_left(body)
        right = self._build_right(body)
        self._build_score_card(right)
        self._build_rules_panel(right)
        self._build_settings(right)
        self._build_statusbar()

    def _build_header(self):
        hdr = tk.Frame(self, bg="#1a252f")
        hdr.pack(fill="x")
        tk.Label(
            hdr, text="LLM Injection Detector",
            font=("Helvetica", 17, "bold"), fg="white", bg="#1a252f", pady=8,
        ).pack()
        tk.Label(
            hdr, text="Heuristic prompt-injection & jailbreak scanner  •  v0.1.0",
            font=("Helvetica", 9), fg="#95a5a6", bg="#1a252f", pady=4,
        ).pack()

    def _build_body(self) -> tk.PanedWindow:
        body = tk.PanedWindow(self, orient="horizontal", sashpad=4, bg="#cccccc")
        body.pack(fill="both", expand=True, padx=6, pady=6)
        return body

    def _build_left(self, body: tk.PanedWindow):
        left = ttk.LabelFrame(body, text=" Input Text ", padding=4)
        body.add(left, minsize=300)
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)

        self._input = scrolledtext.ScrolledText(
            left, wrap="word", font=("Courier New", 11), undo=True, height=18,
        )
        self._input.grid(row=0, column=0, sticky="nsew")
        self._input.insert("1.0", _PLACEHOLDER)
        self._input.config(fg=_PLACEHOLDER_FG)
        self._input.bind("<FocusIn>", self._clear_placeholder)

        btn_row = tk.Frame(left, bg="#f0f0f0")
        btn_row.grid(row=1, column=0, sticky="ew", pady=(5, 0))

        tk.Button(
            btn_row, text="  Analyse  ", command=self._analyse,
            bg="#2980b9", fg="white", font=("Helvetica", 11, "bold"),
            relief="flat", padx=6, pady=4, cursor="hand2",
        ).pack(side="left")
        tk.Button(
            btn_row, text="  Clear  ", command=self._clear_all,
            bg="#7f8c8d", fg="white", font=("Helvetica", 11),
            relief="flat", padx=6, pady=4, cursor="hand2",
        ).pack(side="left", padx=(6, 0))

    def _build_right(self, body: tk.PanedWindow) -> ttk.Frame:
        right = ttk.Frame(body)
        body.add(right, minsize=340)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        return right

    def _build_score_card(self, parent: ttk.Frame):
        card = ttk.LabelFrame(parent, text=" Detection Result ", padding=10)
        card.grid(row=0, column=0, sticky="ew", padx=4, pady=(0, 4))
        card.columnconfigure(2, weight=1)

        tk.Label(card, text="Score:", font=("Helvetica", 11)).grid(
            row=0, column=0, sticky="w")
        self._score_var = tk.StringVar(value="—")
        tk.Label(card, textvariable=self._score_var,
                 font=("Helvetica", 14, "bold"), width=9).grid(
            row=0, column=1, sticky="w", padx=8)
        self._bar = ttk.Progressbar(card, length=180, maximum=100)
        self._bar.grid(row=0, column=2, sticky="ew")

        tk.Label(card, text="Label:", font=("Helvetica", 11)).grid(
            row=1, column=0, sticky="w", pady=(6, 0))
        self._label_var = tk.StringVar(value="—")
        self._badge = tk.Label(
            card, textvariable=self._label_var,
            font=("Helvetica", 13, "bold"), width=14, relief="groove", pady=3,
        )
        self._badge.grid(row=1, column=1, columnspan=2, sticky="w",
                         padx=8, pady=(6, 0))

    def _build_rules_panel(self, parent: ttk.Frame):
        frame = ttk.LabelFrame(parent, text=" Rules Triggered ", padding=4)
        frame.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self._rules = scrolledtext.ScrolledText(
            frame, wrap="word", font=("Courier New", 10),
            state="disabled", bg="#f9f9f9", height=12,
        )
        self._rules.grid(row=0, column=0, sticky="nsew")

    def _build_settings(self, parent: ttk.Frame):
        cfg = ttk.LabelFrame(parent, text=" Thresholds ", padding=6)
        cfg.grid(row=2, column=0, sticky="ew", padx=4, pady=(0, 4))

        self._safe_t = tk.IntVar(value=30)
        self._inj_t = tk.IntVar(value=60)

        tk.Label(cfg, text="Safe ≤").grid(row=0, column=0, sticky="w")
        ttk.Scale(cfg, from_=0, to=99, variable=self._safe_t,
                  orient="horizontal", length=140).grid(row=0, column=1, padx=4)
        tk.Label(cfg, textvariable=self._safe_t, width=3).grid(row=0, column=2)

        tk.Label(cfg, text="Injection ≥").grid(row=1, column=0, sticky="w")
        ttk.Scale(cfg, from_=1, to=100, variable=self._inj_t,
                  orient="horizontal", length=140).grid(row=1, column=1, padx=4)
        tk.Label(cfg, textvariable=self._inj_t, width=3).grid(row=1, column=2)

    def _build_statusbar(self):
        self._status = tk.StringVar(value="Ready — enter text and click Analyse.")
        tk.Label(
            self, textvariable=self._status, anchor="w",
            relief="sunken", font=("Helvetica", 9), bg="#ecf0f1", padx=6,
        ).pack(side="bottom", fill="x")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _clear_placeholder(self, _event=None):
        if self._input.cget("fg") == _PLACEHOLDER_FG:
            self._input.delete("1.0", "end")
            self._input.config(fg="black")

    def _restore_placeholder(self):
        self._input.insert("1.0", _PLACEHOLDER)
        self._input.config(fg=_PLACEHOLDER_FG)

    def _clear_all(self):
        self._input.delete("1.0", "end")
        self._restore_placeholder()
        self._score_var.set("—")
        self._bar["value"] = 0
        self._label_var.set("—")
        self._badge.config(bg=self.cget("bg"), fg="black")
        self._write_rules("")
        self._status.set("Cleared.")

    def _analyse(self):
        self._clear_placeholder()
        text = self._input.get("1.0", "end").strip()

        if not text:
            messagebox.showwarning("Input required",
                                   "Please enter some text to analyse.")
            return

        safe_t = self._safe_t.get()
        inj_t = self._inj_t.get()
        if safe_t >= inj_t:
            messagebox.showerror(
                "Invalid thresholds",
                "Safe threshold must be strictly less than the injection threshold.",
            )
            return

        det = LLMInjectionDetector(safe_threshold=safe_t, suspicious_threshold=inj_t)
        res = det.detect(text)

        # Score
        self._score_var.set(f"{res.score} / 100")
        self._bar["value"] = res.score

        # Label badge
        lbl = res.label.value
        self._label_var.set(lbl)
        self._badge.config(fg=_FG[lbl], bg=_BG[lbl])

        # Rules
        lines = []
        if res.rules_triggered:
            for rule in res.rules_triggered:
                lines.append(f"[{rule['category']}]  weight = {rule['weight']}")
                lines.append(f"  pattern : {rule['pattern']}")
                lines.append("")
        else:
            lines.append("No rules triggered — text appears safe.")
        self._write_rules("\n".join(lines))

        self._status.set(
            f"Done — score {res.score}/100  ({lbl}),  "
            f"{len(res.rules_triggered)} rule(s) triggered."
        )

    def _write_rules(self, text: str):
        self._rules.config(state="normal")
        self._rules.delete("1.0", "end")
        self._rules.insert("1.0", text)
        self._rules.config(state="disabled")


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def launch_gui():
    """Start the desktop GUI application."""
    app = App()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
