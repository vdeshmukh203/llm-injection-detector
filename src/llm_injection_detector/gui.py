"""
Flask-based web GUI for llm-injection-detector.

Launch via the CLI:
    llm-injection-detector --gui [--port 5000]

Or programmatically:
    from llm_injection_detector.gui import create_app
    app = create_app()
    app.run()

The GUI provides:
  - Text input area with real-time analysis
  - Colour-coded score gauge (SAFE / SUSPICIOUS / INJECTION)
  - Per-rule breakdown table
  - Threshold configuration sliders
  - JSON export of any result
  - Analysis history
"""

from __future__ import annotations

import json
import sys
import pathlib
from typing import Any, Dict

try:
    from flask import Flask, request, jsonify, render_template_string
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "Flask is required for the GUI. Install with: "
        "pip install 'llm-injection-detector[gui]'"
    ) from exc

# Support running the module directly (python -m llm_injection_detector.gui)
# as well as when imported from the installed package.
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
try:
    from llm_injection_detector import LLMInjectionDetector, Label
except ImportError:
    from detector import LLMInjectionDetector, Label  # type: ignore


# ---------------------------------------------------------------------------
# HTML template (single-file, no external static directory required)
# ---------------------------------------------------------------------------

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>LLM Injection Detector</title>
  <style>
    /* ---- Reset & base ---- */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #1e1e2e;
      color: #cdd6f4;
      min-height: 100vh;
    }

    /* ---- Layout ---- */
    header {
      background: #181825;
      padding: 1rem 2rem;
      display: flex;
      align-items: baseline;
      gap: 0.75rem;
      border-bottom: 1px solid #313244;
    }
    header h1 { font-size: 1.5rem; color: #cba6f7; }
    header .version { font-size: 0.8rem; color: #6c7086; }

    main {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.5rem;
      padding: 1.5rem;
      max-width: 1400px;
      margin: 0 auto;
    }
    @media (max-width: 800px) {
      main { grid-template-columns: 1fr; }
    }

    /* ---- Cards ---- */
    .card {
      background: #181825;
      border: 1px solid #313244;
      border-radius: 10px;
      padding: 1.25rem;
    }
    .card h2 {
      font-size: 1rem;
      font-weight: 600;
      color: #89dceb;
      margin-bottom: 0.75rem;
    }

    /* ---- Input area ---- */
    #inputText {
      width: 100%;
      height: 180px;
      background: #313244;
      border: 1px solid #45475a;
      border-radius: 6px;
      color: #cdd6f4;
      font-family: 'Courier New', monospace;
      font-size: 0.9rem;
      padding: 0.75rem;
      resize: vertical;
      transition: border-color 0.2s;
    }
    #inputText:focus { outline: none; border-color: #cba6f7; }

    /* ---- Settings ---- */
    .settings-grid {
      display: grid;
      grid-template-columns: auto 1fr auto;
      gap: 0.5rem 0.75rem;
      align-items: center;
      margin-top: 0.5rem;
    }
    .settings-grid label { font-size: 0.85rem; color: #a6adc8; }
    .settings-grid input[type=range] { width: 100%; accent-color: #cba6f7; }
    .settings-grid .val { font-size: 0.85rem; min-width: 2.5rem; text-align: right; }

    /* ---- Buttons ---- */
    .btn-row { display: flex; gap: 0.5rem; margin-top: 0.75rem; flex-wrap: wrap; }
    button {
      padding: 0.5rem 1.25rem;
      border: none;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.9rem;
      font-weight: 600;
      transition: opacity 0.15s;
    }
    button:hover { opacity: 0.85; }
    #analyzeBtn { background: #cba6f7; color: #1e1e2e; }
    .btn-secondary { background: #313244; color: #cdd6f4; }

    /* ---- Score gauge ---- */
    .score-area {
      display: flex;
      align-items: center;
      gap: 1.5rem;
      margin-bottom: 1rem;
    }
    .gauge-wrap { position: relative; width: 110px; height: 110px; flex-shrink: 0; }
    .gauge-wrap svg { transform: rotate(-90deg); }
    .gauge-bg { fill: none; stroke: #313244; stroke-width: 10; }
    .gauge-arc { fill: none; stroke-width: 10; stroke-linecap: round;
      stroke-dasharray: 283; stroke-dashoffset: 283;
      transition: stroke-dashoffset 0.5s ease, stroke 0.5s ease; }
    .gauge-text {
      position: absolute; top: 50%; left: 50%;
      transform: translate(-50%, -50%);
      text-align: center;
    }
    .gauge-text .score-val { font-size: 1.8rem; font-weight: 700; }
    .gauge-text .score-max { font-size: 0.7rem; color: #6c7086; }

    .label-badge {
      display: inline-block;
      padding: 0.3rem 1rem;
      border-radius: 999px;
      font-size: 1.2rem;
      font-weight: 700;
      margin-top: 0.25rem;
    }
    .label-SAFE       { background: #1e3a2f; color: #a6e3a1; }
    .label-SUSPICIOUS { background: #3a2e1e; color: #fab387; }
    .label-INJECTION  { background: #3a1e1e; color: #f38ba8; }

    /* ---- Rules table ---- */
    .table-wrap { overflow-x: auto; max-height: 260px; overflow-y: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
    th {
      background: #313244; color: #89b4fa;
      padding: 0.4rem 0.6rem; text-align: left;
      position: sticky; top: 0; z-index: 1;
    }
    td { padding: 0.35rem 0.6rem; border-bottom: 1px solid #313244; }
    tr:hover td { background: #26263a; }

    /* ---- History ---- */
    #historyList { list-style: none; max-height: 220px; overflow-y: auto; }
    #historyList li {
      display: flex; gap: 0.5rem; align-items: center;
      padding: 0.4rem 0.5rem;
      border-bottom: 1px solid #313244;
      cursor: pointer;
      font-size: 0.82rem;
    }
    #historyList li:hover { background: #26263a; }
    .hist-score { min-width: 2rem; text-align: right; font-weight: 600; }
    .hist-label { min-width: 5rem; }
    .hist-text  { color: #a6adc8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    /* ---- Misc ---- */
    .empty-msg { color: #6c7086; font-size: 0.85rem; padding: 1rem 0; }
    .ts { font-size: 0.78rem; color: #6c7086; }
    #exportBtn { display: none; }
  </style>
</head>
<body>

<header>
  <h1>LLM Injection Detector</h1>
  <span class="version">v{{ version }}</span>
</header>

<main>
  <!-- Left column: input + settings -->
  <div>
    <div class="card">
      <h2>Input</h2>
      <textarea id="inputText" placeholder="Paste prompt or user input here…"></textarea>

      <h2 style="margin-top:1rem;">Thresholds</h2>
      <div class="settings-grid">
        <label>Safe (&lt;)</label>
        <input type="range" id="safeThresh" min="5" max="55" value="30"
               oninput="document.getElementById('safeVal').textContent=this.value" />
        <span class="val" id="safeVal">30</span>

        <label>Injection (≥)</label>
        <input type="range" id="injThresh" min="35" max="95" value="60"
               oninput="document.getElementById('injVal').textContent=this.value" />
        <span class="val" id="injVal">60</span>
      </div>

      <div class="btn-row">
        <button id="analyzeBtn" onclick="analyze()">Analyze</button>
        <button class="btn-secondary" onclick="clearAll()">Clear</button>
        <button class="btn-secondary" id="exportBtn" onclick="exportJSON()">Export JSON</button>
      </div>
    </div>

    <!-- History -->
    <div class="card" style="margin-top:1.5rem;">
      <h2>History</h2>
      <ul id="historyList"><li class="empty-msg">No analyses yet.</li></ul>
    </div>
  </div>

  <!-- Right column: results -->
  <div>
    <div class="card" id="resultsCard">
      <h2>Result</h2>

      <div class="score-area">
        <div class="gauge-wrap">
          <svg viewBox="0 0 100 100" width="110" height="110">
            <circle class="gauge-bg" cx="50" cy="50" r="45" />
            <circle class="gauge-arc" id="gaugeArc" cx="50" cy="50" r="45" stroke="#6c7086"/>
          </svg>
          <div class="gauge-text">
            <div class="score-val" id="scoreVal" style="color:#6c7086">—</div>
            <div class="score-max">/100</div>
          </div>
        </div>

        <div>
          <div style="color:#6c7086;font-size:0.8rem;">Classification</div>
          <span class="label-badge" id="labelBadge">—</span>
          <div class="ts" id="tsDisplay"></div>
        </div>
      </div>

      <h2>Rules Triggered</h2>
      <div class="table-wrap">
        <table id="rulesTable">
          <thead>
            <tr><th>Category</th><th>Weight</th><th>Pattern (truncated)</th></tr>
          </thead>
          <tbody id="rulesBody">
            <tr><td colspan="3" class="empty-msg">Run an analysis to see results.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</main>

<script>
  const history = [];
  let lastResult = null;

  const COLORS = { SAFE: '#a6e3a1', SUSPICIOUS: '#fab387', INJECTION: '#f38ba8' };
  const CIRC = 2 * Math.PI * 45;   // circumference for r=45

  async function analyze() {
    const text = document.getElementById('inputText').value.trim();
    if (!text) { alert('Please enter some text.'); return; }

    const safe = parseInt(document.getElementById('safeThresh').value);
    const inj  = parseInt(document.getElementById('injThresh').value);

    const resp = await fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, safe_threshold: safe, suspicious_threshold: inj })
    });
    const data = await resp.json();
    lastResult = data;
    displayResult(data);
    addHistory(data, text);
  }

  function displayResult(data) {
    const color = COLORS[data.label] || '#6c7086';
    const score = data.score;

    // Gauge arc
    const arc = document.getElementById('gaugeArc');
    const offset = CIRC * (1 - score / 100);
    arc.style.strokeDashoffset = offset;
    arc.style.stroke = color;

    // Score text
    const sv = document.getElementById('scoreVal');
    sv.textContent = score;
    sv.style.color = color;

    // Label badge
    const lb = document.getElementById('labelBadge');
    lb.textContent = data.label;
    lb.className = 'label-badge label-' + data.label;

    // Timestamp
    document.getElementById('tsDisplay').textContent = data.timestamp
      ? 'Analysed: ' + data.timestamp.slice(0, 19) + ' UTC' : '';

    // Rules table
    const tbody = document.getElementById('rulesBody');
    tbody.innerHTML = '';
    if (data.rules_triggered && data.rules_triggered.length > 0) {
      data.rules_triggered.forEach(r => {
        const tr = document.createElement('tr');
        const cat = r.category.replace(/_/g, ' ')
          .replace(/\\b\\w/g, c => c.toUpperCase());
        tr.innerHTML = `<td>${cat}</td><td>${r.weight}</td><td style="font-family:monospace;font-size:0.75rem">${r.pattern}</td>`;
        tbody.appendChild(tr);
      });
    } else {
      tbody.innerHTML = '<tr><td colspan="3" class="empty-msg">No rules triggered — text appears safe.</td></tr>';
    }

    document.getElementById('exportBtn').style.display = 'inline-block';
  }

  function addHistory(data, text) {
    history.unshift({ data, text });
    const ul = document.getElementById('historyList');
    if (ul.querySelector('.empty-msg')) ul.innerHTML = '';

    const color = COLORS[data.label] || '#6c7086';
    const li = document.createElement('li');
    li.onclick = () => loadHistory(history.length - 1 - ul.children.length + 1 +
      Array.from(ul.children).indexOf(li));
    li.innerHTML = `
      <span class="hist-score" style="color:${color}">${data.score}</span>
      <span class="hist-label" style="color:${color}">${data.label}</span>
      <span class="hist-text">${text.slice(0, 60)}${text.length > 60 ? '…' : ''}</span>`;
    ul.insertBefore(li, ul.firstChild);
  }

  function loadHistory(idx) {
    if (idx < 0 || idx >= history.length) return;
    const item = history[history.length - 1 - idx];
    document.getElementById('inputText').value = item.text;
    displayResult(item.data);
    lastResult = item.data;
  }

  function clearAll() {
    document.getElementById('inputText').value = '';
    document.getElementById('scoreVal').textContent = '—';
    document.getElementById('scoreVal').style.color = '#6c7086';
    document.getElementById('gaugeArc').style.strokeDashoffset = CIRC;
    document.getElementById('gaugeArc').style.stroke = '#6c7086';
    const lb = document.getElementById('labelBadge');
    lb.textContent = '—';
    lb.className = 'label-badge';
    document.getElementById('tsDisplay').textContent = '';
    document.getElementById('rulesBody').innerHTML =
      '<tr><td colspan="3" class="empty-msg">Run an analysis to see results.</td></tr>';
    document.getElementById('exportBtn').style.display = 'none';
    lastResult = null;
  }

  function exportJSON() {
    if (!lastResult) return;
    const blob = new Blob([JSON.stringify(lastResult, null, 2)],
                          { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'detection_result.json';
    a.click();
  }

  // Allow Ctrl+Enter to trigger analysis
  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('inputText').addEventListener('keydown', e => {
      if (e.key === 'Enter' && e.ctrlKey) analyze();
    });
  });
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Flask application factory
# ---------------------------------------------------------------------------

def create_app(detector: "LLMInjectionDetector | None" = None) -> Flask:
    """
    Create and return a configured Flask application.

    Parameters
    ----------
    detector : LLMInjectionDetector, optional
        Custom detector instance. If omitted a default one is created.

    Returns
    -------
    Flask
        The Flask application object; call ``app.run()`` to start the server.
    """
    try:
        from llm_injection_detector import __version__
    except ImportError:
        __version__ = "0.1.0"

    app = Flask(__name__)
    _detector = detector or LLMInjectionDetector()

    @app.route("/")
    def index():
        return render_template_string(_HTML, version=__version__)

    @app.route("/analyze", methods=["POST"])
    def analyze() -> Any:
        data: Dict = request.get_json(force=True) or {}
        text: str = data.get("text", "")
        safe_thresh: int = int(data.get("safe_threshold", 30))
        inj_thresh: int = int(data.get("suspicious_threshold", 60))

        # Clamp thresholds to sensible range
        safe_thresh = max(0, min(safe_thresh, 99))
        inj_thresh = max(safe_thresh + 1, min(inj_thresh, 100))

        det = LLMInjectionDetector(
            safe_threshold=safe_thresh,
            suspicious_threshold=inj_thresh,
        )
        result = det.detect(text)
        return jsonify(result.to_dict())

    @app.route("/batch", methods=["POST"])
    def analyze_batch() -> Any:
        data: Dict = request.get_json(force=True) or {}
        texts = data.get("texts", [])
        if not isinstance(texts, list):
            return jsonify({"error": "texts must be a list"}), 400
        results = _detector.detect_batch(texts)
        return jsonify([r.to_dict() for r in results])

    return app


def main():  # pragma: no cover
    """Entry point for ``llm-injection-detector-gui`` console script."""
    import argparse

    parser = argparse.ArgumentParser(description="LLM Injection Detector – Web GUI")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    app = create_app()
    print(f"LLM Injection Detector GUI → http://{args.host}:{args.port}/")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
