# Changelog

All notable changes to llm-injection-detector are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-05-09

### Added
- `gui.py`: interactive Tkinter GUI for point-and-click injection analysis,
  with colour-coded score bar, rules list, threshold sliders, file loading,
  and JSON export.
- New `--safe-threshold` / `--suspicious-threshold` CLI flags (replacing the
  ambiguous `--threshold` flag; old flag removed).
- `__version__`, `__author__`, `__license__` module attributes.
- `__all__` export list in the root module.
- `llm-injection-detector-gui` console-script entry point.

### Changed
- `detect_batch` now isolates per-item exceptions so one bad input cannot
  abort the rest of the batch.
- `DetectionResult.timestamp` now uses UTC-aware `datetime.now(timezone.utc)`
  instead of the deprecated `datetime.utcnow()`.
- Renamed internal `_rules` dict (was `rules`) to make it clearly private.
- Improved docstrings throughout to NumPy/Google style for JOSS compatibility.

### Fixed
- `pyproject.toml` entry-point pointed at non-existent `_cli` symbol; now
  correctly references `main` (a `_cli = main` alias is also kept for any
  existing installs).
- `src/llm_injection_detector/__init__.py` imported from `.detector` and
  `.report` sub-modules that do not exist; now re-exports from the root module.
- Removed the unused `import base64` statement.
- Removed the unused `_init_rule_weights` method and `self.rule_weights`
  attribute (dead code — rule weights live in `_init_rules` tuples).
- Removed misleading comment claiming logarithmic scaling in `_calculate_score`
  (the formula is linear with a rule-count multiplier, not logarithmic).
- `LLMInjectionDetector.__init__` now raises `ValueError` when
  `safe_threshold >= suspicious_threshold`.

## [0.1.0] - 2025-01-15

### Added
- Initial release of LLM Injection Detector.
- Pattern library of 25+ heuristic detection rules across 11 attack categories
  (direct injection, jailbreak/DAN, mode activation, system extraction, data
  exfiltration, Base64 encoding, Unicode manipulation, homoglyph attacks,
  protocol redirect, meta-instructions, sensitive keywords).
- Configurable scoring engine with SAFE / SUSPICIOUS / INJECTION thresholds.
- `detect`, `detect_batch`, and `analyze_rules` module-level convenience
  functions backed by a shared `LLMInjectionDetector` instance.
- CLI with `--text`, `--file`, `--format`, `--verbose`, and `--show-rules`
  flags; exit codes 0/1/2 for SAFE/SUSPICIOUS/INJECTION.
- `DetectionResult.to_dict()` and `DetectionResult.to_json()` for structured
  output suitable for CI pipeline integration.
- Unicode NFKD normalisation and URL-percent decoding in the pre-processing
  pipeline.
- Unit tests with pytest covering imports and basic detection.
- GitHub Actions CI workflow.
