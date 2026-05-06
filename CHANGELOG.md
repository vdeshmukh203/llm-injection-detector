# Changelog

All notable changes to llm-injection-detector are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-04-23

### Added

- Heuristic detection engine with 25+ regular-expression rules across 11 threat
  categories (direct injection, DAN jailbreaks, persona reassignment,
  system-prompt extraction, data exfiltration, base64 obfuscation, Unicode
  manipulation, homoglyph attacks, protocol-redirect, meta-instructions,
  sensitive keywords)
- Logarithmic diminishing-returns score formula (0–100) with configurable
  `safe_threshold` and `injection_threshold`
- Unicode NFKD normalisation and URL-percent-decode pre-processing to resist
  obfuscation
- `DetectionResult` dataclass with `to_dict()` / `to_json()` serialisation
- Module-level `detect`, `detect_batch`, and `analyze_rules` convenience
  functions
- `LLMInjectionDetector` class with `detect`, `detect_batch`, `analyze_rules`
  methods and per-instance threshold configuration
- Command-line interface (`llm-injection-detector`) with `--text`, `--file`,
  `--format` (text/JSON), `--safe-threshold`, `--injection-threshold`,
  `--verbose`, and `--show-rules` flags; exit codes 0/1/2
- Tkinter desktop GUI (`llm-injection-detector-gui`) with colour-coded label
  display, score bar, rules table, threshold sliders, batch file processing,
  and JSON result export
- Pytest test suite covering API surface, injection positives, false-positive
  control, batch processing, serialisation, threshold customisation, and edge
  cases
- MIT licence
