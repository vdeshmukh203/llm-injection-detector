# Changelog

All notable changes to `llm-injection-detector` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-04-27

### Added
- Tkinter graphical user interface (`gui.py` / `llm-injection-detector-gui`)
  with colour-coded result display, interactive score bar, batch file analysis,
  and JSON export.
- `LLMInjectionDetector.get_statistics(texts)` — aggregate safe/suspicious/
  injection counts and mean score over a list of texts.
- `LLMInjectionDetector.get_rule_categories()` — returns the list of active
  threat category names.
- `--version` flag for the CLI.
- `__version__`, `__author__`, `__license__` module attributes.
- Comprehensive test suite: 60+ tests covering all 11 threat categories, edge
  cases, batch processing, scoring invariants, and CLI behaviour.
- Full project documentation in `README.md`.

### Changed
- Pre-compile all regex patterns at initialisation for faster repeated calls.
- Replace `print()` verbose output with `logging.debug()`.
- `DetectionResult.timestamp` now uses timezone-aware UTC timestamps.
- `_TEXT_PREVIEW_LEN` increased from 100 to 120 characters.
- Move `urllib.parse.unquote` import to module level.
- Fix CLI entry point (`pyproject.toml` `[project.scripts]`): was referencing
  non-existent `_cli` symbol; now correctly points to `main`.
- Fix `src/llm_injection_detector/__init__.py`: was importing from non-existent
  `.detector` and `.report` sub-modules; now re-exports from the canonical
  root-level module.

### Fixed
- `LLMInjectionDetector.__init__` now raises `ValueError` when
  `safe_threshold >= suspicious_threshold`.
- Unicode manipulation patterns corrected to use proper Unicode escape ranges.

## [0.1.0] - 2024-01-15

### Added
- Initial release of `llm-injection-detector`.
- Rule-based detection engine with 36 patterns across 11 threat categories:
  direct injection, jailbreak/DAN, mode activation, system extraction, data
  exfiltration, Base-64 encoding, Unicode manipulation, homoglyph attacks,
  protocol redirect, meta-instructions, and sensitive keywords.
- Heuristic scoring engine with configurable sensitivity thresholds.
- Text normalisation pipeline: NFKD Unicode normalisation, URL-percent
  decoding, and whitespace collapse.
- CLI tool (`llm-injection-detector`) supporting single-text and file input,
  text and JSON output formats, configurable thresholds, and CI-friendly exit
  codes.
- `DetectionResult` dataclass with JSON serialisation helpers.
- Basic unit tests (5 tests).
