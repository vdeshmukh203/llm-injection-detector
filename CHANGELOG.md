# Changelog

All notable changes to llm-injection-detector are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Flask-based web GUI (`llm-injection-detector --gui` or `llm-injection-detector-gui`)
  with colour-coded score gauge, per-rule breakdown, threshold sliders, JSON export,
  and analysis history
- `src/llm_injection_detector/` package layout with proper sub-modules:
  - `detector.py` — self-contained core types and `LLMInjectionDetector`
  - `report.py` — `DetectionReport` for batch result aggregation
  - `gui.py` — Flask application factory
- `DetectionReport` class: `label_counts`, `average_score`, `max_score`,
  `flagged`, `summary_text()`, `to_json()`
- `llm-injection-detector-gui` console-script entry point (requires `[gui]` extra)
- `[gui]` and `[dev]` optional dependency groups in `pyproject.toml`
- 35 pytest tests covering API surface, safe/benign inputs, injection patterns,
  Unicode manipulation, batch detection, and custom threshold behaviour

### Fixed
- **False-positive data-exfiltration pattern**: the broad
  `\b(?:send|output|write|save|export)\s+(?:to|at|into|via)` rule was replaced
  with patterns that require an explicit URL or email address as the target,
  eliminating false positives on everyday phrases like "write to a file"
- **False-positive base64 pattern**: minimum match length increased from 20 to 60
  characters and `=`/`==` padding is now required, preventing short tokens,
  UUIDs, and random identifiers from triggering the rule
- **Missing `_cli` entry-point symbol**: `pyproject.toml` declared
  `llm_injection_detector:_cli` as the CLI entry point but the function was not
  defined, making the installed `llm-injection-detector` command crash on launch;
  `_cli = main` alias now defined in the module
- **Homoglyph detection after NFKD normalization**: replaced the literal
  Cyrillic/Latin mixed-character pattern (which was silently discarded after
  Unicode normalization) with a mixed-script adjacency regex that fires correctly
  on post-normalization text
- **Overly broad `jailbreak_dan` sub-patterns**: tightened "evil/malicious" rule
  to require a following noun (mode/version/ai/assistant) to avoid flagging
  normal adjective use
- **Inaccurate score-calculation comment**: the formula previously claimed
  logarithmic diminishing returns but used a linear expression; replaced with
  `log1p(w / 8) × 45` which genuinely provides logarithmic scaling

### Changed
- Scoring formula now uses `log1p(total_weight / 8) × 45` (logarithmic
  diminishing returns) instead of the previous linear `total_weight × (1 + 0.1 × rule_count)`
- `_calculate_score` no longer takes `rule_count` as a parameter (the logarithmic
  formula makes it redundant)
- CLI `--text`/`--file` arguments are now optional when `--gui` is specified;
  a mutually-exclusive group ensures exactly one input mode is used

## [0.1.0] - 2024-01-15

### Added
- Initial release of LLM Injection Detector
- Rule-based heuristic detection engine with 11 attack categories and 30+ patterns
- `LLMInjectionDetector` class with configurable `safe_threshold` and
  `suspicious_threshold` parameters and optional `verbose` logging
- `DetectionResult` dataclass with `score`, `label`, `rules_triggered`,
  `timestamp`, `to_dict()`, and `to_json()` members
- `Label` enum (`SAFE`, `SUSPICIOUS`, `INJECTION`)
- `Rule` dataclass for named rule definitions
- Module-level convenience functions: `detect()`, `detect_batch()`, `analyze_rules()`
- CLI with `--text`, `--file`, `--format`, `--threshold`, `--verbose`, and
  `--show-rules` flags; exits with code 0/1/2 reflecting result severity
- `InjectionDetector` alias for backwards compatibility
- MIT license, `pyproject.toml` build configuration, and GitHub Actions CI workflow
- JOSS paper draft (`paper.md`) and BibTeX bibliography (`paper.bib`)
- `CITATION.cff` for software citation metadata
