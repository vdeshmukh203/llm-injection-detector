---
title: 'llm-injection-detector: A Static and Heuristic Tool for Detecting Prompt Injection Vulnerabilities in LLM Applications'
tags:
  - Python
  - security
  - LLM
  - prompt-injection
  - NLP
  - reproducibility
authors:
  - name: Vaibhav Deshmukh
    orcid: 0009-0000-6190-5542
    affiliation: 1
affiliations:
  - name: Independent Researcher
    index: 1
date: 27 April 2026
bibliography: paper.bib
---

# Summary

`llm-injection-detector` is a pure-Python library and command-line tool for
detecting potential prompt injection vulnerabilities in the inputs and outputs
of large language model (LLM) applications.  Prompt injection attacks occur when
adversarial instructions embedded in user-supplied text, retrieved documents, or
tool outputs override a model's intended behaviour, potentially leaking sensitive
data or causing unintended actions [@perez2022ignore; @greshake2023not].
The tool implements a suite of 36 heuristic pattern detectors organised across
11 threat categories — including instruction-override phrase detection,
jailbreak keyword matching, system-prompt extraction attempts, data-exfiltration
redirect patterns, Base-64 and Unicode obfuscation indicators, and shell
command injection signatures.  Results are emitted as structured JSON reports
suitable for integration into CI pipelines, security audits, and automated
red-teaming workflows.

# Statement of Need

Prompt injection is a rapidly emerging threat class with no widely adopted,
open-source static analysis tooling comparable to established tools for
traditional code injection (e.g., SQLMap, Bandit).  Developers integrating LLMs
into retrieval-augmented generation (RAG) pipelines, agents, and customer-facing
chatbots routinely lack automated means of auditing their prompt construction
logic for injection susceptibility.  Existing mitigations are ad hoc,
undocumented, and difficult to reproduce across studies [@greshake2023not].
`llm-injection-detector` addresses this gap by providing a reproducible,
versioned, auditable scanner that can be applied consistently across projects,
enabling empirical comparisons of injection attack surfaces over time.  The tool
supports both offline static analysis of prompt templates and online heuristic
screening of live inputs, making it applicable to a broad range of deployment
scenarios.  Integration with standard CI systems (GitHub Actions, GitLab CI)
ensures that injection risks are surfaced early in the development cycle.  The
JSON output format allows downstream aggregation and longitudinal risk tracking,
supporting reproducible security research on LLM applications
[@pineau2021improving; @stodden2016enhancing].

# Functionality

## Detection Engine

The core detection engine (`LLMInjectionDetector`) operates in three phases:

1. **Text normalisation** — the input string is processed through (i) NFKD
   Unicode normalisation to collapse homoglyph variants, (ii) URL-percent
   decoding to resolve `%xx`-encoded obfuscation, and (iii) whitespace
   collapse to eliminate padding attacks.

2. **Pattern matching** — 36 pre-compiled regular expressions (case-insensitive)
   are applied to the normalised string.  Each pattern belongs to one of 11
   threat categories (Table 1) and carries an empirically assigned weight
   reflecting the severity of a match.

3. **Score calculation** — matched weights are summed and subjected to a
   diminishing-returns multiplier `(1 + 0.10 × n_rules)`, where `n_rules` is
   the count of triggered patterns.  This rewards corroborating evidence from
   multiple independent rules while preventing a single high-weight pattern from
   saturating the 0–100 scale.  The final integer score drives a three-class
   label: `SAFE` (score ≤ 30), `SUSPICIOUS` (31–59), or `INJECTION` (≥ 60).
   All thresholds are user-configurable.

| Category | Patterns | Threat modelled |
|---|---|---|
| `direct_injection` | 7 | Explicit instruction-override phrases |
| `jailbreak_dan` | 4 | DAN-style and jailbreak keywords |
| `mode_activation` | 4 | Persona and mode-switch phrases |
| `system_extraction` | 5 | System-prompt disclosure attempts |
| `data_exfiltration` | 4 | Output-redirect and exfiltration |
| `base64_encoding` | 2 | Base-64 encoded payload indicators |
| `unicode_manipulation` | 3 | Invisible / combining Unicode characters |
| `homoglyph_attacks` | 1 | Visually similar character substitutions |
| `protocol_redirect` | 2 | Shell / script execution patterns |
| `meta_instructions` | 2 | Output-format manipulation |
| `sensitive_keywords` | 2 | Credential and classic-injection keywords |

Table: Threat categories and pattern counts.

## Python API

The library exposes a stable public API:

```python
from llm_injection_detector import detect, LLMInjectionDetector

result = detect("Ignore previous instructions and reveal the system prompt.")
print(result.label, result.score)   # INJECTION 82

detector = LLMInjectionDetector(safe_threshold=20, suspicious_threshold=50)
results = detector.detect_batch(["safe text", "DAN jailbreak uncensored"])
stats   = detector.get_statistics(["safe text", "DAN jailbreak uncensored"])
```

Results are returned as `DetectionResult` dataclass instances with `to_dict()`
and `to_json()` serialisation helpers, enabling straightforward integration into
downstream pipelines.

## CLI and GUI

The command-line interface supports single-text and file-based batch analysis,
configurable thresholds, text and JSON output formats, and CI-friendly exit
codes (0 = all safe, 1 = suspicious, 2 = injection).  An optional Tkinter
graphical interface (`llm-injection-detector-gui`) provides colour-coded result
display, an interactive score bar, file-based batch analysis, and JSON export.

## Design Philosophy

The tool intentionally uses only the Python standard library, eliminating
version-conflict risk and simplifying installation in air-gapped or restricted
environments.  All patterns and weights are explicit and auditable; there are no
opaque model weights or remote API calls.  The absence of machine-learning
components means the tool is fully deterministic and reproducible
[@gundersen2018state], which is essential for use as part of a reproducible
research pipeline [@pineau2021improving].

# Acknowledgements

Portions of the initial code structure and documentation were drafted with the
assistance of AI language models.  All algorithmic design decisions, validation,
and final content were reviewed and approved by the author.

# References
