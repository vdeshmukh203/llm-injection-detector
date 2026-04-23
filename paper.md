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
date: 23 April 2026
bibliography: paper.bib
---

# Summary

`llm-injection-detector` is a Python command-line tool and library for detecting potential prompt injection vulnerabilities in inputs and outputs of large language model (LLM) applications. Prompt injection attacks occur when adversarial instructions embedded in user-supplied text, retrieved documents, or tool outputs override a model's intended behaviour, potentially leaking sensitive data or causing unintended actions [@perez2022ignore; @greshake2023not]. The tool implements a suite of heuristic detectors—including pattern matching, instruction-override phrase detection, role-reassignment detection, and context-escape analysis—alongside an optional static taint-tracking pass that traces untrusted data flows through application code. Results are emitted as structured JSON reports suitable for integration into CI pipelines, security audits, and automated red-teaming workflows.

# Statement of Need

Prompt injection is a rapidly emerging threat class with no widely adopted, open-source static analysis tooling comparable to established tools for traditional code injection (e.g., SQLMap, Bandit). Developers integrating LLMs into retrieval-augmented generation (RAG) pipelines, agents, and customer-facing chatbots routinely lack automated means of auditing their prompt construction logic for injection susceptibility. Existing mitigations are ad hoc, undocumented, and difficult to reproduce across studies [@greshake2023not]. `llm-injection-detector` addresses this gap by providing a reproducible, versioned, auditable scanner that can be applied consistently across projects, enabling empirical comparisons of injection attack surfaces over time. The tool supports both offline static analysis of prompt templates and online heuristic screening of live inputs, making it applicable to a broad range of deployment scenarios. Integration with standard CI systems (GitHub Actions, GitLab CI) ensures that injection risks are surfaced early in the development cycle. The JSON output format allows downstream aggregation and longitudinal risk tracking, supporting reproducible security research on LLM applications [@pineau2021improving; @stodden2016enhancing].

# Acknowledgements

Portions of the initial code structure and documentation were drafted with the assistance of AI language models. All algorithmic design decisions, validation, and final content were reviewed and approved by the author.

# References
