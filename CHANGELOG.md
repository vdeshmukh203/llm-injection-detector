# Changelog

All notable changes to llm-injection-detector are documented here.

## [0.1.0] - 2024-01-15

### Added
- Initial release of LLM Injection Detector
- Curated pattern library of 200+ known prompt injection signatures
- Heuristic scoring engine with configurable sensitivity thresholds
- Fine-tuned DistilBERT classifier for semantic injection detection
- Real-time scanning middleware compatible with OpenAI and Anthropic SDKs
- Labeled dataset of 5,000 injection and benign prompt pairs
- Evaluation scripts reporting precision, recall, and F1 on held-out test set
- REST API endpoint for third-party integration
- False positive reporting tool for dataset expansion
- Unit and integration tests with pytest
- README covering installation, threat model, and integration guide
