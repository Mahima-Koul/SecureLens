# SecureLens Checklist

## Repository setup and environment
- [ ] Confirm Python 3.11+ and create a virtual environment.
- [ ] Install requirements and configure `.env` from `.env.example`.

## M1 — Foundation and LLM infrastructure
- [x] Create project skeleton, dependencies, config, models, prompts, README stub.
- [x] Implement OpenAI Responses API client, validated disk cache, offline mode.
- [x] Acceptance: repeated operation uses cache; offline hit and miss tested (3 passed).
- [x] Run `python -m pytest -q tests/test_llm.py --basetemp=.pytest-tmp` (3 passed).

## M2 — Scanner, context, and samples
- [x] Implement Semgrep/Bandit scanner and AST context extraction.
- [x] Create four sample projects, tests, and ground truth.
- [x] Acceptance: scan CLI and sample pytest checks for all samples (scanner findings emitted; sample tests 18 passed).

## M3 — LLM triage
- [x] Implement conservative structured triage.
- [x] Acceptance: deterministic mocked SQLi/false-positive check; live API not configured.

## M4 — Patching and diffing
- [x] Implement path-safe patch copy, unified diff, and multiset classification.
- [x] Acceptance: original unchanged; patch copy and classification tests pass (6 passed).

## M5 — Regression and full pipeline
- [x] Implement regression tests, pipeline, and full CLI.
- [x] Acceptance: offline full pipeline completed on all four samples; mocked `wow_app` produced newly failing tests. Live model was unavailable and surfaced as unresolved/RISKY.

## M6 — Streamlit UI
- [x] Implement staged UI with sample/custom path, model/offline controls, findings and context, patch diff, rescan, regression, and status results.
- [x] Acceptance: Streamlit served on localhost; offline SQLi sample flow and session-state persistence were exercised in the browser.

## M7 — Evaluation, documentation, and final tests
- [x] Implement evaluation script with per-sample/aggregate metrics, ground-truth matching, LLM cache/API counters, and unknown outcomes for incomplete samples; complete README and schema docs.
- [x] Acceptance: 29 unit tests and 18 sample tests pass; offline evaluation generated for four samples; requirements and milestone evidence recorded.

## Final review
- [x] Final security and regression review; patch isolation and conservative failure states documented and checked.
- [x] README setup and CLI/UI/evaluation demo commands reviewed against the installed project environment.
