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
- [ ] Implement path-safe patch copy, unified diff, and multiset classification.
- [ ] Acceptance: original unchanged; patch copy and classification tests pass.

## M5 — Regression and full pipeline
- [ ] Implement regression tests, pipeline, and full CLI.
- [ ] Acceptance: full pipeline runs on all four samples; `wow_app` demonstrates regression/new finding.

## M6 — Streamlit UI
- [ ] Implement staged UI and session-state persistence.
- [ ] Acceptance: `streamlit run ui/app.py` starts and sample flow is exercised.

## M7 — Evaluation, documentation, and final tests
- [ ] Implement evaluation script and complete README/docs.
- [ ] Acceptance: tests pass; evaluation generated; every requirement has a status.

## Final review
- [ ] Final security and regression review.
- [ ] README setup and demo verified from a clean environment.
