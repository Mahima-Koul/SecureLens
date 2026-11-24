# SecureLens data schema

Runtime models are Pydantic v2 models in `securelens/models.py`. CLI `--json` serializes `PipelineReport` with `model_dump(mode="json")`. Lists are empty when measured and empty; unavailable pipeline stages use `null`. `errors` and `status_reasons` contain human-readable diagnostics, and `timings` are seconds.

## Finding

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable identifier for this normalized observation |
| `tool` | `semgrep` or `bandit` | Finding source (`semgrep` includes Semgrep\* Java rules) |
| `rule_id` | string | Scanner rule identifier |
| `file` | string | Project-relative path |
| `line` | integer | One-based source line |
| `severity` | `LOW`, `MEDIUM`, `HIGH` | Normalized scanner severity |
| `message` | string | Scanner description |
| `snippet` | string | Nearby source excerpt |
| `function_name` | string or null | Enclosing Java method or Python function when found |
| `cwe` | string or null | Extracted CWE identifier/label from rule metadata when available |
| `fingerprint` | string | Location-independent comparison fingerprint |

## Verdict

| Field | Type | Meaning |
|---|---|---|
| `finding_id` | string | Links to a `Finding.id` |
| `is_true_positive` | boolean | Structured model decision |
| `status` | `confirmed`, `dismissed`, or `uncertain` | 3-way triage classification (`uncertain` when confidence is below threshold, grounding fails, or call is unresolved) |
| `confidence` | float (`0`–`1`) | Model confidence score |
| `reason` | string | Concise triage justification |
| `evidence_line` | integer or null | Source line number cited by the model (or fallback finding line) |
| `evidence_snippet` | string or null | Source code excerpt cited by the model |
| `grounding_verified` | boolean | Whether `verify_evidence_grounding()` verified the cited line and snippet in the real file |

A failed, ungrounded, or low-confidence triage is retained conservatively in `confirmed` (and marked `uncertain` in `status` / tracked in `unresolved` on failure).

## Patch and diff

`Patch` contains `file`, `original_code`, `patched_code`, unified `diff`, `explanation`, `addressed_finding_ids`, and `status` (`"pending"`, `"approved"`, or `"rejected"`, defaulting to `"pending"` for HITL review). `DiffResult` has `fixed`, `remaining`, and `new` lists of `Finding` records, compared as multisets so duplicate alerts are retained.

## Tests and regression

`TestResult` contains integer `passed`, `failed`, and `errors`, `failed_tests` identities, a bounded `raw_output_tail`, and `status` (`"ran"`, `"no_tests"`, or `"unavailable"`). `RegressionResult` contains `original` and `patched` `TestResult` values, `newly_failing` (test identities that failed only after patching), and `fixed_tests` (test identities that transitioned from failing to passing).

## PipelineReport

The report includes `project`, optional `patched_project`, initial `findings`, `verdicts`, `confirmed`, `dismissed`, `uncertain`, and `unresolved`; proposed `patches`; nullable `diff` and `regression`; `errors`; stage `timings`; `llm_stats` (`cache_hits`, `cache_misses`, `api_calls`); `final_status`; and `status_reasons`. `final_status` is `SAFE`, `RISKY`, or `INCOMPLETE`. Repositories where `TestResult.status` is `"no_tests"` or `"unavailable"` are marked `INCOMPLETE` rather than `SAFE`. Incomplete evaluation runs must not encode unavailable outcomes as zero.

## Ground truth

Each sample has a `ground_truth.json` object with an `expected_alerts` array. Every entry has `rule_id_or_category` (string matched against scanner rule/message), optional `line_hint` (integer, approximate match within eight lines), `is_real` (boolean), and optional `note` (string). Matching is intentionally best-effort because scanner rules and line locations may vary by installed rule versions. Evaluation reports unmatched expectations explicitly.
