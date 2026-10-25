# SecureLens data schema

Runtime models are Pydantic v2 models in `securelens/models.py`. CLI `--json` serializes `PipelineReport` with `model_dump(mode="json")`. Lists are empty when measured and empty; unavailable pipeline stages use `null`. `errors` and `status_reasons` contain human-readable diagnostics, and `timings` are seconds.

## Finding

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable identifier for this normalized observation |
| `tool` | `semgrep` or `bandit` | Finding source |
| `rule_id` | string | Scanner rule identifier |
| `file` | string | Project-relative path |
| `line` | integer | One-based source line |
| `severity` | `LOW`, `MEDIUM`, `HIGH` | Normalized scanner severity |
| `message` | string | Scanner description |
| `snippet` | string | Nearby source excerpt |
| `function_name` | string or null | Enclosing Python function/method when found |
| `fingerprint` | string | Location-independent comparison fingerprint |

## Verdict

`finding_id` links to a Finding; `is_true_positive` is the structured model decision; `confidence` is a number from 0 to 1; `reason` is one concise sentence. A failed or unavailable triage is represented as a conservative positive verdict and tracked in `unresolved`.

## Patch and diff

`Patch` contains `file`, `original_code`, `patched_code`, unified `diff`, `explanation`, and `addressed_finding_ids`. `DiffResult` has `fixed`, `remaining`, and `new` lists of Finding records, compared as multisets so duplicate alerts are retained.

## Tests and regression

`TestResult` contains integer `passed`, `failed`, and `errors`, `failed_tests` identities, and a bounded `raw_output_tail`. `RegressionResult` contains `original` and `patched` TestResult values plus `newly_failing`, the test identities that failed only after patching.

## PipelineReport

The report includes `project`, optional `patched_project`, initial `findings`, `verdicts`, `confirmed`, `dismissed`, and `unresolved`; proposed `patches`; nullable `diff` and `regression`; `errors`; stage `timings`; `llm_stats` (`cache_hits`, `cache_misses`, `api_calls`); `final_status`; and `status_reasons`. `final_status` is `SAFE`, `RISKY`, or `INCOMPLETE`. Incomplete evaluation runs must not encode unavailable outcomes as zero.

## Ground truth

Each sample has a `ground_truth.json` object with an `expected_alerts` array. Every entry has `rule_id_or_category` (string matched against scanner rule/message), optional `line_hint` (integer, approximate match within eight lines), `is_real` (boolean), and optional `note` (string). Matching is intentionally best-effort because scanner rules and line locations may vary by installed rule versions. Evaluation reports unmatched expectations explicitly.
