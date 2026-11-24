# SecureLens

SecureLens is a **9-stage AI-assisted security review and automated patch verification platform** focused on **Java** (powered by **Semgrep\*** enhanced rules in `semgreph_data/semgrep_yaml_files/`), with full backward-compatibility for **Python** (Semgrep + Bandit). It supports importing public HTTPS GitHub repositories into an isolated workspace, runs static analysis, extracts AST / Java method context, uses Google Gemini (`gemini-3.5-flash-lite`) for evidence-grounded 3-way triage (`Confirmed` / `Dismissed` / `Uncertain`), proposes complete-file patches with Human-in-the-Loop (HITL) approval, applies approved patches only to an isolated copy under `workdir/`, rescans the patched copy, and compares regression tests.

The final status is **SAFE**, **RISKY**, or **INCOMPLETE**. Unresolved API calls, unverified dismissal evidence, or repositories without a compatible regression test suite (`no_tests`) cannot silently turn into **SAFE**. SecureLens is an educational aid, not a substitute for a security review.

## Requirements

- Python 3.11 or newer
- Git
- Internet access for dependency installation, scanner rule downloads, and live Gemini requests
- A Gemini API key for uncached triage and patch generation (optional for offline mode)

## Install (Windows PowerShell)

```powershell
git clone https://github.com/Mahima-Koul/SecureLens.git
cd SecureLens
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and set `GEMINI_API_KEY` for live model calls (`GOOGLE_API_KEY` is also accepted as a fallback). Never commit `.env`. Linux/macOS users can substitute `python3 -m venv .venv`, `source .venv/bin/activate`, and `cp .env.example .env`.

SecureLens uses Google's recommended [`google-genai` Python SDK](https://ai.google.dev/gemini-api/docs/libraries) and Gemini's [structured output API](https://ai.google.dev/gemini-api/docs/structured-output). Create a key in [Google AI Studio](https://ai.google.dev/gemini-api/docs/api-key).

Optional settings:

| Variable | Default | Purpose |
|---|---|---|
| `GEMINI_API_KEY` | unset | Credentials for Gemini API calls |
| `GEMINI_MODEL` | `gemini-3.5-flash-lite` | Model used for structured triage and patch responses |
| `SECURELENS_OFFLINE` | `0` | `1` restricts LLM use to validated cache entries |
| `SECURELENS_CACHE_DIR` | `.cache/llm` | Local response cache (contains code-derived prompts; keep private) |
| `SECURELENS_TRIAGE_THRESHOLD` | `0.7` | Confidence below which a negative verdict stays confirmed |
| `SECURELENS_TOOL_TIMEOUT` | `60` | Scanner, test, and API timeout in seconds |
| `SECURELENS_SEMGREP_CONFIG` | `semgreph_data/semgrep_yaml_files` (for Java) or `p/python` | Optional Semgrep config override |

## 9-Stage Workflow

1. **GitHub Repository Import & Workspace Explorer (`securelens/repo_manager.py`):** Validates HTTPS GitHub URLs, clones into `workdir/repos/`, supports branch switching, and displays a clickable folder/file explorer with zoomable, line-highlighted Code Viewer in the Streamlit UI.
2. **Static Security Scan (`securelens/scanner.py`):** Runs **Semgrep\*** (29 enhanced Java rules in `semgreph_data/semgrep_yaml_files/`) on Java projects and Semgrep + Bandit on Python projects, extracting CWE metadata and deduplicating alerts.
3. **AST / Java Method Context Extraction & Evidence-Grounded AI Triage (`securelens/context.py`, `securelens/triage.py`):** Pulls package/import statements and the enclosing Java method or Python AST function, classifies findings as `Confirmed`, `Dismissed`, or `Uncertain`, and runs `verify_evidence_grounding()` to verify cited lines and snippets against the real file.
4. **Vulnerability Dashboard & Code Highlighting (`ui/app.py`):** Groups findings by status (`Confirmed`, `Uncertain`, `Dismissed`) and lets reviewers jump directly to highlighted lines in the Code Viewer.
5. **Complete-File Patch Generation (`securelens/fixer.py`):** Generates full-file replacements and unified diffs (`status = "pending"`).
6. **Human-in-the-Loop (HITL) Approval & Isolated Sandbox Application (`ui/app.py`, `securelens/fixer.py`):** Reviewers inspect diffs and **Approve** or **Reject** patches; approved patches are applied only to a cloned copy in `workdir/`.
7. **Post-Patch Rescan (`securelens/differ.py`):** Rescans the patched copy and classifies findings into `Fixed`, `Remaining`, and `New` using location-independent SHA-1 fingerprints.
8. **Functional Regression Testing (`securelens/regression.py`):** Runs `pytest` with JUnit XML parsing; repositories with no compatible tests are recorded as `status = "no_tests"`.
9. **Final Assessment Verdict (`securelens/report.py`):** Emits **SAFE**, **RISKY**, or **INCOMPLETE** (marking `no_tests` repositories as **INCOMPLETE** rather than falsely **SAFE**).

## Run a sample

1. Start with a Java (`Semgrep*`) or Python scan and triage:

   ```powershell
   python -m securelens.cli scan samples/cmdi_java_app
   ```

2. Run the full pipeline (add `--interactive` to approve/reject each patch in the CLI):

   ```powershell
   python -m securelens.cli run samples/cmdi_java_app
   ```

3. Add `--json` to `run` for a machine-readable report, or `--offline` to use only cache entries:

   ```powershell
   python -m securelens.cli run samples/cmdi_java_app --offline --json
   ```

4. Launch the 9-stage Streamlit dashboard:

   ```powershell
   streamlit run ui/app.py
   ```

   Select a source in the sidebar (**Java Samples (Semgrep\*)**, **GitHub Repository**, **Python Samples (Bandit)**, or **Local Folder**), inspect files in the Repository Explorer, run **🚀 Run Semgrep\* Scan & AI Triage**, review findings and highlight lines, approve/reject proposed patches, and inspect the post-patch rescan, regression results, and final verdict. Generated changes go into `workdir/`; the source project is never modified.

5. Run the evaluation over the ground-truth samples:

   ```powershell
   python eval/run_eval.py
   ```

   Set `$env:SECURELENS_OFFLINE = "1"` first to run without API calls. Results are written to `eval/results.json` and `eval/results.md` (ignored by Git because they are run-specific).

6. Run checks:

   ```powershell
   python -m pytest -q tests --basetemp=.pytest-tmp
   python -m pytest -q samples/cmdi_java_app/tests
   python -m pytest -q samples/xxe_java_app/tests
   python -m pytest -q samples/deser_java_app/tests
   python -m pytest -q samples/path_ssrf_java_app/tests
   python -m pytest -q samples/sqli_app/tests
   python -m pytest -q samples/cmdi_app/tests
   python -m pytest -q samples/secrets_deser_app/tests
   python -m pytest -q samples/wow_app/tests
   ```

The four Java samples (`cmdi_java_app`, `xxe_java_app`, `deser_java_app`, `path_ssrf_java_app`) cover OS command injection, XXE, unsafe deserialization, and path traversal/SSRF alongside safe false-positive patterns. The four Python samples cover SQL injection, command injection, hard-coded credential/unsafe deserialization/weak hashing, and dynamic evaluation. Each `ground_truth.json` lists expected alert categories, approximate line hints, and whether each is real.

## Architecture

```text
GitHub Repo (workdir/repos/) or Local Java / Python Project
     |
     +--> Semgrep* (29 Java rules) + Bandit (Python) --> normalized findings (with CWE)
                                                              |
                                                              v
                                            Java method / Python AST context
                                                              |
                                                              v
                                  Gemini structured triage + evidence grounding
                                     (Confirmed / Dismissed / Uncertain)
                                                              |
                                                              v
                     confirmed & uncertain --> proposed full-file patches (pending)
                                                              |
                                                 HITL Approve / Reject
                                                              |
                         original project                     v
                                   \           isolated patched copy (workdir/)
                                    \                         |
                                     +--> Semgrep* rescan + pytest comparison
                                                              |
                                             SAFE / RISKY / INCOMPLETE report
```

The CLI and UI use the same pipeline. Pydantic models validate model output and cached responses. The cache key includes model, prompt, input, and response schema; entries are written atomically. Offline cache misses remain unresolved and are conservatively confirmed. Patch application rejects unsafe paths and stale source, stages changes in a copy, and keeps generated work under `workdir/`.

## Troubleshooting

- **Missing `GEMINI_API_KEY` / authentication error:** set the key in `.env` or the process environment and confirm the selected model is enabled for the account.
- **Model unavailable:** check `GEMINI_MODEL` and account access. SecureLens reports the failed stage and preserves partial results.
- **Semgrep cannot download rules:** allow network access or set `SECURELENS_SEMGREP_CONFIG` to an available local/configured ruleset. Scanner diagnostics are included in the report.
- **Timeout:** increase `SECURELENS_TOOL_TIMEOUT`; long test suites and first-time scanner setup may take longer.
- **Offline cache miss:** run once online with the same model and input to populate the cache, or expect the finding to remain unresolved/RISKY. Cache entries are specific to the full request.
- **Tests differ in a patched copy:** inspect `workdir/` and the report's newly failing test identities. The source project remains untouched.

## Limitations and safety

Static scanners miss vulnerabilities and produce false positives. Model triage and generated patches can be wrong. A SAFE result describes only the configured scanners, model responses, patch rescan, and tests observed during that run; it is not a security guarantee. Tests may be incomplete or environment dependent. Do not run the demo against untrusted projects without reviewing its behavior, and do not put secrets in sample code or prompts. Review every generated patch before using it. `workdir/`, `.cache/`, `.env`, and the virtual environment are local artifacts and are ignored by Git.

See [schema.md](schema.md) for the data contract, [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for acceptance evidence, and [CHECKLIST.md](CHECKLIST.md) for milestone completion.
