# SecureLens

SecureLens is a student demonstration of AI-assisted Python security review. It combines Semgrep and Bandit findings, sends structured code context to Gemini for conservative triage, proposes complete-file patches in an isolated copy, rescans that copy, and compares its pytest results with the original.

The final status is **SAFE**, **RISKY**, or **INCOMPLETE**. A missing API response is kept visible as unresolved and cannot silently turn into a clean result. SecureLens is an educational aid, not a substitute for a security review.

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
| `SECURELENS_SEMGREP_CONFIG` | default Python rules | Optional Semgrep config, such as `p/python` |

## Run a sample

1. Start with a scan and triage:

   ```powershell
   python -m securelens.cli scan samples/sqli_app
   ```

2. Run the full pipeline:

   ```powershell
   python -m securelens.cli run samples/sqli_app
   ```

3. Add `--json` to `run` for a machine-readable report, or `--offline` to use only cache entries:

   ```powershell
   python -m securelens.cli run samples/sqli_app --offline --json
   ```

4. Launch the staged interface:

   ```powershell
   streamlit run ui/app.py
   ```

   Choose a sample or Python project, select the model, and optionally enable offline mode. Use **Scan and triage**, review the finding tabs, then choose **Generate fixes**. Generated changes go into `workdir/<project>_patched` or a unique run directory; the source project is not modified. The UI retains completed stages during reruns.

5. Run the evaluation over all four ground-truth samples:

   ```powershell
   python eval/run_eval.py
   ```

   Set `$env:SECURELENS_OFFLINE = "1"` first to run without API calls. Results are written to `eval/results.json` and `eval/results.md` (ignored by Git because they are run-specific).

6. Run checks:

   ```powershell
   python -m pytest -q tests
   python -m pytest -q samples/sqli_app/tests
   python -m pytest -q samples/cmdi_app/tests
   python -m pytest -q samples/secrets_deser_app/tests
   python -m pytest -q samples/wow_app/tests
   ```

The four small samples cover SQL injection, command injection, hard-coded credential/unsafe deserialization/weak hashing, and dynamic evaluation. They also include safe patterns and regression tests. Each `ground_truth.json` lists expected alert categories, approximate line hints, and whether each is real.

## Architecture

```text
Python project
     |
     +--> Semgrep + Bandit --> normalized findings --> AST context
                                                   |
                                                   v
                                         Gemini structured triage
                                                   |
                                                   v
                          confirmed findings --> proposed full-file patches
                                                   |
                         original project         v
                                   \       isolated patched copy
                                    \             |
                                     +--> rescan + pytest comparison
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
