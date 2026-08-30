# LLM Inspector — Extended README / Build Notes

This is the working notes file for turning LLM Inspector from "the
architecture works end-to-end" into a finished product an end user can
rely on. Nothing here is secret or aspirational marketing — it's the
honest list of what's real, what's stubbed, and everything discovered
while building the first version that still needs doing. Treat this file
as the project's backlog; keep it updated as items get done instead of
letting README.md quietly drift out of sync with reality.

Original design source: `LLM_inspector_Architecturev1.0.pdf` (the
conversation this project was scoped from). The core loop it describes —
an LLM as reasoning brain, LLM Inspector as the MCP client + body, tools
as MCP servers, Planner → Executor → Critic, evidence-driven findings,
budgeted testing, scan memory — is implemented and covered by
`tests/test_smoke_scan.py`. Multi-provider support (Anthropic/Claude,
OpenAI/GPT-4o, Google Gemini, Ollama local) was added in v0.1.0 —
see `agent/llm_client.py`. Everything below is what's still open.

## How to read this file

Each item says what's missing, why it matters, and — where it's not
obvious — a starting pointer for where in the code it plugs in. Items are
grouped by theme, roughly in the order you'd want to tackle them for a
"ready for real end users" milestone, but nothing here is strictly
sequenced; pick based on what your users actually need first.

---

## 1. Real tool integrations still pending

### 1.1 PyRIT (currently a stub)
`mcp_servers/red_team/adapters/pyrit_adapter.py` returns synthetic,
clearly-labeled (`"stub": true`) data instead of running real PyRIT
attacks. The Critic is hard-coded to reject any stub-sourced candidate, so
this cannot currently produce a false "confirmed" finding — it just means
adaptive multi-turn attacks aren't covered yet.

To make it real:
- `pip install pyrit` and pick which model drives PyRIT's own adaptive
  attack generation (PyRIT's `RedTeamingOrchestrator` needs its own
  "attacker" LLM — this could be the same Claude call the rest of the app
  uses, via a PyRIT-compatible target wrapper, or a separately configured
  model).
- Write a PyRIT `PromptTarget` implementation wrapping
  `RestTargetConfig` (same idea as `RestTargetConfig.to_garak_generator_options`
  / `to_promptfoo_provider`, but PyRIT's target interface is Python, not a
  config blob — implement `send_prompt_async`).
- **Important:** `RestTargetConfig` today is stateless — every call is
  independent HTTP POST with no session/conversation continuity. PyRIT's
  real value is multi-turn escalation, which requires the target to
  actually remember prior turns. Decide whether to (a) have LLM Inspector
  manage conversation state client-side and replay full history each call
  (works for stateless chat APIs), or (b) support targets with native
  session/cookie continuity. Either way this needs design work before
  PyRIT integration is worth doing.
- Replace the synthetic scoring in `pyrit_adapter.py` with real PyRIT
  scorers (e.g. `SelfAskScorer`).

### 1.2 LlamaGuard (currently a stub)
`mcp_servers/blue_team/adapters/llamaguard_adapter.py` is a crude keyword
regex, not a real safety classifier. Real integration needs an actual
Llama Guard model — self-hosted (vLLM/Ollama serving
`meta-llama/Llama-Guard-3-8B` or similar; needs a GPU for reasonable
latency) or a hosted inference endpoint with user-supplied credentials.
Decide which before building this — don't silently try to download a
multi-GB model on first run.

### 1.3 NeMo Guardrails (currently a stub)
`mcp_servers/blue_team/adapters/nemoguard_adapter.py` always reports "not
blocked." Real integration means installing `nemoguardrails`, authoring
Colang rail definitions (this is inherently target-specific — there's no
generic rail set that applies to an arbitrary third-party chatbot), and
running traffic through a configured `LLMRails` instance.

### 1.4 Garak's `sysprompt_extraction` probe needs network access to Hugging Face
`garak.probes.sysprompt_extraction.SystemPromptExtraction` downloads
system-prompt datasets from the Hugging Face Hub at run time. In this dev
sandbox, that network path was blocked (`403` on the HF proxy), so this
specific probe could not be verified end-to-end here — the adapter's error
handling was confirmed (it fails cleanly and reports the error back
through the pipeline rather than crashing), but the happy path wasn't. In
a normal end-user environment with regular internet access this should
just work, but needs verification, and ideally:
- A graceful fallback prompt set bundled with LLM Inspector (a small,
  static list of realistic system-prompt-extraction payloads) so this
  technique doesn't have a hard external dependency at all.
- Or: route system-prompt-leak testing through the Promptfoo adapter's
  `system_prompt_leak` category by default (already implemented, offline,
  works today), and treat Garak's version as a "deeper" optional pass.

### 1.5 Garak's `max_attempts` cap is honored inconsistently
`garak_adapter.py` passes `max_attempts` through as a best-effort
`soft_probe_prompt_cap` probe option. Confirmed during testing: some probe
classes respect it (e.g. `sysprompt_extraction`), others ignore it
entirely (e.g. the broad `dan` category ran 127 attempts even with a cap
set). This means a single tool call can blow past the per-call attempt
count Claude requested, though the overall scan budget
(`agent/budget.py`) still caps total tool calls/time/cost regardless. Needs:
- An audit of which garak probe classes honor `soft_probe_prompt_cap`
  (grep `follow_prompt_cap` / `_prune_data` usage across
  `garak/probes/*.py` for the installed version) and either avoid mapping
  our techniques to non-honoring probes, or wrap the subprocess call with
  a hard wall-clock timeout as a backstop.
- A subprocess-level timeout on the `garak`/`promptfoo` calls in general
  (see §3.3) — right now a hung or unexpectedly large probe run can only
  be caught between Claude turns, not mid-tool-call.

---

## 2. Coverage gaps

### 2.1 OWASP LLM Top 10 ontology + cross-cutting categories
`agent/security_ontology.py` covers 8 OWASP categories with real technique →
tool mappings. Not yet covered: LLM03 (Supply Chain) in any depth, LLM08
(Vector/Embedding Weaknesses, relevant to RAG apps), LLM10 (Unbounded
Consumption/resource exhaustion). Extend `OWASP_LLM_TOP_10` and the
corresponding probe/category mappings in `garak_adapter.py` /
`promptfoo_adapter.py` as tools gain relevant coverage. Also: keep this in
sync as Garak ships new probes and OWASP revises the Top 10 list —
consider a periodic audit rather than a one-time pass.

Three cross-cutting categories have been added to `manual_scan.py`'s
`MANUAL_SCAN_CATALOG` beyond the OWASP Top 10:
- **EVASION** (Guardrail Evasion Techniques): encoding bypass, token
  smuggling, ANSI escape injection, glitch token exploits — all via garak
  probes (`encoding`, `smuggling`, `ansiescape`, `glitch`).
- **ADAPTIVE** (Adaptive / Multi-turn Attacks): Tree of Attacks
  (`tap.TAPCached`), GOAT (`goat.GOATAttack`), automatic attack generation
  (`atkgen.Tox`) — garak's multi-turn probe families.
- **SOCIAL_ENG** (Social Engineering / Manipulation): grandma jailbreak,
  Goodside injection, DeepRole attack, Foot-in-the-Door, continuation
  attacks — garak probes targeting social engineering vectors.

These are available in manual scan mode at all intensity levels.

### 2.1b Scan intensity levels
`manual_scan.py` defines 5 scan intensity presets via the `ScanIntensity`
dataclass:

| Level | Probes | Attempts | Tests | Garak buffs |
|---|---|---|---|---|
| `very_small` | 1 per tool/category | 5 | 2 | none |
| `small` | all mapped | 10 | 3 | none |
| `medium` | all mapped | 25 | 5 | none |
| `large` | all + `LARGE_EXTRA_PROBES` | 50 | 10 | none |
| `extended` | same as large | 50 | 10 | `encoding.Base64`, `encoding.CharCode`, `paraphrase` |

The `extended` level applies garak encoding and paraphrase buffs (passed
as `--buffs` to the garak CLI) on top of every garak probe, roughly
doubling garak scan time. Buffs transform each probe's payloads through
encoding layers (Base64, CharCode) and semantic rephrasing, catching
attacks that bypass guardrails through obfuscation. The `buffs` parameter
flows through `resolve_probes()` → `runtime.run_manual_scan()` →
`server.py::run_garak_probe()` → `garak_adapter.py::run_garak_probe()`.

### 2.2 Promptfoo attack library — two modes now available
`promptfoo_adapter.py` provides two complementary modes:
- **`promptfoo` (local/offline):** `ATTACK_LIBRARY` is a curated set of
  hand-written, canary-style prompts per category, scored with regex
  keyword matching (`_score_response`). Deliberately simple, offline-
  capable, no API key required.
- **`promptfoo_redteam` (LLM-generated):** Uses `promptfoo redteam`
  with an LLM (e.g. Groq's `openai/gpt-oss-120b`) to dynamically generate
  attack prompts, send them to the target (local Ollama), and grade
  responses using the same LLM. Supports a `purpose` parameter describing
  the target application to generate more contextual attacks. Uses
  promptfoo plugins (hijacking, ascii-smuggling, prompt-extraction, etc.)
  and strategies (jailbreak, prompt-injection, etc.).

To go deeper:
- Expand `ATTACK_LIBRARY` with more categories/prompts per category for
  the offline mode.
- The `REDTEAM_PLUGIN_SETS` and `STRATEGY_LIST` in `promptfoo_adapter.py`
  can be extended as promptfoo adds new plugins.
- Groq's free tier has an 8000 TPM limit — consider adding rate-limiting
  or prompt compression for larger scan runs.

### 2.3 Everything that isn't detector-flagged is silently dropped
Only evidence items where `detector_hit` is true (from Garak's real
detectors or Promptfoo's regex heuristic) become Critic candidates
(`agent/runtime.py::_update_memory_and_candidates`). This keeps Critic
costs bounded but means a real compliance that neither detector catches
(false negative in the initial heuristic) never gets a chance at Critic
review. Consider an optional "thorough" mode that routes a sample of
non-flagged evidence through the Critic too, or lowers the initial bar and
lets the Critic be the sole filter (more Claude calls, more thorough).

---

## 3. Production hardening

### 3.1 Authorization is a checkbox, not a verified workflow
`target.py` / `TargetManager.register` requires `--i-am-authorized` and an
`authorized_by` string, but nothing verifies domain ownership, checks a
signed authorization document, sets an expiry window, or logs who
approved what beyond a free-text name. For anything beyond solo/internal
use, build: proof-of-ownership verification (e.g. a DNS TXT record or
well-known file challenge, similar to TLS cert issuance), authorization
expiry + renewal, and a revocation flow (`TargetManager` has no `revoke()`
method yet — `authorized` can be flipped to `False` directly in the DB but
nothing in the CLI exposes this).

### 3.2 No multi-user story
Everything is a single local SQLite DB (`storage/database.py`) with no
user accounts or per-user API key isolation — whoever has shell/CLI access
has access to everything. Fine for a solo/local tool; not fine for a
shared or hosted deployment. Needs real auth before that's viable.

### 3.3 No subprocess timeouts
`garak_adapter.py` and `promptfoo_adapter.py` run `garak`/`promptfoo` via
`asyncio.create_subprocess_exec` with no timeout — `await proc.communicate()`
will wait indefinitely for a hung process. Wrap these in
`asyncio.wait_for(...)` with a sane per-call timeout derived from the
scan's remaining budget (`BudgetTracker.remaining_seconds()`).

### 3.4 No target-side rate limiting
Nothing throttles how fast LLM Inspector hits the target's endpoint beyond
Garak's/Promptfoo's own concurrency flags (`--parallel_attempts 4`,
`-j 4`, currently hard-coded). A real product should let the user set a
requests-per-second cap so scanning doesn't accidentally DoS the very
application being tested — important both for safety and for not
violating a target's own rate limits/ToS.

### 3.5 No retry/backoff for transient network failures
A single dropped connection to the target mid-probe currently just shows
up as a failed attempt/lower attempt count rather than being retried.

### 3.6 No SSRF protection on target URIs
Nothing stops a target's `uri` from pointing at `localhost`, a cloud
metadata endpoint (`169.254.169.254`), or another internal address. For a
single-user local CLI tool this is the user's own risk (same trust level
as running `curl` themselves), but if this ever becomes a hosted/shared
service, add URL validation (block private/link-local ranges by default,
require an explicit opt-in flag to test internal targets).

### 3.7 Secrets handling
The Anthropic API key can be passed via `--api-key`, which shows up in
shell history and process listings. Prefer env var / `.env` (already
supported) or add an interactive masked prompt; document the risk in
README if `--api-key` is used. Target headers (which may contain the
target's own auth tokens) are stored in plaintext in the SQLite DB and in
generated reports — fine for local single-user use, but flag this
clearly, and consider at-rest encryption or a secrets-manager integration
before any shared deployment.

### 3.8 LLM cost estimation is approximate
`agent/budget.py::record_llm_usage` delegates to each provider adapter's
`estimate_cost()` method, which uses rough per-provider pricing rather
than exact per-model tiers (which also vary with prompt caching). Fine as
a soft budget guard; for accurate cost reporting, wire in real per-model
pricing tables (possibly user-configurable, since pricing changes over
time). Ollama reports $0 since it's local compute.

### 3.9 Long target responses are flat-truncated
Tool results and Critic inputs are truncated at fixed character counts
(e.g. 3000/8000 chars) rather than token-aware truncation. Fine for now;
revisit if targets that return very large payloads (e.g. full documents)
turn out to be common.

---

## 4. Product surface

### 4.1 Web UI — implemented (basic)
A Flask-based web UI (`web/app.py`) now provides:
- **Scan page** (`/`): Target selector, OWASP category checkboxes, tool
  chips, manual vs prompt mode toggle, target details textarea (for
  promptfoo_redteam purpose), live SSE log streaming, expandable findings
  table. Runs on `localhost:5000`.
- **Target registration** (`/target/new`): 3-step wizard (Target Type →
  Connection Config → Authorization) with HTTP Endpoint and Ollama Local
  support, auto-model-detection for Ollama, test-connection button, and
  authorization confirmation.

Still missing / future enhancements:
- No authentication on the web UI (single-user local tool assumption).
- No WebSocket support — uses SSE (`text/event-stream`) which is
  sufficient but uni-directional.
- No scan history or report browsing page (use the CLI for now).
- No real-time target editing or deletion from the UI.
- Consider migrating to FastAPI + WebSocket for bi-directional streaming
  if the UI grows more interactive features.

### 4.2 Report formats
`findings/report_generator.py` produces Markdown + JSON only. Consider
PDF export (there's a `pdf` skill available in this workspace if building
that here) and a historical trend view across repeated scans of the same
target (has this finding regressed since last time?).

### 4.3 Severity doesn't account for business impact
`findings/finding.py::severity_from_asr` is a pure attack-success-rate
threshold; the Critic can override it per finding but has no structured
signal about how sensitive the affected component is. Consider adding an
optional "risk tier" field to `Target` (e.g. "customer-facing" vs
"internal tool" vs "handles PII") that gets fed into the Critic's prompt
to weight severity more realistically.

### 4.4 Blue Team results aren't used in Executor decision-making yet
`check_llamaguard`/`check_nemoguard` exist as callable tools but nothing
in the system prompt currently pushes Claude to use them to distinguish
"target has no guardrail at all" from "guardrail present but bypassed" —
worth doing once those adapters are real (see §1.2/1.3), since a stubbed
guardrail check isn't worth reasoning over yet.

### 4.5 RestTargetConfig assumes a JSON response
No support yet for targets that return plain text, HTML, or SSE/streaming
responses. Add a `response_mode: "json" | "text" | "sse"` option to
`RestTargetConfig` and corresponding handling in both the garak and
promptfoo translation methods.

---

## 5. Testing, CI, packaging

- **No CI wired up.** Tests exist and pass locally (`pytest -q`, 21/21 at
  time of writing) but nothing runs them automatically on push/PR yet. Add
  a GitHub Actions workflow: fast unit tests on every push, the `slow`
  (real garak/promptfoo) suite at least on PRs to main, since it doesn't
  need any API keys.
- **No packaging/distribution.** Currently only installable from source
  via `pip install -e .`. Consider publishing to PyPI and/or a Docker
  image (bundling `garak` + Node/`promptfoo` so users don't need to
  install them separately).
- **Dependencies are loosely pinned** (`>=` everywhere in `pyproject.toml`).
  Garak, PyRIT, and Promptfoo all evolve their CLIs/APIs; consider pinning
  or maintaining a tested compatibility matrix, especially for the
  `garak` report JSONL schema this project parses directly
  (`_parse_garak_report` in `garak_adapter.py`) and the `promptfoo eval -o`
  JSON schema (`run_promptfoo_test` in `promptfoo_adapter.py`) — both are
  the tools' own report formats, not a documented stable API, so upstream
  changes could silently break parsing.
- **No `__version__`/changelog.** Add both once the release cadence is
  decided.
- **Missing-tool error messages are generic.** `llm-inspector init` checks
  for `garak`/`promptfoo` on PATH, but a scan that hits a missing binary
  mid-run just surfaces a generic subprocess failure. Catch
  `FileNotFoundError` specifically in the adapters and return the same
  install hint `init` gives.

---

## 6. Smaller items / cleanup

- `agent/runtime.py::MAX_EXECUTOR_TURNS` (40) is a hard-coded safety cap,
  not exposed via CLI/config — consider making it configurable alongside
  the existing `--max-seconds`/`--max-usd` scan flags.
- CLI progress output (`rich.console.Console` prints) isn't structured
  logging — fine for a CLI tool, but if the web UI (§4.1) reuses
  `AgentRuntime`, replace ad hoc prints with Python's `logging` module so
  both surfaces can consume the same event stream consistently.
- One `llm-inspector` CLI invocation runs one scan at a time; no
  parallel/batch scanning of multiple targets from a single command.
- `TargetManager` has no `list`-with-filter (by tag, by authorization
  status) — only a flat `list()`.

---

## 7. What's verified vs. assumed

Verified for real, in this environment, during the build (see
`tests/test_smoke_scan.py`, `tests/test_red_team_adapters.py`):
- MCP client ↔ 3 MCP servers (red team / blue team / evaluation)
  discovery and tool-call round-trip, including error propagation for
  unknown/unauthorized targets.
- Real `garak` subprocess execution against a live HTTP target, including
  parsing real `*.report.jsonl` output (attempt/eval/probe_summary
  entries) into structured results with evidence.
- Real `promptfoo eval` subprocess execution against a live HTTP target,
  including parsing real `results.json` output.
- Full Agent Runtime loop (Planner → Executor tool-calling → budget
  enforcement → memory tracking → Critic validation → Finding →
  SQLite persistence → report generation) with a scripted-but-realistic
  fake Claude client standing in for the one piece that needs a live paid
  API key.

Not verified in this environment (needs a user with real credentials/
network access to confirm):
- A live end-to-end run with a **real** API key for any provider (this
  sandbox has none; the smoke test's `FakeLLMClient` proves the pipeline
  is correct but not that the LLM's actual tool-selection behavior matches
  expectations against the real API). Multi-provider support (Anthropic,
  OpenAI, Gemini, Ollama) is implemented in `agent/llm_client.py` and
  needs live validation with each provider.
- Garak's `sysprompt_extraction` probe's Hugging Face dataset download
  (blocked by this sandbox's network policy — see §1.4).
- Behavior against a real, non-trivial third-party LLM application rather
  than the in-repo mock target.
- Each non-Anthropic provider's tool-calling behavior and response format
  with the specific tool schemas LLM Inspector uses (some models may
  struggle with complex tool schemas or return malformed JSON).
