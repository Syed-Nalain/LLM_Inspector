# LLM Inspector v1.0 — Complete Session Context

**Date:** 2026-08-29  
**Project:** `C:\Users\PIXLAPS\Claude Code\LLM Inspector v1.0`  
**Branch:** `main`  
**User:** syednalain (talhayt2024@gmail.com)

---

## 1. What LLM Inspector Is

LLM Inspector is an agentic LLM security testing tool. It uses an LLM "Brain" (Claude, GPT-4o, Gemini, Groq, or local Ollama) as a reasoning engine that plans attacks, calls real offensive-security tools (Garak, Promptfoo, PyRIT) via the Model Context Protocol (MCP), adapts based on results, and produces evidence-backed findings validated by an independent Critic pass.

### Architecture

```
USER → LLM INSPECTOR (Agent Runtime) → LLM BRAIN (reasoning)
                │                              │
                │        tool_use decision      │
                │◄──────────────────────────────┘
                ▼
         MCP CLIENT → MCP SERVERS → Garak / PyRIT / Promptfoo
                                           │
                                           ▼
                                  AUTHORIZED TARGET
                                           │
                ┌──────────────────────────┘
                ▼
   results → LLM adapts → repeats → Critic validates → Report
```

### Two Scan Modes

- **Brain mode**: LLM plans, executes, and adapts attacks autonomously
- **Manual mode**: User selects OWASP categories + tools directly, probes run without Brain LLM planning, Critic still validates findings

### 5 Scan Intensity Levels

| Intensity | Probes | Attempts | Tests | Garak Buffs |
|---|---|---|---|---|
| `very_small` | 1 per tool per category | 5 | 2 | — |
| `small` | All mapped | 10 | 3 | — |
| `medium` (default) | All mapped | 25 | 5 | — |
| `large` | All mapped + extra probe families | 50 | 10 | — |
| `extended` | Same as large + encoding/paraphrase transforms | 50 | 10 | Base64, CharCode, paraphrase |

### Vulnerability Categories

**OWASP LLM Top 10:** LLM01 (Prompt Injection), LLM01b (Jailbreak), LLM02 (Sensitive Info Disclosure), LLM04 (Data/Model Poisoning), LLM05 (Improper Output Handling), LLM06 (Excessive Agency), LLM07 (System Prompt Leakage), LLM09 (Misinformation/Overreliance)

**Cross-cutting (added this session):**
- `EVASION` — Encoding bypass, token smuggling, ANSI escape injection, glitch tokens
- `ADAPTIVE` — Tree of Attacks (TAP), GOAT, automatic attack generation
- `SOCIAL_ENG` — Grandma jailbreak, Goodside injection, DeepRole, Foot-in-the-Door, continuation attacks

---

## 2. What Was Built Across Sessions

### Previous Sessions (before this one)

1. **Core agent runtime** — Planner → Executor → Critic loop with budget tracking, scan memory, structured logging
2. **MCP plumbing** — 3 MCP servers (red team, blue team, evaluation) with client orchestration
3. **Multi-provider LLM support** — Anthropic, OpenAI, Gemini, Groq, Ollama
4. **Garak integration** — Real subprocess execution, JSONL report parsing, evidence extraction
5. **Promptfoo integration** — Local mode (curated attack library) + Redteam mode (LLM-generated attacks via Groq)
6. **Web UI** — Flask app on localhost:5000 with scan page, SSE streaming, target registration wizard
7. **CLI** — Full command set: target add/list, scan run/manual/list/report/categories, init
8. **Target registration** — HTTP endpoints and Ollama local targets with authorization enforcement

### This Session's Work

#### A. Completed the test suite run
- Ran `pytest tests/ -q -x` — **20 passed**, 1 pre-existing failure (`test_smoke_scan.py::test_full_scan_pipeline_against_vulnerable_target` where `critic_calls >= 1` fails)
- The pre-existing failure is now understood to be caused by Bug #01 (evidence sampling drops detector hits)

#### B. Updated README.md and EXTENDED_README.md
- Added scan intensity levels table and CLI example with `--intensity` flag
- Added cross-cutting vulnerability categories table (EVASION, ADAPTIVE, SOCIAL_ENG)
- Added section 2.1b to EXTENDED_README.md documenting intensity levels, `ScanIntensity` dataclass, and garak buffs data flow

#### C. Diagnosed two failed scans

**Scan `2db25a4ffcb0` (SOCIAL_ENG category, Extended intensity):**
- All 5 probes returned 0 attempts
- Root cause: `paraphrase.Fast` buff fails to generate model responses, killing every probe
- Also: `goat.GOATAttack` doesn't exist in garak v0.16.0, `fitd.FITD` detector fails to load

**Scan `e5220fdc0c96` (ADAPTIVE category, Extended intensity):**
- `tree_of_attacks` and `goat_attack`: 0 attempts (same buff/probe issues)
- `auto_attack_gen` (atkgen.Tox): **25 attempts, 2 hits at 8% ASR** — but 0 findings reported
- Root cause: Evidence sampling bug — hits were at positions 10 and 14 but `_parse_garak_report()` only samples the first 5 attempts

#### D. Comprehensive bug audit
Launched 3 parallel audit agents covering:
1. Garak adapter and probe mappings
2. Runtime, scan flow, web UI, CLI
3. Promptfoo adapter

Found **15 confirmed bugs** (detailed in Section 4 below).

---

## 3. Key Files and Their State

### Core Runtime
- **`src/llm_inspector/agent/runtime.py`** — Agent runtime with Planner→Executor→Critic loop and `run_manual_scan()`. Has intensity parameter, SSE event callbacks. Contains the `_update_memory_and_candidates()` method with the evidence filtering logic.
- **`src/llm_inspector/agent/manual_scan.py`** — Scan catalog, `ScanIntensity` dataclass, `SCAN_INTENSITIES` dict (5 levels), `MANUAL_SCAN_CATALOG` (8 OWASP + 3 cross-cutting categories), `resolve_probes()` function with intensity and buffs support.
- **`src/llm_inspector/agent/scan_logger.py`** — Structured scan log writer. Has the JSON truncation bug at line 174.

### MCP Servers / Adapters
- **`src/llm_inspector/mcp_servers/red_team/server.py`** — MCP tool definitions for `run_garak_probe` (with `buffs` param), `run_pyrit_attack`, `run_promptfoo_test`, `run_promptfoo_redteam`.
- **`src/llm_inspector/mcp_servers/red_team/adapters/garak_adapter.py`** — Real garak integration. `TECHNIQUE_TO_GARAK_PROBE` mapping (38 entries including 13 new ones for cross-cutting categories). `run_garak_probe()` builds CLI command with `--buffs` support. `_parse_garak_report()` parses JSONL reports. Has the evidence sampling bug at line 208.
- **`src/llm_inspector/mcp_servers/red_team/adapters/promptfoo_adapter.py`** — Dual-mode: local (offline, regex scoring) and redteam (LLM-generated attacks). Has grading error misinterpretation, UTF-8 encoding, response parsing, and scoring bugs.

### Web UI
- **`src/llm_inspector/web/app.py`** — Flask routes for scan (POST /scan, GET /scan/<id>/stream), target registration (/target/new, /target/ollama-models, /target/test-connection, /target/register). Has scan_id mismatch bug.
- **`src/llm_inspector/web/templates/index.html`** — Scan page with target selector, OWASP category checkboxes, tool chips, 5 intensity cards, manual/prompt mode toggle, SSE log streaming, findings table.
- **`src/llm_inspector/web/templates/target_new.html`** — 3-step registration wizard (Target Type → Connection Config → Authorization).

### CLI
- **`src/llm_inspector/cli/main.py`** — Typer CLI with `scan manual` command including `--intensity` option. Help text missing "large" from intensity list.

### Config / Environment
- **`.env`** — Contains `GROQ_API_KEY`, `LLM_INSPECTOR_PROVIDER=groq`, `LLM_INSPECTOR_MODEL=openai/gpt-oss-120b`, `LLM_INSPECTOR_BASE_URL=http://localhost:11434`
- **`requirements.txt`** — Includes flask>=3.0.0, requests>=2.31.0
- **`pyproject.toml`** — Has flask/requests in dependencies, `llm-inspector-web` console script entry point

### Registered Targets
- ID `98df4d16` — "Qwen 0.5B Local", URI `http://localhost:11434/api/chat`
- ID `91e34b88` — "Gemma3 4B Test", URI `http://localhost:11434/api/chat`

### Important Notes
- **Windows .venv**: Must use `.venv\Scripts\python.exe` not system `python` for imports to work
- **Garak version**: v0.16.0 installed (deprecated `--probes` and `--buffs` CLI flags)
- **Screenshots**: Browser pane screenshots timeout; use `read_page` and `javascript_tool` for verification

---

## 4. Complete Bug List (15 Bugs)

### Critical — Wrong scan results or silent data loss (6 bugs)

**#01 — Evidence sampling drops detector hits → findings silently lost**
- Files: `garak_adapter.py:208` → `runtime.py:417`
- `_parse_garak_report()` collects evidence from the first 5 attempts in insertion order, then sorts by `detector_hit` AFTER truncation. If hits are at position 6+, they're never included. The runtime finds no candidates for the Critic, and findings are silently dropped even with non-zero ASR.
- Evidence: atkgen.Tox returned 25 attempts, 2 hits (positions 10 & 14, scores 0.994 and 0.877). First 5 sampled attempts all scored <0.001. Result: 0 candidates, 0 findings despite 8% ASR.

**#02 — Promptfoo grading errors counted as successful attacks → inflated ASR**
- File: `promptfoo_adapter.py:512-516`
- When the grading LLM returns an API error (e.g. 404), promptfoo defaults `pass` to `false`. The adapter interprets `not false` as "attack succeeded." The `reason` field containing "API error: 404 Not Found" is never checked.
- Evidence: `3bd98b7969.redteam.results.json` had 44 rows. 29 had pass=false due to grading 404s, 7 had pass=true (target blocked), 8 had no grading. Adapter would report 29/44 hits (65.9% ASR). Real result: 0/7 (0% ASR).

**#03 — Paraphrase buff crashes all garak probes in Extended mode**
- Files: `manual_scan.py:67` → `garak_adapter.py:140`
- The bare buff name `"paraphrase"` causes garak to load ALL classes in the module: `paraphrase.Fast` and `paraphrase.PegasusT5`. The `Fast` variant downloads a local T5 model that consistently fails to generate output, killing every probe it touches (0 attempts produced).
- Evidence: 7/48 garak logs show "garak.buffs.paraphrase.Fast failed to generate a model response". Every Extended-mode probe produced 0 attempts.

**#04 — `goat.GOATAttack` probe does not exist in garak v0.16.0**
- File: `garak_adapter.py:59`
- The probe class was never shipped in garak v0.16.0. Every run targeting `goat_attack` silently produces an empty report (garak exits 0 but does nothing).
- Evidence: Log shows "failed to load probe probes.goat.GOATAttack"

**#05 — `fitd.FITD` detector fails → probe skipped entirely**
- File: `garak_adapter.py:65`
- The FITD probe exists but its required detector `judge.RefusalOnlyAdversarial` cannot be instantiated. Garak skips probes with no working detectors.
- Evidence: Log shows "detector load failed: judge.RefusalOnlyAdversarial, skipping >> No detectors, nothing to do"

**#06 — `sysprompt_extraction` crashes with IndexError**
- File: `garak_adapter.py:45-46`
- Two mappings (`system_prompt_extraction` and `system_prompt_leak_probe`) point to `sysprompt_extraction.SystemPromptExtraction`, which generates an empty prompt list then crashes on `prompts[0]`. Garak process exits non-zero. Affects LLM02 and LLM07 categories.
- Evidence: Log shows "IndexError: list index out of range" in garak/probes/base.py line 402

### Moderate — Incorrect stats, display issues, or data mismatches (4 bugs)

**#07 — Scan logger always reports "Total probes run: 0"**
- Files: `runtime.py:259,535` → `scan_logger.py:174`
- Tool results truncated to 4000 chars before passing to scan logger. Garak/promptfoo results exceed this (evidence array has full prompts/responses). Truncated JSON is invalid, `json.loads` raises `JSONDecodeError`, probe stats counter never incremented.

**#08 — Web UI scan_id doesn't match the database scan_id**
- Files: `web/app.py:112-113,130-131` vs `runtime.py` (internal UUID)
- Web app generates one UUID and returns it to the client. Runtime generates a different UUID internally. SSE streaming works (keyed on queue object), but any client-side lookup by the returned scan_id finds nothing. If the UUID isn't set within the 5-second polling window, it becomes the literal string `"pending"`.

**#09 — `_score_response()` false negatives for 3 of 5 categories**
- File: `promptfoo_adapter.py:141-149`
- The refusal-pattern gate uses `"OK" in p` to decide whether to let a hit through despite a refusal phrase. Only 2 of 5 categories have patterns containing "OK". For `system_prompt_leak`, `pii_exfiltration_canary`, and `excessive_agency_tool_claim`, any response containing a refusal phrase is unconditionally marked as "not a hit" even if the model also complied.

**#10 — Smoke test assertion failure is caused by Bug #01**
- File: `test_smoke_scan.py:164`
- `critic_calls >= 1` fails because evidence sampling bug (#01) means no candidates reach the Critic. Not a test bug — it's Bug #01 manifesting under real garak execution.

### Low — Edge-case crashes, wrong docs, or deprecated APIs (5 bugs)

**#11 — Local promptfoo mode missing UTF-8 encoding → crash on Windows**
- File: `promptfoo_adapter.py:217`
- `output_path.read_text()` without `encoding="utf-8"` uses system default (cp1252 on Windows). Non-ASCII characters cause `UnicodeDecodeError`. Redteam mode at line 503 correctly specifies UTF-8; local mode does not.

**#12 — Local promptfoo mode crashes when `response` is `None`**
- File: `promptfoo_adapter.py:225`
- `row.get("response", {}).get("output", "")` crashes with `AttributeError` when the key exists but value is `None`. Redteam mode uses the safe pattern `(row.get("response") or {}).get(...)`.

**#13 — Wrong environment variable for Gemini provider in promptfoo**
- File: `promptfoo_adapter.py:274`
- Sets `GEMINI_API_KEY` but promptfoo's `google:` provider reads `GOOGLE_API_KEY`. Redteam mode silently fails to authenticate when Gemini is used as brain LLM.

**#14 — Deprecated garak CLI flags: `--probes` and `--buffs`**
- File: `garak_adapter.py:125-126, 140`
- Both flags deprecated since garak v0.15.1.pre1. Still function in v0.16.0 but will be removed. Garak now expects probe/buff config via YAML config files.
- Evidence: 100% of garak runs show deprecation warnings.

**#15 — CLI help text for `--intensity` omits "large"**
- File: `cli/main.py:330`
- Help string lists `very_small, small, medium, extended` but omits `large`. Runtime correctly accepts all five levels.

---

## 5. What's NOT Broken (Working Correctly)

- MCP client ↔ server communication and tool discovery
- Target registration and authorization enforcement (CLI + Web UI)
- Brain LLM mode planning and execution loop
- Budget tracking (time, cost, tool call limits)
- Garak subprocess execution and report parsing (when probes actually work)
- Promptfoo redteam YAML generation and subprocess execution
- SSE streaming from Flask to browser
- Web UI rendering (scan page, target wizard, intensity cards)
- `resolve_probes()` function with intensity levels
- Scan memory and structured scan logging (format, not stats)
- Multi-provider LLM client (Anthropic, OpenAI, Gemini, Groq, Ollama)
- Test suite (20/21 pass; the 1 failure is Bug #01)

---

## 6. Pending / Next Steps

1. **Fix the 15 bugs** — prioritized by severity (Critical first)
2. **Run a real scan after fixes** to verify end-to-end
3. **Update README/EXTENDED_README** for any fix-related changes
4. **Re-run test suite** to confirm the smoke test passes after Bug #01 fix

---

## 7. Environment Details

- **Python:** 3.x in `.venv` (must use `.venv\Scripts\python.exe`)
- **Garak:** v0.16.0
- **Promptfoo:** installed via npm globally
- **Ollama:** Running locally at `http://localhost:11434`
- **Models available:** qwen2.5:0.5b, gemma3:4b
- **OS:** Windows 11 Home 10.0.26200
- **Groq API Key:** Set in `.env` (gsk_4Nof...)
