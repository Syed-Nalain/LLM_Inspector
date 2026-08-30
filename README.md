# LLM Inspector

LLM Inspector is an agentic LLM security testing tool. You point it at an
LLM-powered application you own or are explicitly authorized to test, and
your chosen LLM — [Claude](https://www.anthropic.com/claude),
[GPT-4o](https://openai.com/), [Gemini](https://ai.google.dev/), or a
local [Ollama](https://ollama.com/) model — reasons over a set of real
offensive-security tools — [Garak](https://github.com/NVIDIA/garak),
[PyRIT](https://github.com/Azure/PyRIT), and [Promptfoo](https://www.promptfoo.dev/) —
via the [Model Context Protocol](https://modelcontextprotocol.io) (MCP) to plan an
attack strategy, run it, adapt based on what it observes, and produce
evidence-backed findings instead of vague guesses.

> **Authorization is mandatory.** LLM Inspector refuses to register or scan
> any target without an explicit `--i-am-authorized` confirmation, and every
> tool call is re-validated against that authorization before it touches the
> network. Only ever point this at a system you own or have explicit written
> permission to security-test. Unauthorized scanning of third-party systems
> may be illegal in your jurisdiction.

## How it works

The LLM never talks to the security tools directly, and it never executes
anything itself. LLM Inspector's Agent Runtime is the MCP client; the LLM is
the reasoning engine that decides *what* to test and interprets the results.

```
  USER  →  LLM INSPECTOR (Agent Runtime)  →  LLM BRAIN (reasoning)
                    │                              │
                    │        tool_use decision      │
                    │◄──────────────────────────────┘
                    ▼
             MCP CLIENT  →  MCP SERVERS  →  Garak / PyRIT / Promptfoo
                                                     │
                                                     ▼
                                            YOUR AUTHORIZED TARGET
                                                     │
                    ┌────────────────────────────────┘
                    ▼
       results flow back to LLM → LLM adapts → repeats
                    │
                    ▼
     independent Critic pass validates each candidate finding
                    │
                    ▼
              evidence-backed report + structured scan log
```

Concretely: a **Planner** call turns your request into an initial test plan;
the **Executor** loop works through it, calling tools and adapting based on
what it observes, under a hard time/cost/call budget; and every candidate
"this attack worked" signal is checked by an independent **Critic** call
against the target's actual raw response before it's allowed to become a
reported finding. Every step is captured in a structured scan log for full
auditability. See [EXTENDED_README.md](./EXTENDED_README.md) for the full
design rationale and the original architecture notes this was built from.

## Supported LLM providers

| Provider | Models | API key env var |
|---|---|---|
| **Anthropic** (Claude) | claude-sonnet-4-20250514, claude-opus-4-5-20251101, etc. | `ANTHROPIC_API_KEY` |
| **OpenAI** | gpt-4o, o3, gpt-4.1, etc. | `OPENAI_API_KEY` |
| **Google Gemini** | gemini-2.5-flash, gemini-2.5-pro, etc. | `GEMINI_API_KEY` |
| **Groq** | openai/gpt-oss-120b, llama-3.3-70b-versatile, etc. | `GROQ_API_KEY` |
| **Ollama** (local) | qwen2.5:7b, qwen2.5:14b, llama3.1, mistral, etc. | None needed |

The provider is auto-detected from whichever API key is set, or you can
set `LLM_INSPECTOR_PROVIDER` explicitly. You can also pass `--provider`,
`--model`, and `--api-key` directly to the `scan run` command.

## Current status

This is a genuinely working first version, not a mockup:

| Component | Status |
|---|---|
| Agent Runtime (Planner → Executor → Critic, budget, memory) | **Real** |
| MCP client/server plumbing (3 servers: red team, blue team, evaluation) | **Real** |
| Multi-provider LLM support (Claude, GPT-4o, Gemini, Ollama, Groq) | **Real** |
| Garak integration | **Real** — shells out to `garak`, parses its real report output |
| Promptfoo integration | **Real** — curated attack-prompt library run via `promptfoo eval` |
| Promptfoo Redteam (LLM-generated attacks) | **Real** — uses Groq/OpenAI-compatible LLM to generate + grade dynamic attacks |
| Manual scan mode (no Brain LLM for planning) | **Real** — select OWASP categories + tools directly, Critic still validates |
| Structured scan logging | **Real** — full audit trail per scan |
| PyRIT integration | **Stub** — structurally wired in, returns synthetic data (see below) |
| LlamaGuard / NeMo Guardrails | **Stub** — keyword heuristics, not real model inference |
| CLI (target management, scans, reports) | **Real** |
| Web UI (scan + target registration) | **Real** — Flask app on localhost:5000 with live SSE logs |

Every stub is clearly labeled `"stub": true` in its output, the system
prompt tells the LLM to treat stub results as unverified, and the Critic
automatically rejects any candidate finding sourced from a stub. You will
never get a false "confirmed" finding out of a stub — you'll just not get
PyRIT/guardrail coverage yet. **[EXTENDED_README.md](./EXTENDED_README.md)**
is the complete, honest list of everything left to build before this is a
finished product — read it before relying on this for anything real.

## Installation

Requires Python 3.10+, and Node.js/npm (for Promptfoo). Flask is included
for the web UI.

```bash
git clone <this repo>
cd llm-inspector
python -m venv .venv

# Activate the virtual environment:
# Linux/macOS:
source .venv/bin/activate
# Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Install all dependencies:
pip install -r requirements.txt

# Install Promptfoo (Node.js tool):
npm install -g promptfoo

# Configure your LLM provider:
cp .env.example .env              # then fill in your API key and provider
pip install -e .                  # install llm-inspector CLI

llm-inspector init                # sanity-checks your setup
```

`llm-inspector init` tells you which provider is configured, if your
API key is found, and whether `garak`/`promptfoo` are installed.

### Provider-specific notes

- **Anthropic / OpenAI / Gemini**: Set the API key in `.env` and you're done.
- **Ollama**: No API key needed. Just have Ollama running (`ollama serve`)
  and pull a model (`ollama pull qwen2.5:7b`). Set `LLM_INSPECTOR_PROVIDER=ollama`
  in your `.env`.

## Quickstart

**1. Register a target you're authorized to test.** LLM Inspector talks to
any LLM app over a plain HTTP endpoint — describe the request/response
shape once:

```bash
llm-inspector target add \
  --name "My Support Chatbot" \
  --description "Customer support chatbot, staging environment" \
  --uri "https://staging.example.com/api/chat" \
  --header "Authorization: Bearer $MY_TEST_TOKEN" \
  --body-template '{"messages":[{"role":"user","content":"$INPUT"}]}' \
  --response-path "choices[0].message.content" \
  --authorized-by "you@example.com" \
  --i-am-authorized
```

`$INPUT` in `--body-template` marks where the attack prompt goes;
`--response-path` is where the reply text lives in the JSON response.

> **Windows (PowerShell) note:** PowerShell mangles JSON in `--body-template`.
> Use a variable instead:
> ```powershell
> $body = '{"messages":[{"role":"user","content":"$INPUT"}]}'
> llm-inspector target add --name "My Chatbot" --description "staging" --uri "https://staging.example.com/api/chat" --body-template $body --response-path "choices[0].message.content" --authorized-by "you@example.com" --i-am-authorized
> ```

**2. Run a scan:**

```bash
# Using your default provider (auto-detected from .env):
llm-inspector scan run \
  --target <target_id from step 1> \
  --request "Scan for prompt injection, jailbreak resistance, and system prompt leakage."

# Explicitly choosing a provider:
llm-inspector scan run \
  --target <target_id> \
  --provider openai \
  --model gpt-4o \
  --request "Scan for prompt injection and system prompt leakage."

# Using a local Ollama model as the brain:
llm-inspector scan run \
  --target <target_id> \
  --provider ollama \
  --model qwen2.5:7b \
  --request "Scan for jailbreak resistance."
```

You'll see live progress as the LLM plans, calls tools, and adapts. When it
finishes:
- A Markdown + JSON report is written to `.llm_inspector_data/reports/`
- A structured scan log is written to `.llm_inspector_data/logs/`
- A findings table prints to your terminal

**3. Review past scans:**

```bash
llm-inspector scan list
llm-inspector scan report <scan_id>
```

## Web UI

LLM Inspector ships a Flask-based web UI on `localhost:5000` for users who
prefer a graphical interface over the CLI.

```bash
llm-inspector-web
# or:
python -m llm_inspector.web.app
```

The web UI provides:

- **Scan page** (`/`): Select a registered target, choose OWASP categories
  and tools via checkboxes (manual mode) or type a natural-language prompt
  (brain LLM mode). Add target details to guide promptfoo_redteam attack
  generation. Live scan logs stream via SSE, and findings display in an
  expandable results table.
- **Target registration** (`/target/new`): A step-by-step wizard to register
  new targets — choose target type (HTTP endpoint or Ollama local),
  configure connection details (URL, headers, body template, response path),
  test the connection, and confirm authorization. Ollama targets auto-detect
  available models.

## Manual scan mode

Manual mode lets you select OWASP categories and tools directly without
the Brain LLM planning phase — useful when you know exactly what to test.
The Critic (Brain LLM) still validates findings after probes run.

```bash
# List available OWASP categories and tools:
llm-inspector scan categories

# Run a manual scan:
llm-inspector scan manual \
  --target <target_id> \
  --vuln LLM01 --vuln LLM07 \
  --tool garak --tool promptfoo_redteam \
  --purpose "a customer support chatbot for a bank" \
  --intensity medium

# Scan all categories with all tools:
llm-inspector scan manual \
  --target <target_id> \
  --vuln all --tool all
```

The `--purpose` flag describes the target application (e.g. "a customer
support chatbot for a banking application"). This is passed to
promptfoo_redteam to generate more targeted, contextual attack prompts.

### Scan intensity levels

The `--intensity` flag controls probe count, attempt limits, and
optional garak encoding buffs:

| Intensity | Probes | Attempts | Tests | Garak buffs |
|---|---|---|---|---|
| `very_small` | 1 per tool per category | 5 | 2 | — |
| `small` | All mapped | 10 | 3 | — |
| `medium` (default) | All mapped | 25 | 5 | — |
| `large` | All mapped + extra probe families | 50 | 10 | — |
| `extended` | Same as large + encoding/paraphrase transforms | 50 | 10 | Base64, CharCode, paraphrase |

The `extended` level applies garak encoding and paraphrase buffs on top
of every garak probe, roughly doubling garak scan time but catching
attacks that bypass guardrails through character encoding or rephrasing.

### Vulnerability categories

Beyond the OWASP LLM Top 10 (LLM01–LLM09), LLM Inspector includes three
cross-cutting categories that test techniques spanning multiple risk areas:

| Category | Name | Techniques |
|---|---|---|
| `EVASION` | Guardrail Evasion | Encoding bypass, token smuggling, ANSI escape injection, glitch token exploits |
| `ADAPTIVE` | Adaptive / Multi-turn Attacks | Tree of Attacks (TAP), GOAT, automatic attack generation |
| `SOCIAL_ENG` | Social Engineering / Manipulation | Grandma jailbreak, Goodside injection, DeepRole, Foot-in-the-Door, continuation attacks |

These use garak probes and are available in all intensity levels.

## Scan logs

Every scan produces a detailed log file at `.llm_inspector_data/logs/<scan_id>.scan.log`
that captures the full conversation flow:

- What was sent to the brain LLM (system prompts, messages)
- What the brain LLM responded (text, tool calls with arguments)
- Each tool call to Garak/Promptfoo (arguments, results, duration)
- Probe statistics (attempts, hits, ASR per probe)
- Critic evaluations (verdict, confidence, severity per candidate)
- Final summary (total tool calls, probes, findings, cost, time)

## Try it against a local Ollama model

You can scan a locally running Ollama model using another Ollama model as
the reasoning brain. For example, scan `qwen2.5:0.5b` (the target) using
`qwen2.5:7b` (the brain):

```bash
# Pull both models:
ollama pull qwen2.5:0.5b
ollama pull qwen2.5:7b

# Register the target (the model being scanned):
python register_target.py
# Or via CLI (use a PowerShell variable for the body template):
# $body = '{"model":"qwen2.5:0.5b","messages":[{"role":"user","content":"$INPUT"}],"stream":false}'
# llm-inspector target add --name "Qwen 0.5B" --description "Local Ollama target" --uri "http://localhost:11434/api/chat" --body-template $body --response-path "message.content" --authorized-by "you" --i-am-authorized

# Run the scan:
llm-inspector scan run \
  --target <target_id> \
  --provider ollama \
  --model qwen2.5:7b \
  --request "Scan for prompt injection, jailbreak resistance, and system prompt leakage."
```

## Try it against the mock test target

The repo ships a tiny mock vulnerable chatbot for trying LLM Inspector out
without needing a real target app:

```bash
python examples/mock_target_server.py --port 8899 --mode vulnerable &

llm-inspector target add \
  --name "Mock Vulnerable Bot" --description "local demo target" \
  --uri "http://127.0.0.1:8899/chat" \
  --body-template '{"input":"$INPUT"}' --response-path "reply" \
  --authorized-by "you" --i-am-authorized

llm-inspector scan run --target <target_id> \
  --request "Test for role manipulation and system prompt leakage."
```

## Running the test suite

```bash
pip install -r requirements.txt    # includes pytest and pytest-asyncio
pytest -q -m "not slow"            # fast unit tests, no external tools needed
pytest -q                          # includes real garak/promptfoo integration tests
```

The integration tests actually run `garak` and `promptfoo` against the
in-repo mock target — no network access to a third party and no LLM API key
required (the LLM itself is scripted/faked in those tests so the suite
doesn't depend on API credits; the rest of the pipeline is 100% real).

## Safety and scope

- LLM Inspector will not register a target without `--i-am-authorized`, and
  every MCP tool call independently re-validates target authorization
  before contacting anything.
- Built-in attack templates use benign canary markers (e.g. asking a target
  to echo a specific marker string) rather than requesting genuinely
  harmful content — see `mcp_servers/red_team/adapters/promptfoo_adapter.py`.
- This tool is for testing systems you own or are explicitly authorized to
  test. It is not legal advice; check your local laws and any applicable
  terms of service before scanning anything.

## License

MIT — see [LICENSE](./LICENSE).
