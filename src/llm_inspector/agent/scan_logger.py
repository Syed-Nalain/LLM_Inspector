"""
Structured scan logger for LLM Inspector.

Produces a single, human-readable log file per scan that captures the
full conversation flow: what was sent to the brain LLM, what it
responded, which tools it called, what the tools returned, probe
statistics, and budget state. Designed to make debugging and auditing
straightforward.
"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ScanLogger:
    def __init__(self, scan_id: str, log_dir: Path, provider: str, model: str) -> None:
        self.scan_id = scan_id
        self.provider = provider
        self.model = model
        log_dir.mkdir(parents=True, exist_ok=True)
        self._path = log_dir / f"{scan_id}.scan.log"
        self._lines: list[str] = []
        self._tool_call_count = 0
        self._tool_success = 0
        self._tool_fail = 0
        self._total_probes = 0
        self._total_probes_hit = 0

        self._write_header()

    def _ts(self) -> str:
        return datetime.now(timezone.utc).strftime("%H:%M:%S")

    def _write_header(self) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._append(f"""{'='*80}
  LLM INSPECTOR — SCAN LOG
{'='*80}
  Scan ID   : {self.scan_id}
  Started   : {now}
  Provider  : {self.provider}
  Model     : {self.model}
{'='*80}
""")

    def _append(self, text: str) -> None:
        self._lines.append(text)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(text + "\n")

    def _section(self, title: str) -> None:
        self._append(f"\n{'─'*80}\n  [{self._ts()}] {title}\n{'─'*80}")

    def _subsection(self, title: str) -> None:
        self._append(f"\n  ┌─ {title}")

    def _kv(self, key: str, value: Any, indent: int = 4) -> None:
        pad = " " * indent
        val_str = str(value)
        if len(val_str) > 200:
            val_str = val_str[:200] + "..."
        self._append(f"{pad}{key}: {val_str}")

    def _block(self, label: str, content: str, max_lines: int = 30) -> None:
        lines = content.split("\n")
        truncated = len(lines) > max_lines
        display = lines[:max_lines]
        self._append(f"\n    ┌── {label} ──")
        for line in display:
            self._append(f"    │ {line}")
        if truncated:
            self._append(f"    │ ... ({len(lines) - max_lines} more lines)")
        self._append(f"    └{'─'*40}")

    # ── Phase markers ──────────────────────────────────────

    def log_target(self, target_id: str, name: str, uri: str) -> None:
        self._section("TARGET")
        self._kv("Target ID", target_id)
        self._kv("Name", name)
        self._kv("URI", uri)

    def log_budget(self, budget: dict) -> None:
        self._subsection("Budget Configuration")
        for k, v in budget.items():
            self._kv(k, v, indent=6)

    # ── Planner ────────────────────────────────────────────

    def log_planner_request(self, system_prompt: str, user_message: str) -> None:
        self._section("PLANNER PHASE")
        self._block("System Prompt → Brain LLM", system_prompt, max_lines=15)
        self._block("User Message → Brain LLM", user_message, max_lines=20)

    def log_planner_response(self, plan: list[dict], input_tok: int, output_tok: int) -> None:
        self._subsection(f"Brain LLM Response (tokens: {input_tok} in / {output_tok} out)")
        self._append("")
        self._append("    Plan Items:")
        for i, item in enumerate(plan, 1):
            pri = item.get("priority", "?")
            tech = item.get("technique", "?")
            tool = item.get("tool", "?")
            owasp = item.get("owasp_id", "?")
            rationale = item.get("rationale", "")
            self._append(f"      [{pri}] {tech} ({owasp}) via {tool}")
            self._append(f"           → {rationale}")

    # ── Executor ───────────────────────────────────────────

    def log_executor_start(self) -> None:
        self._section("EXECUTOR PHASE")

    def log_executor_turn(self, turn: int, budget_summary: dict) -> None:
        self._append(f"\n  ┌─ Turn {turn}")
        elapsed = budget_summary.get("elapsed_seconds", 0)
        calls = budget_summary.get("tool_calls_made", 0)
        cost = budget_summary.get("estimated_usd_spent", 0)
        self._kv("Elapsed", f"{elapsed}s", indent=6)
        self._kv("Tool calls so far", calls, indent=6)
        self._kv("Estimated cost", f"${cost:.4f}", indent=6)

    def log_llm_request(self, system_prompt_summary: str, messages_count: int) -> None:
        self._subsection(f"→ Brain LLM Request (conversation: {messages_count} messages)")

    def log_llm_response(
        self, text: str | None, tool_calls: list[dict], input_tok: int, output_tok: int
    ) -> None:
        self._subsection(f"← Brain LLM Response (tokens: {input_tok} in / {output_tok} out)")
        if text:
            self._block("Text Response", text, max_lines=15)
        if tool_calls:
            self._append(f"\n    Tool calls requested: {len(tool_calls)}")
            for tc in tool_calls:
                args_str = json.dumps(tc.get("arguments", {}), indent=2)
                self._append(f"      • {tc['name']}()")
                for line in args_str.split("\n"):
                    self._append(f"          {line}")
        if not text and not tool_calls:
            self._append("    (empty response — no text, no tool calls)")

    def log_executor_done(self, reason: str) -> None:
        self._append(f"\n    ■ Executor stopped: {reason}")

    # ── Tool calls ─────────────────────────────────────────

    def log_tool_call(
        self,
        tool_name: str,
        arguments: dict,
        result_text: str,
        is_error: bool,
        duration_seconds: float,
        result_stats: dict | None = None,
    ) -> None:
        self._tool_call_count += 1
        status = "ERROR" if is_error else "OK"
        if is_error:
            self._tool_fail += 1
        else:
            self._tool_success += 1

        self._subsection(f"Tool Call #{self._tool_call_count}: {tool_name} [{status}]")
        self._kv("Duration", f"{duration_seconds:.1f}s", indent=6)

        args_str = json.dumps(arguments, indent=2)
        self._block("Arguments", args_str, max_lines=10)

        result_data = result_stats
        if result_data is None:
            try:
                result_data = json.loads(result_text)
            except (json.JSONDecodeError, TypeError):
                result_data = None

        if isinstance(result_data, dict) and not is_error:
            attempts = result_data.get("attempts", 0)
            successful = result_data.get("successful", 0)
            asr = result_data.get("asr", 0)
            probe = result_data.get("probe") or result_data.get("test_category", "?")
            self._total_probes += attempts
            self._total_probes_hit += successful
            self._append(f"\n      Probe    : {probe}")
            self._append(f"      Attempts : {attempts}")
            self._append(f"      Hits     : {successful}")
            self._append(f"      ASR      : {asr:.0%}" if isinstance(asr, float) else f"      ASR      : {asr}")
            evidence = result_data.get("evidence", [])
            if evidence:
                self._append(f"      Evidence items: {len(evidence)}")
                for j, ev in enumerate(evidence[:3]):
                    hit = ev.get("detector_hit", False)
                    marker = "HIT" if hit else "miss"
                    attack_preview = str(ev.get("attack", ""))[:100]
                    self._append(f"        [{marker}] {attack_preview}")
        elif isinstance(result_data, dict) and "error" in result_data:
            self._block("Error Detail", result_data["error"], max_lines=5)
            if result_data.get("log_tail"):
                self._block("Garak Log Tail", result_data["log_tail"], max_lines=10)
        elif result_data is None:
            self._block("Raw Result", result_text[:2000], max_lines=15)

    # ── Critic ─────────────────────────────────────────────

    def log_critic_start(self, candidate_count: int) -> None:
        self._section(f"CRITIC PHASE ({candidate_count} candidates)")

    def log_critic_evaluation(
        self,
        index: int,
        technique: str,
        tool: str,
        verdict: str,
        confidence: float,
        severity: str,
        notes: str,
        is_stub: bool,
    ) -> None:
        icon = "✓" if verdict == "CONFIRMED" else "✗"
        self._subsection(f"Candidate #{index + 1}: {technique} (from {tool})")
        self._kv("Verdict", f"{icon} {verdict}", indent=6)
        self._kv("Confidence", f"{confidence:.2f}", indent=6)
        self._kv("Severity", severity, indent=6)
        self._kv("Stub data", is_stub, indent=6)
        if notes:
            self._kv("Notes", notes[:300], indent=6)

    # ── Final summary ──────────────────────────────────────

    def log_scan_complete(
        self,
        findings_count: int,
        budget_summary: dict,
        severity_counts: dict | None = None,
    ) -> None:
        self._section("SCAN COMPLETE")
        self._append(f"""
    Findings confirmed : {findings_count}
    Total tool calls   : {self._tool_call_count} ({self._tool_success} ok, {self._tool_fail} failed)
    Total probes run   : {self._total_probes}
    Total probe hits   : {self._total_probes_hit}
    Elapsed time       : {budget_summary.get('elapsed_seconds', 0)}s
    Estimated cost     : ${budget_summary.get('estimated_usd_spent', 0):.4f}
    Tool call breakdown: {json.dumps(budget_summary.get('calls_per_tool', {}))}""")

        if severity_counts:
            self._append("\n    Severity breakdown:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                count = severity_counts.get(sev, 0)
                if count:
                    self._append(f"      {sev}: {count}")

        self._append(f"\n{'='*80}")
        self._append(f"  Log file: {self._path}")
        self._append(f"{'='*80}\n")

    @property
    def log_path(self) -> Path:
        return self._path
