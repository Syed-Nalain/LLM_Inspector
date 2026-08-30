"""
Agent Runtime: the "body + nervous system" around the LLM brain,
per the architecture doc's framing. This module owns the full
Planner -> Executor -> Critic loop:

  1. Planner: one LLM call producing an initial test plan (agent/planner.py).
  2. Executor: the agent loop -- the LLM reasons, calls MCP tools (via
     mcp_client/client.py, which talks to the Red/Blue/Evaluation MCP
     servers), observes results, and adapts, all under a hard budget
     (agent/budget.py) and backed by running scan memory (agent/memory.py).
  3. Critic: for every candidate finding surfaced by tool evidence during
     execution, an independent LLM call (agent/critic.py) validates it
     before it is allowed to become a reported Finding.

The LLM never talks MCP directly and never executes a tool itself -- see
mcp_client/client.py's docstring for that boundary.

The reasoning brain can be any supported provider (Anthropic, OpenAI,
Gemini, Ollama) -- see agent/llm_client.py.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from llm_inspector.agent.budget import BudgetTracker
from llm_inspector.agent.critic import run_critic
from llm_inspector.agent.llm_client import BaseLLMClient, LLMResponse, build_llm_client
from llm_inspector.agent.manual_scan import resolve_probes
from llm_inspector.agent.memory import ScanMemory
from llm_inspector.agent.planner import PLANNER_SYSTEM_PROMPT, render_plan_for_prompt, run_planner
from llm_inspector.agent.scan_logger import ScanLogger
from llm_inspector.agent.security_ontology import find_technique
from llm_inspector.agent.system_prompt import build_executor_system_prompt
from llm_inspector.config import Settings
from llm_inspector.findings.finding import Finding, Severity, severity_from_asr
from llm_inspector.mcp_client.client import MCPOrchestrator
from llm_inspector.mcp_servers.red_team.adapters.garak_adapter import (
    GARAK_PROBE_TO_TECHNIQUE,
)
from llm_inspector.mcp_servers.red_team.adapters.pyrit_adapter import (
    STRATEGY_TO_TECHNIQUE,
)
from llm_inspector.storage.database import Database
from llm_inspector.target.manager import TargetManager
from llm_inspector.target.target import Target

MAX_EXECUTOR_TURNS = 40  # hard safety cap independent of the budget tracker

# MCP tool name -> BudgetTracker per-tool key (see config.Budget.max_probes_per_tool)
TOOL_TO_BUDGET_KEY: dict[str, str] = {
    "run_garak_probe": "garak",
    "run_pyrit_attack": "pyrit",
    "run_promptfoo_test": "promptfoo",
    "run_promptfoo_redteam": "promptfoo",
}


@dataclass
class CandidateEvidence:
    technique: str
    owasp_id: str
    tool: str
    attack: str
    response: str
    is_stub: bool = False
    affected_component: str = ""
    reproducibility: str = ""
    raw_evidence_summary: str = ""


@dataclass
class ScanResult:
    scan_id: str
    target: Target
    plan: list[dict]
    findings: list[Finding]
    memory: ScanMemory
    budget_summary: dict
    executor_summary: str
    status: str = "completed"


def _response_to_conversation_blocks(resp: LLMResponse) -> list[dict[str, Any]]:
    """Convert a unified LLMResponse into Anthropic-style content blocks
    for the conversation history. This is the internal canonical format
    used for the conversation list -- each provider adapter knows how to
    translate from this format when it receives messages."""
    out: list[dict[str, Any]] = []
    if resp.text:
        out.append({"type": "text", "text": resp.text})
    for tc in resp.tool_calls:
        out.append({"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.arguments})
    return out


class AgentRuntime:
    def __init__(self, settings: Settings, db: Database, target_manager: TargetManager):
        self.settings = settings
        self.db = db
        self.target_manager = target_manager

    async def run_scan(
        self,
        target_id: str,
        user_request: str,
        requester: str,
        api_key_override: str | None = None,
        on_event=None,
        client: BaseLLMClient | None = None,
    ) -> ScanResult:
        def emit(msg: str) -> None:
            if on_event:
                on_event(msg)

        target = self.target_manager.require_authorized(target_id)
        if client is None:
            api_key = api_key_override or self.settings.api_key
            client = build_llm_client(
                provider=self.settings.provider,
                api_key=api_key,
                base_url=self.settings.base_url,
            )
        model = self.settings.model

        budget = BudgetTracker(self.settings.budget)
        memory = ScanMemory(target_name=target.name)
        scan_id = uuid.uuid4().hex[:12]

        log_dir = self.settings.data_dir / "logs"
        slog = ScanLogger(
            scan_id=scan_id,
            log_dir=log_dir,
            provider=getattr(client, "provider_name", self.settings.provider),
            model=model,
        )
        slog.log_target(target.id, target.name, target.rest_config.uri)
        slog.log_budget(budget.summary()["budget"])

        self.db.create_scan(
            scan_id=scan_id,
            target_id=target.id,
            started_at=datetime.now(timezone.utc).isoformat(),
            budget=budget.summary()["budget"],
        )

        # ── Planner ────────────────────────────────────────
        emit(f"Planning phase: asking {self.settings.provider} for an initial test strategy...")

        planner_user_msg = (
            f"TARGET\nname: {target.name}\ndescription: {target.description}\n\n"
            f"USER REQUEST\n{user_request}"
        )
        slog.log_planner_request(PLANNER_SYSTEM_PROMPT, planner_user_msg)

        plan = await run_planner(client, model, target, user_request)

        slog.log_planner_response(plan, 0, 0)
        emit(f"Plan produced with {len(plan)} test item(s).")

        # ── Executor ───────────────────────────────────────
        slog.log_executor_start()

        system_prompt = build_executor_system_prompt(target, render_plan_for_prompt(plan))
        candidates: list[CandidateEvidence] = []
        conversation: list[dict[str, Any]] = [
            {"role": "user", "content": user_request}
        ]

        async with MCPOrchestrator() as orch:
            tools_schema = orch.tool_definitions()
            turn = 0
            final_text = ""
            while turn < MAX_EXECUTOR_TURNS:
                turn += 1
                if budget.elapsed_seconds() >= budget.budget.max_seconds:
                    slog.log_executor_done("Time budget exhausted")
                    emit("Time budget exhausted; stopping executor loop.")
                    break

                slog.log_executor_turn(turn, budget.summary())

                sys_text = (
                    system_prompt
                    + "\n\nCURRENT SCAN MEMORY\n"
                    + memory.render_for_prompt()
                    + f"\n\nBUDGET STATUS\n{json.dumps(budget.summary())}"
                )
                slog.log_llm_request(
                    f"Executor system prompt ({len(sys_text)} chars)",
                    len(conversation),
                )

                response = await client.create_message(
                    model=model,
                    max_tokens=2048,
                    system=sys_text,
                    messages=conversation,
                    tools=tools_schema,
                )
                budget.record_llm_usage(
                    response.input_tokens,
                    response.output_tokens,
                    client,
                )

                slog.log_llm_response(
                    text=response.text or None,
                    tool_calls=[
                        {"name": tc.name, "id": tc.id, "arguments": tc.arguments}
                        for tc in response.tool_calls
                    ],
                    input_tok=response.input_tokens,
                    output_tok=response.output_tokens,
                )

                conversation.append(
                    {"role": "assistant", "content": _response_to_conversation_blocks(response)}
                )

                if response.text:
                    final_text = response.text

                if not response.has_tool_calls:
                    slog.log_executor_done("No further tool calls requested")
                    emit("Executor phase concluded (no further tool calls requested).")
                    break

                tool_result_blocks: list[dict[str, Any]] = []
                for tc in response.tool_calls:
                    budget_key = TOOL_TO_BUDGET_KEY.get(tc.name, tc.name)
                    allowed, reason = budget.can_call(budget_key)
                    if not allowed:
                        tool_result_blocks.append(
                            {
                                "type": "tool_result",
                                "tool_use_id": tc.id,
                                "content": reason or "Budget exceeded.",
                                "is_error": True,
                            }
                        )
                        continue

                    emit(f"Calling {tc.name}({json.dumps(tc.arguments)[:120]}...)")
                    started = time.monotonic()
                    outcome = await orch.call_tool(tc.name, tc.arguments)
                    call_duration = time.monotonic() - started
                    budget.record_call(budget_key)

                    try:
                        _parsed_stats = json.loads(outcome.text)
                    except (json.JSONDecodeError, TypeError):
                        _parsed_stats = None
                    slog.log_tool_call(
                        tool_name=tc.name,
                        arguments=tc.arguments,
                        result_text=outcome.text[:4000],
                        is_error=outcome.is_error,
                        duration_seconds=round(call_duration, 1),
                        result_stats=_parsed_stats,
                    )

                    self.db.log_tool_call(
                        call_id=uuid.uuid4().hex[:12],
                        scan_id=scan_id,
                        seq=budget.tool_calls_made,
                        tool_name=tc.name,
                        arguments=tc.arguments,
                        result={"is_error": outcome.is_error, "text": outcome.text[:4000]},
                        started_at=datetime.fromtimestamp(
                            time.time() - call_duration, tz=timezone.utc
                        ).isoformat(),
                        finished_at=datetime.now(timezone.utc).isoformat(),
                    )
                    self._update_memory_and_candidates(
                        tc.name, tc.arguments, outcome, memory, candidates, target
                    )
                    tool_result_blocks.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": tc.id,
                            "content": outcome.text[:8000],
                            "is_error": outcome.is_error,
                        }
                    )
                conversation.append({"role": "user", "content": tool_result_blocks})

            if turn >= MAX_EXECUTOR_TURNS:
                slog.log_executor_done("Hard turn cap reached")
                emit("Hard turn cap reached; stopping executor loop.")

        # ── Critic ─────────────────────────────────────────
        slog.log_critic_start(len(candidates))
        emit(
            f"Critic phase: independently validating {len(candidates)} candidate "
            "finding(s)..."
        )
        findings: list[Finding] = []
        for i, cand in enumerate(candidates):
            verdict = await run_critic(
                client,
                model,
                technique=cand.technique,
                owasp_id=cand.owasp_id,
                tool=cand.tool,
                attack=cand.attack,
                response=cand.response,
                is_stub=cand.is_stub,
            )

            slog.log_critic_evaluation(
                index=i,
                technique=cand.technique,
                tool=cand.tool,
                verdict=verdict.verdict,
                confidence=verdict.confidence,
                severity=verdict.severity,
                notes=verdict.notes,
                is_stub=cand.is_stub,
            )

            if verdict.verdict != "CONFIRMED":
                memory.add_note(
                    f"Critic did not confirm a candidate {cand.technique} finding "
                    f"from {cand.tool} (verdict={verdict.verdict})."
                )
                continue
            try:
                severity = Severity(verdict.severity)
            except ValueError:
                severity = severity_from_asr(0.1)
            finding = Finding(
                vulnerability=cand.technique.replace("_", " ").title(),
                owasp_id=cand.owasp_id,
                technique=cand.technique,
                severity=severity,
                confidence=verdict.confidence,
                attack=cand.attack,
                target_response=cand.response,
                expected_behavior=verdict.expected_behavior,
                actual_behavior=verdict.actual_behavior,
                evidence=cand.raw_evidence_summary,
                reproducibility=cand.reproducibility,
                affected_component=cand.affected_component or target.name,
                recommended_mitigation=verdict.recommended_mitigation,
                source_tool=cand.tool,
                validated_by_critic=True,
                critic_notes=verdict.notes,
            )
            findings.append(finding)
            self.db.save_finding(
                finding_id=finding.id,
                scan_id=scan_id,
                data=finding.to_dict(),
                created_at=finding.created_at,
            )

        # ── Wrap up ────────────────────────────────────────
        self.db.finish_scan(
            scan_id=scan_id,
            status="completed",
            finished_at=datetime.now(timezone.utc).isoformat(),
            usage=budget.summary(),
        )

        severity_counts = {}
        for f in findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        slog.log_scan_complete(
            findings_count=len(findings),
            budget_summary=budget.summary(),
            severity_counts=severity_counts,
        )

        emit(f"Scan complete: {len(findings)} confirmed finding(s).")
        emit(f"Scan log: {slog.log_path}")

        return ScanResult(
            scan_id=scan_id,
            target=target,
            plan=plan,
            findings=findings,
            memory=memory,
            budget_summary=budget.summary(),
            executor_summary=final_text,
        )

    def _update_memory_and_candidates(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        outcome: Any,
        memory: ScanMemory,
        candidates: list[CandidateEvidence],
        target: Target,
    ) -> None:
        if outcome.is_error:
            memory.add_note(f"{tool_name} call failed: {outcome.text[:200]}")
            return
        try:
            result = json.loads(outcome.text)
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(result, dict) or "error" in result:
            if isinstance(result, dict) and "error" in result:
                memory.add_note(f"{tool_name} reported an error: {result['error'][:200]}")
            return

        technique, owasp_id, tool_label = self._resolve_technique(tool_name, result)
        attempts = result.get("attempts", 0)
        successful = result.get("successful", 0)
        memory.record_result(technique, tool_label, attempts, successful)

        is_stub = bool(result.get("stub", False))
        evidence_items = result.get("evidence", [])
        hits = [e for e in evidence_items if e.get("detector_hit")]
        for hit in hits[:3]:
            candidates.append(
                CandidateEvidence(
                    technique=technique,
                    owasp_id=owasp_id,
                    tool=tool_label,
                    attack=str(hit.get("attack", ""))[:3000],
                    response=str(hit.get("response", ""))[:3000],
                    is_stub=is_stub,
                    affected_component=target.name,
                    reproducibility=f"{successful}/{attempts} attempts triggered this "
                    f"behavior (ASR {result.get('asr', 0):.0%})",
                    raw_evidence_summary=(
                        f"{tool_label} probe '{result.get('probe') or result.get('test_category') or result.get('attack_strategy')}': "
                        f"{successful}/{attempts} attempts succeeded (ASR "
                        f"{result.get('asr', 0):.0%})."
                    ),
                )
            )

    @staticmethod
    def _resolve_technique(tool_name: str, result: dict[str, Any]) -> tuple[str, str, str]:
        tool_label = result.get("tool", tool_name)
        if tool_label == "garak":
            probe = result.get("probe", "")
            technique = GARAK_PROBE_TO_TECHNIQUE.get(probe, probe)
        elif tool_label == "promptfoo":
            technique = result.get("test_category", "unknown")
        elif tool_label == "pyrit":
            strategy = result.get("attack_strategy", "")
            technique = STRATEGY_TO_TECHNIQUE.get(strategy, strategy)
        else:
            technique = tool_name

        owasp_id = result.get("owasp_id", "")
        if not owasp_id:
            found = find_technique(technique)
            owasp_id = found[0].owasp_id if found else "UNKNOWN"
        return technique, owasp_id, tool_label

    async def run_manual_scan(
        self,
        target_id: str,
        owasp_ids: list[str],
        tools: list[str],
        requester: str,
        max_attempts: int = 20,
        num_tests: int = 5,
        purpose: str = "security testing of an LLM application",
        intensity: str = "medium",
        on_event=None,
    ) -> ScanResult:
        """Run a scan without the Brain LLM — probes are determined
        directly from the user's OWASP category + tool selections."""

        def emit(msg: str) -> None:
            if on_event:
                on_event(msg)

        target = self.target_manager.require_authorized(target_id)
        budget = BudgetTracker(self.settings.budget)
        memory = ScanMemory(target_name=target.name)
        scan_id = uuid.uuid4().hex[:12]

        log_dir = self.settings.data_dir / "logs"
        slog = ScanLogger(
            scan_id=scan_id,
            log_dir=log_dir,
            provider="manual",
            model="none",
        )
        slog.log_target(target.id, target.name, target.rest_config.uri)
        slog.log_budget(budget.summary()["budget"])

        self.db.create_scan(
            scan_id=scan_id,
            target_id=target.id,
            started_at=datetime.now(timezone.utc).isoformat(),
            budget=budget.summary()["budget"],
        )

        probe_calls = resolve_probes(
            owasp_ids, tools, target_id, max_attempts, num_tests, purpose,
            intensity=intensity,
        )
        plan = [
            {
                "technique": c["label"],
                "owasp_id": c["owasp_id"],
                "tool": c["tool_name"].replace("run_", "").replace("_probe", "").replace("_test", "").replace("_attack", ""),
                "rationale": "Manual selection",
                "priority": 3,
            }
            for c in probe_calls
        ]

        emit(f"Manual scan [{intensity}]: {len(probe_calls)} probe(s) across {', '.join(tools)} for {', '.join(owasp_ids)}")

        candidates: list[CandidateEvidence] = []

        async with MCPOrchestrator() as orch:
            for i, call in enumerate(probe_calls, 1):
                if budget.elapsed_seconds() >= budget.budget.max_seconds:
                    emit("Time budget exhausted; stopping.")
                    break

                emit(f"[{i}/{len(probe_calls)}] Running {call['label']}...")
                started = time.monotonic()
                outcome = await orch.call_tool(call["tool_name"], call["args"])
                call_duration = time.monotonic() - started
                budget.record_call(TOOL_TO_BUDGET_KEY.get(call["tool_name"], call["tool_name"]))

                try:
                    _parsed_stats = json.loads(outcome.text)
                except (json.JSONDecodeError, TypeError):
                    _parsed_stats = None
                slog.log_tool_call(
                    tool_name=call["tool_name"],
                    arguments=call["args"],
                    result_text=outcome.text[:4000],
                    is_error=outcome.is_error,
                    duration_seconds=round(call_duration, 1),
                    result_stats=_parsed_stats,
                )
                self.db.log_tool_call(
                    call_id=uuid.uuid4().hex[:12],
                    scan_id=scan_id,
                    seq=i,
                    tool_name=call["tool_name"],
                    arguments=call["args"],
                    result={"is_error": outcome.is_error, "text": outcome.text[:4000]},
                    started_at=datetime.fromtimestamp(
                        time.time() - call_duration, tz=timezone.utc
                    ).isoformat(),
                    finished_at=datetime.now(timezone.utc).isoformat(),
                )
                self._update_memory_and_candidates(
                    call["tool_name"], call["args"], outcome, memory, candidates, target,
                )

                if not outcome.is_error:
                    try:
                        result = json.loads(outcome.text)
                        hits = result.get("successful", 0)
                        total = result.get("attempts", 0)
                        asr = result.get("asr", 0)
                        emit(f"    → {hits}/{total} hits (ASR {asr:.0%}) in {call_duration:.1f}s")
                    except (json.JSONDecodeError, TypeError):
                        pass
                else:
                    emit(f"    → Error: {outcome.text[:200]}")

        # ── Critic ─────────────────────────────────────────
        api_key = self.settings.api_key
        client = build_llm_client(
            provider=self.settings.provider,
            api_key=api_key,
            base_url=self.settings.base_url,
        )
        model = self.settings.model

        slog.log_critic_start(len(candidates))
        emit(
            f"Critic phase: Brain LLM validating {len(candidates)} candidate "
            "finding(s)..."
        )
        findings: list[Finding] = []
        for i, cand in enumerate(candidates):
            verdict = await run_critic(
                client,
                model,
                technique=cand.technique,
                owasp_id=cand.owasp_id,
                tool=cand.tool,
                attack=cand.attack,
                response=cand.response,
                is_stub=cand.is_stub,
            )

            slog.log_critic_evaluation(
                index=i,
                technique=cand.technique,
                tool=cand.tool,
                verdict=verdict.verdict,
                confidence=verdict.confidence,
                severity=verdict.severity,
                notes=verdict.notes,
                is_stub=cand.is_stub,
            )

            if verdict.verdict != "CONFIRMED":
                memory.add_note(
                    f"Critic did not confirm a candidate {cand.technique} finding "
                    f"from {cand.tool} (verdict={verdict.verdict})."
                )
                continue
            try:
                severity = Severity(verdict.severity)
            except ValueError:
                severity = severity_from_asr(0.1)
            finding = Finding(
                vulnerability=cand.technique.replace("_", " ").title(),
                owasp_id=cand.owasp_id,
                technique=cand.technique,
                severity=severity,
                confidence=verdict.confidence,
                attack=cand.attack,
                target_response=cand.response,
                expected_behavior=verdict.expected_behavior,
                actual_behavior=verdict.actual_behavior,
                evidence=cand.raw_evidence_summary,
                reproducibility=cand.reproducibility,
                affected_component=cand.affected_component or target.name,
                recommended_mitigation=verdict.recommended_mitigation,
                source_tool=cand.tool,
                validated_by_critic=True,
                critic_notes=verdict.notes,
            )
            findings.append(finding)
            self.db.save_finding(
                finding_id=finding.id,
                scan_id=scan_id,
                data=finding.to_dict(),
                created_at=finding.created_at,
            )

        self.db.finish_scan(
            scan_id=scan_id,
            status="completed",
            finished_at=datetime.now(timezone.utc).isoformat(),
            usage=budget.summary(),
        )

        severity_counts = {}
        for f in findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        slog.log_scan_complete(
            findings_count=len(findings),
            budget_summary=budget.summary(),
            severity_counts=severity_counts,
        )

        emit(f"Scan complete: {len(findings)} confirmed finding(s).")
        emit(f"Scan log: {slog.log_path}")

        return ScanResult(
            scan_id=scan_id,
            target=target,
            plan=plan,
            findings=findings,
            memory=memory,
            budget_summary=budget.summary(),
            executor_summary=f"Manual scan: {len(probe_calls)} probes, {len(findings)} findings.",
        )
