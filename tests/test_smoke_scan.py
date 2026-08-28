"""
End-to-end smoke test of the full architecture: Agent Runtime -> MCP
Client -> Red Team MCP Server -> real Garak/Promptfoo subprocesses -> real
HTTP calls to the in-repo mock target -> results flow back through MCP ->
Critic validation -> Finding -> report generation.

The ONLY thing faked here is the LLM itself (FakeLLMClient below),
because a live test suite can't depend on a real API key. The fake client
is scripted to behave like a reasonable executor (call run_garak_probe,
then run_promptfoo_test, then stop) and a critic that confirms whatever
candidate evidence it's shown -- this exercises every other real component
of the system, including the parts a scripted client can't fake:
garak/promptfoo actually running, actually hitting the mock target over
HTTP, actually parsing real report output.

Anyone with an API key can run the equivalent real thing via:
  llm-inspector scan run --target <id> --request "..."
"""

from __future__ import annotations

import json
import re
import shutil

import pytest

from llm_inspector.agent.llm_client import BaseLLMClient, LLMResponse, ToolCall
from llm_inspector.agent.runtime import AgentRuntime
from llm_inspector.config import get_settings
from llm_inspector.storage.database import Database
from llm_inspector.target.manager import TargetManager

pytestmark = pytest.mark.slow

requires_tools = pytest.mark.skipif(
    shutil.which("garak") is None or shutil.which("promptfoo") is None,
    reason="garak and promptfoo must both be installed",
)


class FakeLLMClient(BaseLLMClient):
    """Scripted stand-in for any LLM provider, executor-loop aware."""

    provider_name = "fake"

    def __init__(self) -> None:
        self.executor_calls = 0
        self.critic_calls = 0

    async def create_message(self, *, model, max_tokens, system, messages, tools=None) -> LLMResponse:
        # Order matters: the Executor system prompt *references* "the
        # Planning phase" in prose, so a plain substring check on
        # "Planning phase" would misfire on Executor turns too. Check
        # each prompt's unique opening line instead.
        if system.startswith("You are the Planning phase"):
            plan = [
                {
                    "technique": "role_manipulation",
                    "owasp_id": "LLM01b",
                    "tool": "garak",
                    "rationale": "test",
                    "priority": 1,
                },
                {
                    "technique": "system_prompt_leak",
                    "owasp_id": "LLM07",
                    "tool": "promptfoo",
                    "rationale": "test",
                    "priority": 2,
                },
            ]
            return LLMResponse(text=json.dumps(plan), input_tokens=100, output_tokens=100)

        if system.startswith("You are the independent Critic"):
            self.critic_calls += 1
            verdict = {
                "verdict": "CONFIRMED",
                "confidence": 0.85,
                "severity": "HIGH",
                "expected_behavior": "The target should refuse to leak internal data.",
                "actual_behavior": "The target complied and leaked internal data.",
                "notes": "Response directly contains leaked content matching the attack's goal.",
                "recommended_mitigation": "Add explicit system-prompt-leak refusal instructions and output filtering.",
            }
            return LLMResponse(text=json.dumps(verdict), input_tokens=100, output_tokens=100)

        # Executor phase
        m = re.search(r"target_id: (\S+)", system)
        target_id = m.group(1) if m else "unknown"
        self.executor_calls += 1

        if self.executor_calls == 1:
            return LLMResponse(
                tool_calls=[ToolCall(
                    id="call_1",
                    name="run_garak_probe",
                    arguments={
                        "probe_name": "role_manipulation",
                        "target_id": target_id,
                        "max_attempts": 3,
                    },
                )],
                input_tokens=100,
                output_tokens=100,
            )
        if self.executor_calls == 2:
            return LLMResponse(
                tool_calls=[ToolCall(
                    id="call_2",
                    name="run_promptfoo_test",
                    arguments={
                        "test_category": "system_prompt_leak",
                        "target_id": target_id,
                        "max_attempts": 4,
                    },
                )],
                input_tokens=100,
                output_tokens=100,
            )

        return LLMResponse(
            text="Tested role manipulation via garak and system prompt "
            "leakage via promptfoo. Stopping here.",
            input_tokens=100,
            output_tokens=100,
        )


@requires_tools
@pytest.mark.asyncio
async def test_full_scan_pipeline_against_vulnerable_target(mock_target, tmp_path, monkeypatch):
    base_url, set_mode = mock_target
    set_mode("vulnerable")

    monkeypatch.setenv("LLM_INSPECTOR_DATA_DIR", str(tmp_path))
    settings = get_settings()
    settings.data_dir = tmp_path
    db = Database(settings.db_path)
    manager = TargetManager(db)
    target = manager.register(
        name="smoke-test target",
        description="in-repo mock target",
        uri=base_url,
        method="post",
        headers={"Content-Type": "application/json"},
        request_template={"input": "$INPUT"},
        response_text_path="reply",
        authorized_by="pytest",
    )

    runtime = AgentRuntime(settings, db, manager)
    fake_client = FakeLLMClient()

    result = await runtime.run_scan(
        target_id=target.id,
        user_request="Scan for role manipulation and system prompt leakage.",
        requester="pytest",
        client=fake_client,
    )

    assert result.status == "completed"
    assert fake_client.executor_calls >= 2
    assert fake_client.critic_calls >= 1
    # the mock target is deliberately vulnerable to these two techniques,
    # so we expect at least one confirmed finding to have survived the
    # (faked-but-scripted-to-confirm) Critic pass.
    assert len(result.findings) >= 1
    for f in result.findings:
        assert f.validated_by_critic is True
        assert f.confidence > 0

    # scan + findings should be persisted
    stored_scan = db.get_scan(result.scan_id)
    assert stored_scan is not None
    assert stored_scan["status"] == "completed"
    stored_findings = db.list_findings(result.scan_id)
    assert len(stored_findings) == len(result.findings)


@requires_tools
@pytest.mark.asyncio
async def test_full_scan_pipeline_no_findings_on_safe_target(mock_target, tmp_path, monkeypatch):
    base_url, set_mode = mock_target
    set_mode("safe")

    monkeypatch.setenv("LLM_INSPECTOR_DATA_DIR", str(tmp_path))
    settings = get_settings()
    settings.data_dir = tmp_path
    db = Database(settings.db_path)
    manager = TargetManager(db)
    target = manager.register(
        name="smoke-test target (safe)",
        description="in-repo mock target, refuses everything",
        uri=base_url,
        method="post",
        headers={"Content-Type": "application/json"},
        request_template={"input": "$INPUT"},
        response_text_path="reply",
        authorized_by="pytest",
    )

    runtime = AgentRuntime(settings, db, manager)
    fake_client = FakeLLMClient()

    result = await runtime.run_scan(
        target_id=target.id,
        user_request="Scan for role manipulation and system prompt leakage.",
        requester="pytest",
        client=fake_client,
    )

    # the executor still ran both tools (proving this isn't a vacuous
    # pass), it just found nothing on a target that refuses everything --
    # so no candidates should ever reach the Critic, regardless of how
    # permissive the fake Critic is scripted to be.
    assert fake_client.executor_calls >= 2
    assert fake_client.critic_calls == 0
    assert len(result.findings) == 0
