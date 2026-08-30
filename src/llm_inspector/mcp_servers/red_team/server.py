"""
Red Team MCP Server.

Architecture doc: "MCP is essentially providing the standardized interface:
Claude's decision -> Inspector Agent Runtime -> MCP Client -> MCP Server ->
Actual tool." This process IS that MCP Server for the red-team tools
(Garak, PyRIT, Promptfoo). It is spawned as a stdio subprocess by
mcp_client/client.py and never talked to directly by Claude -- Claude only
ever sees the tool name/description/schema below and produces a
`tool_use` request that the Agent Runtime forwards here over MCP.

Every tool takes a `target_id` (never a raw URL) and re-validates
authorization against the same TargetManager/DB the CLI uses, as a second
independent gate in addition to the one the Agent Runtime applies before
issuing the call -- defense in depth, not a substitute for it.
"""

from __future__ import annotations

import asyncio
from typing import Any

from mcp.server import MCPServer

from llm_inspector.config import get_settings
from llm_inspector.mcp_servers.red_team.adapters import (
    garak_adapter,
    promptfoo_adapter,
    pyrit_adapter,
)
from llm_inspector.storage.database import Database
from llm_inspector.target.manager import TargetManager, TargetNotAuthorizedError

mcp = MCPServer(
    name="llm-inspector-red-team",
    instructions="Red team tools: Garak, PyRIT, Promptfoo. Requires target_id.",
)

_settings = get_settings()
_db = Database(_settings.db_path)
_targets = TargetManager(_db)


def _get_authorized_target(target_id: str):
    try:
        return _targets.require_authorized(target_id)
    except (KeyError, TargetNotAuthorizedError) as e:
        raise ValueError(str(e)) from e


@mcp.tool()
async def run_garak_probe(
    probe_name: str, target_id: str, max_attempts: int = 20,
    buffs: list[str] | None = None,
) -> dict[str, Any]:
    """Run a Garak security probe. Returns attempts, successful, asr, evidence.
    Optional buffs: list of garak buff selectors (e.g. 'encoding.Base64') to transform probes."""
    target = _get_authorized_target(target_id)
    return await garak_adapter.run_garak_probe(
        probe_name=probe_name,
        target_config=target.rest_config,
        max_attempts=max_attempts,
        work_dir=_settings.data_dir,
        buffs=buffs,
    )


@mcp.tool()
async def run_pyrit_attack(
    attack_strategy: str, target_id: str, max_turns: int = 5
) -> dict[str, Any]:
    """Run a PyRIT adaptive multi-turn attack (STUB). Returns synthetic evidence."""
    target = _get_authorized_target(target_id)
    return await pyrit_adapter.run_pyrit_attack(
        attack_strategy=attack_strategy,
        target_config=target.rest_config,
        max_turns=max_turns,
        work_dir=_settings.data_dir,
    )


@mcp.tool()
async def run_promptfoo_test(
    test_category: str, target_id: str, max_attempts: int = 10
) -> dict[str, Any]:
    """Run a local Promptfoo evaluation (13 hardcoded prompts, offline). Returns attempts, successful, asr, evidence."""
    target = _get_authorized_target(target_id)
    return await promptfoo_adapter.run_promptfoo_test(
        test_category=test_category,
        target_config=target.rest_config,
        max_attempts=max_attempts,
        work_dir=_settings.data_dir,
    )


@mcp.tool()
async def run_promptfoo_redteam(
    redteam_category: str,
    target_id: str,
    num_tests: int = 5,
    purpose: str = "security testing of an LLM application",
) -> dict[str, Any]:
    """Run Promptfoo LLM-powered redteam (generates diverse attacks using Brain's API key). Returns attempts, successful, asr, evidence."""
    target = _get_authorized_target(target_id)
    if not _settings.api_key:
        return {
            "tool": "promptfoo",
            "test_category": redteam_category,
            "mode": "llm",
            "error": (
                "run_promptfoo_redteam requires an LLM API key for attack "
                "generation and grading. Set your provider's API key in .env "
                "(e.g. GROQ_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY)."
            ),
        }
    return await promptfoo_adapter.run_promptfoo_redteam(
        redteam_category=redteam_category,
        target_config=target.rest_config,
        num_tests=num_tests,
        work_dir=_settings.data_dir,
        provider=_settings.provider,
        model=_settings.model,
        api_key=_settings.api_key,
        purpose=purpose,
    )


def main() -> None:
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
