"""
Blue Team MCP Server: defensive/guardrail checks (LlamaGuard, NeMo
Guardrails) used to evaluate whether a *response* (the target's output,
or a candidate attack prompt) would be flagged by a content-safety layer.
Both adapters are currently stubs -- see EXTENDED_README.md.
"""

from __future__ import annotations

import asyncio
from typing import Any

from mcp.server import MCPServer

from llm_inspector.mcp_servers.blue_team.adapters import llamaguard_adapter, nemoguard_adapter

mcp = MCPServer(
    name="llm-inspector-blue-team",
    instructions="Defensive guardrail classifiers (stubs).",
)


@mcp.tool()
async def check_llamaguard(input_text: str) -> dict[str, Any]:
    """[STUB] Llama Guard content safety check. Returns unsafe, categories, confidence."""
    return await llamaguard_adapter.check_llamaguard(input_text)


@mcp.tool()
async def check_nemoguard(input_text: str) -> dict[str, Any]:
    """[STUB] NeMo Guardrails check. Returns blocked, triggered_rails."""
    return await nemoguard_adapter.check_nemoguard(input_text)


def main() -> None:
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
