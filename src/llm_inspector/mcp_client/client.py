"""
MCP client used by the Agent Runtime.

This is the piece labeled "MCP Client" in the architecture doc's high-level
diagram. It is owned by LLM Inspector, not by Claude: Claude never talks
MCP directly. Claude produces a tool_use request in the Anthropic API
sense; this client is what turns that into an actual MCP `tools/call`
against one of our own MCP servers (red_team, blue_team, evaluation),
each spawned as a stdio subprocess.
"""

from __future__ import annotations

import os
import sys
from contextlib import AsyncExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

SERVERS_DIR = Path(__file__).resolve().parent.parent / "mcp_servers"

# Which MCP server module implements which server, and under what name
# Claude will see tools grouped as. Matches the architecture doc's
# Red Team MCP Server / Blue Team MCP Server / Evaluation MCP Server split.
SERVER_MODULES: dict[str, str] = {
    "red_team": "llm_inspector.mcp_servers.red_team.server",
    "blue_team": "llm_inspector.mcp_servers.blue_team.server",
    "evaluation": "llm_inspector.mcp_servers.evaluation.server",
}


@dataclass
class ToolCallOutcome:
    is_error: bool
    text: str
    structured: Any = None


class MCPOrchestrator:
    """
    Owns one ClientSession per MCP server, keeps a name->server_key index
    so tool calls are routed to the right subprocess, and exposes the
    aggregate tool list in Anthropic `tools=[...]` format.
    """

    def __init__(self) -> None:
        self._stack = AsyncExitStack()
        self._sessions: dict[str, ClientSession] = {}
        self._tool_owner: dict[str, str] = {}
        self._tools_by_server: dict[str, list[types.Tool]] = {}

    async def connect_all(self, server_keys: list[str] | None = None) -> None:
        keys = server_keys or list(SERVER_MODULES.keys())
        for key in keys:
            await self._connect_one(key)

    async def _connect_one(self, key: str) -> None:
        module = SERVER_MODULES[key]
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", module],
            # The MCP SDK's default subprocess environment is a filtered
            # safe subset. Our servers need LLM_INSPECTOR_DATA_DIR (to open
            # the same SQLite DB the CLI/runtime uses for target lookups)
            # so we explicitly inherit the full parent environment instead.
            env=dict(os.environ),
        )
        read, write = await self._stack.enter_async_context(stdio_client(params))
        session = await self._stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        listed = await session.list_tools()
        self._sessions[key] = session
        self._tools_by_server[key] = listed.tools
        for tool in listed.tools:
            self._tool_owner[tool.name] = key

    async def aclose(self) -> None:
        await self._stack.aclose()

    async def __aenter__(self) -> "MCPOrchestrator":
        await self.connect_all()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    def tool_definitions(self) -> list[dict[str, Any]]:
        """Aggregate MCP tool definitions into a provider-agnostic schema.
        Each tool is {name, description, input_schema} -- the LLM client
        adapters translate this into each provider's native format."""
        out: list[dict[str, Any]] = []
        for tools in self._tools_by_server.values():
            for t in tools:
                out.append(
                    {
                        "name": t.name,
                        "description": t.description or "",
                        "input_schema": t.input_schema,
                    }
                )
        return out

    def describe_tools_by_server(self) -> dict[str, list[str]]:
        return {
            key: [t.name for t in tools] for key, tools in self._tools_by_server.items()
        }

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolCallOutcome:
        owner = self._tool_owner.get(name)
        if owner is None:
            return ToolCallOutcome(
                is_error=True, text=f"Unknown tool {name!r}. Not offered by any MCP server."
            )
        session = self._sessions[owner]
        result = await session.call_tool(name, arguments)
        text_parts = [
            block.text for block in result.content if isinstance(block, types.TextContent)
        ]
        return ToolCallOutcome(
            is_error=result.is_error,
            text="\n".join(text_parts) if text_parts else "(no text content)",
            structured=result.structured_content,
        )
