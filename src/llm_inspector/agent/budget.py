"""
BudgetTracker: runtime enforcement of the scan's resource constraints.

Architecture doc, component (6): without an explicit budget, an agentic
loop can trivially spiral into "attack, attack, attack, attack, attack...".
This tracker is consulted before every tool call the agent wants to make;
once a cap is hit, the corresponding tool is no longer offered to the LLM
and the agent loop is nudged toward wrapping up and producing a report.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from llm_inspector.config import Budget

if TYPE_CHECKING:
    from llm_inspector.agent.llm_client import BaseLLMClient


class BudgetExceededError(Exception):
    pass


@dataclass
class BudgetTracker:
    budget: Budget
    _start_time: float = field(default_factory=time.monotonic)
    tool_calls_made: int = 0
    calls_per_tool: dict[str, int] = field(default_factory=dict)
    estimated_usd_spent: float = 0.0

    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._start_time

    def remaining_seconds(self) -> float:
        return max(0.0, self.budget.max_seconds - self.elapsed_seconds())

    def can_call(self, tool_name: str) -> tuple[bool, str | None]:
        if self.elapsed_seconds() >= self.budget.max_seconds:
            return False, (
                f"Scan time budget exhausted ({self.budget.max_seconds}s). "
                "No further tool calls permitted; wrap up and report findings."
            )
        if self.tool_calls_made >= self.budget.max_tool_calls:
            return False, (
                f"Tool call budget exhausted ({self.budget.max_tool_calls} calls). "
                "No further tool calls permitted; wrap up and report findings."
            )
        if self.estimated_usd_spent >= self.budget.max_usd:
            return False, (
                f"Cost budget exhausted (${self.budget.max_usd:.2f}). "
                "No further tool calls permitted; wrap up and report findings."
            )
        per_tool_cap = self.budget.max_probes_per_tool.get(tool_name)
        if per_tool_cap is not None:
            used = self.calls_per_tool.get(tool_name, 0)
            if used >= per_tool_cap:
                return False, (
                    f"Per-tool budget for {tool_name!r} exhausted "
                    f"({per_tool_cap} calls). Try a different tool or wrap up."
                )
        return True, None

    def record_call(self, tool_name: str, estimated_cost_usd: float = 0.0) -> None:
        self.tool_calls_made += 1
        self.calls_per_tool[tool_name] = self.calls_per_tool.get(tool_name, 0) + 1
        self.estimated_usd_spent += estimated_cost_usd

    def record_llm_usage(
        self,
        input_tokens: int,
        output_tokens: int,
        client: BaseLLMClient | None = None,
    ) -> None:
        if client is not None:
            self.estimated_usd_spent += client.estimate_cost(input_tokens, output_tokens)
        else:
            self.estimated_usd_spent += (input_tokens / 1_000_000) * 3.0
            self.estimated_usd_spent += (output_tokens / 1_000_000) * 15.0

    def summary(self) -> dict:
        return {
            "elapsed_seconds": round(self.elapsed_seconds(), 1),
            "tool_calls_made": self.tool_calls_made,
            "calls_per_tool": dict(self.calls_per_tool),
            "estimated_usd_spent": round(self.estimated_usd_spent, 4),
            "budget": {
                "max_seconds": self.budget.max_seconds,
                "max_tool_calls": self.budget.max_tool_calls,
                "max_usd": self.budget.max_usd,
            },
        }
