"""
STUB adapter for NVIDIA NeMo Guardrails.

*** NOT A REAL INTEGRATION YET. *** See EXTENDED_README.md, "Real
guardrail integrations (LlamaGuard / NeMo Guardrails)". Real integration
means installing `nemoguardrails`, authoring Colang rail definitions, and
running the target's traffic through a configured `LLMRails` instance --
a meaningfully sized task of its own (rail authoring is target-specific).
This stub returns a structurally identical result shape so the rest of
the pipeline can call it uniformly today.
"""

from __future__ import annotations

from typing import Any


async def check_nemoguard(input_text: str) -> dict[str, Any]:
    """STUB: always reports "not blocked" -- there is no real rail engine
    behind this yet. Exists purely so blue-team MCP wiring and the
    Evaluation MCP server have a second guardrail tool to call while real
    NeMo Guardrails integration is pending."""
    return {
        "tool": "nemoguard",
        "input_preview": input_text[:200],
        "blocked": False,
        "triggered_rails": [],
        "stub": True,
        "stub_warning": (
            "NeMo Guardrails is not yet integrated -- this adapter does not "
            "run any real rails. See EXTENDED_README.md."
        ),
    }
