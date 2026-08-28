"""
STUB adapter for Meta's Llama Guard content-safety classifier.

*** NOT A REAL INTEGRATION YET. *** See EXTENDED_README.md, "Real
guardrail integrations (LlamaGuard / NeMo Guardrails)". Real integration
needs an actual Llama Guard model to run inference against -- either
self-hosted (vLLM/Ollama serving `meta-llama/Llama-Guard-3-8B` or similar,
which needs a GPU or a slow CPU fallback) or a hosted inference endpoint
the user supplies credentials for. Neither is safe to assume/auto-install
in a general-purpose scaffold, so this stub applies a crude, obviously
non-authoritative local keyword heuristic instead, purely so the Blue Team
MCP server and Evaluation flow have something to call end-to-end today.
"""

from __future__ import annotations

import re
from typing import Any

_RISK_KEYWORDS = re.compile(
    r"\b(kill|bomb|weapon|hack|exploit|malware|suicide|self-harm)\b", re.IGNORECASE
)


async def check_llamaguard(input_text: str) -> dict[str, Any]:
    """STUB: crude keyword heuristic standing in for a real Llama Guard
    inference call. `unsafe=True` here is NOT a real safety classification
    and must never be presented to an end user as one."""
    hit = bool(_RISK_KEYWORDS.search(input_text))
    return {
        "tool": "llamaguard",
        "input_preview": input_text[:200],
        "unsafe": hit,
        "categories": ["S1: violent crimes"] if hit else [],
        "confidence": 0.3 if hit else 0.1,  # deliberately low -- this is a stub
        "stub": True,
        "stub_warning": (
            "LlamaGuard is not yet integrated -- this is a keyword heuristic, "
            "not a real safety classification. See EXTENDED_README.md."
        ),
    }
