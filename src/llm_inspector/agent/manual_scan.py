"""
Manual scan mode: user directly selects OWASP categories and tools,
probes run without the Brain LLM.

Maps each OWASP LLM Top 10 category to the concrete probe parameters
for each supported tool (garak, promptfoo local, promptfoo redteam).
"""

from __future__ import annotations

from typing import Any


MANUAL_SCAN_CATALOG: dict[str, dict[str, Any]] = {
    "LLM01": {
        "name": "Prompt Injection",
        "garak": [
            "direct_injection",
            "indirect_injection",
            "instruction_override",
        ],
        "promptfoo": [
            "direct_prompt_injection",
            "indirect_injection_marker",
        ],
        "promptfoo_redteam": [
            "prompt_injection",
        ],
    },
    "LLM01b": {
        "name": "Jailbreak",
        "garak": [
            "role_manipulation",
            "known_jailbreak_corpus",
        ],
        "promptfoo_redteam": [
            "jailbreak",
        ],
    },
    "LLM02": {
        "name": "Sensitive Information Disclosure",
        "garak": [
            "system_prompt_extraction",
            "training_data_leakage_probe",
        ],
        "promptfoo": [
            "pii_exfiltration_canary",
        ],
        "promptfoo_redteam": [
            "pii_leak",
            "system_prompt_leak",
        ],
    },
    "LLM04": {
        "name": "Data and Model Poisoning",
        "garak": [
            "poisoned_content_response_probe",
        ],
    },
    "LLM05": {
        "name": "Improper Output Handling",
        "garak": [
            "code_injection_via_output",
        ],
    },
    "LLM06": {
        "name": "Excessive Agency",
        "promptfoo": [
            "excessive_agency_tool_claim",
        ],
        "promptfoo_redteam": [
            "excessive_agency",
        ],
    },
    "LLM07": {
        "name": "System Prompt Leakage",
        "garak": [
            "system_prompt_leak_probe",
        ],
        "promptfoo": [
            "system_prompt_leak",
        ],
        "promptfoo_redteam": [
            "system_prompt_leak",
        ],
    },
    "LLM09": {
        "name": "Misinformation / Overreliance",
        "garak": [
            "hallucination_probe",
        ],
        "promptfoo_redteam": [
            "hallucination",
            "overreliance",
        ],
    },
}


def list_categories() -> list[dict[str, str]]:
    """Return list of available OWASP categories for display."""
    return [
        {"id": oid, "name": info["name"]}
        for oid, info in MANUAL_SCAN_CATALOG.items()
    ]


def list_tools_for_category(owasp_id: str) -> list[str]:
    """Return which tools have probes for a given OWASP category."""
    cat = MANUAL_SCAN_CATALOG.get(owasp_id, {})
    return [k for k in cat if k != "name"]


def resolve_probes(
    owasp_ids: list[str],
    tools: list[str],
    target_id: str,
    max_attempts: int = 20,
    num_tests: int = 5,
    purpose: str = "security testing of an LLM application",
) -> list[dict[str, Any]]:
    """Resolve OWASP IDs + tools into concrete MCP tool calls."""
    calls: list[dict[str, Any]] = []
    for oid in owasp_ids:
        cat = MANUAL_SCAN_CATALOG.get(oid)
        if not cat:
            continue
        for tool in tools:
            probes = cat.get(tool, [])
            for probe in probes:
                if tool == "garak":
                    calls.append({
                        "tool_name": "run_garak_probe",
                        "args": {
                            "probe_name": probe,
                            "target_id": target_id,
                            "max_attempts": max_attempts,
                        },
                        "owasp_id": oid,
                        "label": f"garak:{probe}",
                    })
                elif tool == "promptfoo":
                    calls.append({
                        "tool_name": "run_promptfoo_test",
                        "args": {
                            "test_category": probe,
                            "target_id": target_id,
                            "max_attempts": max_attempts,
                        },
                        "owasp_id": oid,
                        "label": f"promptfoo:{probe}",
                    })
                elif tool == "promptfoo_redteam":
                    calls.append({
                        "tool_name": "run_promptfoo_redteam",
                        "args": {
                            "redteam_category": probe,
                            "target_id": target_id,
                            "num_tests": num_tests,
                            "purpose": purpose,
                        },
                        "owasp_id": oid,
                        "label": f"promptfoo_redteam:{probe}",
                    })
    return calls
