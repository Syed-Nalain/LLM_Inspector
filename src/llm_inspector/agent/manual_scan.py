"""
Manual scan mode: user directly selects OWASP categories and tools,
probes run without the Brain LLM.

Maps each OWASP LLM Top 10 category to the concrete probe parameters
for each supported tool (garak, promptfoo local, promptfoo redteam).

Scan intensity levels control how many probes and attempts are used:
  - very_small: Quick smoke test — 1 probe per tool per category
  - small: Light coverage — all mapped probes, low attempt counts
  - medium: Balanced — all probes, moderate counts (default)
  - large: Full coverage — all probes + extra garak families + high counts
  - extended: Large + garak encoding/paraphrase buffs on every garak probe
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanIntensity:
    label: str
    description: str
    max_attempts: int
    num_tests: int
    max_probes_per_tool: int | None  # None = unlimited
    garak_buffs: list[str] = field(default_factory=list)


SCAN_INTENSITIES: dict[str, ScanIntensity] = {
    "very_small": ScanIntensity(
        label="Very Small",
        description="Quick smoke test — 1 probe per tool per category, minimal attempts",
        max_attempts=5,
        num_tests=2,
        max_probes_per_tool=1,
    ),
    "small": ScanIntensity(
        label="Small",
        description="Light coverage — all mapped probes, low attempt counts",
        max_attempts=10,
        num_tests=3,
        max_probes_per_tool=None,
    ),
    "medium": ScanIntensity(
        label="Medium",
        description="Balanced scan — all probes, moderate attempt counts",
        max_attempts=25,
        num_tests=5,
        max_probes_per_tool=None,
    ),
    "large": ScanIntensity(
        label="Large",
        description="Full coverage — complete garak probe families + dynamic redteam generation, high attempt counts",
        max_attempts=50,
        num_tests=10,
        max_probes_per_tool=None,
    ),
    "extended": ScanIntensity(
        label="Extended",
        description="Large + garak encoding buffs (Base64, CharCode) — increases garak scan time but catches encoding-based evasion bypasses",
        max_attempts=50,
        num_tests=10,
        max_probes_per_tool=None,
        garak_buffs=["encoding.Base64", "encoding.CharCode"],
    ),
}

# Large and extended modes add these extra probes per category
LARGE_EXTRA_PROBES: dict[str, dict[str, list[str]]] = {
    "LLM01": {
        "garak": [
            "context_manipulation",
        ],
        "promptfoo_redteam": [
            "jailbreak",
        ],
    },
    "LLM01b": {
        "garak": [
            "context_manipulation",
        ],
        "promptfoo_redteam": [
            "prompt_injection",
        ],
    },
    "LLM02": {
        "garak": [
            "system_prompt_leak_probe",
        ],
        "promptfoo_redteam": [
            "hallucination",
        ],
    },
    "LLM07": {
        "garak": [
            "system_prompt_extraction",
        ],
    },
    "LLM09": {
        "promptfoo_redteam": [
            "excessive_agency",
        ],
    },
}


MANUAL_SCAN_CATALOG: dict[str, dict[str, Any]] = {
    # ── OWASP LLM Top 10 categories ──
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
    # ── Cross-cutting categories (beyond OWASP Top 10) ──
    "EVASION": {
        "name": "Guardrail Evasion Techniques",
        "garak": [
            "encoding_bypass",
            "token_smuggling",
            "ansi_escape_injection",
            "glitch_token_exploit",
        ],
    },
    "ADAPTIVE": {
        "name": "Adaptive / Multi-turn Attacks",
        "garak": [
            "tree_of_attacks",
            "auto_attack_gen",
        ],
    },
    "SOCIAL_ENG": {
        "name": "Social Engineering / Manipulation",
        "garak": [
            "grandma_jailbreak",
            "goodside_injection",
            "deeprole_attack",
            "continuation_attack",
        ],
    },
}


def list_categories() -> list[dict[str, str]]:
    """Return list of available categories for display."""
    return [
        {"id": oid, "name": info["name"]}
        for oid, info in MANUAL_SCAN_CATALOG.items()
    ]


def list_tools_for_category(owasp_id: str) -> list[str]:
    """Return which tools have probes for a given category."""
    cat = MANUAL_SCAN_CATALOG.get(owasp_id, {})
    return [k for k in cat if k != "name"]


def resolve_probes(
    owasp_ids: list[str],
    tools: list[str],
    target_id: str,
    max_attempts: int = 20,
    num_tests: int = 5,
    purpose: str = "security testing of an LLM application",
    intensity: str = "medium",
) -> list[dict[str, Any]]:
    """Resolve category IDs + tools into concrete MCP tool calls.

    The intensity parameter overrides max_attempts and num_tests with
    preset values, and may limit or extend the probe set.
    """
    preset = SCAN_INTENSITIES.get(intensity)
    if preset:
        max_attempts = preset.max_attempts
        num_tests = preset.num_tests

    use_extras = intensity in ("large", "extended")

    calls: list[dict[str, Any]] = []
    for oid in owasp_ids:
        cat = MANUAL_SCAN_CATALOG.get(oid)
        if not cat:
            continue
        for tool in tools:
            probes = list(cat.get(tool, []))

            if use_extras:
                extras = LARGE_EXTRA_PROBES.get(oid, {}).get(tool, [])
                for ep in extras:
                    if ep not in probes:
                        probes.append(ep)

            if preset and preset.max_probes_per_tool is not None:
                probes = probes[:preset.max_probes_per_tool]

            for probe in probes:
                if tool == "garak":
                    args: dict[str, Any] = {
                        "probe_name": probe,
                        "target_id": target_id,
                        "max_attempts": max_attempts,
                    }
                    if preset and preset.garak_buffs:
                        args["buffs"] = preset.garak_buffs
                    calls.append({
                        "tool_name": "run_garak_probe",
                        "args": args,
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
