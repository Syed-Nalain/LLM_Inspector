"""
Structured security knowledge base for the reasoning brain.

Per the architecture doc, component (2): Claude already has general
knowledge, but LLM Inspector should hand it a *structured* map from
OWASP LLM Top 10 categories -> attack techniques -> tools -> detectors,
rather than relying on it to recall this from training data. This module
is injected into the system prompt (see agent/system_prompt.py) as the
"security ontology" Claude reasons from when it says things like
"I need to test prompt injection -- Garak is good for systematic probes."

This is a starting ontology covering the categories the architecture doc
calls out explicitly. Extending it to the full OWASP LLM Top 10 (2025) and
keeping tool/probe names in sync with upstream Garak/PyRIT/Promptfoo
releases is tracked in EXTENDED_README.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AttackTechnique:
    name: str
    description: str
    tools: list[str]  # tool identifiers, see agent/tool_manager.py TOOL_REGISTRY


@dataclass
class VulnerabilityCategory:
    owasp_id: str
    name: str
    description: str
    techniques: list[AttackTechnique] = field(default_factory=list)


OWASP_LLM_TOP_10: list[VulnerabilityCategory] = [
    VulnerabilityCategory(
        owasp_id="LLM01",
        name="Prompt Injection",
        description=(
            "Untrusted input overrides the model's intended instructions, "
            "either directly (attacker talks to the model) or indirectly "
            "(attacker's payload arrives via a document/tool/webpage the "
            "model reads)."
        ),
        techniques=[
            AttackTechnique(
                "direct_injection",
                "Attacker input directly instructs the model to ignore its "
                "system prompt or prior instructions.",
                tools=["garak", "promptfoo"],
            ),
            AttackTechnique(
                "indirect_injection",
                "Malicious instructions are smuggled in via a tool result, "
                "retrieved document, or webpage the model is asked to read.",
                tools=["promptfoo"],
            ),
            AttackTechnique(
                "role_manipulation",
                "Attacker convinces the model it is playing a different "
                "role/persona with fewer restrictions.",
                tools=["garak", "pyrit"],
            ),
            AttackTechnique(
                "instruction_override",
                'Explicit "ignore previous instructions" style payloads.',
                tools=["garak"],
            ),
            AttackTechnique(
                "context_manipulation",
                "Multi-turn conversation is used to gradually shift context "
                "until the model accepts an instruction it would otherwise "
                "refuse.",
                tools=["pyrit"],
            ),
        ],
    ),
    VulnerabilityCategory(
        owasp_id="LLM01b",
        name="Jailbreak",
        description=(
            "Techniques aimed at bypassing the model's safety training "
            "entirely, rather than overriding a specific system prompt."
        ),
        techniques=[
            AttackTechnique(
                "known_jailbreak_corpus",
                "Replay known jailbreak prompt families (DAN and "
                "derivatives) to check whether the target still falls for "
                "publicly documented bypasses.",
                tools=["garak"],
            ),
            AttackTechnique(
                "adaptive_multi_turn_jailbreak",
                "Iteratively mutate a jailbreak attempt based on the "
                "target's previous refusal, searching for a bypass.",
                tools=["pyrit"],
            ),
        ],
    ),
    VulnerabilityCategory(
        owasp_id="LLM02",
        name="Sensitive Information Disclosure",
        description=(
            "The model reveals data it should not: training data "
            "fragments, PII, secrets, or its own system prompt/instructions."
        ),
        techniques=[
            AttackTechnique(
                "system_prompt_extraction",
                "Attempt to make the model reveal its system prompt or "
                "hidden instructions verbatim.",
                tools=["garak", "promptfoo"],
            ),
            AttackTechnique(
                "training_data_leakage_probe",
                "Probe for memorized/regurgitated sensitive training data.",
                tools=["garak"],
            ),
            AttackTechnique(
                "pii_extraction",
                "Attempt to extract PII the model may have been exposed to "
                "via context or fine-tuning.",
                tools=["promptfoo"],
            ),
        ],
    ),
    VulnerabilityCategory(
        owasp_id="LLM04",
        name="Data and Model Poisoning",
        description=(
            "The model's behavior has been corrupted via poisoned "
            "training, fine-tuning, or retrieval data."
        ),
        techniques=[
            AttackTechnique(
                "poisoned_content_response_probe",
                "Check whether the target reproduces or amplifies known "
                "poisoned/trigger phrases.",
                tools=["garak"],
            ),
        ],
    ),
    VulnerabilityCategory(
        owasp_id="LLM05",
        name="Improper Output Handling",
        description=(
            "Downstream systems trust model output without sanitization, "
            "enabling injection attacks (XSS, SQLi, command injection) via "
            "generated content."
        ),
        techniques=[
            AttackTechnique(
                "code_injection_via_output",
                "Prompt the model to emit content that would be dangerous "
                "if a downstream system rendered/executed it unsanitized.",
                tools=["garak", "promptfoo"],
            ),
        ],
    ),
    VulnerabilityCategory(
        owasp_id="LLM06",
        name="Excessive Agency",
        description=(
            "The model (in an agentic setup) is granted more autonomy, "
            "tool access, or permissions than the task requires, and can "
            "be manipulated into misusing them."
        ),
        techniques=[
            AttackTechnique(
                "unauthorized_tool_invocation",
                "Attempt to get an agentic target to call a tool/action "
                "outside its intended scope.",
                tools=["promptfoo"],
            ),
        ],
    ),
    VulnerabilityCategory(
        owasp_id="LLM07",
        name="System Prompt Leakage",
        description=(
            "Distinct from general sensitive-info disclosure: specifically "
            "the system prompt containing secrets, business logic, or "
            "instructions that should not be user-visible."
        ),
        techniques=[
            AttackTechnique(
                "system_prompt_leak_probe",
                "Direct and indirect attempts to have the target repeat, "
                "summarize, or leak its system prompt.",
                tools=["garak", "promptfoo"],
            ),
        ],
    ),
    VulnerabilityCategory(
        owasp_id="LLM09",
        name="Misinformation / Overreliance Risk",
        description=(
            "The model confidently produces false or harmful information "
            "that a downstream user could over-trust."
        ),
        techniques=[
            AttackTechnique(
                "hallucination_probe",
                "Probe for confident fabrication on adversarially chosen "
                "questions.",
                tools=["garak"],
            ),
        ],
    ),
]


def find_category(owasp_id: str) -> VulnerabilityCategory | None:
    for cat in OWASP_LLM_TOP_10:
        if cat.owasp_id == owasp_id:
            return cat
    return None


def find_technique(
    technique_name: str,
) -> tuple[VulnerabilityCategory, AttackTechnique] | None:
    for cat in OWASP_LLM_TOP_10:
        for tech in cat.techniques:
            if tech.name == technique_name:
                return cat, tech
    return None


def render_ontology_for_prompt() -> str:
    """Render the ontology as compact text for injection into the system prompt."""
    lines: list[str] = []
    for cat in OWASP_LLM_TOP_10:
        techs = ", ".join(t.name for t in cat.techniques)
        lines.append(f"{cat.owasp_id} {cat.name}: {techs}")
    return "\n".join(lines)


def render_tool_catalog() -> str:
    """Compact reference of exact parameter values each tool accepts."""
    from llm_inspector.mcp_servers.red_team.adapters.garak_adapter import (
        TECHNIQUE_TO_GARAK_PROBE,
    )
    from llm_inspector.mcp_servers.red_team.adapters.promptfoo_adapter import (
        ATTACK_LIBRARY,
        REDTEAM_PLUGIN_SETS,
    )

    garak_probes = ", ".join(t for t in TECHNIQUE_TO_GARAK_PROBE if not t.startswith("_"))
    pf_cats = ", ".join(ATTACK_LIBRARY.keys())
    rt_cats = ", ".join(REDTEAM_PLUGIN_SETS.keys())

    return (
        "VALID PARAMETER VALUES:\n"
        f"run_garak_probe probe_name: {garak_probes}\n"
        f"run_promptfoo_test test_category: {pf_cats}\n"
        f"run_promptfoo_redteam redteam_category: {rt_cats}\n"
        "run_pyrit_attack attack_strategy: crescendo, pair, flip"
    )
