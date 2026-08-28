"""
Report generation: turns a completed scan's Findings + metadata into a
human-readable Markdown report and a machine-readable JSON report.

This happens once, at the end of a scan, driven by the CLI/runtime -- not
exposed as an MCP tool Claude calls mid-loop (see mcp_servers/evaluation
server's docstring for why).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from llm_inspector.findings.finding import Finding, Severity

if TYPE_CHECKING:
    from llm_inspector.agent.runtime import ScanResult

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def render_markdown_report(result: "ScanResult", user_request: str) -> str:
    findings_sorted = sorted(
        result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
    )
    counts = _severity_counts(result.findings)
    generated_at = datetime.now(timezone.utc).isoformat()

    lines: list[str] = []
    lines.append(f"# LLM Inspector Security Report")
    lines.append("")
    lines.append(f"**Target:** {result.target.name} (`{result.target.id}`)")
    lines.append(f"**Description:** {result.target.description}")
    lines.append(f"**Scan ID:** {result.scan_id}")
    lines.append(f"**Generated:** {generated_at}")
    lines.append(f"**Request:** {user_request}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(
        f"{len(result.findings)} confirmed finding(s) — "
        f"{counts['CRITICAL']} Critical, {counts['HIGH']} High, "
        f"{counts['MEDIUM']} Medium, {counts['LOW']} Low, {counts['INFO']} Info."
    )
    lines.append("")
    lines.append("Every finding below was independently validated by a separate "
                  "Critic reasoning pass against the target's actual raw response "
                  "before being included here -- see EXTENDED_README.md for what "
                  "this validation does and does not guarantee.")
    lines.append("")

    lines.append("## Test Plan")
    lines.append("")
    for item in sorted(result.plan, key=lambda x: x.get("priority", 99)):
        lines.append(
            f"- **{item.get('technique')}** ({item.get('owasp_id', '?')}) via "
            f"`{item.get('tool')}` — {item.get('rationale', '')}"
        )
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not findings_sorted:
        lines.append("No confirmed vulnerabilities were found in this scan.")
    else:
        for f in findings_sorted:
            lines.append(f.to_markdown())
    lines.append("")

    lines.append("## Scan Statistics")
    lines.append("")
    lines.append(f"- Tools used: {', '.join(sorted(result.memory.tools_used)) or 'none'}")
    lines.append(f"- Techniques tested: {len(result.memory.stats_by_technique)}")
    for technique, stats in result.memory.stats_by_technique.items():
        lines.append(
            f"  - {technique}: {stats.attempts} attempts, {stats.successful} "
            f"successful ({stats.success_rate:.0%} ASR)"
        )
    lines.append(f"- Estimated cost: ${result.budget_summary['estimated_usd_spent']:.4f}")
    lines.append(f"- Elapsed time: {result.budget_summary['elapsed_seconds']:.1f}s")
    lines.append(f"- Tool calls made: {result.budget_summary['tool_calls_made']}")
    lines.append("")

    if result.executor_summary:
        lines.append("## Executor Summary")
        lines.append("")
        lines.append(result.executor_summary)
        lines.append("")

    return "\n".join(lines)


def render_json_report(result: "ScanResult", user_request: str) -> dict:
    return {
        "scan_id": result.scan_id,
        "target": result.target.to_dict(),
        "request": user_request,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "plan": result.plan,
        "findings": [f.to_dict() for f in result.findings],
        "severity_counts": _severity_counts(result.findings),
        "memory": result.memory.to_dict(),
        "budget_summary": result.budget_summary,
        "executor_summary": result.executor_summary,
    }


def write_reports(result: "ScanResult", user_request: str, reports_dir: Path) -> dict[str, Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    md_path = reports_dir / f"{result.scan_id}.report.md"
    json_path = reports_dir / f"{result.scan_id}.report.json"
    md_path.write_text(render_markdown_report(result, user_request), encoding="utf-8")
    json_path.write_text(json.dumps(render_json_report(result, user_request), indent=2, ensure_ascii=False), encoding="utf-8")
    return {"markdown": md_path, "json": json_path}
