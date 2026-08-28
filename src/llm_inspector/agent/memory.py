"""
ScanMemory: what the agent remembers about the current scan.

Architecture doc, component (5) "Add memory": the agent should reason
using a running summary of what has already been tried and found, not
just the raw conversation transcript (which is what conversation history
already gives Claude implicitly). ScanMemory is a structured, queryable
summary that gets rendered into the prompt so Claude can reason like:
"prompt injection appears promising, jailbreak attacks have failed,
increase prompt injection testing, don't waste budget on jailbreak
attacks" -- the example from the architecture doc.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TechniqueStats:
    attempts: int = 0
    successful: int = 0
    suspicious: int = 0

    @property
    def success_rate(self) -> float:
        return self.successful / self.attempts if self.attempts else 0.0


@dataclass
class ScanMemory:
    target_name: str
    stats_by_technique: dict[str, TechniqueStats] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    tools_used: set[str] = field(default_factory=set)

    def record_result(
        self,
        technique: str,
        tool: str,
        attempts: int,
        successful: int,
        suspicious: int = 0,
    ) -> None:
        stats = self.stats_by_technique.setdefault(technique, TechniqueStats())
        stats.attempts += attempts
        stats.successful += successful
        stats.suspicious += suspicious
        self.tools_used.add(tool)

    def add_note(self, note: str) -> None:
        self.notes.append(note)

    def render_for_prompt(self) -> str:
        if not self.stats_by_technique and not self.notes:
            return "(no tests run yet)"
        lines = [f"Target: {self.target_name}", "", "Tests performed so far:"]
        for technique, stats in self.stats_by_technique.items():
            lines.append(
                f"  - {technique}: {stats.attempts} attempts, "
                f"{stats.successful} successful "
                f"({stats.success_rate:.0%} ASR), {stats.suspicious} suspicious"
            )
        if self.notes:
            lines.append("")
            lines.append("Agent notes:")
            for n in self.notes:
                lines.append(f"  - {n}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "target_name": self.target_name,
            "stats_by_technique": {
                k: {"attempts": v.attempts, "successful": v.successful, "suspicious": v.suspicious}
                for k, v in self.stats_by_technique.items()
            },
            "notes": self.notes,
            "tools_used": sorted(self.tools_used),
        }
