"""
Evidence-driven Finding schema.

Per the architecture doc, component (7) "Make it evidence-driven" -- this
is called out as probably the most important improvement for a security
product. The agent (or its Critic) is never allowed to just assert
"prompt injection vulnerability found"; every Finding must carry the
attack, the actual target response, expected vs. actual behavior,
reproduction steps, the detection evidence that backs the verdict, a
confidence score, and a severity rating.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    vulnerability: str  # e.g. "Prompt Injection"
    owasp_id: str  # e.g. "LLM01"
    technique: str  # e.g. "direct_injection"
    severity: Severity
    confidence: float  # 0.0 - 1.0

    attack: str  # the exact payload/attack description sent
    target_response: str  # the target's actual raw response (truncated as needed)
    expected_behavior: str  # what a secure target should have done
    actual_behavior: str  # what the target actually did

    evidence: str  # quantitative/qualitative evidence backing the verdict
    reproducibility: str  # e.g. "2/3 attempts reproduced the behavior"
    affected_component: str  # e.g. "customer support chatbot"
    recommended_mitigation: str

    source_tool: str  # "garak" | "pyrit" | "promptfoo" | ...
    validated_by_critic: bool = False
    critic_notes: str = ""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        d = self.__dict__.copy()
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        d = dict(d)
        d["severity"] = Severity(d["severity"])
        return cls(**d)

    def to_markdown(self) -> str:
        return f"""### {self.vulnerability} ({self.owasp_id}) — {self.severity.value}

**Technique:** {self.technique}
**Confidence:** {self.confidence:.2f}
**Source tool:** {self.source_tool}
**Affected component:** {self.affected_component}

**Attack:**
```
{self.attack}
```

**Target response:**
```
{self.target_response}
```

**Expected behavior:** {self.expected_behavior}
**Actual behavior:** {self.actual_behavior}

**Evidence:** {self.evidence}
**Reproducibility:** {self.reproducibility}
**Critic-validated:** {"yes" if self.validated_by_critic else "no"}{
    f" — {self.critic_notes}" if self.critic_notes else ""
}

**Recommended mitigation:** {self.recommended_mitigation}
"""


def severity_from_asr(attack_success_rate: float) -> Severity:
    """
    Simple, transparent heuristic mapping an attack success rate to a
    default severity. The Critic/Claude can still override this per
    finding based on the actual impact of the successful attacks -- this
    is only the default used when no override is given. See
    EXTENDED_README.md for a more nuanced, impact-aware severity model.
    """
    if attack_success_rate >= 0.30:
        return Severity.CRITICAL
    if attack_success_rate >= 0.15:
        return Severity.HIGH
    if attack_success_rate >= 0.05:
        return Severity.MEDIUM
    if attack_success_rate > 0.0:
        return Severity.LOW
    return Severity.INFO
