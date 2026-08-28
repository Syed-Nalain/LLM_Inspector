from llm_inspector.findings.finding import Finding, Severity, severity_from_asr


def test_severity_from_asr_thresholds():
    assert severity_from_asr(0.0) == Severity.INFO
    assert severity_from_asr(0.01) == Severity.LOW
    assert severity_from_asr(0.05) == Severity.MEDIUM
    assert severity_from_asr(0.15) == Severity.HIGH
    assert severity_from_asr(0.30) == Severity.CRITICAL
    assert severity_from_asr(0.99) == Severity.CRITICAL


def test_finding_roundtrip_dict():
    f = Finding(
        vulnerability="Prompt Injection",
        owasp_id="LLM01",
        technique="direct_injection",
        severity=Severity.HIGH,
        confidence=0.9,
        attack="ignore instructions",
        target_response="sure, here you go",
        expected_behavior="refuse",
        actual_behavior="complied",
        evidence="2/20 attacks succeeded",
        reproducibility="2/3 reproduced",
        affected_component="chatbot",
        recommended_mitigation="add input validation",
        source_tool="garak",
    )
    d = f.to_dict()
    f2 = Finding.from_dict(d)
    assert f2.severity == Severity.HIGH
    assert f2.id == f.id
    assert f2.owasp_id == "LLM01"


def test_finding_to_markdown_contains_key_fields():
    f = Finding(
        vulnerability="Prompt Injection",
        owasp_id="LLM01",
        technique="direct_injection",
        severity=Severity.CRITICAL,
        confidence=0.95,
        attack="ATTACK_TEXT",
        target_response="RESPONSE_TEXT",
        expected_behavior="refuse",
        actual_behavior="complied",
        evidence="evidence text",
        reproducibility="3/3",
        affected_component="chatbot",
        recommended_mitigation="fix it",
        source_tool="promptfoo",
    )
    md = f.to_markdown()
    assert "ATTACK_TEXT" in md
    assert "RESPONSE_TEXT" in md
    assert "CRITICAL" in md
    assert "LLM01" in md
