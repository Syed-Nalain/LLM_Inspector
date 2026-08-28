from llm_inspector.agent.security_ontology import find_category, find_technique, render_ontology_for_prompt


def test_find_category():
    cat = find_category("LLM01")
    assert cat is not None
    assert cat.name == "Prompt Injection"


def test_find_technique():
    found = find_technique("direct_injection")
    assert found is not None
    category, technique = found
    assert category.owasp_id == "LLM01"
    assert "garak" in technique.tools


def test_find_technique_unknown_returns_none():
    assert find_technique("not_a_real_technique") is None


def test_render_ontology_contains_expected_categories():
    text = render_ontology_for_prompt()
    assert "Prompt Injection" in text
    assert "Sensitive Information Disclosure" in text
