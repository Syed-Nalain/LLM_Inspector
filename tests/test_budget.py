from llm_inspector.agent.budget import BudgetTracker
from llm_inspector.config import Budget


def test_per_tool_cap_enforced():
    budget = Budget(max_seconds=999, max_tool_calls=999, max_usd=999)
    budget.max_probes_per_tool = {"garak": 2}
    tracker = BudgetTracker(budget=budget)

    ok, _ = tracker.can_call("garak")
    assert ok
    tracker.record_call("garak")
    ok, _ = tracker.can_call("garak")
    assert ok
    tracker.record_call("garak")
    ok, reason = tracker.can_call("garak")
    assert not ok
    assert "garak" in reason


def test_overall_tool_call_cap_enforced():
    budget = Budget(max_seconds=999, max_tool_calls=1, max_usd=999)
    tracker = BudgetTracker(budget=budget)
    tracker.record_call("promptfoo")
    ok, reason = tracker.can_call("promptfoo")
    assert not ok
    assert "budget exhausted" in reason.lower()


def test_cost_cap_enforced():
    budget = Budget(max_seconds=999, max_tool_calls=999, max_usd=0.01)
    tracker = BudgetTracker(budget=budget)
    tracker.record_llm_usage(input_tokens=10_000, output_tokens=10_000)
    ok, reason = tracker.can_call("garak")
    assert not ok
    assert "cost budget" in reason.lower()


def test_unlimited_tool_not_capped_by_per_tool_dict():
    budget = Budget(max_seconds=999, max_tool_calls=999, max_usd=999)
    budget.max_probes_per_tool = {"garak": 1}
    tracker = BudgetTracker(budget=budget)
    for _ in range(5):
        ok, _ = tracker.can_call("analyze_attack_result")
        assert ok
        tracker.record_call("analyze_attack_result")
