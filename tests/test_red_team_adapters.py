"""
Real (non-mocked) integration tests: these actually invoke `garak` and
`promptfoo` as subprocesses against the in-repo mock target server. They
are slower than the rest of the suite and need `garak`/`promptfoo`
installed -- see README.md "Installation".
"""

import shutil

import pytest

from llm_inspector.mcp_servers.red_team.adapters.garak_adapter import run_garak_probe
from llm_inspector.mcp_servers.red_team.adapters.promptfoo_adapter import run_promptfoo_test
from llm_inspector.target.target import RestTargetConfig

pytestmark = pytest.mark.slow


def _rest_config(base_url: str) -> RestTargetConfig:
    return RestTargetConfig(
        uri=base_url,
        method="post",
        headers={"Content-Type": "application/json"},
        request_template={"input": "$INPUT"},
        response_text_path="reply",
    )


@pytest.mark.skipif(shutil.which("promptfoo") is None, reason="promptfoo not installed")
@pytest.mark.asyncio
async def test_promptfoo_detects_leak_on_vulnerable_target(mock_target, tmp_path):
    base_url, set_mode = mock_target
    set_mode("vulnerable")
    result = await run_promptfoo_test(
        "system_prompt_leak", _rest_config(base_url), max_attempts=4, work_dir=tmp_path
    )
    assert result["tool"] == "promptfoo"
    assert result["attempts"] == 4
    assert result["successful"] >= 1
    assert any(e["detector_hit"] for e in result["evidence"])


@pytest.mark.skipif(shutil.which("promptfoo") is None, reason="promptfoo not installed")
@pytest.mark.asyncio
async def test_promptfoo_finds_nothing_on_safe_target(mock_target, tmp_path):
    base_url, set_mode = mock_target
    set_mode("safe")
    result = await run_promptfoo_test(
        "system_prompt_leak", _rest_config(base_url), max_attempts=4, work_dir=tmp_path
    )
    assert result["successful"] == 0
    assert result["asr"] == 0.0


@pytest.mark.skipif(shutil.which("garak") is None, reason="garak not installed")
@pytest.mark.asyncio
async def test_garak_runs_end_to_end_against_mock_target(mock_target, tmp_path):
    base_url, set_mode = mock_target
    set_mode("vulnerable")
    result = await run_garak_probe(
        "role_manipulation", _rest_config(base_url), max_attempts=5, work_dir=tmp_path
    )
    assert result["tool"] == "garak"
    assert "error" not in result
    assert result["attempts"] > 0
    assert 0.0 <= result["asr"] <= 1.0
    assert "evidence" in result
