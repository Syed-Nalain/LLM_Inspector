"""
Real integration with Garak (https://github.com/NVIDIA/garak), NVIDIA's LLM
vulnerability scanner. This adapter shells out to `python -m garak` using
garak's generic `rest` generator so it can attack ANY target the user has
described as a RestTargetConfig -- Garak never talks to the target
directly on our behalf without going through the target the user
authorized.

We deliberately parse garak's own `*.report.jsonl` output rather than
scraping stdout, because that JSONL is garak's stable, documented report
format (entry_type: attempt / eval / probe_summary / ...).

Known limitation (tracked in EXTENDED_README.md): `max_attempts` is passed
to garak as a best-effort `soft_probe_prompt_cap` probe option. Not every
garak probe class honors that cap (some probe families always run their
full fixed prompt set), so the actual number of attempts a probe makes can
exceed the requested cap for a handful of probes. We surface the *actual*
attempt count from the report rather than pretending the cap was exact.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from llm_inspector.target.target import RestTargetConfig

# Maps the technique names used in our security ontology to concrete garak
# probe module/class selectors. Extending this as new garak probes ship
# upstream is tracked in EXTENDED_README.md.
TECHNIQUE_TO_GARAK_PROBE: dict[str, str] = {
    "direct_injection": "promptinject.HijackHateHumans",
    "indirect_injection": "latentinjection.LatentInjectionReport",
    "role_manipulation": "dan.DAN_Jailbreak",
    "instruction_override": "promptinject.HijackKillHumans",
    "context_manipulation": "latentinjection.LatentJailbreak",
    "known_jailbreak_corpus": "dan",  # the whole family, deliberately broad
    "system_prompt_extraction": "sysprompt_extraction.SystemPromptExtraction",
    "system_prompt_leak_probe": "sysprompt_extraction.SystemPromptExtraction",
    "training_data_leakage_probe": "leakreplay.LiteratureCloze",
    "code_injection_via_output": "web_injection.MarkdownXSS",
    "unauthorized_tool_invocation": "promptinject.HijackLongPrompt",
    "hallucination_probe": "leakreplay.NYTCloze",
    "poisoned_content_response_probe": "leakreplay.PotterCloze",
    # smoke-test / CI use only
    "_smoke_test": "test.Blank",
}



# reverse of TECHNIQUE_TO_GARAK_PROBE, used by the Agent Runtime to map a
# garak result's `probe` field back to an ontology technique name.
GARAK_PROBE_TO_TECHNIQUE: dict[str, str] = {
    v: k for k, v in TECHNIQUE_TO_GARAK_PROBE.items()
}


class GarakNotAvailableError(RuntimeError):
    pass


def resolve_probe(probe_name: str) -> str:
    """Accept either a technique name from our ontology or a raw garak probe
    selector (e.g. 'dan.DAN_Jailbreak') passed straight through."""
    return TECHNIQUE_TO_GARAK_PROBE.get(probe_name, probe_name)


async def run_garak_probe(
    probe_name: str,
    target_config: RestTargetConfig,
    max_attempts: int,
    work_dir: Path,
    generations: int = 1,
) -> dict[str, Any]:
    if shutil.which("garak") is None:
        # fall back to `python -m garak`, which is always available if the
        # package is importable even when the console script isn't on PATH
        pass

    probe_selector = resolve_probe(probe_name)
    run_id = uuid.uuid4().hex[:10]
    run_dir = work_dir / "garak_runs"
    run_dir.mkdir(parents=True, exist_ok=True)
    genopts_path = (run_dir / f"{run_id}.genopts.json").resolve()
    probeopts_path = (run_dir / f"{run_id}.probeopts.json").resolve()
    report_prefix = str((run_dir / run_id).resolve())

    genopts_path.write_text(json.dumps(target_config.to_garak_generator_options()))
    top_module = probe_selector.split(".", 1)[0]
    probeopts_path.write_text(
        json.dumps({top_module: {"soft_probe_prompt_cap": max(1, max_attempts)}})
    )

    cmd = [
        sys.executable,
        "-m",
        "garak",
        "--target_type",
        "rest",
        "--target_name",
        target_config.uri,
        "--probes",
        probe_selector,
        "--generator_option_file",
        str(genopts_path),
        "--probe_option_file",
        str(probeopts_path),
        "--report_prefix",
        report_prefix,
        "--generations",
        str(generations),
        "--parallel_attempts",
        "4",
    ]

    env = {**os.environ, "PYTHONUTF8": "1"}

    started = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
    )
    stdout, _ = await proc.communicate()
    duration = time.monotonic() - started
    log_text = stdout.decode(errors="replace") if stdout else ""

    log_path = run_dir / f"{run_id}.stdout.log"
    log_path.write_text(log_text, encoding="utf-8")

    report_path = Path(f"{report_prefix}.report.jsonl")
    if proc.returncode != 0 or not report_path.exists():
        return {
            "tool": "garak",
            "probe": probe_selector,
            "error": f"garak run failed (exit {proc.returncode})",
            "log_tail": log_text[-4000:],
            "log_path": str(log_path),
            "duration_seconds": round(duration, 2),
        }

    return _parse_garak_report(report_path, probe_selector, duration)


def _parse_garak_report(
    report_path: Path, probe_selector: str, duration: float
) -> dict[str, Any]:
    attempts_by_uuid: dict[str, dict[str, Any]] = {}
    eval_rows: list[dict[str, Any]] = []

    with report_path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            etype = entry.get("entry_type")
            if etype == "attempt" and entry.get("status") == 2:
                attempts_by_uuid[entry["uuid"]] = entry
            elif etype == "eval":
                eval_rows.append(entry)

    total_evaluated = sum(r.get("total_evaluated", 0) for r in eval_rows)
    total_fails = sum(r.get("fails", 0) for r in eval_rows)
    # normalize: if multiple detectors ran per probe, avoid double counting
    # attempts -- report success rate as fails / total_evaluated per
    # detector, then take the max detector's ASR as the probe's ASR (an
    # attack that trips ANY detector is a hit).
    detector_asrs = [
        (r["fails"] / r["total_evaluated"]) if r.get("total_evaluated") else 0.0
        for r in eval_rows
    ]
    asr = max(detector_asrs) if detector_asrs else 0.0
    attempts_count = max(
        (r.get("total_evaluated", 0) for r in eval_rows), default=len(attempts_by_uuid)
    )

    # collect a few concrete evidence transcripts: prefer attempts where a
    # detector fired if we can tell, else just include the first few.
    evidence: list[dict[str, str]] = []
    for att in list(attempts_by_uuid.values())[:5]:
        try:
            prompt_text = att["prompt"]["turns"][-1]["content"]["text"]
        except Exception:
            prompt_text = str(att.get("prompt"))
        outputs = att.get("outputs") or []
        output_text = outputs[0].get("text", "") if outputs else ""
        detector_results = att.get("detector_results", {})
        hit = any(
            any(score is not None and score >= 0.5 for score in scores)
            for scores in detector_results.values()
        )
        evidence.append(
            {
                "attack": prompt_text,
                "response": output_text,
                "detector_hit": hit,
                "detector_results": detector_results,
            }
        )
    # sort so hits show first (most interesting evidence)
    evidence.sort(key=lambda e: e["detector_hit"], reverse=True)

    return {
        "tool": "garak",
        "probe": probe_selector,
        "attempts": attempts_count,
        "successful": total_fails,
        "blocked": max(0, attempts_count - total_fails),
        "asr": round(asr, 4),
        "detectors": [
            {
                "detector": r["detector"],
                "passed": r.get("passed", 0),
                "fails": r.get("fails", 0),
                "total_evaluated": r.get("total_evaluated", 0),
            }
            for r in eval_rows
        ],
        "evidence": evidence[:5],
        "duration_seconds": round(duration, 2),
        "report_path": str(report_path),
    }
