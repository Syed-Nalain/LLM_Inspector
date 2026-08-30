"""
LLM Inspector Web UI — simple Flask app on localhost:5000.

Two scan modes:
  1. Manual mode: user selects OWASP categories + tools via checkboxes
  2. Prompt mode: user types a natural-language request for the Brain LLM
"""

from __future__ import annotations

import asyncio
import json
import queue
import threading
from pathlib import Path

import requests as http_requests

from flask import Flask, Response, redirect, render_template, request, url_for

from llm_inspector.agent.manual_scan import MANUAL_SCAN_CATALOG, list_categories
from llm_inspector.agent.runtime import AgentRuntime
from llm_inspector.config import get_settings
from llm_inspector.findings.report_generator import write_reports
from llm_inspector.storage.database import Database
from llm_inspector.target.manager import TargetManager

app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates"),
)

scan_logs: dict[str, queue.Queue] = {}


def _get_targets() -> list[dict]:
    settings = get_settings()
    db = Database(settings.db_path)
    manager = TargetManager(db)
    targets = manager.list()
    return [
        {"id": t.id, "name": t.name, "uri": t.rest_config.uri}
        for t in targets
    ]


@app.route("/")
def index():
    categories = list_categories()
    for cat in categories:
        cat["tools"] = [k for k in MANUAL_SCAN_CATALOG[cat["id"]] if k != "name"]
    targets = _get_targets()
    return render_template("index.html", categories=categories, targets=targets)


@app.route("/scan", methods=["POST"])
def start_scan():
    data = request.get_json()
    scan_mode = data.get("mode", "manual")
    target_id = data.get("target_id")
    if not target_id:
        return {"error": "No target selected"}, 400

    scan_queue = queue.Queue()
    scan_id_holder = [None]

    import uuid as _uuid
    stream_id = _uuid.uuid4().hex[:12]

    def run_in_thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(
                _run_scan(data, scan_mode, scan_queue, scan_id_holder)
            )
        except Exception as e:
            scan_queue.put({"type": "error", "message": str(e)})
        finally:
            scan_queue.put(None)
            loop.close()

    scan_logs[stream_id] = scan_queue
    t = threading.Thread(target=run_in_thread, daemon=True)
    t.start()

    return {"scan_id": stream_id}


async def _run_scan(data, scan_mode, log_queue, scan_id_holder):
    settings = get_settings()
    db = Database(settings.db_path)
    manager = TargetManager(db)
    runtime = AgentRuntime(settings, db, manager)

    target_id = data["target_id"]

    def on_event(msg):
        log_queue.put({"type": "log", "message": msg})

    if scan_mode == "prompt":
        prompt_text = data.get("prompt", "")
        if not prompt_text:
            log_queue.put({"type": "error", "message": "No prompt provided"})
            return

        on_event(f"Brain LLM mode — prompt: {prompt_text}")
        result = await runtime.run_scan(
            target_id=target_id,
            user_request=prompt_text,
            requester="web-ui",
            on_event=on_event,
        )
    else:
        vulns = data.get("vulns", [])
        tools = data.get("tools", [])
        if not vulns or not tools:
            log_queue.put({"type": "error", "message": "Select at least one vulnerability and one tool"})
            return

        purpose = data.get("purpose", "security testing of an LLM application")
        intensity = data.get("intensity", "medium")
        result = await runtime.run_manual_scan(
            target_id=target_id,
            owasp_ids=vulns,
            tools=tools,
            requester="web-ui",
            max_attempts=int(data.get("max_attempts", 20)),
            num_tests=int(data.get("num_tests", 5)),
            purpose=purpose,
            intensity=intensity,
            on_event=on_event,
        )

    scan_id_holder[0] = result.scan_id

    paths = write_reports(
        result,
        data.get("prompt", f"Manual: {','.join(data.get('vulns', []))}"),
        settings.data_dir / "reports",
    )

    findings_list = []
    for f in result.findings:
        findings_list.append({
            "severity": f.severity.value,
            "vulnerability": f.vulnerability,
            "owasp_id": f.owasp_id,
            "confidence": round(f.confidence, 2),
            "tool": f.source_tool,
            "attack": f.attack[:500],
            "response": f.target_response[:500],
            "mitigation": f.recommended_mitigation,
        })

    log_queue.put({
        "type": "result",
        "scan_id": result.scan_id,
        "findings": findings_list,
        "report_md": str(paths["markdown"]),
        "report_json": str(paths["json"]),
    })


@app.route("/scan/<scan_id>/stream")
def stream_logs(scan_id):
    q = scan_logs.get(scan_id)
    if not q:
        return {"error": "Unknown scan"}, 404

    def generate():
        while True:
            try:
                item = q.get(timeout=120)
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'log', 'message': 'Waiting...'})}\n\n"
                continue
            if item is None:
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                break
            yield f"data: {json.dumps(item)}\n\n"

    return Response(generate(), mimetype="text/event-stream")


@app.route("/target/new")
def target_new():
    return render_template("target_new.html")


@app.route("/target/ollama-models")
def ollama_models():
    ollama_url = request.args.get("url", "http://localhost:11434")
    try:
        resp = http_requests.get(f"{ollama_url}/api/tags", timeout=5)
        resp.raise_for_status()
        models = [m["name"] for m in resp.json().get("models", [])]
        return {"models": models}
    except Exception as e:
        return {"error": str(e), "models": []}


@app.route("/target/test-connection", methods=["POST"])
def test_connection():
    data = request.get_json()
    url = data.get("url", "")
    method = data.get("method", "POST").upper()
    headers = data.get("headers", {})
    body_template = data.get("body_template", {})
    response_path = data.get("response_path", "")

    body_str = json.dumps(body_template).replace('"$INPUT"', '"Hello, are you there?"')
    body_str = body_str.replace("$INPUT", "Hello, are you there?")
    try:
        body = json.loads(body_str)
    except json.JSONDecodeError:
        return {"error": "Invalid body template JSON"}

    try:
        if method == "POST":
            resp = http_requests.post(url, json=body, headers=headers, timeout=15)
        else:
            resp = http_requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        result = resp.json()

        reply = result
        for key in response_path.split("."):
            if key and isinstance(reply, dict):
                reply = reply.get(key, "")

        return {
            "success": True,
            "status_code": resp.status_code,
            "response": str(reply)[:500],
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.route("/target/register", methods=["POST"])
def target_register():
    data = request.get_json()
    name = data.get("name", "").strip()
    description = data.get("description", "").strip()
    url = data.get("url", "").strip()
    method = data.get("method", "post").lower()
    headers = data.get("headers", {})
    body_template = data.get("body_template", {})
    response_path = data.get("response_path", "")
    authorized_by = data.get("authorized_by", "").strip()

    if not name or not url or not authorized_by:
        return {"error": "Name, URL, and Authorized By are required."}, 400

    if isinstance(body_template, str):
        try:
            body_template = json.loads(body_template)
        except json.JSONDecodeError:
            return {"error": "Invalid body template JSON."}, 400

    settings = get_settings()
    db = Database(settings.db_path)
    manager = TargetManager(db)
    target = manager.register(
        name=name,
        description=description,
        uri=url,
        method=method,
        headers=headers,
        request_template=body_template,
        response_text_path=response_path,
        authorized_by=authorized_by,
        tags=data.get("tags", []),
    )
    return {"success": True, "target_id": target.id, "name": target.name}


def main():
    print("LLM Inspector Web UI → http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)


if __name__ == "__main__":
    main()
