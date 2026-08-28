"""
LLM Inspector CLI.

This is the first user-facing surface for LLM Inspector (see README.md /
EXTENDED_README.md for the plan to add a web UI on top of the same
Agent Runtime later). Everything here is a thin layer over
llm_inspector.agent.runtime.AgentRuntime and llm_inspector.target.manager.TargetManager
-- the CLI does no security-testing logic of its own.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from llm_inspector.agent.manual_scan import MANUAL_SCAN_CATALOG, list_categories
from llm_inspector.agent.runtime import AgentRuntime
from llm_inspector.config import get_settings
from llm_inspector.findings.finding import Severity
from llm_inspector.findings.report_generator import write_reports
from llm_inspector.storage.database import Database
from llm_inspector.target.manager import TargetManager, TargetNotAuthorizedError

app = typer.Typer(
    name="llm-inspector",
    help=(
        "LLM Inspector: an agentic LLM security testing tool. Your chosen LLM "
        "(Claude, GPT-4o, Gemini, or a local Ollama model) reasons over "
        "authorized security tools (Garak, PyRIT, Promptfoo) via MCP to "
        "red-team and evaluate a target LLM application you own or are "
        "explicitly authorized to test."
    ),
    no_args_is_help=True,
)
target_app = typer.Typer(help="Manage authorized scan targets.")
scan_app = typer.Typer(help="Run and inspect security scans.")
app.add_typer(target_app, name="target")
app.add_typer(scan_app, name="scan")

console = Console()


def _db() -> Database:
    settings = get_settings()
    return Database(settings.db_path)


SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


@app.command()
def init(
    provider: Optional[str] = typer.Option(
        None, help="LLM provider: anthropic, openai, gemini, ollama."
    ),
) -> None:
    """Initialize the local data directory and check your setup."""
    settings = get_settings(provider_override=provider)
    console.print(f"[green]Data directory ready:[/] {settings.data_dir.resolve()}")
    console.print(f"[green]LLM provider:[/] {settings.provider}")
    console.print(f"[green]Model:[/] {settings.model}")

    if settings.provider == "ollama":
        console.print(
            f"[green]Ollama endpoint:[/] {settings.base_url or 'http://localhost:11434'}"
        )
    elif settings.api_key:
        console.print(f"[green]API key found for {settings.provider}.[/]")
    else:
        env_map = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "gemini": "GEMINI_API_KEY",
        }
        env_var = env_map.get(settings.provider, "API_KEY")
        console.print(
            f"[yellow]No API key set for {settings.provider}.[/] "
            f"Set {env_var} in your .env file, or pass --api-key to `llm-inspector scan run`."
        )

    for tool, hint in [
        ("garak", "pip install garak"),
        ("promptfoo", "npm install -g promptfoo"),
    ]:
        import shutil

        found = shutil.which(tool) or shutil.which(f"{tool}.cmd")
        status = "[green]found[/]" if found else f"[yellow]not found[/] (install: {hint})"
        console.print(f"{tool}: {status}")


@target_app.command("add")
def target_add(
    name: str = typer.Option(..., help="Human-readable target name."),
    description: str = typer.Option(..., help="What this target is."),
    uri: str = typer.Option(..., help="HTTP endpoint of the target LLM app."),
    method: str = typer.Option("post", help="HTTP method."),
    header: list[str] = typer.Option(
        [], help="HTTP header as 'Key: Value'. Repeatable."
    ),
    body_template: str = typer.Option(
        '{"input": "$INPUT"}',
        help="JSON request body template; $INPUT marks where the attack prompt goes.",
    ),
    response_path: str = typer.Option(
        "response", help="Dotted path to the reply text in the JSON response."
    ),
    tag: list[str] = typer.Option([], help="Free-form tag. Repeatable."),
    authorized_by: str = typer.Option(
        ..., help="Name/email of the person authorizing this target for testing."
    ),
    i_am_authorized: bool = typer.Option(
        False,
        "--i-am-authorized",
        help=(
            "Required. Confirms you own this target or have explicit written "
            "authorization to security-test it. LLM Inspector refuses to "
            "register a target without this flag."
        ),
    ),
) -> None:
    """Register a new authorized scan target."""
    if not i_am_authorized:
        console.print(
            "[red]Refusing to register target: pass --i-am-authorized to confirm "
            "you own this target or have explicit written authorization to "
            "security-test it. Unauthorized scanning of third-party systems may "
            "be illegal.[/]"
        )
        raise typer.Exit(code=1)

    headers = {}
    for h in header:
        if ":" not in h:
            console.print(f"[red]Invalid header (expected 'Key: Value'): {h}[/]")
            raise typer.Exit(code=1)
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()

    try:
        template = json.loads(body_template)
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid --body-template JSON: {e}[/]")
        raise typer.Exit(code=1)

    manager = TargetManager(_db())
    target = manager.register(
        name=name,
        description=description,
        uri=uri,
        method=method,
        headers=headers,
        request_template=template,
        response_text_path=response_path,
        authorized_by=authorized_by,
        tags=tag,
    )
    console.print(f"[green]Registered target[/] {target.id} ({target.name})")


@target_app.command("list")
def target_list() -> None:
    """List registered targets."""
    manager = TargetManager(_db())
    targets = manager.list()
    table = Table(title="Targets")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("URI")
    table.add_column("Authorized")
    table.add_column("Tags")
    for t in targets:
        table.add_row(
            t.id,
            t.name,
            t.rest_config.uri,
            "yes" if t.authorized else "no",
            ", ".join(t.tags),
        )
    console.print(table)


@scan_app.command("run")
def scan_run(
    target_id: str = typer.Option(..., "--target", help="Target ID from `target list`."),
    request: str = typer.Option(
        ..., "--request", help="What to test, in natural language."
    ),
    requester: str = typer.Option("cli-user", help="Who is running this scan."),
    provider: Optional[str] = typer.Option(
        None, help="LLM provider: anthropic, openai, gemini, ollama."
    ),
    api_key: Optional[str] = typer.Option(
        None, help="API key for the chosen LLM provider (overrides env var)."
    ),
    model: Optional[str] = typer.Option(
        None, help="Model name (e.g. gpt-4o, claude-sonnet-4-20250514, gemini-2.5-flash)."
    ),
    base_url: Optional[str] = typer.Option(
        None, help="Base URL for the LLM API (for Ollama or OpenAI-compatible endpoints)."
    ),
    max_seconds: Optional[int] = typer.Option(None, help="Override the time budget."),
    max_usd: Optional[float] = typer.Option(None, help="Override the cost budget."),
) -> None:
    """Run a security scan against a registered target."""
    settings = get_settings(
        api_key_override=api_key,
        provider_override=provider,
        model_override=model,
        base_url_override=base_url,
    )
    if max_seconds:
        settings.budget.max_seconds = max_seconds
    if max_usd:
        settings.budget.max_usd = max_usd

    db = Database(settings.db_path)
    manager = TargetManager(db)
    runtime = AgentRuntime(settings, db, manager)

    console.print(f"[dim]Provider: {settings.provider} | Model: {settings.model}[/]")

    def on_event(msg: str) -> None:
        console.print(f"[dim]•[/] {msg}")

    async def _run() -> None:
        try:
            result = await runtime.run_scan(
                target_id=target_id,
                user_request=request,
                requester=requester,
                on_event=on_event,
            )
        except TargetNotAuthorizedError as e:
            console.print(f"[red]{e}[/]")
            raise typer.Exit(code=1)
        except KeyError as e:
            console.print(f"[red]{e}[/]")
            raise typer.Exit(code=1)
        except ValueError as e:
            console.print(f"[red]{e}[/]")
            raise typer.Exit(code=1)

        paths = write_reports(result, request, settings.data_dir / "reports")

        console.print("")
        console.print(f"[bold]Scan {result.scan_id} complete.[/]")
        table = Table(title="Findings")
        table.add_column("Severity")
        table.add_column("Vulnerability")
        table.add_column("OWASP")
        table.add_column("Confidence")
        table.add_column("Tool")
        for f in result.findings:
            color = SEVERITY_COLOR.get(f.severity.value, "white")
            table.add_row(
                f"[{color}]{f.severity.value}[/]",
                f.vulnerability,
                f.owasp_id,
                f"{f.confidence:.2f}",
                f.source_tool,
            )
        console.print(table)
        console.print(f"\nMarkdown report: {paths['markdown']}")
        console.print(f"JSON report: {paths['json']}")

    asyncio.run(_run())


@scan_app.command("categories")
def scan_categories() -> None:
    """List available OWASP vulnerability categories and their supported tools."""
    table = Table(title="OWASP LLM Top 10 — Manual Scan Categories")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Tools")
    for cat in list_categories():
        tools = [k for k in MANUAL_SCAN_CATALOG[cat["id"]] if k != "name"]
        table.add_row(cat["id"], cat["name"], ", ".join(tools))
    console.print(table)
    console.print(
        "\n[dim]Usage: llm-inspector scan manual --target <ID> --vuln LLM01 --tool garak[/]"
    )


@scan_app.command("manual")
def scan_manual(
    target_id: str = typer.Option(..., "--target", help="Target ID from `target list`."),
    vuln: list[str] = typer.Option(
        ..., "--vuln",
        help="OWASP category ID (e.g. LLM01, LLM01b, LLM02). Use 'all' for everything. Repeatable.",
    ),
    tool: list[str] = typer.Option(
        ..., "--tool",
        help="Tool to use: garak, promptfoo, promptfoo_redteam. Use 'all' for all available. Repeatable.",
    ),
    requester: str = typer.Option("cli-user", help="Who is running this scan."),
    max_attempts: int = typer.Option(20, help="Max attempts per garak/promptfoo probe."),
    num_tests: int = typer.Option(5, help="Number of tests for promptfoo_redteam."),
    purpose: str = typer.Option(
        "security testing of an LLM application",
        help="Describe the target LLM (e.g. 'a customer support chatbot for a bank'). Guides promptfoo_redteam attack generation.",
    ),
    provider: Optional[str] = typer.Option(
        None, help="LLM provider (only needed for promptfoo_redteam).",
    ),
    api_key: Optional[str] = typer.Option(
        None, help="API key (only needed for promptfoo_redteam).",
    ),
    model: Optional[str] = typer.Option(
        None, help="Model name (only needed for promptfoo_redteam).",
    ),
    base_url: Optional[str] = typer.Option(
        None, help="Base URL (only needed for promptfoo_redteam).",
    ),
    max_seconds: Optional[int] = typer.Option(None, help="Override the time budget."),
) -> None:
    """Run a manual security scan — select OWASP categories and tools directly, no Brain LLM."""
    if "all" in vuln:
        vuln = list(MANUAL_SCAN_CATALOG.keys())

    valid_tools = ["garak", "promptfoo", "promptfoo_redteam"]
    if "all" in tool:
        tool = valid_tools

    for v in vuln:
        if v not in MANUAL_SCAN_CATALOG:
            console.print(
                f"[red]Unknown vulnerability category: {v}[/]\n"
                "Run `llm-inspector scan categories` to see available options."
            )
            raise typer.Exit(code=1)
    for t in tool:
        if t not in valid_tools:
            console.print(f"[red]Unknown tool: {t}. Choose from: {', '.join(valid_tools)}[/]")
            raise typer.Exit(code=1)

    settings = get_settings(
        api_key_override=api_key,
        provider_override=provider,
        model_override=model,
        base_url_override=base_url,
    )
    if max_seconds:
        settings.budget.max_seconds = max_seconds

    db = Database(settings.db_path)
    manager = TargetManager(db)
    runtime = AgentRuntime(settings, db, manager)

    console.print(f"[bold]Manual scan mode[/] — no Brain LLM involved")
    console.print(f"[dim]Vulnerabilities: {', '.join(vuln)}[/]")
    console.print(f"[dim]Tools: {', '.join(tool)}[/]")

    def on_event(msg: str) -> None:
        console.print(f"[dim]•[/] {msg}")

    async def _run() -> None:
        try:
            result = await runtime.run_manual_scan(
                target_id=target_id,
                owasp_ids=vuln,
                tools=tool,
                requester=requester,
                max_attempts=max_attempts,
                num_tests=num_tests,
                purpose=purpose,
                on_event=on_event,
            )
        except TargetNotAuthorizedError as e:
            console.print(f"[red]{e}[/]")
            raise typer.Exit(code=1)
        except KeyError as e:
            console.print(f"[red]{e}[/]")
            raise typer.Exit(code=1)
        except ValueError as e:
            console.print(f"[red]{e}[/]")
            raise typer.Exit(code=1)

        paths = write_reports(
            result, f"Manual scan: {', '.join(vuln)} with {', '.join(tool)}",
            settings.data_dir / "reports",
        )

        console.print("")
        console.print(f"[bold]Scan {result.scan_id} complete.[/]")
        table = Table(title="Findings")
        table.add_column("Severity")
        table.add_column("Vulnerability")
        table.add_column("OWASP")
        table.add_column("Confidence")
        table.add_column("Tool")
        for f in result.findings:
            color = SEVERITY_COLOR.get(f.severity.value, "white")
            table.add_row(
                f"[{color}]{f.severity.value}[/]",
                f.vulnerability,
                f.owasp_id,
                f"{f.confidence:.2f}",
                f.source_tool,
            )
        console.print(table)
        console.print(f"\nMarkdown report: {paths['markdown']}")
        console.print(f"JSON report: {paths['json']}")

    asyncio.run(_run())


@scan_app.command("list")
def scan_list(target: Optional[str] = typer.Option(None, help="Filter by target ID.")) -> None:
    """List past scans."""
    db = _db()
    scans = db.list_scans(target_id=target)
    table = Table(title="Scans")
    table.add_column("Scan ID")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Started")
    for s in scans:
        table.add_row(s["id"], s["target_id"], s["status"], s["started_at"])
    console.print(table)


@scan_app.command("report")
def scan_report(scan_id: str) -> None:
    """Print the markdown report for a past scan."""
    settings = get_settings()
    path = settings.data_dir / "reports" / f"{scan_id}.report.md"
    if not path.exists():
        console.print(f"[red]No report found at {path}[/]")
        raise typer.Exit(code=1)
    console.print(path.read_text())


if __name__ == "__main__":
    app()
