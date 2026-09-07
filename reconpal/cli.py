"""ReconPal command line interface.

Two ways in: `reconpal scan <target>` for people who know what they want, and
`reconpal wizard` for a guided walkthrough that explains each choice.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from .core.http import PoliteClient
from .core.models import ScanResult, Severity
from .core.report import write_html, write_json
from .core.scope import Scope, ScopeError, host_of, normalise_target
from .modules import audit, mcp, recon

console = Console()

BANNER = r"""
  ___                    ___      _
 | _ \___ __ ___ _ _    | _ \__ _| |
 |   / -_) _/ _ \ ' \   |  _/ _` | |
 |_|_\___\__\___/_||_|  |_| \__,_|_|
"""

TAGLINE = "your friendly recon companion for authorised security testing"

MODULE_LABELS = {
    "subdomains": "Certificate-transparency subdomain lookup",
    "fingerprint": "Technology fingerprinting",
    "endpoints": "Interesting-path discovery",
    "headers": "Security header audit",
    "cors": "CORS policy check",
    "cookies": "Cookie flag review",
    "disclosure": "Credential-pattern scan",
    "mcp": "MCP deployment discovery",
}

DEFAULT_MODULES = ["fingerprint", "endpoints", "headers", "cors", "cookies", "disclosure"]


def show_banner() -> None:
    console.print(
        Align.center(
            Group(
                Text(BANNER, style="bold cyan"),
                Text(TAGLINE, style="italic grey62"),
            )
        )
    )
    console.print()


def authorisation_gate(target: str, assume_yes: bool = False) -> bool:
    """Make the tester state, out loud, that they are allowed to do this.

    This is not legal protection. It is a speed bump that has, in practice,
    caught more than one paste of the wrong hostname.
    """
    panel = Panel(
        Text.from_markup(
            f"You are about to scan [bold]{target}[/bold].\n\n"
            "ReconPal sends live requests to this host. Only continue if you have "
            "written authorisation to test it — a bug bounty program scope, a "
            "signed engagement, or your own infrastructure.",
        ),
        title="[bold yellow]Authorisation check[/bold yellow]",
        border_style="yellow",
    )
    console.print(panel)
    if assume_yes:
        console.print("[grey62]--yes supplied; proceeding.[/grey62]\n")
        return True
    return Confirm.ask("Do you have authorisation to test this target?", default=False)


async def run_scan(
    target: str,
    modules: list[str],
    *,
    rps: float,
    headers: dict[str, str],
    include_subdomains: bool,
    allow_private: bool,
    mcp_register: bool,
) -> ScanResult:
    result = ScanResult(target=target)
    scope = Scope.from_target(target, include_subdomains=include_subdomains)
    scope.allow_private = allow_private

    console.print(f"[grey62]Scope:[/grey62] {scope.describe()}")
    console.print(f"[grey62]Pacing:[/grey62] {rps} requests/second with jitter\n")

    async with PoliteClient(scope, rps=rps, extra_headers=headers) as client:
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=28, complete_style="cyan"),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Starting…", total=len(modules))

            for name in modules:
                progress.update(task, description=MODULE_LABELS.get(name, name))
                try:
                    await _dispatch(name, client, result, target, mcp_register)
                    result.modules_run.append(name)
                except ScopeError as exc:
                    result.errors.append(f"{name}: blocked by scope — {exc}")
                except Exception as exc:  # a broken module must not kill the run
                    result.errors.append(f"{name}: {type(exc).__name__}: {exc}")
                progress.advance(task)

        result.request_count = client.request_count
        if client.blocked_count:
            result.errors.append(
                f"{client.blocked_count} request(s) suppressed by the scope guard"
            )

    result.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return result


async def _dispatch(
    name: str,
    client: PoliteClient,
    result: ScanResult,
    target: str,
    mcp_register: bool,
) -> None:
    if name == "subdomains":
        await recon.passive_subdomains(client, result, host_of(target))
    elif name == "fingerprint":
        await recon.fingerprint(client, result, target)
    elif name == "endpoints":
        await recon.discover_endpoints(client, result, target)
    elif name == "headers":
        await audit.security_headers(client, result, target)
    elif name == "cors":
        await audit.cors_policy(client, result, target)
    elif name == "cookies":
        await audit.cookie_flags(client, result, target)
    elif name == "disclosure":
        await audit.content_leakage(client, result, target)
    elif name == "mcp":
        await mcp.detect(client, result, target)
        documents = await mcp.discovery_metadata(client, result, target)
        if documents:
            await mcp.registration_surface(
                client, result, documents, attempt_registration=mcp_register
            )
    else:
        raise ValueError(f"unknown module: {name}")


def render_results(result: ScanResult) -> None:
    counts = result.counts
    highest = result.highest

    summary = Table.grid(padding=(0, 2))
    summary.add_column(justify="right", style="grey62")
    summary.add_column()
    summary.add_row("Target", result.target)
    summary.add_row("Requests sent", str(result.request_count))
    summary.add_row("Modules", ", ".join(result.modules_run) or "none")
    summary.add_row(
        "Highest severity",
        Text(highest.value, style=highest.colour) if highest else Text("none", style="green"),
    )
    console.print(Panel(summary, title="[bold]Scan summary[/bold]", border_style="cyan"))

    tally = Table.grid(padding=(0, 3))
    tally.add_column()
    for sev in Severity:
        tally.add_row(
            Text(f"{counts[sev.value]}  {sev.value}", style=sev.colour if counts[sev.value] else "grey42")
        )
    console.print(tally)
    console.print()

    if not result.findings:
        console.print("[green]No findings recorded.[/green] That is not the same as "
                      "'no vulnerabilities' — it means these checks saw nothing.\n")
    else:
        table = Table(show_lines=False, header_style="bold grey70", expand=True)
        table.add_column("Severity", width=9, no_wrap=True)
        table.add_column("Confidence", width=11, no_wrap=True)
        table.add_column("Finding", ratio=1)
        table.add_column("Check", width=13, no_wrap=True)
        for f in result.sorted_findings():
            # Show the leaf of the module path; the prefix is noise in a table
            # this narrow, and truncation renders badly on legacy consoles.
            check = f.module.rsplit(".", 1)[-1]
            label = "Info" if f.severity is Severity.INFO else f.severity.value
            table.add_row(
                Text(label, style=f.severity.colour),
                Text(f.confidence.value, style="grey62"),
                f.title,
                Text(check, style="grey62"),
            )
        console.print(table)
        console.print()

    assets = len(result.assets)
    if assets:
        kinds = {}
        for a in result.assets:
            kinds[a.kind] = kinds.get(a.kind, 0) + 1
        breakdown = ", ".join(f"{v} {k}" for k, v in sorted(kinds.items()))
        console.print(f"[grey62]Assets discovered:[/grey62] {assets} ({breakdown})\n")

    if result.errors:
        console.print("[yellow]Notes:[/yellow]")
        for err in result.errors:
            console.print(f"  [grey62]•[/grey62] {err}")
        console.print()


def wizard() -> argparse.Namespace:
    """Guided setup for people who would rather not read --help."""
    show_banner()
    console.print(
        Panel(
            "I will ask a few questions and then run the scan. "
            "Press Enter to accept the value in brackets.",
            border_style="cyan",
            title="[bold]Wizard[/bold]",
        )
    )
    console.print()

    target = Prompt.ask("[bold]Target[/bold] (hostname or URL)")

    console.print("\n[grey62]Which checks would you like?[/grey62]")
    console.print("  [cyan]1[/cyan]  Quick     — headers, CORS, cookies")
    console.print("  [cyan]2[/cyan]  Standard  — quick, plus fingerprinting and paths")
    console.print("  [cyan]3[/cyan]  Full      — standard, plus subdomains and MCP discovery")
    choice = Prompt.ask("Profile", choices=["1", "2", "3"], default="2")

    modules = {
        "1": ["headers", "cors", "cookies"],
        "2": DEFAULT_MODULES,
        "3": DEFAULT_MODULES + ["subdomains", "mcp"],
    }[choice]

    rps = float(Prompt.ask("\nRequests per second", default="4"))
    out = Prompt.ask("Report directory", default="reports")

    console.print()
    return argparse.Namespace(
        target=target,
        modules=modules,
        rps=rps,
        out=out,
        header=[],
        subdomains=("subdomains" in modules),
        allow_private=False,
        mcp_register=False,
        yes=False,
        no_html=False,
    )


def parse_headers(pairs: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for pair in pairs or []:
        if ":" not in pair:
            console.print(f"[yellow]Ignoring malformed header:[/yellow] {pair}")
            continue
        key, _, value = pair.partition(":")
        headers[key.strip()] = value.strip()
    return headers


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconpal",
        description="ReconPal — friendly recon for authorised security testing.",
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a target")
    scan.add_argument("target", help="hostname or URL")
    scan.add_argument(
        "-m", "--modules", nargs="+", choices=list(MODULE_LABELS),
        default=DEFAULT_MODULES, help="modules to run",
    )
    scan.add_argument("--rps", type=float, default=4.0, help="requests per second (default 4)")
    scan.add_argument("-o", "--out", default="reports", help="report directory")
    scan.add_argument(
        "-H", "--header", action="append", default=[],
        help="extra header, repeatable, e.g. -H 'X-Bug-Bounty: yourname'",
    )
    scan.add_argument("--allow-private", action="store_true",
                      help="permit targets resolving to private ranges")
    scan.add_argument("--mcp-register", action="store_true",
                      help="attempt MCP dynamic client registration (creates state)")
    scan.add_argument("-y", "--yes", action="store_true",
                      help="skip the authorisation prompt")
    scan.add_argument("--no-html", action="store_true", help="write JSON only")

    sub.add_parser("wizard", help="guided interactive setup")
    sub.add_parser("modules", help="list available modules")
    return parser


def list_modules() -> None:
    show_banner()
    table = Table(header_style="bold grey70")
    table.add_column("Module")
    table.add_column("What it does")
    table.add_column("Default", width=8)
    for name, label in MODULE_LABELS.items():
        table.add_row(
            Text(name, style="cyan"),
            label,
            "yes" if name in DEFAULT_MODULES else "-",
        )
    console.print(table)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "modules":
        list_modules()
        return 0

    if args.command == "wizard":
        args = wizard()
    elif args.command != "scan":
        show_banner()
        parser.print_help()
        return 0
    else:
        show_banner()

    try:
        target = normalise_target(args.target)
    except ValueError as exc:
        console.print(f"[red]Bad target:[/red] {exc}")
        return 2

    if not authorisation_gate(target, assume_yes=getattr(args, "yes", False)):
        console.print("\n[grey62]Stopped. Nothing was sent.[/grey62]")
        return 1
    console.print()

    modules = list(args.modules)
    if getattr(args, "mcp_register", False) and "mcp" not in modules:
        modules.append("mcp")

    try:
        result = asyncio.run(
            run_scan(
                target,
                modules,
                rps=args.rps,
                headers=parse_headers(getattr(args, "header", [])),
                include_subdomains=True,
                allow_private=getattr(args, "allow_private", False),
                mcp_register=getattr(args, "mcp_register", False),
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow] No report written.")
        return 130

    console.print()
    render_results(result)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    slug = host_of(target).replace(".", "-")
    out_dir = Path(args.out)
    json_path = write_json(result, out_dir / f"{slug}-{stamp}.json")
    console.print(f"[grey62]JSON report:[/grey62] {json_path}")
    if not getattr(args, "no_html", False):
        html_path = write_html(result, out_dir / f"{slug}-{stamp}.html")
        console.print(f"[grey62]HTML report:[/grey62] {html_path}")

    console.print(
        "\n[grey62]Findings are automated observations, not confirmed "
        "vulnerabilities. Verify each one before reporting it.[/grey62]"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
