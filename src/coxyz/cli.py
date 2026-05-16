"""coxyz CLI entry point."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__
from .config import Config, load_config
from .policy import (
    Finding,
    ServiceReport,
    Severity,
    apply_findings,
    audit_category,
    audit_service,
    list_categories,
    list_services,
    resolve_service,
)
from .scaffold import CreateRequest, create_service, validate_service_name
from .system import (
    CommandExecutionError,
    check_required_bins,
    detect_acl_support,
    principal_exists,
)

app = typer.Typer(
    name="coxyz",
    help="CLI to manage Docker services under /srv/docker.",
    no_args_is_help=True,
    add_completion=True,
)
console = Console()
err_console = Console(stderr=True)


# ─── Global state ─────────────────────────────────────────────────────────────

class Ctx:
    config: Config
    config_source: Optional[Path]
    acl_enabled: bool
    principals_available: dict[str, bool]


ctx = Ctx()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"coxyz {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    config_path: Annotated[
        Optional[Path],
        typer.Option("--config", "-c", help="Path to config.yaml (overrides defaults)."),
    ] = None,
    version: Annotated[
        Optional[bool],
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = None,
) -> None:
    """Manage Docker services under /srv/docker (coxyz rules)."""
    missing = check_required_bins()
    if missing:
        err_console.print(f"[red]ERROR[/red] Missing required binaries: {', '.join(missing)}")
        raise typer.Exit(code=2)
    try:
        cfg, source = load_config(config_path)
    except (FileNotFoundError, ValueError) as e:
        err_console.print(f"[red]ERROR[/red] Config: {e}")
        raise typer.Exit(code=2)
    ctx.config = cfg
    ctx.config_source = source
    ctx.acl_enabled = detect_acl_support(cfg.root_dir)
    ctx.principals_available = {
        name: principal_exists(principal.name, principal.kind)
        for name, principal in cfg.settings.principals.items()
    }


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _severity_style(sev: Severity) -> str:
    return {
        Severity.OK: "green",
        Severity.DRIFT: "yellow",
        Severity.WARN: "magenta",
        Severity.ERROR: "red",
    }[sev]


def _severity_symbol(sev: Severity) -> str:
    return {
        Severity.OK: "✓",
        Severity.DRIFT: "✗",
        Severity.WARN: "!",
        Severity.ERROR: "✗",
    }[sev]


def _print_runtime_banner() -> None:
    src = str(ctx.config_source) if ctx.config_source else "<bundled default>"
    principals = ", ".join(
        f"{p.name}({p.kind})" for p in ctx.config.settings.principals.values()
    )
    console.print(
        f"[dim]root={ctx.config.root_dir}  "
        f"principals={principals}  "
        f"acl={'on' if ctx.acl_enabled else 'off'}  "
        f"config={src}[/dim]"
    )


def _print_finding(finding: Finding, *, indent: str = "  ") -> None:
    style = _severity_style(finding.severity)
    sym = _severity_symbol(finding.severity)
    console.print(
        f"{indent}[{style}]{sym}[/{style}] "
        f"[dim]{finding.rule_name:14}[/dim] {finding.path}"
    )
    for issue in finding.issues:
        console.print(f"{indent}    [dim]→[/dim] {issue}")


def _display_target_for_apply(path: Path) -> str:
    try:
        rel = path.resolve().relative_to(ctx.config.root_dir.resolve())
    except ValueError:
        return str(path)
    parts = rel.parts
    if len(parts) >= 2 and parts[0] in ctx.config.categories:
        return f"{parts[0]}/{parts[1]}"
    if len(parts) >= 1 and parts[0] in ctx.config.categories:
        return parts[0]
    return str(path)


def _print_finding_apply(finding: Finding, *, indent: str = "  ") -> None:
    style = _severity_style(finding.severity)
    sym = _severity_symbol(finding.severity)
    target = _display_target_for_apply(finding.path)
    console.print(
        f"{indent}[{style}]{sym}[/{style}] "
        f"[dim]{finding.rule_name:14}[/dim] {target}"
    )
    for issue in finding.issues:
        console.print(f"{indent}    [dim]→[/dim] {issue}")


# ─── Compose parsing for `list` ───────────────────────────────────────────────

_IMAGE_RE = re.compile(r"^\s*image:\s*(.+?)\s*$", re.MULTILINE)
_EXPOSE_RE = re.compile(r"^\s*-\s*[\"']?(\d+(?:/\w+)?)[\"']?\s*$", re.MULTILINE)


def _parse_compose_summary(compose_path: Path) -> tuple[str, list[str]]:
    """Cheap parse of image + expose ports without pulling in a YAML lib for this view."""
    if not compose_path.is_file():
        return "—", []
    try:
        text = compose_path.read_text(encoding="utf-8")
    except OSError:
        return "?", []
    image_match = _IMAGE_RE.search(text)
    image = image_match.group(1).strip().strip("\"'") if image_match else "—"
    # Capture ports under expose: only
    ports: list[str] = []
    in_expose = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("expose:"):
            in_expose = True
            continue
        if in_expose:
            if stripped.startswith("- "):
                p = stripped[2:].strip().strip("\"'")
                ports.append(p)
            elif stripped and not line.startswith((" ", "\t")):
                in_expose = False
            elif stripped and ":" in stripped and not stripped.startswith("- "):
                in_expose = False
    return image, ports


# ─── Commands ─────────────────────────────────────────────────────────────────

@app.command("list")
def list_cmd(
    category: Annotated[
        Optional[str],
        typer.Option("--category", "-C", help="Filter by category."),
    ] = None,
) -> None:
    """List services with image, ports, and compliance status."""
    _print_runtime_banner()

    services = list_services(ctx.config, category=category)
    if not services:
        console.print("[dim]No services found.[/dim]")
        raise typer.Exit()

    table = Table(show_header=True, header_style="bold")
    table.add_column("Category")
    table.add_column("Service")
    table.add_column("Image")
    table.add_column("Ports")
    table.add_column("Status")

    n_compliant = 0
    n_drift = 0
    n_warn = 0

    for cat, svc, path in services:
        image, ports = _parse_compose_summary(path / "compose.yaml")
        report = audit_service(
            ctx.config, cat, svc,
            acl_enabled=ctx.acl_enabled,
            principals_available=ctx.principals_available,
        )
        if report.compliant:
            status = Text("✓ ok", style="green")
            n_compliant += 1
        elif report.drift_count > 0:
            status = Text(f"✗ {report.drift_count} drift", style="yellow")
            n_drift += 1
            if report.warn_count:
                status.append(f", {report.warn_count} warn", style="magenta")
        else:
            status = Text(f"! {report.warn_count} warn", style="magenta")
            n_warn += 1

        table.add_row(
            cat, svc, image,
            ", ".join(ports) if ports else "—",
            status,
        )

    console.print(table)
    console.print(
        f"[dim]Total {len(services)} — "
        f"[green]{n_compliant} compliant[/green], "
        f"[yellow]{n_drift} with drift[/yellow], "
        f"[magenta]{n_warn} warn-only[/magenta][/dim]"
    )


@app.command("check")
def check_cmd(
    service: Annotated[
        Optional[str],
        typer.Argument(help="Service name (e.g. 'bitwarden' or 'apps/bitwarden'). Default: all."),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show OK findings too.")] = False,
) -> None:
    """Audit permissions/ACL (read-only). Exits non-zero if drift detected."""
    _print_runtime_banner()

    if service:
        try:
            cat, svc, _ = resolve_service(ctx.config, service)
            reports = [audit_service(
                ctx.config, cat, svc,
                acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
            )]
        except ValueError as e:
            err_console.print(f"[red]ERROR[/red] {e}")
            raise typer.Exit(code=2)
    else:
        reports = [
            audit_service(
                ctx.config, cat, svc,
                acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
            )
            for cat, svc, _ in list_services(ctx.config)
        ]

    # Also audit each category directory once
    cat_findings: dict[str, Finding] = {}
    for cat in list_categories(ctx.config):
        cat_findings[cat] = audit_category(
            ctx.config, cat,
            acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
        )

    total_drift = 0
    total_warn = 0
    for f in cat_findings.values():
        if f.severity is Severity.DRIFT:
            total_drift += 1
        elif f.severity is Severity.WARN:
            total_warn += 1

    # Print category findings (only non-OK or in verbose)
    if any(f.severity is not Severity.OK for f in cat_findings.values()) or verbose:
        console.print("\n[bold]Categories[/bold]")
        for f in cat_findings.values():
            if verbose or f.severity is not Severity.OK:
                _print_finding(f)

    for report in reports:
        if report.compliant and not verbose:
            console.print(
                f"\n[bold]{report.category}/{report.service}[/bold] [green]✓ compliant[/green]"
            )
            continue
        marker = "[green]✓[/green]" if report.compliant else "[yellow]✗[/yellow]"
        console.print(f"\n[bold]{report.category}/{report.service}[/bold] {marker}")
        for finding in report.findings:
            if verbose or finding.severity is not Severity.OK:
                _print_finding(finding)
        total_drift += report.drift_count
        total_warn += report.warn_count

    console.print(
        f"\n[dim]Summary:[/dim] "
        f"[yellow]{total_drift} drift[/yellow], "
        f"[magenta]{total_warn} warn-only[/magenta]"
    )

    if total_drift > 0:
        raise typer.Exit(code=1)


@app.command("apply")
def apply_cmd(
    service: Annotated[
        Optional[str],
        typer.Argument(help="Service name. Default: all."),
    ] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt.")] = False,
) -> None:
    """Apply correct permissions/ACL to services after confirmation."""
    _print_runtime_banner()

    if service:
        try:
            cat, svc, _ = resolve_service(ctx.config, service)
            targets: list[tuple[str, str]] = [(cat, svc)]
        except ValueError as e:
            err_console.print(f"[red]ERROR[/red] {e}")
            raise typer.Exit(code=2)
    else:
        targets = [(c, s) for c, s, _ in list_services(ctx.config)]

    # Audit categories AND services to build the full finding list
    all_findings: list[Finding] = []
    if not service:
        for cat in list_categories(ctx.config):
            all_findings.append(audit_category(
                ctx.config, cat,
                acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
            ))
    else:
        # When targeting one service, also include its category
        cat = targets[0][0]
        all_findings.append(audit_category(
            ctx.config, cat,
            acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
        ))

    for cat, svc in targets:
        report = audit_service(
            ctx.config, cat, svc,
            acl_enabled=ctx.acl_enabled, principals_available=ctx.principals_available,
        )
        all_findings.extend(report.findings)

    drifts = [f for f in all_findings if f.severity is Severity.DRIFT]
    warns = [f for f in all_findings if f.severity is Severity.WARN]
    errors = [f for f in all_findings if f.severity is Severity.ERROR]

    if not drifts and not warns and not errors:
        console.print("[green]✓ All compliant — nothing to do.[/green]")
        raise typer.Exit()

    if drifts:
        console.print(f"\n[yellow]Planned changes ({len(drifts)}):[/yellow]")
        for f in drifts:
            _print_finding_apply(f)
            for cmd in f.fixes:
                console.print(f"      [dim]$[/dim] {' '.join(cmd)}")

    if warns:
        console.print(f"\n[magenta]Audit-only warnings ({len(warns)}) — NOT touched:[/magenta]")
        for f in warns:
            _print_finding_apply(f)

    if errors:
        console.print(f"\n[red]Errors ({len(errors)}) — blocking:[/red]")
        for f in errors:
            _print_finding_apply(f)
        raise typer.Exit(code=2)

    if not yes and not typer.confirm(f"\nApply {len(drifts)} fix(es)?"):
        console.print("[dim]Aborted.[/dim]")
        raise typer.Exit(code=1)

    try:
        result = apply_findings(drifts, dry_run=False)
    except CommandExecutionError as e:
        err_console.print("[red]ERROR[/red] Failed to apply fixes: a shell command failed.")
        err_console.print(f"[red]Command[/red]: {' '.join(e.command)}")
        if e.stdout.strip():
            err_console.print(f"[red]stdout[/red]:\n{e.stdout.rstrip()}")
        if e.stderr.strip():
            err_console.print(f"[red]stderr[/red]:\n{e.stderr.rstrip()}")
        raise typer.Exit(code=2)
    console.print(f"\n[green]✓ Done — {len(result.commands_run)} command(s) executed.[/green]")


@app.command("create")
def create_cmd(
    category: Annotated[
        Optional[str],
        typer.Option("--category", "-C", help="Service category."),
    ] = None,
    name: Annotated[
        Optional[str],
        typer.Option("--name", "-n", help="Service name."),
    ] = None,
    image: Annotated[
        Optional[str],
        typer.Option("--image", "-i", help="Docker image (e.g. nginx:1.27)."),
    ] = None,
    port: Annotated[
        Optional[int],
        typer.Option("--port", "-p", help="Internal port to expose."),
    ] = None,
    timezone: Annotated[
        Optional[str],
        typer.Option("--timezone", help="TZ env value."),
    ] = None,
    apply_changes: Annotated[
        bool,
        typer.Option("--apply", help="Actually create the service (default: dry-run)."),
    ] = False,
) -> None:
    """Scaffold a new service (interactive prompts for missing arguments)."""
    _print_runtime_banner()

    cfg = ctx.config

    # Interactive prompts for missing arguments
    if not category:
        cats = sorted(cfg.categories)
        console.print("Available categories: " + ", ".join(cats))
        category = typer.prompt("Category", default=cats[0])
    if category not in cfg.categories:
        err_console.print(
            f"[red]ERROR[/red] Unknown category '{category}'. "
            f"Authorized: {', '.join(sorted(cfg.categories))}"
        )
        raise typer.Exit(code=2)

    if not name:
        name = typer.prompt("Service name")
    try:
        validate_service_name(name)
    except ValueError as e:
        err_console.print(f"[red]ERROR[/red] {e}")
        raise typer.Exit(code=2)

    if not image:
        image = typer.prompt("Docker image (with tag)", default="your-image:latest")
    if port is None:
        port = typer.prompt(
            "Internal port",
            default=cfg.compose_template.default_internal_port,
            type=int,
        )
    if not timezone:
        timezone = typer.prompt("Timezone", default=cfg.compose_template.default_timezone)

    req = CreateRequest(
        category=category, service=name, image=image,
        port=port, timezone=timezone,
    )
    svc_path = cfg.root_dir / category / name

    console.print()
    console.print("[bold]Will create:[/bold]")
    console.print(f"  path     : {svc_path}/")
    console.print(f"  owner    : {cfg.category(category).owner_spec}")
    console.print(f"  image    : {image}")
    console.print(f"  port     : {port}")
    console.print(f"  timezone : {timezone}")
    console.print()

    try:
        executed = create_service(
            cfg, req,
            dry_run=not apply_changes,
            acl_enabled=ctx.acl_enabled,
            principals_available=ctx.principals_available,
        )
    except (ValueError, RuntimeError) as e:
        err_console.print(f"[red]ERROR[/red] {e}")
        raise typer.Exit(code=2)

    for cmd in executed:
        prefix = "[dim]DRY[/dim]" if not apply_changes else "[green]RUN[/green]"
        console.print(f"  {prefix} {' '.join(cmd)}")

    if not apply_changes:
        console.print(
            f"\n[dim]Dry-run mode — {len(executed)} action(s) planned. "
            "Re-run with [bold]--apply[/bold] to execute.[/dim]"
        )
    else:
        console.print(f"\n[green]✓ Created {svc_path}[/green]")
        console.print(f"  Next: edit {svc_path}/compose.yaml and deploy via Komodo.")


@app.command("show-config")
def show_config_cmd() -> None:
    """Print the resolved configuration."""
    _print_runtime_banner()
    cfg = ctx.config

    console.print(f"\n[bold]Categories[/bold] ({len(cfg.categories)})")
    for name, c in sorted(cfg.categories.items()):
        console.print(f"  {name:12} → {c.owner_spec}")

    console.print(f"\n[bold]Exclude[/bold] ({len(cfg.exclude)})")
    for pattern in cfg.exclude:
        console.print(f"  - {pattern}")

    console.print(f"\n[bold]Rules[/bold] ({len(cfg.rules)})")
    table = Table(show_header=True, header_style="bold dim")
    table.add_column("Rule")
    table.add_column("Mode")
    table.add_column("ACL")
    table.add_column("Audit only")
    table.add_column("Owner override")
    for name, r in cfg.rules.items():
        acl = "—"
        if r.acl:
            acl = ", ".join(f"{principal}:{perms}" for principal, perms in r.acl.items())
        table.add_row(
            name, r.mode,
            acl,
            "yes" if r.audit_only else "no",
            r.owner or "—",
        )
    console.print(table)


@app.command("edit")
def edit_cmd() -> None:
    """Edit the main configuration file."""
    cfg_path = Path("/etc/coxyz/config.yaml")
    if not cfg_path.exists():
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        src = files("coxyz").joinpath("default_config.yaml")
        cfg_path.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        console.print(f"[dim]Created {cfg_path} from bundled defaults.[/dim]")
    editor = os.environ.get("EDITOR")
    if editor and editor.strip():
        editor_cmd = editor.strip()
        if shutil.which(editor_cmd) is None and not Path(editor_cmd).is_file():
            err_console.print(f"[red]ERROR[/red] Editor not found: {editor_cmd}")
            raise typer.Exit(code=2)
        command = [editor_cmd, str(cfg_path)]
    else:
        command = None
        for candidate in ("nano", "vi", "vim"):
            if shutil.which(candidate):
                command = [candidate, str(cfg_path)]
                break
        if command is None:
            err_console.print("[red]ERROR[/red] No editor found (set $EDITOR).")
            raise typer.Exit(code=2)
    try:
        subprocess.run(command, check=True)
    except FileNotFoundError:
        err_console.print(f"[red]ERROR[/red] Editor not found: {command[0]}")
        raise typer.Exit(code=2)


def cli_main() -> None:  # pragma: no cover
    """Module-level entry point (also used by `python -m coxyz`)."""
    app()


if __name__ == "__main__":  # pragma: no cover
    cli_main()
