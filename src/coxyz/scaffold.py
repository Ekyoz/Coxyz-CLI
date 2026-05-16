"""Scaffold a new service directory tree."""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from .config import Config
from .policy import plan_path
from .system import CommandRunner, group_exists, user_exists

SERVICE_NAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$")


@dataclass(frozen=True)
class CreateRequest:
    category: str
    service: str
    image: str
    port: int
    timezone: str


def validate_service_name(name: str) -> None:
    if not SERVICE_NAME_RE.match(name):
        raise ValueError(
            f"Invalid service name '{name}' "
            "(alphanumeric and hyphens, no leading/trailing hyphen)"
        )


def render_compose(req: CreateRequest, svc_path: Path, network: str) -> str:
    """Render the compose.yaml template."""
    tpl = files("coxyz").joinpath("templates/compose.yaml.tpl").read_text(encoding="utf-8")
    return tpl.format(
        service=req.service,
        image=req.image,
        network=network,
        port=req.port,
        timezone=req.timezone,
        svc_path=svc_path,
    )


def create_service(
    config: Config,
    req: CreateRequest,
    *,
    dry_run: bool,
    acl_enabled: bool,
    principals_available: dict[str, bool],
) -> list[list[str]]:
    """Create the service tree. Returns the list of commands executed (or planned)."""
    validate_service_name(req.service)
    cat = config.category(req.category)

    if not user_exists(cat.user):
        raise RuntimeError(f"System user '{cat.user}' does not exist. Create it first.")
    if not group_exists(cat.group):
        raise RuntimeError(f"System group '{cat.group}' does not exist. Create it first.")

    svc_path = config.root_dir / req.category / req.service
    if svc_path.exists():
        raise RuntimeError(f"Service path already exists: {svc_path}")

    runner = CommandRunner(dry_run=dry_run)

    def apply_rule(path: Path, rule_name: str, *, is_dir: bool) -> None:
        for command in plan_path(
            path, config.rule(rule_name), cat.owner_spec, config,
            is_dir=is_dir, acl_enabled=acl_enabled,
            principals_available=principals_available,
        ):
            runner.run(command)

    # Directory tree (mkdir -p is idempotent, so an existing category dir is fine).
    apply_rule(config.root_dir / req.category, "category_dir", is_dir=True)
    apply_rule(svc_path, "service_dir", is_dir=True)
    apply_rule(svc_path / "config", "config_dir", is_dir=True)
    apply_rule(svc_path / "data", "data_dir", is_dir=True)

    # compose.yaml: write the file first, then own/permission it.
    compose_file = svc_path / "compose.yaml"
    content = render_compose(req, svc_path, config.compose_template.external_network)
    runner.write_file(compose_file, content)
    apply_rule(compose_file, "compose_file", is_dir=False)

    return runner.executed
