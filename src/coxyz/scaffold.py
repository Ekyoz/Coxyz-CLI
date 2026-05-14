"""Scaffold a new service directory tree."""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from .config import Config
from .system import (
    CommandRunner,
    acl_entry_for,
    group_exists,
    user_exists,
)

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
    komodo_available: bool,
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

    cat_dir = config.root_dir / req.category
    config_dir = svc_path / "config"
    data_dir = svc_path / "data"
    compose_file = svc_path / "compose.yaml"

    owner = cat.owner_spec
    runner = CommandRunner(dry_run=dry_run)

    def apply_dir(path: Path, rule_name: str) -> None:
        rule = config.rule(rule_name)
        runner.chown(path, owner)
        # ACL first (it can affect the displayed mode via the mask)
        if rule.acl and acl_enabled and komodo_available:
            entry = acl_entry_for(config.komodo.name, config.komodo.kind, rule.acl)
            mask = rule.acl
            runner.setfacl_entry(path, entry, mask)
        # chmod last so the path ends up in the expected mode
        runner.chmod(path, rule.mode)

    def apply_file(path: Path, rule_name: str) -> None:
        rule = config.rule(rule_name)
        runner.chown(path, owner)
        if rule.acl and acl_enabled and komodo_available:
            entry = acl_entry_for(config.komodo.name, config.komodo.kind, rule.acl)
            runner.setfacl_entry(path, entry, rule.acl)
        runner.chmod(path, rule.mode)

    # 1) Category dir (idempotent)
    if not cat_dir.exists():
        runner.mkdir(cat_dir)
    apply_dir(cat_dir, "category_dir")

    # 2) Service dir
    runner.mkdir(svc_path)
    apply_dir(svc_path, "service_dir")

    # 3) config/
    runner.mkdir(config_dir)
    apply_dir(config_dir, "config_dir")

    # 4) data/
    runner.mkdir(data_dir)
    apply_dir(data_dir, "data_dir")

    # 5) compose.yaml
    content = render_compose(req, svc_path, config.compose_template.external_network)
    runner.write_file(compose_file, content)
    apply_file(compose_file, "compose_file")

    return runner.executed
