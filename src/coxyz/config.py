"""Typed configuration loader for coxyz."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Literal

import yaml

PrincipalKind = Literal["group", "user"]
AclPerms = Literal["rx", "rw", "rwx", "x"]


@dataclass(frozen=True)
class PrincipalConfig:
    name: str
    kind: PrincipalKind


@dataclass(frozen=True)
class SettingsConfig:
    principals: dict[str, PrincipalConfig]


@dataclass(frozen=True)
class CategoryConfig:
    user: str
    group: str

    @property
    def owner_spec(self) -> str:
        return f"{self.user}:{self.group}"


@dataclass(frozen=True)
class RuleConfig:
    """Rule applied to a path (directory or file)."""

    mode: str  # octal as string e.g. "750"
    acl: dict[str, AclPerms] | None = None
    owner: str | None = None  # "user:group" override; None = use category owner
    audit_only: bool = False


@dataclass(frozen=True)
class ComposeTemplateConfig:
    default_internal_port: int
    default_timezone: str
    external_network: str


@dataclass(frozen=True)
class Config:
    root_dir: Path
    settings: SettingsConfig
    categories: dict[str, CategoryConfig]
    rules: dict[str, RuleConfig]
    exclude: list[str]
    compose_template: ComposeTemplateConfig

    def category(self, name: str) -> CategoryConfig:
        if name not in self.categories:
            raise KeyError(
                f"Unknown category '{name}'. "
                f"Authorized: {', '.join(sorted(self.categories))}"
            )
        return self.categories[name]

    def rule(self, name: str) -> RuleConfig:
        if name not in self.rules:
            raise KeyError(f"Missing rule '{name}' in config")
        return self.rules[name]


# ─── Loading ────────────────────────────────────────────────────────────

DEFAULT_CONFIG_LOCATIONS: tuple[Path, ...] = (
    Path("/etc/coxyz/config.yaml"),
    Path.home() / ".config" / "coxyz" / "config.yaml",
)


def _load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level YAML must be a mapping")
    return data


def _load_bundled_default() -> dict:
    """Load the default config bundled with the package."""
    resource = files("coxyz").joinpath("default_config.yaml")
    return yaml.safe_load(resource.read_text(encoding="utf-8"))


def _parse_settings(raw: dict) -> SettingsConfig:
    if "settings" in raw:
        settings_raw = raw["settings"]
        principals_raw = settings_raw.get("principals")
        if not isinstance(principals_raw, dict) or not principals_raw:
            raise ValueError("settings.principals must be a non-empty mapping")
        principals: dict[str, PrincipalConfig] = {}
        for key, entry in principals_raw.items():
            if not isinstance(entry, dict):
                raise ValueError(f"settings.principals.{key} must be a mapping")
            name = str(entry["name"])
            kind = entry["kind"]
            if kind not in ("group", "user"):
                raise ValueError(
                    f"settings.principals.{key}.kind must be 'group' or 'user', got {kind!r}"
                )
            principals[str(key)] = PrincipalConfig(name=name, kind=kind)
        return SettingsConfig(principals=principals)

    # Backward-compatible shim for old 'komodo' config
    if "komodo" in raw:
        komodo = raw["komodo"]
        kind = komodo["kind"]
        if kind not in ("group", "user"):
            raise ValueError(f"komodo.kind must be 'group' or 'user', got {kind!r}")
        return SettingsConfig(
            principals={
                "komodo": PrincipalConfig(name=str(komodo["name"]), kind=kind)
            }
        )

    raise ValueError("Missing required key in config: settings (or legacy komodo)")


def _parse_rule_acl(
    acl_raw: object,
    settings: SettingsConfig,
    rule_name: str,
) -> dict[str, AclPerms] | None:
    if acl_raw is None:
        return None
    if isinstance(acl_raw, str):
        if "komodo" not in settings.principals:
            raise ValueError(f"rules.{rule_name}.acl uses legacy string but no 'komodo' principal")
        return {"komodo": acl_raw}
    if not isinstance(acl_raw, dict):
        raise ValueError(f"rules.{rule_name}.acl must be a mapping or null")

    acl: dict[str, AclPerms] = {}
    for principal_name, perms in acl_raw.items():
        if principal_name not in settings.principals:
            raise ValueError(
                f"rules.{rule_name}.acl references unknown principal '{principal_name}'"
            )
        if perms is None:
            raise ValueError(
                f"rules.{rule_name}.acl.{principal_name} must be a permission string"
            )
        acl[str(principal_name)] = str(perms)
    return acl


def _parse_config(raw: dict) -> Config:
    try:
        settings = _parse_settings(raw)

        categories = {
            name: CategoryConfig(user=str(c["user"]), group=str(c["group"]))
            for name, c in raw["categories"].items()
        }

        rules: dict[str, RuleConfig] = {}
        for name, r in raw["rules"].items():
            rules[name] = RuleConfig(
                mode=str(r["mode"]),
                acl=_parse_rule_acl(r.get("acl"), settings, name),
                owner=r.get("owner"),
                audit_only=bool(r.get("audit_only", False)),
            )

        ct = raw["compose_template"]
        compose_template = ComposeTemplateConfig(
            default_internal_port=int(ct["default_internal_port"]),
            default_timezone=str(ct["default_timezone"]),
            external_network=str(ct["external_network"]),
        )

        exclude_raw = raw.get("exclude", [])
        if not isinstance(exclude_raw, list):
            raise ValueError("exclude must be a list of glob patterns")

        return Config(
            root_dir=Path(raw["root_dir"]),
            settings=settings,
            categories=categories,
            rules=rules,
            exclude=[str(p) for p in exclude_raw],
            compose_template=compose_template,
        )
    except KeyError as e:
        raise ValueError(f"Missing required key in config: {e}") from e


def find_config_path(explicit: Path | None = None) -> Path | None:
    """Return the first existing config path, or None if only the bundled default is used."""
    if explicit is not None:
        if not explicit.is_file():
            raise FileNotFoundError(f"Config not found: {explicit}")
        return explicit
    for candidate in DEFAULT_CONFIG_LOCATIONS:
        if candidate.is_file():
            return candidate
    return None


def load_config(explicit: Path | None = None) -> tuple[Config, Path | None]:
    """Load config; returns (config, source_path). source_path is None if using bundled defaults."""
    source = find_config_path(explicit)
    raw = _load_yaml(source) if source is not None else _load_bundled_default()
    return _parse_config(raw), source
