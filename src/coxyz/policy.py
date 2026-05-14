"""Core policy engine: audit and apply permissions/ACL on services."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .config import Config, RuleConfig
from .system import (
    CommandRunner,
    PathState,
    acl_entry_for,
    has_any_default_acl,
    has_komodo_entry,
    komodo_principal_exists,
    read_state,
    user_exists,
    group_exists,
)


class Severity(str, Enum):
    OK = "ok"
    DRIFT = "drift"          # fixable
    WARN = "warn"            # audit-only drift (data/, .env)
    ERROR = "error"          # blocking (missing user, etc.)


@dataclass
class Finding:
    path: Path
    rule_name: str
    severity: Severity
    issues: list[str] = field(default_factory=list)
    fixes: list[list[str]] = field(default_factory=list)  # planned commands

    @property
    def is_compliant(self) -> bool:
        return self.severity is Severity.OK


@dataclass
class ServiceReport:
    category: str
    service: str
    path: Path
    findings: list[Finding] = field(default_factory=list)

    @property
    def compliant(self) -> bool:
        return all(f.is_compliant for f in self.findings)

    @property
    def drift_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.DRIFT)

    @property
    def warn_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.WARN)


# ─── Path discovery ───────────────────────────────────────────────────────────

def list_categories(config: Config) -> list[str]:
    """Return existing categories on disk (filtered by config)."""
    if not config.root_dir.is_dir():
        return []
    found: list[str] = []
    for entry in sorted(config.root_dir.iterdir()):
        if entry.is_dir() and entry.name in config.categories:
            found.append(entry.name)
    return found


def list_services(config: Config, category: str | None = None) -> list[tuple[str, str, Path]]:
    """Return [(category, service, path), ...] sorted."""
    out: list[tuple[str, str, Path]] = []
    categories = [category] if category else list_categories(config)
    for cat in categories:
        cat_dir = config.root_dir / cat
        if not cat_dir.is_dir():
            continue
        for entry in sorted(cat_dir.iterdir()):
            if entry.is_dir():
                out.append((cat, entry.name, entry))
    return out


def resolve_service(config: Config, name: str) -> tuple[str, str, Path]:
    """Resolve a service by 'category/service' or just 'service' (must be unique).

    Raises ValueError if not found or ambiguous.
    """
    if "/" in name:
        cat, svc = name.split("/", 1)
        path = config.root_dir / cat / svc
        if not path.is_dir():
            raise ValueError(f"Service not found: {cat}/{svc}")
        return cat, svc, path

    matches = [s for s in list_services(config) if s[1] == name]
    if not matches:
        raise ValueError(f"Service not found: {name}")
    if len(matches) > 1:
        locs = ", ".join(f"{c}/{s}" for c, s, _ in matches)
        raise ValueError(f"Ambiguous service '{name}' (found in: {locs}). Use 'category/service'.")
    return matches[0]


# ─── Auditing ─────────────────────────────────────────────────────────────────

def _expected_owner(config: Config, category: str, rule: RuleConfig) -> str:
    if rule.owner:
        return rule.owner
    cat = config.category(category)
    return cat.owner_spec


def _audit_path(
    path: Path,
    rule_name: str,
    rule: RuleConfig,
    expected_owner: str,
    config: Config,
    *,
    acl_enabled: bool,
    komodo_available: bool,
) -> Finding:
    """Audit a single path against a rule, return a Finding (with planned fixes)."""
    state = read_state(path)
    issues: list[str] = []
    fixes: list[list[str]] = []

    if not state.exists:
        return Finding(
            path=path, rule_name=rule_name, severity=Severity.ERROR,
            issues=[f"path does not exist"], fixes=[],
        )

    # Mode check
    if state.mode != rule.mode:
        issues.append(f"mode={state.mode}, expected {rule.mode}")
        fixes.append(["chmod", rule.mode, str(path)])

    # Owner check
    actual_owner = f"{state.owner}:{state.group}"
    if actual_owner != expected_owner:
        # Verify expected user/group exist before scheduling chown
        u, g = expected_owner.split(":", 1)
        if not user_exists(u):
            issues.append(f"owner={actual_owner}, expected {expected_owner} (user '{u}' missing)")
        elif not group_exists(g):
            issues.append(f"owner={actual_owner}, expected {expected_owner} (group '{g}' missing)")
        else:
            issues.append(f"owner={actual_owner}, expected {expected_owner}")
            fixes.append(["chown", expected_owner, str(path)])

    # ACL check
    if rule.acl is not None:
        if not acl_enabled:
            issues.append(f"acl missing ({rule.acl}); ACL support disabled on filesystem")
        elif not komodo_available:
            issues.append(f"acl missing ({rule.acl}); komodo principal not found")
        elif not has_komodo_entry(state, config.komodo.name, config.komodo.kind, rule.acl):
            entry = acl_entry_for(config.komodo.name, config.komodo.kind, rule.acl)
            issues.append(f"acl missing or wrong: expected {entry}")
            mask = "rx" if (rule.acl == "x" and state.is_dir) else rule.acl.replace("-", "")
            if has_any_default_acl(state):
                fixes.append(["setfacl", "-k", str(path)])
            fixes.append(["setfacl", "-m", entry, str(path)])
            fixes.append(["setfacl", "-m", f"m:{mask}", str(path)])
    else:
        # acl is None → verify there is NO extended komodo ACL
        if any(
            e.startswith((f"user:{config.komodo.name}:", f"group:{config.komodo.name}:"))
            for e in state.acl_entries
        ):
            issues.append(f"unexpected acl entry for {config.komodo.name}")
            # We do not auto-fix removal in audit_only mode; only flag.
            if not rule.audit_only:
                fixes.append(["setfacl", "-x",
                              f"{'g' if config.komodo.kind == 'group' else 'u'}:{config.komodo.name}",
                              str(path)])

    if not issues:
        return Finding(path=path, rule_name=rule_name, severity=Severity.OK)
    severity = Severity.WARN if rule.audit_only else Severity.DRIFT
    return Finding(path=path, rule_name=rule_name, severity=severity, issues=issues, fixes=fixes)


def audit_service(
    config: Config,
    category: str,
    service: str,
    *,
    acl_enabled: bool,
    komodo_available: bool,
) -> ServiceReport:
    """Run full audit of a single service."""
    svc_path = config.root_dir / category / service
    report = ServiceReport(category=category, service=service, path=svc_path)

    def add(path: Path, rule_name: str) -> None:
        rule = config.rule(rule_name)
        owner = _expected_owner(config, category, rule)
        report.findings.append(
            _audit_path(
                path, rule_name, rule, owner, config,
                acl_enabled=acl_enabled, komodo_available=komodo_available,
            )
        )

    # Service dir
    add(svc_path, "service_dir")

    # compose.yaml
    compose = svc_path / "compose.yaml"
    if compose.exists():
        add(compose, "compose_file")
    else:
        report.findings.append(Finding(
            path=compose, rule_name="compose_file", severity=Severity.WARN,
            issues=["compose.yaml not found"],
        ))

    # config/ dir — only the directory itself, not its contents
    config_dir = svc_path / "config"
    if config_dir.is_dir():
        add(config_dir, "config_dir")

    # data/ dir — only the directory itself, not its contents (audit only)
    data_dir = svc_path / "data"
    if data_dir.is_dir():
        add(data_dir, "data_dir")

    # .env file (audit only)
    env_file = svc_path / ".env"
    if env_file.is_file():
        add(env_file, "env_file")

    return report


def audit_category(
    config: Config, category: str,
    *, acl_enabled: bool, komodo_available: bool,
) -> Finding:
    """Audit the category directory itself."""
    rule = config.rule("category_dir")
    owner = _expected_owner(config, category, rule)
    return _audit_path(
        config.root_dir / category, "category_dir", rule, owner, config,
        acl_enabled=acl_enabled, komodo_available=komodo_available,
    )


# ─── Applying ─────────────────────────────────────────────────────────────────

@dataclass
class ApplyResult:
    findings_before: list[Finding]
    commands_run: list[list[str]]
    dry_run: bool


def _order_fixes(fixes: list[list[str]]) -> list[list[str]]:
    """Order fixes per path so chmod runs LAST.

    setfacl -m m:<mask> can widen the displayed group-mode bits (e.g. 750 → 770),
    so chmod must come after any setfacl call to leave the path in the expected
    mode.
    """
    def priority(cmd: list[str]) -> int:
        if not cmd:
            return 99
        if cmd[0] == "chown":
            return 0
        if cmd[0] == "setfacl":
            return 1
        if cmd[0] == "chmod":
            return 2
        return 3

    return sorted(fixes, key=priority)


def apply_findings(findings: list[Finding], *, dry_run: bool) -> ApplyResult:
    """Execute the planned fixes for non-OK, non-WARN findings."""
    runner = CommandRunner(dry_run=dry_run)
    for finding in findings:
        if finding.severity is Severity.DRIFT:
            for cmd in _order_fixes(finding.fixes):
                runner.run(cmd)
    return ApplyResult(
        findings_before=list(findings),
        commands_run=runner.executed,
        dry_run=dry_run,
    )
