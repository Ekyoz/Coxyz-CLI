"""Core policy engine: audit and apply permissions/ACL on services."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .config import Config, RuleConfig
from .system import (
    CommandRunner,
    PathState,
    acl_entry_for,
    has_any_default_acl,
    has_principal_entry,
    read_state,
    user_exists,
    group_exists,
)


class Severity(str, Enum):
    OK = "ok"
    DRIFT = "drift"          # fixable
    WARN = "warn"            # audit-only drift (data/, .env)
    ERROR = "error"          # blocking (missing user, etc.)


AUTO_CREATE_DIR_RULES = {"category_dir", "service_dir", "config_dir", "data_dir"}


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

def _relative_to_root(config: Config, path: Path) -> str:
    try:
        return path.resolve().relative_to(config.root_dir.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def is_excluded_path(config: Config, path: Path) -> bool:
    """Return True if path matches one of config exclude glob patterns."""
    rel = _relative_to_root(config, path)
    abs_path = path.as_posix()

    for pattern in config.exclude:
        pat = pattern.strip()
        if not pat:
            continue
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(abs_path, pat):
            return True
        if pat.endswith("/"):
            dir_pat = pat.rstrip("/")
            for candidate in [path, *path.parents]:
                crel = _relative_to_root(config, candidate)
                cabs = candidate.as_posix()
                if fnmatch.fnmatch(crel, dir_pat) or fnmatch.fnmatch(cabs, dir_pat):
                    return True
    return False


def list_categories(config: Config) -> list[str]:
    """Return existing categories on disk (filtered by config)."""
    if not config.root_dir.is_dir():
        return []
    found: list[str] = []
    for entry in sorted(config.root_dir.iterdir()):
        if entry.is_dir() and entry.name in config.categories and not is_excluded_path(config, entry):
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
            if entry.is_dir() and not is_excluded_path(config, entry):
                out.append((cat, entry.name, entry))
    return out


def resolve_service(config: Config, name: str) -> tuple[str, str, Path]:
    """Resolve a service by 'category/service' or just 'service' (must be unique).

    Raises ValueError if not found or ambiguous.
    """
    if "/" in name:
        cat, svc = name.split("/", 1)
        path = config.root_dir / cat / svc
        if not path.is_dir() or is_excluded_path(config, path):
            raise ValueError(f"Service not found: {cat}/{svc}")
        return cat, svc, path

    matches = [s for s in list_services(config) if s[1] == name and not is_excluded_path(config, s[2])]
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


def _acl_mask_for_rule_acl(acl: str, *, is_dir: bool) -> str:
    if acl == "x" and is_dir:
        return "rx"
    return acl.replace("-", "")


def _acl_mask_for_rule(rule_acl: dict[str, str], *, is_dir: bool) -> str:
    perms: set[str] = set()
    for acl in rule_acl.values():
        perms.update(_acl_mask_for_rule_acl(acl, is_dir=is_dir))
    return "".join(c for c in "rwx" if c in perms)


def _audit_path(
    path: Path,
    rule_name: str,
    rule: RuleConfig,
    expected_owner: str,
    config: Config,
    *,
    acl_enabled: bool,
    principal_available: dict[str, bool],
) -> Finding:
    """Audit a single path against a rule, return a Finding (with planned fixes)."""
    state = read_state(path)
    issues: list[str] = []
    fixes: list[list[str]] = []

    if not state.exists:
        if rule_name in AUTO_CREATE_DIR_RULES:
            issues.append("path does not exist")
            fixes.append(["mkdir", "-p", str(path)])

            u, g = expected_owner.split(":", 1)
            if not user_exists(u):
                issues.append(f"owner expected {expected_owner} (user '{u}' missing)")
            elif not group_exists(g):
                issues.append(f"owner expected {expected_owner} (group '{g}' missing)")
            else:
                fixes.append(["chown", expected_owner, str(path)])

            if rule.acl is not None:
                if not acl_enabled:
                    issues.append(f"acl missing ({rule.acl}); ACL support disabled on filesystem")
                else:
                    missing = [
                        name for name in rule.acl
                        if not principal_available.get(name, False)
                    ]
                    if missing:
                        issues.append(
                            f"acl missing ({rule.acl}); principal(s) not found: {', '.join(missing)}"
                        )
                    else:
                        mask = _acl_mask_for_rule(rule.acl, is_dir=True)
                        for principal_name, perms in rule.acl.items():
                            principal = config.settings.principals[principal_name]
                            entry = acl_entry_for(principal.name, principal.kind, perms)
                            fixes.append(["setfacl", "-m", entry, str(path)])
                        fixes.append(["setfacl", "-m", f"m:{mask}", str(path)])

            fixes.append(["chmod", rule.mode, str(path)])
            return Finding(
                path=path,
                rule_name=rule_name,
                severity=Severity.DRIFT,
                issues=issues,
                fixes=fixes,
            )
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
        else:
            missing = [
                name for name in rule.acl
                if not principal_available.get(name, False)
            ]
            if missing:
                issues.append(
                    f"acl missing ({rule.acl}); principal(s) not found: {', '.join(missing)}"
                )
            else:
                mask = _acl_mask_for_rule(rule.acl, is_dir=state.is_dir)
                need_default_cleanup = has_any_default_acl(state)
                for principal_name, perms in rule.acl.items():
                    principal = config.settings.principals[principal_name]
                    if not has_principal_entry(state, principal.name, principal.kind, perms):
                        entry = acl_entry_for(principal.name, principal.kind, perms)
                        issues.append(f"acl missing or wrong: expected {entry}")
                        if need_default_cleanup:
                            fixes.append(["setfacl", "-k", str(path)])
                            need_default_cleanup = False
                        fixes.append(["setfacl", "-m", entry, str(path)])
                if any("setfacl" in cmd for cmd in fixes):
                    fixes.append(["setfacl", "-m", f"m:{mask}", str(path)])
    else:
        # acl is None → verify there is NO extended ACL
        if state.acl_entries:
            issues.append("unexpected acl entries present")
            # We do not auto-fix removal in audit_only mode; only flag.
            if not rule.audit_only:
                fixes.append(["setfacl", "-b", str(path)])

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
    principal_available: dict[str, bool],
) -> ServiceReport:
    """Run full audit of a single service."""
    svc_path = config.root_dir / category / service
    report = ServiceReport(category=category, service=service, path=svc_path)

    def add(path: Path, rule_name: str) -> None:
        if is_excluded_path(config, path):
            return
        rule = config.rule(rule_name)
        owner = _expected_owner(config, category, rule)
        report.findings.append(
            _audit_path(
                path, rule_name, rule, owner, config,
                acl_enabled=acl_enabled, principal_available=principal_available,
            )
        )

    # Service dir
    add(svc_path, "service_dir")

    # compose.yaml
    compose = svc_path / "compose.yaml"
    if compose.exists():
        add(compose, "compose_file")
    elif not is_excluded_path(config, compose):
        report.findings.append(Finding(
            path=compose, rule_name="compose_file", severity=Severity.WARN,
            issues=["compose.yaml not found"],
        ))

    # config/ dir — only the directory itself, not its contents
    config_dir = svc_path / "config"
    add(config_dir, "config_dir")

    # data/ dir — only the directory itself, not its contents (audit only)
    data_dir = svc_path / "data"
    add(data_dir, "data_dir")

    # .env file (audit only)
    env_file = svc_path / ".env"
    if env_file.is_file():
        add(env_file, "env_file")

    return report


def audit_category(
    config: Config, category: str,
    *, acl_enabled: bool, principal_available: dict[str, bool],
) -> Finding:
    """Audit the category directory itself."""
    cat_path = config.root_dir / category
    if is_excluded_path(config, cat_path):
        return Finding(path=cat_path, rule_name="category_dir", severity=Severity.OK)
    rule = config.rule("category_dir")
    owner = _expected_owner(config, category, rule)
    return _audit_path(
        cat_path, "category_dir", rule, owner, config,
        acl_enabled=acl_enabled, principal_available=principal_available,
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
        if cmd[0] == "mkdir":
            return -1
        if cmd[0] == "chown":
            return 0
        if cmd[0] == "setfacl":
            return 1
        if cmd[0] == "chmod":
            return 2
        return 3

    return sorted(fixes, key=priority)


def _target_path(cmd: list[str]) -> Path | None:
    if not cmd:
        return None
    candidate = cmd[-1]
    if not candidate.startswith("/"):
        return None
    return Path(candidate)


def _normalize_command(cmd: list[str]) -> list[str]:
    if cmd and cmd[0] == "mkdir":
        return ["mkdir", "-p", cmd[-1]]
    return cmd


def apply_findings(findings: list[Finding], *, dry_run: bool) -> ApplyResult:
    """Execute the planned fixes for non-OK, non-WARN findings."""
    runner = CommandRunner(dry_run=dry_run)
    created_dirs: set[Path] = set()
    for finding in findings:
        if finding.severity is Severity.DRIFT:
            for cmd in _order_fixes(finding.fixes):
                normalized_cmd = _normalize_command(cmd)
                target = _target_path(normalized_cmd)
                if target is not None:
                    parent = target.parent
                    if parent not in created_dirs and not parent.exists():
                        runner.run(["mkdir", "-p", str(parent)])
                        created_dirs.add(parent)
                if normalized_cmd and normalized_cmd[0] == "mkdir" and target is not None:
                    if target in created_dirs:
                        continue
                    created_dirs.add(target)
                runner.run(normalized_cmd)
    return ApplyResult(
        findings_before=list(findings),
        commands_run=runner.executed,
        dry_run=dry_run,
    )
