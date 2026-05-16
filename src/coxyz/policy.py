"""Core policy engine: audit and apply permissions/ACL on services.

The ACL model is deliberately simple and deterministic:

* A path managed by an ACL rule is brought to compliance with a *single*
  ``setfacl --set`` call. That call sets the base entries (``u::``/``g::``/
  ``o::``, i.e. the octal mode) and the named entries in one shot, and lets
  ``setfacl`` recompute the mask as the union of the owning group and every
  named entry. No ``chmod`` ever runs on an ACL-managed path.

This avoids the classic bug where ``chmod`` (run after ``setfacl``) rewrites
the ACL *mask* instead of the group bits, silently shrinking the effective
rights of every named entry.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .config import Config, RuleConfig
from .system import (
    Acl,
    CommandRunner,
    PathState,
    group_exists,
    mode_to_perms,
    normalize_perms,
    perms_to_symbolic,
    read_state,
    union_perms,
    user_exists,
)


class Severity(str, Enum):
    OK = "ok"
    DRIFT = "drift"      # fixable
    WARN = "warn"        # audit-only drift (data/, .env): reported, never touched
    ERROR = "error"      # blocking (missing user, etc.)


# Rules whose missing directories are created automatically. ``data_dir`` is
# created even though it is audit-only, so a new service tree is complete.
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
    """Return True if path matches one of the config's exclude glob patterns."""
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
    return [
        entry.name
        for entry in sorted(config.root_dir.iterdir())
        if entry.is_dir()
        and entry.name in config.categories
        and not is_excluded_path(config, entry)
    ]


def list_services(config: Config, category: str | None = None) -> list[tuple[str, str, Path]]:
    """Return ``[(category, service, path), ...]`` sorted."""
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
    """Resolve a service by ``category/service`` or bare ``service`` (must be unique).

    Raises ValueError if not found or ambiguous.
    """
    if "/" in name:
        cat, svc = name.split("/", 1)
        path = config.root_dir / cat / svc
        if not path.is_dir() or is_excluded_path(config, path):
            raise ValueError(f"Service not found: {cat}/{svc}")
        return cat, svc, path

    matches = [s for s in list_services(config) if s[1] == name]
    if not matches:
        raise ValueError(f"Service not found: {name}")
    if len(matches) > 1:
        locs = ", ".join(f"{c}/{s}" for c, s, _ in matches)
        raise ValueError(f"Ambiguous service '{name}' (found in: {locs}). Use 'category/service'.")
    return matches[0]


# ─── ACL planning ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class NamedAclEntry:
    """A concrete named ACL entry (a principal resolved to a system user/group)."""

    kind: str   # "user" or "group"
    name: str   # system user/group name
    perms: str  # canonical perms, e.g. "rx"

    @property
    def token(self) -> str:
        """The ``setfacl`` token, e.g. ``g:komodo_runner:r-x``."""
        prefix = "g" if self.kind == "group" else "u"
        return f"{prefix}:{self.name}:{perms_to_symbolic(self.perms)}"


def resolve_acl_entries(rule: RuleConfig, config: Config) -> list[NamedAclEntry]:
    """Translate a rule's ACL principals into concrete named ACL entries."""
    entries: list[NamedAclEntry] = []
    for principal_key, perms in (rule.acl or {}).items():
        principal = config.settings.principals[principal_key]
        entries.append(
            NamedAclEntry(kind=principal.kind, name=principal.name,
                          perms=normalize_perms(perms))
        )
    return entries


def desired_acl(rule: RuleConfig, config: Config) -> Acl:
    """The :class:`Acl` an ACL-managed path should end up with."""
    user, group, other = mode_to_perms(rule.mode)
    entries = resolve_acl_entries(rule, config)
    named = {(e.kind, e.name): e.perms for e in entries}
    mask = union_perms(group, *(e.perms for e in entries))
    return Acl(user=user, group=group, other=other,
               named=named, mask=mask, has_default=False)


def acl_set_spec(rule: RuleConfig, config: Config) -> str:
    """Build the ``setfacl --set`` argument for an ACL-managed path.

    The base entries carry the octal mode; the named entries carry the
    per-principal ACL. ``setfacl`` recomputes the mask from these, so every
    named entry stays fully effective.
    """
    user, group, other = mode_to_perms(rule.mode)
    tokens = [
        f"u::{perms_to_symbolic(user)}",
        f"g::{perms_to_symbolic(group)}",
        f"o::{perms_to_symbolic(other)}",
    ]
    tokens += [e.token for e in resolve_acl_entries(rule, config)]
    return ",".join(tokens)


def _acl_applicable(
    rule: RuleConfig, acl_enabled: bool, principals_available: dict[str, bool],
) -> bool:
    """True if the rule's ACL can actually be applied on this host."""
    if not rule.acl or not acl_enabled:
        return False
    return all(principals_available.get(key, False) for key in rule.acl)


def _acl_unavailable_reason(
    rule: RuleConfig, acl_enabled: bool, principals_available: dict[str, bool],
) -> str:
    if not acl_enabled:
        return "ACL unsupported on this filesystem (mode enforced without ACL)"
    missing = [k for k in (rule.acl or {}) if not principals_available.get(k, False)]
    return f"ACL principal(s) not found: {', '.join(missing)} (mode enforced without ACL)"


def _setfacl_set_cmd(path: Path, rule: RuleConfig, config: Config) -> list[str]:
    """One atomic command: drop any default ACL and set the full access ACL."""
    return ["setfacl", "-k", "--set", acl_set_spec(rule, config), str(path)]


def plan_path(
    path: Path,
    rule: RuleConfig,
    owner: str,
    config: Config,
    *,
    is_dir: bool,
    acl_enabled: bool,
    principals_available: dict[str, bool],
) -> list[list[str]]:
    """Commands that bring ``path`` to full compliance with ``rule`` from scratch.

    Used both to scaffold a brand-new path (``create``) and as the fix plan
    for a missing audited path. When an ACL applies, the mode is enforced
    through the ACL base entries; otherwise through ``chmod``.
    """
    commands: list[list[str]] = []
    if is_dir:
        commands.append(["mkdir", "-p", str(path)])

    user, _, group = owner.partition(":")
    if user_exists(user) and group_exists(group):
        commands.append(["chown", owner, str(path)])

    if _acl_applicable(rule, acl_enabled, principals_available):
        commands.append(_setfacl_set_cmd(path, rule, config))
    else:
        commands.append(["chmod", rule.mode, str(path)])
    return commands


# ─── ACL diffing ──────────────────────────────────────────────────────────────

def _fmt_perms(perms: str | None) -> str:
    if perms is None:
        return "(none)"
    return perms_to_symbolic(perms) if perms else "---"


def _diff_acl(actual: Acl, desired: Acl) -> list[str]:
    """Human-readable description of how ``actual`` differs from ``desired``."""
    issues: list[str] = []

    for label, got, want in (
        ("owner", actual.user, desired.user),
        ("group", actual.group, desired.group),
        ("other", actual.other, desired.other),
    ):
        if got != want:
            issues.append(f"{label} perms {_fmt_perms(got)}, expected {_fmt_perms(want)}")

    for (kind, name), want in desired.named.items():
        got = actual.named.get((kind, name))
        if got is None:
            issues.append(f"missing acl entry {kind}:{name}:{_fmt_perms(want)}")
        elif got != want:
            issues.append(
                f"acl entry {kind}:{name} is {_fmt_perms(got)}, expected {_fmt_perms(want)}"
            )
    for kind, name in actual.named:
        if (kind, name) not in desired.named:
            issues.append(f"unexpected acl entry {kind}:{name}")

    if actual.mask != desired.mask:
        issues.append(
            f"acl mask is {_fmt_perms(actual.mask)}, expected {_fmt_perms(desired.mask)} "
            "(a narrow mask silently reduces effective rights)"
        )
    if actual.has_default:
        issues.append("unexpected default acl present")

    return issues


# ─── Auditing ─────────────────────────────────────────────────────────────────

def _expected_owner(config: Config, category: str, rule: RuleConfig) -> str:
    if rule.owner:
        return rule.owner
    return config.category(category).owner_spec


def _should_auto_create_dir(rule_name: str, rule: RuleConfig) -> bool:
    """Return True if a missing path for this rule should be created."""
    if rule_name not in AUTO_CREATE_DIR_RULES:
        return False
    # data_dir is audit-only but still created as part of a complete tree.
    return not rule.audit_only or rule_name == "data_dir"


def _owner_resolution_error(expected_owner: str) -> str | None:
    """Return why ``expected_owner`` cannot be applied, or None if it can."""
    user, _, group = expected_owner.partition(":")
    if not user_exists(user):
        return f"user '{user}' missing"
    if not group_exists(group):
        return f"group '{group}' missing"
    return None


def _audit_owner(
    state: PathState, expected_owner: str,
    issues: list[str], fixes: list[list[str]],
) -> None:
    actual_owner = f"{state.owner}:{state.group}"
    if actual_owner == expected_owner:
        return
    error = _owner_resolution_error(expected_owner)
    if error:
        issues.append(f"owner={actual_owner}, expected {expected_owner} ({error})")
    else:
        issues.append(f"owner={actual_owner}, expected {expected_owner}")
        fixes.append(["chown", expected_owner, str(state.path)])


def _audit_plain_mode(
    state: PathState, rule: RuleConfig,
    issues: list[str], fixes: list[list[str]],
) -> None:
    """Audit a path whose rule defines no ACL: enforce the octal mode only."""
    if state.mode != rule.mode:
        issues.append(f"mode={state.mode}, expected {rule.mode}")
        fixes.append(["chmod", rule.mode, str(state.path)])
    if state.acl is not None and state.acl.is_extended:
        issues.append("unexpected acl entries present")
        fixes.append(["setfacl", "-b", str(state.path)])


def _audit_acl(
    state: PathState, rule: RuleConfig, config: Config,
    issues: list[str], fixes: list[list[str]],
    *, acl_enabled: bool, principals_available: dict[str, bool],
) -> None:
    """Audit a path whose rule defines an ACL."""
    if not _acl_applicable(rule, acl_enabled, principals_available):
        # Cannot manage the ACL here — fall back to enforcing the octal mode.
        issues.append(_acl_unavailable_reason(rule, acl_enabled, principals_available))
        if state.mode != rule.mode:
            issues.append(f"mode={state.mode}, expected {rule.mode}")
            fixes.append(["chmod", rule.mode, str(state.path)])
        return

    if state.acl is None:
        issues.append("could not read acl (getfacl failed)")
    else:
        acl_issues = _diff_acl(state.acl, desired_acl(rule, config))
        if not acl_issues:
            return
        issues.extend(acl_issues)
    # A single setfacl --set fixes the mode, every named entry and the mask.
    fixes.append(_setfacl_set_cmd(state.path, rule, config))


def _audit_path(
    path: Path,
    rule_name: str,
    rule: RuleConfig,
    expected_owner: str,
    config: Config,
    *,
    acl_enabled: bool,
    principals_available: dict[str, bool],
) -> Finding:
    """Audit a single path against a rule; return a Finding with planned fixes."""
    state = read_state(path)

    # ── Missing path ─────────────────────────────────────────────────────────
    if not state.exists:
        if not _should_auto_create_dir(rule_name, rule):
            return Finding(path, rule_name, Severity.ERROR, ["path does not exist"])
        issues = ["path does not exist"]
        error = _owner_resolution_error(expected_owner)
        if error:
            issues.append(f"expected owner {expected_owner} ({error})")
        if rule.acl and not _acl_applicable(rule, acl_enabled, principals_available):
            issues.append(_acl_unavailable_reason(rule, acl_enabled, principals_available))
        fixes = plan_path(
            path, rule, expected_owner, config, is_dir=True,
            acl_enabled=acl_enabled, principals_available=principals_available,
        )
        return Finding(path, rule_name, Severity.DRIFT, issues, fixes)

    # ── Existing path ────────────────────────────────────────────────────────
    issues: list[str] = []
    fixes: list[list[str]] = []

    _audit_owner(state, expected_owner, issues, fixes)
    if rule.acl is None:
        _audit_plain_mode(state, rule, issues, fixes)
    else:
        _audit_acl(state, rule, config, issues, fixes,
                   acl_enabled=acl_enabled, principals_available=principals_available)

    if not issues:
        return Finding(path, rule_name, Severity.OK)
    if rule.audit_only:
        # Audit-only rules are reported but never modified.
        return Finding(path, rule_name, Severity.WARN, issues)
    return Finding(path, rule_name, Severity.DRIFT, issues, fixes)


def audit_service(
    config: Config,
    category: str,
    service: str,
    *,
    acl_enabled: bool,
    principals_available: dict[str, bool],
) -> ServiceReport:
    """Run a full audit of a single service."""
    svc_path = config.root_dir / category / service
    report = ServiceReport(category=category, service=service, path=svc_path)

    def add(path: Path, rule_name: str) -> None:
        if is_excluded_path(config, path):
            return
        rule = config.rule(rule_name)
        report.findings.append(
            _audit_path(
                path, rule_name, rule, _expected_owner(config, category, rule), config,
                acl_enabled=acl_enabled, principals_available=principals_available,
            )
        )

    add(svc_path, "service_dir")

    compose = svc_path / "compose.yaml"
    if compose.exists():
        add(compose, "compose_file")
    elif not is_excluded_path(config, compose):
        report.findings.append(Finding(
            path=compose, rule_name="compose_file", severity=Severity.WARN,
            issues=["compose.yaml not found"],
        ))

    # config/ and data/: only the directory itself, not its contents.
    add(svc_path / "config", "config_dir")
    add(svc_path / "data", "data_dir")

    env_file = svc_path / ".env"
    if env_file.is_file():
        add(env_file, "env_file")

    return report


def audit_category(
    config: Config, category: str,
    *, acl_enabled: bool, principals_available: dict[str, bool],
) -> Finding:
    """Audit the category directory itself."""
    cat_path = config.root_dir / category
    if is_excluded_path(config, cat_path):
        return Finding(path=cat_path, rule_name="category_dir", severity=Severity.OK)
    rule = config.rule("category_dir")
    return _audit_path(
        cat_path, "category_dir", rule, _expected_owner(config, category, rule), config,
        acl_enabled=acl_enabled, principals_available=principals_available,
    )


# ─── Applying ─────────────────────────────────────────────────────────────────

@dataclass
class ApplyResult:
    findings_before: list[Finding]
    commands_run: list[list[str]]
    dry_run: bool


# Command ordering within a single path. mkdir must run first; on the rare
# non-ACL path that also carries a stray ACL, `setfacl -b` must run before
# `chmod` so chmod writes the real group bits rather than the ACL mask.
_FIX_PRIORITY = {"mkdir": 0, "chown": 1, "setfacl": 2, "chmod": 3}


def _order_fixes(fixes: list[list[str]]) -> list[list[str]]:
    return sorted(fixes, key=lambda cmd: _FIX_PRIORITY.get(cmd[0] if cmd else "", 99))


def _normalize_command(cmd: list[str]) -> list[str]:
    if cmd and cmd[0] == "mkdir":
        return ["mkdir", "-p", cmd[-1]]
    return cmd


def _target_path(cmd: list[str]) -> Path | None:
    if not cmd:
        return None
    candidate = cmd[-1]
    return Path(candidate) if candidate.startswith("/") else None


def apply_findings(findings: list[Finding], *, dry_run: bool) -> ApplyResult:
    """Execute the planned fixes for DRIFT findings (WARN/OK/ERROR are skipped)."""
    runner = CommandRunner(dry_run=dry_run)
    created_dirs: set[Path] = set()
    for finding in findings:
        if finding.severity is not Severity.DRIFT:
            continue
        for cmd in _order_fixes(finding.fixes):
            command = _normalize_command(cmd)
            target = _target_path(command)
            if target is not None:
                parent = target.parent
                if parent not in created_dirs and not parent.exists():
                    runner.run(["mkdir", "-p", str(parent)])
                    created_dirs.add(parent)
            if command and command[0] == "mkdir" and target is not None:
                if target in created_dirs:
                    continue
                created_dirs.add(target)
            runner.run(command)
    return ApplyResult(
        findings_before=list(findings),
        commands_run=runner.executed,
        dry_run=dry_run,
    )
