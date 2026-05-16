"""Low-level filesystem and POSIX ACL primitives.

This module is configuration-agnostic: it only deals with paths, octal modes,
ownership and ACL entries. All policy decisions live in ``policy.py``.
"""

from __future__ import annotations

import grp
import pwd
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


# ─── Errors ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CommandExecutionError(RuntimeError):
    """Raised when a shell command exits with a non-zero status."""

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


# ─── Permission helpers ───────────────────────────────────────────────────────

# (letter, bit) pairs in canonical display order.
_RWX: tuple[tuple[str, int], ...] = (("r", 4), ("w", 2), ("x", 1))


def normalize_perms(perms: str) -> str:
    """Canonicalise a permission string to ordered ``rwx`` letters.

    Drops ``-`` placeholders and reorders, so ``"r-x"`` and ``"xr"`` both
    become ``"rx"``.
    """
    present = set(perms)
    return "".join(letter for letter, _ in _RWX if letter in present)


def perms_to_symbolic(perms: str) -> str:
    """Render perms as a fixed 3-char string, e.g. ``"rx"`` -> ``"r-x"``."""
    present = set(perms)
    return "".join(letter if letter in present else "-" for letter, _ in _RWX)


def octal_digit_to_perms(digit: int) -> str:
    """Convert one octal digit (0-7) to canonical perms, e.g. ``5`` -> ``"rx"``."""
    return "".join(letter for letter, bit in _RWX if digit & bit)


def mode_to_perms(mode: str) -> tuple[str, str, str]:
    """Split an octal mode string (e.g. ``"750"``) into (user, group, other) perms."""
    digits = mode.strip()[-3:].zfill(3)
    try:
        return tuple(octal_digit_to_perms(int(d)) for d in digits)  # type: ignore[return-value]
    except ValueError as exc:
        raise ValueError(f"Invalid octal mode: {mode!r}") from exc


def union_perms(*perms: str) -> str:
    """Return the canonical union of several permission strings."""
    merged: set[str] = set()
    for chunk in perms:
        merged.update(chunk)
    return normalize_perms("".join(merged))


# ─── Required binaries ────────────────────────────────────────────────────────

REQUIRED_BINS = ("chmod", "chown", "getfacl", "setfacl")


def check_required_bins() -> list[str]:
    """Return the required binaries that are missing from PATH."""
    return [b for b in REQUIRED_BINS if shutil.which(b) is None]


# ─── User / group lookup ──────────────────────────────────────────────────────

def user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def group_exists(name: str) -> bool:
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


def principal_exists(name: str, kind: str) -> bool:
    """Return True if a user/group principal resolves on this host."""
    if kind == "group":
        return group_exists(name)
    if kind == "user":
        return user_exists(name)
    return False


# ─── ACL model ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Acl:
    """The POSIX access ACL of a path, in canonical form.

    ``named`` maps ``(kind, name)`` -> canonical perms, where ``kind`` is
    ``"user"`` or ``"group"``. ``mask`` is ``None`` when the path carries no
    extended ACL entries (the mask only exists alongside named entries).
    """

    user: str                                       # owner perms  (u::)
    group: str                                      # owning-group perms (g::)
    other: str                                      # other perms  (o::)
    named: dict[tuple[str, str], str] = field(default_factory=dict)
    mask: str | None = None
    has_default: bool = False

    @property
    def is_extended(self) -> bool:
        """True if the ACL holds named entries beyond the base mode."""
        return bool(self.named)


@dataclass(frozen=True)
class PathState:
    """Observed state of a path on disk."""

    path: Path
    exists: bool
    is_dir: bool
    mode: str          # octal, e.g. "750" (group digit is the ACL mask when extended)
    owner: str         # user name (or numeric uid if unresolved)
    group: str         # group name (or numeric gid if unresolved)
    acl: Acl | None    # None only when the path does not exist or getfacl fails


# ─── State observation ───────────────────────────────────────────────────────

def _uid_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _gid_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def read_state(path: Path) -> PathState:
    """Read mode, ownership and ACL of a path."""
    if not path.exists():
        return PathState(
            path=path, exists=False, is_dir=False,
            mode="000", owner="", group="", acl=None,
        )
    st = path.stat()
    return PathState(
        path=path,
        exists=True,
        is_dir=stat.S_ISDIR(st.st_mode),
        mode=oct(st.st_mode & 0o7777)[2:].zfill(3),
        owner=_uid_name(st.st_uid),
        group=_gid_name(st.st_gid),
        acl=read_acl(path),
    )


def read_acl(path: Path) -> Acl | None:
    """Parse the access ACL of ``path`` via getfacl, or None if getfacl fails."""
    try:
        output = subprocess.run(
            ["getfacl", "-pcE", str(path)],  # -p keep names, -c no header, -E no effective
            check=True, capture_output=True, text=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return _parse_getfacl(output)


def _parse_getfacl(output: str) -> Acl:
    """Parse ``getfacl -pcE`` output into an :class:`Acl`."""
    user = group = other = ""
    mask: str | None = None
    named: dict[tuple[str, str], str] = {}
    has_default = False

    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("default:"):
            has_default = True
            continue
        parts = line.split(":")
        if len(parts) != 3:
            continue
        tag, qualifier, perms = parts
        perms = normalize_perms(perms)
        if tag == "user" and not qualifier:
            user = perms
        elif tag == "group" and not qualifier:
            group = perms
        elif tag == "other":
            other = perms
        elif tag == "mask":
            mask = perms
        elif tag in ("user", "group") and qualifier:
            named[(tag, qualifier)] = perms

    return Acl(user=user, group=group, other=other,
               named=named, mask=mask, has_default=has_default)


def detect_acl_support(root_dir: Path) -> bool:
    """Return True if setfacl works on the filesystem hosting ``root_dir``.

    Probes ``root_dir`` first, then falls back to ``/tmp`` when ``root_dir`` is
    absent or not writable (e.g. a read-only command run without root).
    """
    for base in (root_dir, Path("/tmp")):
        if not base.is_dir():
            continue
        try:
            with tempfile.NamedTemporaryFile(
                dir=base, prefix=".coxyz-acl-probe.", delete=False,
            ) as handle:
                probe = Path(handle.name)
        except OSError:
            continue
        try:
            result = subprocess.run(
                ["setfacl", "-m", "u:root:r", str(probe)],
                capture_output=True, text=True,
            )
            return result.returncode == 0
        finally:
            subprocess.run(["setfacl", "-b", str(probe)], capture_output=True)
            probe.unlink(missing_ok=True)
    return False


# ─── Command execution ────────────────────────────────────────────────────────

class CommandRunner:
    """Executes shell commands, recording each one. Supports dry-run."""

    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self.executed: list[list[str]] = []

    def run(self, command: list[str]) -> None:
        """Run a command, raising :class:`CommandExecutionError` on failure."""
        self.executed.append(command)
        if self.dry_run:
            return
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as exc:
            raise CommandExecutionError(
                command=tuple(command),
                returncode=exc.returncode,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
            ) from exc

    def write_file(self, path: Path, content: str) -> None:
        """Write a text file (recorded as a ``write_file`` pseudo-command)."""
        if not self.dry_run:
            path.write_text(content, encoding="utf-8")
        self.executed.append(["write_file", str(path)])
