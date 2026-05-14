"""Low-level filesystem and ACL operations."""

from __future__ import annotations

import grp
import pwd
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PathState:
    """Observable state of a path on disk."""

    path: Path
    exists: bool
    is_dir: bool
    mode: str  # octal as string e.g. "750"
    owner: str  # user name
    group: str  # group name
    acl_entries: tuple[str, ...]  # raw extended ACL entries (excluding base)


# ─── Binary discovery ────────────────────────────────────────────────────────

REQUIRED_BINS = ("chmod", "chown", "getfacl", "setfacl", "getent")


def check_required_bins() -> list[str]:
    """Return list of missing required binaries."""
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


# ─── State observation ───────────────────────────────────────────────────────

def read_state(path: Path) -> PathState:
    """Read the current state of a path."""
    if not path.exists():
        return PathState(
            path=path, exists=False, is_dir=False,
            mode="000", owner="", group="", acl_entries=(),
        )
    st = path.stat()
    mode = oct(st.st_mode & 0o7777)[2:].zfill(3)
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return PathState(
        path=path,
        exists=True,
        is_dir=stat.S_ISDIR(st.st_mode),
        mode=mode,
        owner=owner,
        group=group,
        acl_entries=_read_extended_acl(path),
    )


def _read_extended_acl(path: Path) -> tuple[str, ...]:
    """Return only the extended ACL entries (user:NAME, group:NAME, mask, default:*)."""
    try:
        out = subprocess.run(
            ["getfacl", "-pE", str(path)],
            check=True, capture_output=True, text=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ()
    entries: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Keep only named user/group entries, masks, and defaults
        if (
            (line.startswith(("user:", "group:")) and not line.startswith(("user::", "group::")))
            or line.startswith("mask::")
            or line.startswith("default:")
        ):
            entries.append(line)
    return tuple(entries)


# ─── ACL helpers ─────────────────────────────────────────────────────────────

def detect_acl_support(root_dir: Path) -> bool:
    """Test if setfacl works on a sample path under root_dir (or /tmp)."""
    base = root_dir if root_dir.is_dir() else Path("/tmp")
    with tempfile.NamedTemporaryFile(dir=base, prefix=".coxyzacltest.", delete=False) as f:
        tmp = Path(f.name)
    try:
        r = subprocess.run(
            ["setfacl", "-m", "u:root:r", str(tmp)],
            capture_output=True, text=True,
        )
        return r.returncode == 0
    finally:
        subprocess.run(["setfacl", "-b", str(tmp)], capture_output=True)
        tmp.unlink(missing_ok=True)


def komodo_principal_exists(name: str, kind: str) -> bool:
    if kind == "group":
        return group_exists(name)
    if kind == "user":
        return user_exists(name)
    return False


def acl_entry_for(name: str, kind: str, perms: str) -> str:
    """Build a setfacl -m argument like 'g:komodo_runner:rx'."""
    prefix = "g" if kind == "group" else "u"
    # Normalize perms: remove dashes
    norm = perms.replace("-", "")
    return f"{prefix}:{name}:{norm}"


def has_komodo_entry(state: PathState, name: str, kind: str, perms: str) -> bool:
    """Check if state already has the expected komodo entry."""
    prefix = "group" if kind == "group" else "user"
    norm = perms.replace("-", "")
    needle = f"{prefix}:{name}:"
    for entry in state.acl_entries:
        if entry.startswith(needle):
            # Strip "#effective:..." comments
            actual = entry[len(needle):].split("\t")[0].split("#")[0].strip()
            if set(actual.replace("-", "")) == set(norm):
                return True
            return False
    return False


def has_any_default_acl(state: PathState) -> bool:
    return any(e.startswith("default:") for e in state.acl_entries)


# ─── Mutating operations ─────────────────────────────────────────────────────

class CommandRunner:
    """Runs shell commands; supports dry-run."""

    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self.executed: list[list[str]] = []

    def run(self, args: list[str]) -> None:
        self.executed.append(args)
        if self.dry_run:
            return
        subprocess.run(args, check=True, capture_output=True, text=True)

    def chmod(self, path: Path, mode: str) -> None:
        self.run(["chmod", mode, str(path)])

    def chown(self, path: Path, owner_spec: str) -> None:
        self.run(["chown", owner_spec, str(path)])

    def setfacl_remove_default(self, path: Path) -> None:
        self.run(["setfacl", "-k", str(path)])

    def setfacl_entry(self, path: Path, entry: str, mask_perms: str) -> None:
        self.run(["setfacl", "-m", entry, str(path)])
        self.run(["setfacl", "-m", f"m:{mask_perms}", str(path)])

    def mkdir(self, path: Path) -> None:
        self.run(["mkdir", "-p", str(path)])

    def write_file(self, path: Path, content: str) -> None:
        if self.dry_run:
            self.executed.append(["write_file", str(path)])
            return
        path.write_text(content, encoding="utf-8")
        self.executed.append(["write_file", str(path)])
