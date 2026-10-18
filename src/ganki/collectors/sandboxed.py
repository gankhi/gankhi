"""Apps installed with snap or flatpak (read-only).

Only the list of what is installed. These apps carry their own libraries inside, so the
Ubuntu list does not describe them; Ganki says so instead of pretending to check them.
"""

from __future__ import annotations

import logging
import re
import subprocess  # noqa: S404  (only to catch the errors that runner.run raises)
from dataclasses import dataclass
from pathlib import Path

from ganki.runner import FLATPAK, SNAP, run

log = logging.getLogger(__name__)

MAX_APPS = 2000
SNAP_FOLDER = Path("/var/lib/snapd/snaps")  # one <name>_<revision>.snap file per installed app
_UNITS = {"b": 1, "bytes": 1, "kb": 1000, "mb": 1000**2, "gb": 1000**3, "tb": 1000**4}
_SNAP_SYSTEM_NOTES = ("base", "snapd")  # runtimes and the snap system itself, not apps


@dataclass(frozen=True)
class SandboxedApp:
    name: str
    version: str
    tool: str  # snap or flatpak
    source: str  # who publishes it (snap) or the remote it came from (flatpak)
    size_kib: int | None = None  # what it takes on disk; None when it cannot be known


def _snap_size(name: str, revision: str, folder: Path) -> int | None:
    """Size of the app's package file, which is what snap keeps on disk for it."""
    try:
        return (folder / f"{name}_{revision}.snap").stat().st_size // 1024
    except OSError:
        return None


def _flatpak_size(text: str) -> int | None:
    """``245.1 MB`` (flatpak counts in thousands) -> KiB."""
    match = re.match(r"^\s*([\d.,]+)\s*([A-Za-z]+)\s*$", text.replace("\u00a0", " "))
    unit = _UNITS.get(match.group(2).lower()) if match else None
    if match is None or unit is None:
        return None
    try:
        return int(float(match.group(1).replace(",", ".")) * unit) // 1024
    except ValueError:
        return None


def parse_snap(output: str, folder: Path = SNAP_FOLDER) -> list[SandboxedApp]:
    """``snap list`` -> the apps (not the runtimes). The first line is the header."""
    apps = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        notes = parts[5] if len(parts) > 5 else ""
        if any(word in notes.split(",") for word in _SNAP_SYSTEM_NOTES):
            continue
        source = parts[4].rstrip("*✓✪")
        apps.append(
            SandboxedApp(parts[0], parts[1], "snap", source, _snap_size(parts[0], parts[2], folder))
        )
    return apps[:MAX_APPS]


def parse_flatpak(output: str) -> list[SandboxedApp]:
    """``flatpak list --app --columns=application,name,version,origin,size`` (tab separated)."""
    apps = []
    for line in output.splitlines():
        parts = [part.strip() for part in line.split("\t")]
        if len(parts) < 5 or not parts[0]:
            continue
        application, name, version, origin, size = parts[:5]
        apps.append(
            SandboxedApp(name or application, version, "flatpak", origin, _flatpak_size(size))
        )
    return apps[:MAX_APPS]


def collect_sandboxed() -> list[SandboxedApp]:
    found: list[SandboxedApp] = []
    jobs = (
        (SNAP, ["list"], parse_snap),
        (
            FLATPAK,
            ["list", "--app", "--columns=application,name,version,origin,size"],
            parse_flatpak,
        ),
    )
    for command, arguments, parse in jobs:
        if not Path(command).is_file():
            continue
        try:
            found += parse(run([command, *arguments], timeout=60))
        except (OSError, subprocess.SubprocessError):
            log.info("%s could not list its apps", command, exc_info=True)
    return found
