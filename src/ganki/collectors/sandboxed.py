"""Apps installed with snap or flatpak (read-only).

Only the list of what is installed. These apps carry their own libraries inside, so the
Ubuntu list does not describe them; Ganki says so instead of pretending to check them.
"""

from __future__ import annotations

import logging
import subprocess  # noqa: S404  (only to catch the errors that runner.run raises)
from dataclasses import dataclass
from pathlib import Path

from ganki.runner import FLATPAK, SNAP, run

log = logging.getLogger(__name__)

MAX_APPS = 2000
_SNAP_SYSTEM_NOTES = ("base", "snapd")  # runtimes and the snap system itself, not apps


@dataclass(frozen=True)
class SandboxedApp:
    name: str
    version: str
    tool: str  # snap or flatpak
    source: str  # who publishes it (snap) or the remote it came from (flatpak)
    size: str = ""  # as flatpak reports it, e.g. "245.1 MB"; empty for snap


def parse_snap(output: str) -> list[SandboxedApp]:
    """``snap list`` -> the apps (not the runtimes). The first line is the header."""
    apps = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        notes = parts[5] if len(parts) > 5 else ""
        if any(word in notes.split(",") for word in _SNAP_SYSTEM_NOTES):
            continue
        apps.append(SandboxedApp(parts[0], parts[1], "snap", parts[4].rstrip("*✓✪")))
    return apps[:MAX_APPS]


def parse_flatpak(output: str) -> list[SandboxedApp]:
    """``flatpak list --app --columns=application,name,version,origin,size`` (tab separated)."""
    apps = []
    for line in output.splitlines():
        parts = [part.strip() for part in line.split("\t")]
        if len(parts) < 5 or not parts[0]:
            continue
        application, name, version, origin, size = parts[:5]
        apps.append(SandboxedApp(name or application, version, "flatpak", origin, size))
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
