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
    app_id: str = ""  # what the command needs: the snap name or the flatpak application id


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
            SandboxedApp(
                parts[0], parts[1], "snap", source, _snap_size(parts[0], parts[2], folder), parts[0]
            )
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
            SandboxedApp(
                name or application, version, "flatpak", origin, _flatpak_size(size), application
            )
        )
    return apps[:MAX_APPS]


_SNAP_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_FLATPAK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
# snaps that other snaps are built on: removing one can break apps that look unrelated
_SHARED_SNAP = re.compile(r"^(?:gnome-|gtk-|mesa-|kf\d|qt\d|core\d|ffmpeg-|bare$)")


def update_command(app: SandboxedApp) -> str | None:
    """The command to update this app; Ganki never runs it. None if the name looks odd."""
    if app.tool == "snap" and _SNAP_NAME.match(app.app_id):
        return f"sudo snap refresh {app.app_id}"
    if app.tool == "flatpak" and _FLATPAK_ID.match(app.app_id):
        return f"flatpak update {app.app_id}"
    return None


def remove_command(app: SandboxedApp) -> str | None:
    if app.tool == "snap" and _SNAP_NAME.match(app.app_id):
        return f"sudo snap remove {app.app_id}"
    if app.tool == "flatpak" and _FLATPAK_ID.match(app.app_id):
        return f"flatpak uninstall {app.app_id}"
    return None


def is_shared_runtime(app: SandboxedApp) -> bool:
    return app.tool == "snap" and bool(_SHARED_SNAP.match(app.app_id))


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
