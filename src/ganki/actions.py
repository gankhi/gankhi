"""Preview what an update or a removal would do. Nothing here changes the system.

Every preview is a *simulation* (``apt-get -s``). The person copies the real command
and runs it themselves; Ganki does not run it. See ``runner.py`` for what is allowed.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from ganki.runner import APT_GET, run, valid_package

UPDATE, REMOVE, UPDATE_ALL, CLEAN = "update", "remove", "all", "clean"
ACTIONS = (UPDATE, REMOVE, UPDATE_ALL, CLEAN)

# A private temporary file: it is emptied by the system, so copies never pile up in the home.
SNAPSHOT_COMMAND = 'dpkg --get-selections > "$(mktemp -t ganki-programas.XXXXXX)"'

_INSTALL_LINE = re.compile(r"^Inst\s+(\S+)(?:\s+\[([^\]]+)\])?\s+\((\S+)")
_REMOVE_LINE = re.compile(r"^Remv\s+(\S+)")
_DOWNLOAD = re.compile(r"Need to get ([\d.,]+) ([kMG]?B)")
_DISK_USED = re.compile(r"After this operation, ([\d.,]+) ([kMG]?B) of additional disk space")
_DISK_FREED = re.compile(r"After this operation, ([\d.,]+) ([kMG]?B) disk space will be freed")
_UNITS = {"B": 1, "kB": 1000, "MB": 1000**2, "GB": 1000**3}

# Programs that usually look after data of their own (databases, containers, servers).
_HOLDS_DATA = re.compile(
    r"^(mysql|mariadb|postgresql|redis|mongodb|docker|containerd|podman|nginx|apache2|libvirt)"
)
BIG_DOWNLOAD_BYTES = 1_000_000_000

Simulator = Callable[[str, str, bool], str]  # (action, package, want_download_sizes)


@dataclass(frozen=True)
class Preview:
    action: str
    package: str  # empty for UPDATE_ALL
    upgrades: list[str] = field(default_factory=list)  # packages that are already installed
    installs: list[str] = field(default_factory=list)  # packages that are new
    removals: list[str] = field(default_factory=list)
    download_bytes: int = 0
    # positive: uses more space, negative: frees space, None: apt does not say (simulations
    # of updates do not print it)
    disk_change_bytes: int | None = None
    blocked: str = ""  # message key when Ganki refuses to preview this
    simulation: str = ""  # the simulation command, shown as text
    warnings: tuple[tuple[str, str], ...] = ()  # (message key, value shown in it)

    @property
    def commands(self) -> list[str]:
        """What the person can copy and run: first save the list, then the change."""
        if self.blocked:
            return []
        if self.action == CLEAN:
            return [real_command(CLEAN, "")]  # only deletes downloaded files: nothing to save
        return [SNAPSHOT_COMMAND, real_command(self.action, self.package)]


def warnings_for(result: Preview) -> tuple[tuple[str, str], ...]:
    """Things the person should know before confirming. Any warning asks for a tick."""
    found: list[tuple[str, str]] = []
    extra = len(result.removals) - (1 if result.action == REMOVE else 0)
    if extra > 0:
        found.append(("warn_drags", str(extra)))
    if result.action == REMOVE and _HOLDS_DATA.match(result.package):
        found.append(("warn_data", result.package))
    if any(name.startswith("linux-image") for name in result.upgrades + result.installs):
        found.append(("warn_reboot", ""))
    if result.download_bytes >= BIG_DOWNLOAD_BYTES:
        found.append(("warn_big", ""))
    return tuple(found)


def real_command(action: str, package: str) -> str:
    if action == CLEAN:
        return "sudo apt-get clean"
    if action == REMOVE:
        return f"sudo apt-get remove {package}"
    if action == UPDATE:
        return f"sudo apt-get install --only-upgrade {package}"
    return "sudo apt-get full-upgrade"


def simulation_command(action: str, package: str) -> list[str]:
    if action == REMOVE:
        return [APT_GET, "-s", "remove", package]
    if action == UPDATE:
        return [APT_GET, "-s", "install", "--only-upgrade", package]
    return [APT_GET, "-s", "full-upgrade"]


def download_command(action: str, package: str) -> list[str]:
    """Lists what would be downloaded and how big it is; downloads nothing."""
    if action == UPDATE:
        return [APT_GET, "--print-uris", "-y", "-qq", "install", "--only-upgrade", package]
    return [APT_GET, "--print-uris", "-y", "-qq", "full-upgrade"]


def simulate(action: str, package: str, download_sizes: bool = False) -> str:
    """Run the simulation. Raises ``CommandNotAllowedError`` for anything not allowlisted."""
    command = (
        download_command(action, package) if download_sizes else simulation_command(action, package)
    )
    return run(command, timeout=120)


def download_total(output: str) -> int:
    """Sum of the sizes in ``apt-get --print-uris`` lines: ``'url' file size checksum``."""
    total = 0
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].startswith("'") and parts[2].isdigit():
            total += int(parts[2])
    return total


def _bytes(number: str, unit: str) -> int:
    return int(float(number.replace(",", "")) * _UNITS[unit])


def parse(action: str, package: str, output: str) -> Preview:
    upgrades, installs, removals = [], [], []
    for line in output.splitlines():
        inst = _INSTALL_LINE.match(line)
        if inst:
            (upgrades if inst.group(2) else installs).append(inst.group(1))
            continue
        gone = _REMOVE_LINE.match(line)
        if gone:
            removals.append(gone.group(1))
    download = _DOWNLOAD.search(output)
    used = _DISK_USED.search(output)
    freed = _DISK_FREED.search(output)
    change: int | None = None
    if used:
        change = _bytes(*used.groups())
    elif freed:
        change = -_bytes(*freed.groups())
    return Preview(
        action=action,
        package=package,
        upgrades=upgrades,
        installs=installs,
        removals=removals,
        download_bytes=_bytes(*download.groups()) if download else 0,
        disk_change_bytes=change,
        simulation=" ".join(simulation_command(action, package)[1:]),
    )


def preview(
    action: str,
    package: str,
    installed: set[str],
    protected: set[str],
    simulator: Simulator = simulate,
    sizes_kib: dict[str, int] | None = None,
    cache_kib: int = 0,
) -> Preview:
    """Simulate ``action``; refuse (``blocked``) when it would touch protected software."""
    sizes_kib = sizes_kib or {}
    if action not in ACTIONS:
        return Preview(action, package, blocked="blocked_unknown")
    if action == CLEAN:
        # Nothing to simulate: it only empties apt's folder of downloaded packages.
        if cache_kib <= 0:
            return Preview(action, "", blocked="blocked_nothing_to_clean")
        return Preview(action, "", disk_change_bytes=-cache_kib * 1024)
    if action != UPDATE_ALL and (not valid_package(package) or package not in installed):
        return Preview(action, package, blocked="blocked_unknown")
    if action == REMOVE and package in protected:
        return Preview(action, package, blocked="blocked_protected")
    result = parse(action, package, simulator(action, package, False))
    if action != REMOVE:
        result = replace(result, download_bytes=download_total(simulator(action, package, True)))
    elif result.disk_change_bytes is None and result.removals:
        freed = sum(sizes_kib.get(name, 0) for name in result.removals) * 1024
        result = replace(result, disk_change_bytes=-freed)
    if any(name in protected for name in result.removals):
        return Preview(action, package, blocked="blocked_drags_protected")
    return replace(result, warnings=warnings_for(result))
