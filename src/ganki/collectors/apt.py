"""Collector for packages installed through apt/dpkg.

Reads the dpkg database (read-only) and returns ``Package`` objects.
Nothing in this module modifies the system.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

DPKG_INFO_DIR = Path("/var/lib/dpkg/info")

# Absolute paths + fixed argument lists: no shell, no user-controlled input.
DPKG_QUERY = "/usr/bin/dpkg-query"
APT_MARK = "/usr/bin/apt-mark"

_SEP = "\t"
_FIELDS = (
    "${binary:Package}",
    "${Version}",
    "${Architecture}",
    "${Installed-Size}",
    "${db:Status-Abbrev}",
    "${binary:Summary}",
)
_QUERY_FORMAT = _SEP.join(_FIELDS) + "\n"


@dataclass(frozen=True)
class Package:
    """One installed apt package."""

    name: str
    version: str
    architecture: str
    size_kib: int
    description: str
    manual: bool = False  # True if the user asked for it (not just a dependency)
    installed_at: datetime | None = None  # approximate, see install_date()


def _to_int(value: str) -> int:
    """Parse an integer field; dpkg may leave it empty."""
    try:
        return int(value)
    except ValueError:
        return 0


def parse_dpkg_query(output: str) -> list[Package]:
    """Parse ``dpkg-query`` output, keeping only fully installed packages."""
    packages: list[Package] = []
    for line in output.splitlines():
        parts = line.split(_SEP)
        if len(parts) != len(_FIELDS):
            continue  # malformed line: skip instead of crashing
        name, version, arch, size, status, summary = parts
        if not status.startswith("ii"):
            continue  # removed or half-configured package
        packages.append(
            Package(
                name=name,
                version=version,
                architecture=arch,
                size_kib=_to_int(size),
                description=summary,
            )
        )
    return packages


def parse_manual(output: str) -> set[str]:
    """Parse ``apt-mark showmanual`` output into a set of package names."""
    return {line.strip() for line in output.splitlines() if line.strip()}


def install_date(
    name: str, architecture: str, info_dir: Path = DPKG_INFO_DIR
) -> datetime | None:
    """Approximate install date from the modification time of the .list file.

    dpkg has no real install date. The file time changes when a package is
    upgraded, so treat this as "installed or last upgraded".
    """
    base = name.split(":")[0]
    for candidate in (f"{name}.list", f"{base}:{architecture}.list"):
        path = info_dir / candidate
        try:
            return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            continue
    return None


def _run(args: list[str]) -> str:
    """Run a fixed command (no shell) and return its stdout."""
    result = subprocess.run(  # noqa: S603  (fixed absolute path and arguments)
        args, capture_output=True, text=True, check=True, timeout=60
    )
    return result.stdout


def collect() -> list[Package]:
    """Return all installed apt packages, sorted by name."""
    packages = parse_dpkg_query(
        _run([DPKG_QUERY, "--show", f"--showformat={_QUERY_FORMAT}"])
    )
    manual = parse_manual(_run([APT_MARK, "showmanual"]))
    enriched = [
        replace(
            pkg,
            manual=pkg.name in manual or pkg.name.split(":")[0] in manual,
            installed_at=install_date(pkg.name, pkg.architecture),
        )
        for pkg in packages
    ]
    return sorted(enriched, key=lambda p: p.name)
