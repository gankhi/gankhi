"""Collector for packages installed through apt/dpkg.

Reads the dpkg database (read-only) and returns ``Package`` objects.
Nothing in this module modifies the system.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from ganki.runner import APT_MARK, DPKG_QUERY, run

DPKG_INFO_DIR = Path("/var/lib/dpkg/info")

_SEP = "\t"
_FIELDS = (
    "${binary:Package}",
    "${Version}",
    "${Architecture}",
    "${Installed-Size}",
    "${db:Status-Abbrev}",
    "${binary:Summary}",
    "${source:Package}",
    "${source:Version}",
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
    # Vulnerability databases are keyed by *source* package, not binary package.
    source_name: str = ""
    source_version: str = ""


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
        name, version, arch, size, status, summary, source, source_version = parts
        if not status.startswith("ii"):
            continue  # removed or half-configured package
        packages.append(
            Package(
                name=name,
                version=version,
                architecture=arch,
                size_kib=_to_int(size),
                description=summary,
                source_name=source or name.split(":")[0],
                source_version=source_version or version,
            )
        )
    return packages


def parse_manual(output: str) -> set[str]:
    """Parse ``apt-mark showmanual`` output into a set of package names."""
    return {line.strip() for line in output.splitlines() if line.strip()}


def install_date(name: str, architecture: str, info_dir: Path = DPKG_INFO_DIR) -> datetime | None:
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


def collect() -> list[Package]:
    """Return all installed apt packages, sorted by name."""
    packages = parse_dpkg_query(run([DPKG_QUERY, "--show", f"--showformat={_QUERY_FORMAT}"]))
    manual = parse_manual(run([APT_MARK, "showmanual"]))
    enriched = [
        replace(
            pkg,
            manual=pkg.name in manual or pkg.name.split(":")[0] in manual,
            installed_at=install_date(pkg.name, pkg.architecture),
        )
        for pkg in packages
    ]
    return sorted(enriched, key=lambda p: p.name)
