"""Collector for packages installed through apt/dpkg.

Reads the dpkg database (read-only) and returns ``Package`` objects.
Nothing in this module modifies the system.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from gankhi.runner import APT_MARK, DPKG_QUERY, run

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
    "${Section}",
    "${Priority}",
    "${Essential}",
)
_QUERY_FORMAT = _SEP.join(_FIELDS) + "\n"

APPLICATIONS_DIR = "/usr/share/applications/"

# Sections whose manually installed packages are tools a person chose to have
# (git, python, docker...). Libraries, the kernel, fonts and system plumbing
# are deliberately absent: they are dependencies, not programs.
TOOL_SECTIONS = frozenset(
    {
        "vcs",
        "interpreters",
        "devel",
        "database",
        "web",
        "javascript",
        "golang",
        "rust",
        "java",
        "games",  # a game installed on purpose is something to decide about, menu entry or not
    }
)
SYSTEM_PRIORITIES = frozenset({"required", "important"})
# Support packages that live in tool sections but are not tools themselves:
# libraries, shared data, versioned compiler internals (gcc-13), multiarch pieces.
_SUPPORT_NAME = re.compile(r"^lib|-(common|data|dev|doc|dbg)(:|$)|-\d+(:|$)|-linux-gnu|-java$|-pom")


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
    section: str = ""  # "universe/devel" is stored as "devel"
    priority: str = ""
    essential: bool = False
    has_menu_entry: bool = False  # ships a launcher shown in the applications menu
    component: str = "main"  # main, restricted, universe or multiverse (from "universe/devel")

    @property
    def is_program(self) -> bool:
        """Something a person would recognise and decide about, not a dependency.

        Either it has an entry in the applications menu, or it was installed on
        purpose and is a development/user tool (not a library, the kernel or a
        basic system package).
        """
        if self.has_menu_entry:
            return True
        return (
            self.manual
            and self.section in TOOL_SECTIONS
            and self.priority not in SYSTEM_PRIORITIES
            and not self.essential
            and not _SUPPORT_NAME.search(self.name)
        )


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
        name, version, arch, size, status, summary, source, source_version = parts[:8]
        section, priority, essential = parts[8:]
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
                section=section.rsplit("/", 1)[-1],
                component=section.split("/", 1)[0] if "/" in section else "main",
                priority=priority,
                essential=essential == "yes",
            )
        )
    return packages


def parse_manual(output: str) -> set[str]:
    """Parse ``apt-mark showmanual`` output into a set of package names."""
    return {line.strip() for line in output.splitlines() if line.strip()}


def _is_visible_launcher(path: Path) -> bool:
    """A ``.desktop`` file that shows up in the applications menu."""
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return False
    lines = {line.strip() for line in text.splitlines()}
    return "Type=Application" in lines and not lines & {"NoDisplay=true", "Hidden=true"}


def menu_packages(info_dir: Path = DPKG_INFO_DIR) -> set[str]:
    """Names of packages that ship a visible launcher (read-only scan of dpkg's file lists)."""
    found: set[str] = set()
    for listing in info_dir.glob("*.list"):
        try:
            with listing.open(errors="ignore") as handle:
                for line in handle:
                    path = line.strip()
                    if (
                        path.startswith(APPLICATIONS_DIR)
                        and path.endswith(".desktop")
                        and _is_visible_launcher(Path(path))
                    ):
                        found.add(listing.stem)
                        break
        except OSError:
            continue
    return found


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
    launchers = menu_packages()
    enriched = [
        replace(
            pkg,
            manual=pkg.name in manual or pkg.name.split(":")[0] in manual,
            installed_at=install_date(pkg.name, pkg.architecture),
            has_menu_entry=pkg.name in launchers or pkg.name.split(":")[0] in launchers,
        )
        for pkg in packages
    ]
    return sorted(enriched, key=lambda p: p.name)
