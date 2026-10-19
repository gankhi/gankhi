"""One row per pip or npm package: is it affected, how badly, and what to do about it."""

from __future__ import annotations

import re
import shlex
import sysconfig
from dataclasses import dataclass
from pathlib import Path

from ganki import versions
from ganki.collectors.external import ExternalPackage
from ganki.osv_external import ExternalFinding
from ganki.tools import CveLine

PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
MAX_CVE_LINES = 12


@dataclass(frozen=True)
class ExternalTool:
    name: str
    version: str
    tool: str  # pip or npm
    ecosystem: str
    vulnerable: bool
    top_priority: str = ""
    cve_count: int = 0
    fixed_in: str | None = None  # the version that fixes everything fixable
    malicious: bool = False
    cves: tuple[CveLine, ...] = ()


_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$")


def externally_managed() -> bool:
    """Does the system's Python refuse pip changes unless told otherwise (PEP 668)?

    Ubuntu 23.04 and later (and Debian 12) mark their Python this way: a plain
    ``pip install`` or ``pip uninstall`` stops with "externally-managed-environment".
    """
    try:
        return (Path(sysconfig.get_path("stdlib")) / "EXTERNALLY-MANAGED").is_file()
    except (OSError, KeyError):
        return False


def _pip_flag() -> str:
    return " --break-system-packages" if externally_managed() else ""


def update_command(tool: ExternalTool) -> str | None:
    """The command the person can run to get the fixed version; Ganki never runs it itself."""
    if not tool.fixed_in or not _NAME.match(tool.name) or not _VERSION.match(tool.fixed_in):
        return None  # an odd name or version is never pasted into a command
    wanted = shlex.quote(f"{tool.name}>={tool.fixed_in}")
    if tool.tool == "pip":
        return f"python3 -m pip install --upgrade{_pip_flag()} {wanted}"
    if tool.tool == "npm":
        return f"npm install -g {shlex.quote(f'{tool.name}@>={tool.fixed_in}')}"
    return None


def remove_command(tool: ExternalTool) -> str | None:
    """The command to remove it, for a package the person does not need."""
    if not _NAME.match(tool.name):
        return None
    if tool.tool == "pip":
        return f"python3 -m pip uninstall{_pip_flag()} {shlex.quote(tool.name)}"
    if tool.tool == "npm":
        return f"npm uninstall -g {shlex.quote(tool.name)}"
    return None


def build_external_tools(
    packages: list[ExternalPackage], findings: list[ExternalFinding]
) -> list[ExternalTool]:
    """Every package, the affected ones first and the most urgent of those at the top."""
    by_package: dict[tuple[str, str], list[ExternalFinding]] = {}
    for finding in findings:
        by_package.setdefault((finding.ecosystem, finding.name), []).append(finding)
    tools = []
    for package in packages:
        found = sorted(
            by_package.get((package.ecosystem, package.name), []),
            key=lambda f: (PRIORITY_ORDER.get(f.priority, 4), f.key),
        )
        fixes = [
            (parsed, f.fixed_version)
            for f in found
            if f.fixed_version
            and (parsed := versions.parse(package.ecosystem, f.fixed_version)) is not None
        ]
        fixed_in = max(fixes, key=lambda pair: pair[0])[1] if fixes else None
        tools.append(
            ExternalTool(
                name=package.name,
                version=package.version,
                tool=package.tool,
                ecosystem=package.ecosystem,
                vulnerable=bool(found),
                top_priority=found[0].priority if found else "",
                cve_count=len(found),
                fixed_in=fixed_in if all(f.fixed_version for f in found) else None,
                malicious=any(f.malicious for f in found),
                cves=tuple(
                    CveLine(
                        f.key,
                        f.priority,
                        f.summary,
                        f.fixed_version,
                        "fix_available" if f.fixed_version else "no_fix",
                    )
                    for f in found[:MAX_CVE_LINES]
                ),
            )
        )
    return sorted(
        tools,
        key=lambda t: (
            not t.vulnerable,
            PRIORITY_ORDER.get(t.top_priority, 4),
            t.name,
        ),
    )
