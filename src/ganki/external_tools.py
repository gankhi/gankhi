"""One row per pip or npm package: is it affected, how badly, and what to do about it."""

from __future__ import annotations

from dataclasses import dataclass

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
