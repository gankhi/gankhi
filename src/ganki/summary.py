"""Turn the raw list of findings into something a person can act on.

A raw scan returns one row per (CVE, package). That is tens of thousands of rows,
mostly from the kernel: every kernel version still installed is reported on its
own, and old ones are missing hundreds of fixes that the newer ones already have.

This module groups findings per source package and installed version, and tells
three situations apart:

- ``program``: a normal installed program.
- ``running_kernel``: the kernel the machine is running right now.
- ``old_kernel``: a kernel version that is installed but not running. It is not
  an exposure today; the useful action is to remove it, not to patch it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ganki import debversion
from ganki.osv import PRIORITY_ORDER, Finding

PROGRAM = "program"
RUNNING_KERNEL = "running_kernel"
OLD_KERNEL = "old_kernel"

_RELEASE_ABI = re.compile(r"^(\d+\.\d+\.\d+-\d+)")  # "6.8.0-137-generic" -> "6.8.0-137"
_VERSION_ABI = re.compile(r"^(\d+\.\d+\.\d+-\d+)\.")  # "6.8.0-137.137"    -> "6.8.0-137"
_UNKNOWN_RANK = len(PRIORITY_ORDER)


@dataclass(frozen=True)
class PackageRisk:
    """All findings of one source package at one installed version."""

    source_package: str
    installed_version: str
    packages: tuple[str, ...]  # installed binary packages built from this source
    kind: str  # PROGRAM, RUNNING_KERNEL or OLD_KERNEL
    cve_count: int
    top_priority: str  # most urgent priority among its CVEs ("" if none known)
    by_priority: dict[str, int] = field(default_factory=dict)
    fix_available: int = 0  # CVEs fixed by updating
    fix_with_pro: int = 0  # CVEs fixed only with Ubuntu Pro
    no_fix: int = 0  # CVEs with no fix released yet
    target_version: str | None = None  # version that fixes everything fixable


def _is_kernel_source(source: str) -> bool:
    return source == "linux" or source.startswith("linux-")


def running_kernel_abi(release: str) -> str | None:
    """ABI part of ``uname -r`` (``6.8.0-137-generic`` -> ``6.8.0-137``)."""
    match = _RELEASE_ABI.match(release)
    return match.group(1) if match else None


def _classify(source: str, installed: str, running_abi: str | None) -> str:
    if not _is_kernel_source(source) or running_abi is None:
        return PROGRAM
    match = _VERSION_ABI.match(installed)
    if match is None:
        return PROGRAM  # not a versioned kernel image (e.g. a meta package)
    return RUNNING_KERNEL if match.group(1) == running_abi else OLD_KERNEL


def _rank(priority: str) -> int:
    return PRIORITY_ORDER.get(priority, _UNKNOWN_RANK)


def summarize(findings: list[Finding], running_release: str = "") -> list[PackageRisk]:
    """Group findings per (source package, installed version).

    Most actionable first: programs and the running kernel before old kernels,
    then by urgency, then by number of CVEs.
    """
    running_abi = running_kernel_abi(running_release)
    groups: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        groups.setdefault((finding.source_package, finding.installed_version), []).append(finding)

    risks = []
    for (source, installed), items in groups.items():
        by_priority: dict[str, int] = {}
        for item in items:
            key = item.priority or "unknown"
            by_priority[key] = by_priority.get(key, 0) + 1
        fixes = [i.fixed_version for i in items if i.fixed_version]
        target = fixes[0] if fixes else None
        for fixed in fixes[1:]:
            if target is not None and debversion.compare(fixed, target) > 0:
                target = fixed
        risks.append(
            PackageRisk(
                source_package=source,
                installed_version=installed,
                packages=tuple(sorted({name for i in items for name in i.packages})),
                kind=_classify(source, installed, running_abi),
                cve_count=len({i.cve_id for i in items}),
                top_priority=min((i.priority for i in items), key=_rank),
                by_priority=dict(sorted(by_priority.items(), key=lambda kv: _rank(kv[0]))),
                fix_available=sum(1 for i in items if i.status == "fix_available"),
                fix_with_pro=sum(1 for i in items if i.status == "fix_with_pro"),
                no_fix=sum(1 for i in items if i.status == "no_fix"),
                target_version=target,
            )
        )
    return sorted(
        risks,
        key=lambda r: (
            r.kind == OLD_KERNEL,
            _rank(r.top_priority),
            -r.cve_count,
            r.source_package,
            r.installed_version,
        ),
    )
