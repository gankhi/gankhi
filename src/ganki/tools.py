"""The list of installed tools with one status each: vulnerable, outdated or up to date."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

from ganki import debversion
from ganki.collectors.apt import SYSTEM_PRIORITIES, Package
from ganki.collectors.updates import Update
from ganki.osv import PRIORITY_ORDER, Finding

VULNERABLE, OUTDATED, OK = "vulnerable", "outdated", "ok"
_UNKNOWN = len(PRIORITY_ORDER)
MAX_CVE_LINES = 5  # most urgent CVEs shown per tool

# Newest Node.js major that no longer gets fixes from its authors
# (https://nodejs.org/en/about/previous-releases: 18 ended in 2025, 20 in April 2026).
NODE_LAST_UNSUPPORTED_MAJOR = 20
_LEADING_NUMBER = re.compile(r"^(?:\d+:)?(\d+)")


# Packages whose removal can leave the machine unable to boot, log in or update.
_PROTECTED_NAME = re.compile(
    r"^(linux-(generic|image-generic|headers-generic|lowlatency|virtual)\b"
    r"|ubuntu-(desktop|minimal|standard|server|keyring|release-upgrader)"
    r"|systemd|udev|apt|dpkg|libc6|bash|sudo|grub|shim|initramfs-tools|xorg|xserver-xorg"
    r"|network-manager|netplan|lightdm|sddm|gdm3|linuxlite|lite-|dbus|policykit-1|polkitd)"
)
_RUNNING_KERNEL_PART = re.compile(
    r"^linux-(image|modules|modules-extra|headers|tools)-(\d+\.\d+\.\d+-\d+)"
)
_RELEASE_ABI = re.compile(r"^(\d+\.\d+\.\d+-\d+)")


def is_protected(pkg: Package, kernel_release: str = "") -> bool:
    """Packages Ganki will never offer to remove: the system depends on them."""
    if pkg.essential or pkg.priority in SYSTEM_PRIORITIES:
        return True
    if _PROTECTED_NAME.match(pkg.name.split(":")[0]):
        return True
    abi = _RELEASE_ABI.match(kernel_release)
    part = _RUNNING_KERNEL_PART.match(pkg.name)
    return bool(abi and part and part.group(2) == abi.group(1))


def end_of_support(name: str, version: str) -> bool:
    """True when the upstream project no longer fixes this version (only well-known cases)."""
    if name.split(":")[0] == "nodejs":
        match = _LEADING_NUMBER.match(version)
        return bool(match) and int(match.group(1)) <= NODE_LAST_UNSUPPORTED_MAJOR
    return False


@dataclass(frozen=True)
class CveLine:
    cve_id: str
    priority: str
    summary: str
    fixed_version: str | None
    status: str  # fix_available / fix_with_pro / no_fix


@dataclass(frozen=True)
class Tool:
    name: str
    version: str
    size_kib: int
    description: str
    is_program: bool  # a program or tool (True) or a library/system dependency (False)
    state: str  # VULNERABLE, OUTDATED or OK
    update_to: str | None = None  # newer version available from the repositories
    cve_count: int = 0
    top_priority: str = ""
    fixable: int = 0  # CVEs fixed by updating (or by Ubuntu Pro)
    unfixable: int = 0  # CVEs with no fix published yet
    fixed_in: str | None = None  # version that fixes everything fixable
    cves: tuple[CveLine, ...] = ()
    protected: bool = False  # never offered for removal
    end_of_support: bool = False  # the authors no longer publish fixes for this version
    component: str = "main"  # main, restricted, universe or multiverse
    installed_version: str = ""  # the full version, to compare with what a notice says
    section: str = ""  # the package's own category in the distribution (net, mail, graphics...)


def _rank(priority: str) -> int:
    return PRIORITY_ORDER.get(priority, _UNKNOWN)


def _tier(tool: Tool) -> int:
    """What the person can do about it, so the list starts with what can be fixed now.

    0: updating fixes all of its notices. 1: updating fixes some, others stay open. 2: only
    outdated. 3: it has notices that no update fixes (no patch yet, or the project is no
    longer supported). 4: up to date.
    """
    if tool.state == VULNERABLE:
        if tool.fixed_in and tool.update_to:
            return 1 if tool.unfixable else 0
        return 3
    return 2 if tool.state == OUTDATED else 4


def _sample(unique: dict[str, Finding]) -> tuple[CveLine, ...]:
    """The most urgent notices of each kind, so the ones without a fix are never left out."""
    shown = {"fixed": 0, "open": 0}
    lines = []
    for found in unique.values():
        group = "open" if found.status == "no_fix" else "fixed"
        if shown[group] < MAX_CVE_LINES:
            shown[group] += 1
            lines.append(
                CveLine(
                    found.cve_id, found.priority, found.summary, found.fixed_version, found.status
                )
            )
    return tuple(lines)


def build_tools(
    packages: list[Package],
    findings: list[Finding],
    updates: list[Update],
    kernel_release: str = "",
) -> list[Tool]:
    """One ``Tool`` per installed package, most urgent first."""
    by_name: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        for name in finding.packages:
            by_name[name].append(finding)
    pending = {u.name: u.candidate_version for u in updates}

    tools = []
    for pkg in packages:
        found = by_name.get(pkg.name, [])
        candidate = pending.get(pkg.name.split(":")[0])
        if found:
            state = VULNERABLE
        elif candidate:
            state = OUTDATED
        else:
            state = OK
        unique: dict[str, Finding] = {}
        for item in sorted(found, key=lambda f: (_rank(f.priority), f.cve_id)):
            unique.setdefault(item.cve_id, item)
        fixes = [f.fixed_version for f in unique.values() if f.fixed_version]
        fixed_in = None
        for version in fixes:
            if fixed_in is None or debversion.compare(version, fixed_in) > 0:
                fixed_in = version
        tools.append(
            Tool(
                name=pkg.name,
                version=pkg.version,
                size_kib=pkg.size_kib,
                description=pkg.description,
                is_program=pkg.is_program,
                state=state,
                update_to=candidate,
                cve_count=len(unique),
                top_priority=min((f.priority for f in unique.values()), key=_rank, default=""),
                fixable=sum(1 for f in unique.values() if f.status != "no_fix"),
                unfixable=sum(1 for f in unique.values() if f.status == "no_fix"),
                fixed_in=fixed_in,
                component=pkg.component,
                installed_version=pkg.version,
                section=pkg.section,
                protected=is_protected(pkg, kernel_release),
                end_of_support=end_of_support(pkg.name, pkg.version),
                cves=_sample(unique),
            )
        )
    return sorted(
        tools,
        key=lambda t: (_tier(t), _rank(t.top_priority), -t.cve_count, t.name),
    )
