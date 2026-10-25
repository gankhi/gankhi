"""The list of installed tools with one status each: vulnerable, outdated or up to date."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, replace

from gankhi import debversion
from gankhi.advice import profile_for
from gankhi.collectors.apt import SYSTEM_PRIORITIES, Package
from gankhi.collectors.updates import Update
from gankhi.osv import PRIORITY_ORDER, Finding

VULNERABLE, OUTDATED, OK = "vulnerable", "outdated", "ok"
UNCHECKED = "unchecked"  # comes from outside Ubuntu: no list of notices to compare it with
_UNKNOWN = len(PRIORITY_ORDER)
MAX_CVE_LINES = 200  # CVEs listed per tool and kind (fixed or not); beyond it, a count
URGENT_PRIORITIES = ("critical", "high")  # notices that cannot wait

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


_VERSIONED_KERNEL = re.compile(
    r"^linux-(image|headers|modules|tools|buildinfo)\S*-\d+\.\d+\.\d+-\d+"
)
_KERNEL_META = ("linux-generic", "linux-image-generic", "linux-headers-generic")


def _update_via(tool: Tool, by_name: dict[str, Tool]) -> str:
    """The kernel meta-package that brings this versioned kernel package's fix, if it can update.

    A kernel is installed once per version, under a name that carries the version, so the new
    one is a different package and the old one never has a newer version of its own.
    """
    if tool.update_to or not tool.fixed_in or not _VERSIONED_KERNEL.match(tool.name):
        return ""
    for name in _KERNEL_META:
        meta = by_name.get(name)
        if meta is not None and meta.update_to:
            return name
    return ""


# Development headers: they are only used to compile programs. Their notices come from the
# source they are built from, and removing them takes the compilers' packages along.
KEEP_PACKAGES = frozenset({"linux-libc-dev"})
_KERNEL_NUMBER = re.compile(r"(\d+\.\d+\.\d+-\d+)")
_STATE_ORDER = (VULNERABLE, OUTDATED, UNCHECKED, OK)


def group_kernels(tools: list[Tool], kernel_release: str = "") -> list[Tool]:
    """Join the packages of each installed kernel into one tool.

    The notices of a kernel apply to all its packages, so counting each package would count the
    same flaws several times, and twice over while an old and a new kernel are installed.
    """
    members: dict[str, list[Tool]] = {}
    rest: list[Tool] = []
    for tool in tools:
        number = _KERNEL_NUMBER.search(tool.name) if _VERSIONED_KERNEL.match(tool.name) else None
        if number:
            members.setdefault(number.group(1), []).append(tool)
        else:
            rest.append(tool)
    for number, parts in members.items():
        lead = max(parts, key=lambda t: (t.cve_count, t.name))
        state = min((t.state for t in parts), key=_STATE_ORDER.index)
        rest.append(
            replace(
                lead,
                name=f"linux-{number}",
                description="",
                state=state,
                size_kib=sum(t.size_kib for t in parts),
                update_via=next((t.update_via for t in parts if t.update_via), ""),
                protected=True,
                core=True,
                urgent=any(t.urgent for t in parts),
                is_program=any(t.is_program for t in parts),
                group=tuple(sorted(t.name for t in parts)),
                kernel_in_use=bool(kernel_release) and number in kernel_release,
            )
        )
    return rest


def is_protected(pkg: Package, kernel_release: str = "") -> bool:
    """Packages Gankhi will never offer to remove: the system depends on them."""
    return pkg.priority in SYSTEM_PRIORITIES or is_core(pkg, kernel_release)


def is_core(pkg: Package, kernel_release: str = "") -> bool:
    """Packages that must stay even when apt says nothing needs them any more.

    The stricter test for ``autoremove``: apt already decided nothing depends on the package,
    so a high distribution priority alone (a leftover 32-bit library, say) is not a reason to
    refuse. Essential packages, the known system names and the running kernel still are.
    """
    if pkg.essential:
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
    state: str  # VULNERABLE, OUTDATED, UNCHECKED or OK
    update_to: str | None = None  # newer version available from the repositories
    cve_count: int = 0
    top_priority: str = ""
    fixable: int = 0  # CVEs fixed by updating (or by Ubuntu Pro)
    unfixable: int = 0  # CVEs with no fix published yet
    fixed_in: str | None = None  # version that fixes everything fixable
    cves: tuple[CveLine, ...] = ()
    protected: bool = False  # never offered for removal
    core: bool = False  # never removed, not even when apt says nothing needs it
    end_of_support: bool = False  # the authors no longer publish fixes for this version
    component: str = "main"  # main, restricted, universe or multiverse
    installed_version: str = ""  # the full version, to compare with what a notice says
    section: str = ""  # the package's own category in the distribution (net, mail, graphics...)
    update_security: bool = False  # the newer version comes from Ubuntu's security channel
    update_origin: str = ""  # where the newer version comes from, as apt reports it
    # The package that carries this one's fix when this package itself has no newer version
    # (a kernel with its version in the name: the fix arrives through the kernel meta-package).
    update_via: str = ""
    # A kernel is one item, however many packages it has (image, headers, modules...): these
    # are the names of the packages grouped here, empty for any other tool.
    group: tuple[str, ...] = ()
    keep_hint: bool = False  # removing it is not worth it: the notices shown do not make it risky
    kernel_in_use: bool = False
    fixable_priority: str = ""  # most urgent priority among the notices an update fixes
    urgent: bool = False  # worth updating before anything else
    origin: str = ""  # where it comes from when that is not Ubuntu ("cloud-sdk", "local")


def _rank(priority: str) -> int:
    return PRIORITY_ORDER.get(priority, _UNKNOWN)


def _tier(tool: Tool) -> int:
    """What the person can do about it, so the list starts with what matters most.

    0: urgent according to Ubuntu (see ``_is_urgent``). 1: an outdated browser, which Ubuntu
    publishes no notices for but is the most exposed kind of program. 2: updating fixes all of
    its notices. 3: updating fixes some, others stay open. 4: only outdated. 5: it has notices
    that no update fixes (no patch yet, or the project is no longer supported). 6: up to date.
    7: not checked (it comes from outside Ubuntu).
    """
    if tool.urgent:
        return 0
    if tool.state == VULNERABLE:
        if tool.fixed_in and (tool.update_to or tool.update_via):
            return 3 if tool.unfixable else 2
        return 5
    if tool.state == OUTDATED:
        return 1 if _is_browser(tool) else 4
    if tool.state == UNCHECKED:
        return 7
    return 6


def is_parked(tool: Tool) -> bool:
    """Has known flaws and no fix exists yet (or the newer version does not include one), so
    there is nothing to act on. It goes to its own place instead of the list of what to act on.
    A published fix that is not installable yet (for example Ubuntu Pro) is still something
    to act on, so it stays in the main list."""
    return tool.state == VULNERABLE and not tool.fixed_in


def _is_browser(tool: Tool) -> bool:
    return profile_for(tool.name, "", tool.description, tool.section) == "browser"


def _is_urgent(tool: Tool) -> bool:
    """An update is on offer and Ubuntu says it matters: it fixes critical or high notices, or
    it comes from Ubuntu's security channel."""
    if not tool.update_to:
        return False
    if tool.state == VULNERABLE:
        return bool(tool.fixed_in) and tool.fixable_priority in URGENT_PRIORITIES
    return tool.update_security


def _sample(unique: dict[str, Finding]) -> tuple[CveLine, ...]:
    """The notices, most urgent first. Fixed and unfixed are capped apart so a flood of one kind
    never pushes the other out."""
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
    third_party: dict[str, str] | None = None,
) -> list[Tool]:
    """One ``Tool`` per installed package, most urgent first.

    ``third_party`` maps the packages that do not come from Ubuntu to where they come from.
    Ubuntu's list says nothing about them, so with no pending update they are "not checked",
    never "up to date".
    """
    outside = third_party or {}
    by_name: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        for name in finding.packages:
            by_name[name].append(finding)
    pending = {u.name: u for u in updates}

    tools = []
    for pkg in packages:
        found = by_name.get(pkg.name, [])
        update = pending.get(pkg.name.split(":")[0])
        candidate = update.candidate_version if update else None
        origin = outside.get(pkg.name.split(":")[0], "")
        if found:
            state = VULNERABLE
        elif candidate:
            state = OUTDATED
        elif origin:
            state = UNCHECKED
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
                update_security=bool(update and update.is_security),
                update_origin=update.origin if update else "",
                cve_count=len(unique),
                top_priority=min((f.priority for f in unique.values()), key=_rank, default=""),
                fixable=sum(1 for f in unique.values() if f.status != "no_fix"),
                unfixable=sum(1 for f in unique.values() if f.status == "no_fix"),
                fixed_in=fixed_in,
                fixable_priority=min(
                    (f.priority for f in unique.values() if f.status != "no_fix"),
                    key=_rank,
                    default="",
                ),
                component=pkg.component,
                installed_version=pkg.version,
                section=pkg.section,
                protected=is_protected(pkg, kernel_release),
                core=is_core(pkg, kernel_release),
                end_of_support=end_of_support(pkg.name, pkg.version),
                cves=_sample(unique),
                origin=origin,
            )
        )
    tools = [replace(t, urgent=_is_urgent(t)) for t in tools]
    by_name = {t.name: t for t in tools}
    tools = [replace(t, update_via=_update_via(t, by_name)) for t in tools]
    tools = group_kernels(tools, kernel_release)
    tools = [replace(t, keep_hint=t.name.split(":")[0] in KEEP_PACKAGES) for t in tools]
    return sorted(
        tools,
        key=lambda t: (
            _tier(t),
            _rank(t.fixable_priority or t.top_priority),
            -t.cve_count,
            t.name,
        ),
    )
