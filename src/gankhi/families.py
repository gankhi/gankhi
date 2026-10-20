"""Packages that belong together (the pieces of one kernel, of one Java...) shown as one row."""

from __future__ import annotations

import os.path
import re
from dataclasses import dataclass

from gankhi.tools import Tool

PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4}
_KERNEL = re.compile(
    r"^linux-(image|modules|modules-extra|headers|tools|libc-dev|source|generic|cloud-tools"
    r"|hwe|oem|lowlatency)(-|$)"
)
_JAVA = re.compile(r"^openjdk-(\d+)")
_ZFS = re.compile(r"^(libzfs|libzpool|libnvpair|libuutil|zfs|zfsutils)")
MAX_LISTED = 3  # a group of up to this many packages shows their names...
MAX_LISTED_CHARS = 40  # ...when they are short enough not to make the row tall


def _base(name: str) -> str:
    return name.split(":")[0]


def is_kernel(name: str) -> bool:
    return bool(_KERNEL.match(_base(name)))


def family_key(name: str) -> str:
    base = _base(name)
    if is_kernel(base):
        return "kernel"
    java = _JAVA.match(base)
    if java:
        return f"openjdk-{java.group(1)}"
    if base.startswith("virtualbox"):
        return "virtualbox"
    if _ZFS.match(base):
        return "zfs"
    if base.startswith("lite-"):
        return "lite"
    return base.split("-")[0]


@dataclass(frozen=True)
class Group:
    key: str
    tools: tuple[Tool, ...]

    @property
    def count(self) -> int:
        return len(self.tools)

    @property
    def top(self) -> Tool:
        """The member to read the priority and the advice from: the most urgent one."""
        return min(
            self.tools,
            key=lambda t: (PRIORITY_ORDER.get(t.top_priority, 5), t.name),
        )

    @property
    def top_priority(self) -> str:
        return self.top.top_priority

    @property
    def version(self) -> str:
        versions = {t.version for t in self.tools}
        return next(iter(versions)) if len(versions) == 1 else ""

    def label(self, kernel_name: str) -> str:
        """What to call the group: the family, or the one package when it is alone."""
        if self.count == 1:
            return self.tools[0].name
        if self.key == "kernel":
            return kernel_name
        if self.key == "lite":
            return "lite-*"
        if self.key == "zfs":
            return "ZFS"
        names = [_base(t.name) for t in self.tools]
        prefix = os.path.commonprefix(names)
        # Only cut at a whole word: "openjdk-17-j" would be a made-up name.
        whole = all(len(n) == len(prefix) or n[len(prefix)] in "-." for n in names)
        if not whole and "-" in prefix:
            prefix = prefix[: prefix.rfind("-")]
        prefix = prefix.rstrip("-.")
        return prefix if len(prefix) >= 3 else self.key

    def members(self) -> str:
        """The package names, when there are only a few."""
        if self.count == 1 or self.count > MAX_LISTED or self.key == "kernel":
            return ""
        names = ", ".join(sorted(t.name for t in self.tools))
        return names if len(names) <= MAX_LISTED_CHARS else ""


def group(tools: list[Tool]) -> list[Group]:
    """One group per family, most urgent first."""
    families: dict[str, list[Tool]] = {}
    for tool in tools:
        families.setdefault(family_key(tool.name), []).append(tool)
    groups = [Group(key, tuple(members)) for key, members in families.items()]
    return sorted(
        groups,
        key=lambda g: (PRIORITY_ORDER.get(g.top_priority, 5), g.tools[0].name),
    )
