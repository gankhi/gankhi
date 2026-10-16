"""Detect which Ubuntu release the system is based on.

Vulnerability data is published per Ubuntu release, e.g. ``Ubuntu:24.04:LTS``.
Derivatives such as Linux Lite or Linux Mint report their own version in
``VERSION_ID``, so we use ``UBUNTU_CODENAME`` and map it to the Ubuntu release.
"""

from __future__ import annotations

from pathlib import Path

OS_RELEASE = Path("/etc/os-release")

# Ubuntu codename -> OSV ecosystem name used by Canonical's feed.
# Extend this table when a new Ubuntu release comes out.
ECOSYSTEMS = {
    "focal": "Ubuntu:20.04:LTS",
    "jammy": "Ubuntu:22.04:LTS",
    "noble": "Ubuntu:24.04:LTS",
    "plucky": "Ubuntu:25.04",
    "questing": "Ubuntu:25.10",
    "resolute": "Ubuntu:26.04:LTS",
}


def pro_ecosystem(ecosystem: str) -> str:
    """The Ubuntu Pro variant of an ecosystem: ``Ubuntu:24.04:LTS`` -> ``Ubuntu:Pro:24.04:LTS``."""
    return ecosystem.replace("Ubuntu:", "Ubuntu:Pro:", 1)


class UnsupportedReleaseError(RuntimeError):
    """The system is not based on an Ubuntu release Ganki knows how to check."""


def parse_os_release(text: str) -> dict[str, str]:
    """Parse ``KEY=value`` lines (values may be quoted) into a dictionary."""
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def detect_ecosystem(os_release: Path = OS_RELEASE) -> str:
    """Return the OSV ecosystem for this machine, or raise UnsupportedReleaseError."""
    try:
        info = parse_os_release(os_release.read_text(encoding="utf-8"))
    except OSError as error:
        raise UnsupportedReleaseError(f"cannot read {os_release}: {error}") from error

    codename = info.get("UBUNTU_CODENAME") or (
        info.get("VERSION_CODENAME") if info.get("ID") == "ubuntu" else ""
    )
    try:
        return ECOSYSTEMS[codename]
    except KeyError:
        raise UnsupportedReleaseError(
            f"unsupported or non-Ubuntu release (codename: {codename or 'unknown'})"
        ) from None
