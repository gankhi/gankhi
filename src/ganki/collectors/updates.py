"""Collector for pending apt updates.

Parses ``apt list --upgradable`` (read-only). It reports what the local package
index says; the index is only as fresh as the last ``apt update``, so callers
should also show ``last_index_refresh()`` to the user.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ganki.runner import APT, run

# apt writes this file after every successful `apt update`.
APT_UPDATE_STAMP = Path("/var/lib/apt/periodic/update-success-stamp")

# Example line (C locale):
#   bash/noble-updates,noble-security 5.2.21-2ubuntu4.1 amd64 [upgradable from: 5.2.21-2ubuntu4]
_LINE = re.compile(
    r"^(?P<name>[^/\s]+)/(?P<origin>\S+)\s+(?P<candidate>\S+)\s+(?P<arch>\S+)\s+"
    r"\[upgradable from:\s+(?P<current>[^\]\s]+)\]"
)


@dataclass(frozen=True)
class Update:
    """One package with a newer version available."""

    name: str
    architecture: str
    current_version: str
    candidate_version: str
    origin: str  # e.g. "noble-updates,noble-security"
    is_security: bool  # True if any origin is a security pocket


def parse_upgradable(output: str) -> list[Update]:
    """Parse ``apt list --upgradable`` output; unknown lines are ignored."""
    updates: list[Update] = []
    for line in output.splitlines():
        match = _LINE.match(line.strip())
        if match is None:
            continue  # header ("Listing...") or anything unexpected
        origin = match["origin"]
        updates.append(
            Update(
                name=match["name"],
                architecture=match["arch"],
                current_version=match["current"],
                candidate_version=match["candidate"],
                origin=origin,
                is_security="-security" in origin,
            )
        )
    return updates


def last_index_refresh(stamp: Path = APT_UPDATE_STAMP) -> datetime | None:
    """When the package index was last refreshed, or None if unknown."""
    try:
        return datetime.fromtimestamp(stamp.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return None


def collect_updates() -> list[Update]:
    """Return packages with pending updates, security ones first, then by name."""
    updates = parse_upgradable(run([APT, "list", "--upgradable"]))
    return sorted(updates, key=lambda u: (not u.is_security, u.name))
