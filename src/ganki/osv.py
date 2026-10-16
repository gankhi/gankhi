"""Read Ubuntu vulnerability records (OSV format) and match them to installed packages.

Input is Canonical's ``osv-all.tar.xz`` feed: one JSON record per CVE. Everything
here runs on the local machine; nothing about your packages is sent anywhere.

Safety notes:
- The archive is never extracted to disk. Members are read in memory, so a
  malicious archive cannot write files (no path traversal).
- Only regular files named ``UBUNTU-CVE-*.json`` are read, each capped in size,
  and the total number of members is capped.
- JSON is parsed with the standard library (no XML, no code execution).
"""

from __future__ import annotations

import json
import tarfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ganki import debversion
from ganki.collectors.apt import Package

MAX_RECORD_BYTES = 2 * 1024 * 1024  # a single CVE record is far smaller than this
MAX_MEMBERS = 500_000  # the feed has tens of thousands of files


@dataclass(frozen=True)
class Advisory:
    """One CVE as it applies to one source package on one Ubuntu release."""

    cve_id: str  # e.g. "CVE-2025-6491"
    summary: str
    source_package: str
    fixed_version: str | None  # None: no fixed version has been released
    requires_subscription: bool  # fix only via Ubuntu Pro (heuristic, see below)


@dataclass(frozen=True)
class Finding:
    """An installed package that is affected by an advisory."""

    cve_id: str
    package: str  # binary package name as installed
    source_package: str
    installed_version: str
    fixed_version: str | None
    summary: str
    requires_subscription: bool


def _fixed_version(affected: dict[str, Any]) -> str | None:
    """First ``fixed`` event found in the affected entry's ranges, if any."""
    for version_range in affected.get("ranges", []):
        for event in version_range.get("events", []):
            fixed = event.get("fixed")
            if isinstance(fixed, str) and fixed:
                return fixed
    return None


def _needs_subscription(affected: dict[str, Any]) -> bool:
    """Heuristic: the record says the fix needs a subscription (Ubuntu Pro)."""
    specific = affected.get("ecosystem_specific")
    availability = specific.get("availability", "") if isinstance(specific, dict) else ""
    text = str(availability).lower()
    return bool(text) and "no subscription" not in text


def parse_record(record: dict[str, Any], ecosystem: str) -> list[Advisory]:
    """Extract advisories for ``ecosystem`` from one OSV record (defensive parsing)."""
    cve_id = str(record.get("id", "")).removeprefix("UBUNTU-")
    if not cve_id.startswith("CVE-"):
        return []
    summary = str(record.get("summary") or "").strip()
    advisories: list[Advisory] = []
    for affected in record.get("affected", []):
        package = affected.get("package") or {}
        if package.get("ecosystem") != ecosystem or not package.get("name"):
            continue
        advisories.append(
            Advisory(
                cve_id=cve_id,
                summary=summary,
                source_package=str(package["name"]),
                fixed_version=_fixed_version(affected),
                requires_subscription=_needs_subscription(affected),
            )
        )
    return advisories


def load_advisories(archive: Path, ecosystem: str) -> dict[str, list[Advisory]]:
    """Read the feed archive and index advisories by source package name."""
    index: dict[str, list[Advisory]] = defaultdict(list)
    with tarfile.open(archive, mode="r:xz") as tar:
        for count, member in enumerate(tar):
            if count >= MAX_MEMBERS:
                break
            name = Path(member.name).name
            if not (member.isfile() and name.startswith("UBUNTU-CVE-") and name.endswith(".json")):
                continue
            if member.size > MAX_RECORD_BYTES:
                continue
            handle = tar.extractfile(member)  # in-memory read, nothing written to disk
            if handle is None:
                continue
            try:
                record = json.loads(handle.read())
            except (ValueError, UnicodeDecodeError):
                continue  # one broken record must not stop the scan
            if not isinstance(record, dict):
                continue
            for advisory in parse_record(record, ecosystem):
                index[advisory.source_package].append(advisory)
    return dict(index)


def find_findings(
    packages: list[Package], index: dict[str, list[Advisory]]
) -> list[Finding]:
    """Match installed packages against advisories.

    A package is affected when no fix exists yet, or when its installed *source*
    version is older than the fixed version.
    """
    findings: list[Finding] = []
    for pkg in packages:
        source = pkg.source_name or pkg.name.split(":")[0]
        installed = pkg.source_version or pkg.version
        for advisory in index.get(source, []):
            fixed = advisory.fixed_version
            if fixed is not None and debversion.compare(installed, fixed) >= 0:
                continue  # already patched
            findings.append(
                Finding(
                    cve_id=advisory.cve_id,
                    package=pkg.name,
                    source_package=source,
                    installed_version=installed,
                    fixed_version=fixed,
                    summary=advisory.summary,
                    requires_subscription=advisory.requires_subscription,
                )
            )
    return sorted(findings, key=lambda f: (f.cve_id, f.package), reverse=True)
