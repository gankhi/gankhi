"""Read Ubuntu vulnerability records (OSV format) and match them to installed packages.

Input is Canonical's ``osv-all.tar.xz`` feed: one JSON record per CVE. Everything
here runs on the local machine; nothing about your packages is sent anywhere.

How a record is interpreted (checked against the real feed):
- ``withdrawn`` records are skipped.
- For each release, an ``affected`` entry names a *source* package.
  - With a ``fixed`` version: affected if the installed version is older.
  - Without ``fixed``: no fix has been released, and the entry lists the exact
    affected source versions in ``versions``; affected only if installed is one of them.
- A matching entry under the ``Ubuntu:Pro:<release>`` ecosystem means a fix exists
  but needs an Ubuntu Pro subscription.

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
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from ganki import debversion
from ganki.collectors.apt import Package
from ganki.release import pro_ecosystem

MAX_RECORD_BYTES = 2 * 1024 * 1024  # a single CVE record is far smaller than this
MAX_MEMBERS = 500_000  # the feed has tens of thousands of files
SUMMARY_CHARS = 240

# Ubuntu priority, most urgent first. Unknown priorities sort last.
PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4}


@dataclass(frozen=True)
class Advisory:
    """One CVE as it applies to one source package on one Ubuntu release."""

    cve_id: str  # e.g. "CVE-2025-6491"
    summary: str
    priority: str  # Ubuntu priority ("high", "medium", ...) or "" if not given
    source_package: str
    fixed_version: str | None  # None: no fixed version has been released
    affected_versions: frozenset[str]  # exact vulnerable versions (used when no fix)
    pro_fixed_version: str | None = None  # fix that needs an Ubuntu Pro subscription


@dataclass(frozen=True)
class Finding:
    """An installed source package (at one version) affected by one CVE."""

    cve_id: str
    source_package: str
    packages: tuple[str, ...]  # installed binary packages built from that source
    installed_version: str
    fixed_version: str | None
    pro_fixed_version: str | None
    priority: str
    summary: str

    @property
    def status(self) -> str:
        """``fix_available``, ``fix_with_pro`` or ``no_fix``."""
        if self.fixed_version is not None:
            return "fix_available"
        if self.pro_fixed_version is not None:
            return "fix_with_pro"
        return "no_fix"


def _fixed_version(affected: dict[str, Any]) -> str | None:
    """First ``fixed`` event found in the affected entry's ranges, if any."""
    for version_range in affected.get("ranges", []):
        for event in version_range.get("events", []):
            fixed = event.get("fixed")
            if isinstance(fixed, str) and fixed:
                return fixed
    return None


def _summary(record: dict[str, Any]) -> str:
    """First non-empty line of ``details`` (records have no ``summary`` field)."""
    text = record.get("summary") or record.get("details") or ""
    for line in str(text).splitlines():
        line = line.strip()
        if line:
            return line[:SUMMARY_CHARS]
    return ""


def _priority(record: dict[str, Any]) -> str:
    """Ubuntu's own priority from the ``severity`` list (``type`` == ``Ubuntu``)."""
    severity = record.get("severity")
    if not isinstance(severity, list):
        return ""
    for item in severity:
        if isinstance(item, dict) and item.get("type") == "Ubuntu":
            return str(item.get("score", "")).strip().lower()
    return ""


def _versions(affected: dict[str, Any]) -> frozenset[str]:
    versions = affected.get("versions")
    if not isinstance(versions, list):
        return frozenset()
    return frozenset(v for v in versions if isinstance(v, str))


def parse_record(record: dict[str, Any], ecosystem: str) -> list[Advisory]:
    """Extract advisories for ``ecosystem`` from one OSV record (defensive parsing)."""
    if record.get("withdrawn"):
        return []
    cve_id = str(record.get("id", "")).removeprefix("UBUNTU-")
    if not cve_id.startswith("CVE-"):
        return []
    summary = _summary(record)
    priority = _priority(record)
    pro = pro_ecosystem(ecosystem)

    plain: dict[str, Advisory] = {}
    pro_fixed: dict[str, str] = {}
    for affected in record.get("affected", []):
        package = affected.get("package") or {}
        name = package.get("name")
        if not name:
            continue
        name = str(name)
        if package.get("ecosystem") == ecosystem:
            entry = Advisory(
                cve_id=cve_id,
                summary=summary,
                priority=priority,
                source_package=name,
                fixed_version=_fixed_version(affected),
                affected_versions=_versions(affected),
            )
            previous = plain.get(name)
            if previous is not None:  # same package listed twice: merge, keep any fix
                entry = replace(
                    entry,
                    fixed_version=entry.fixed_version or previous.fixed_version,
                    affected_versions=entry.affected_versions | previous.affected_versions,
                )
            plain[name] = entry
        elif package.get("ecosystem") == pro:
            fixed = _fixed_version(affected)
            if fixed:
                pro_fixed[name] = fixed
    return [replace(adv, pro_fixed_version=pro_fixed.get(name)) for name, adv in plain.items()]


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


def _is_affected(advisory: Advisory, installed: str) -> bool:
    """Is this installed source version vulnerable to the advisory?"""
    if advisory.fixed_version is not None:
        return debversion.compare(installed, advisory.fixed_version) < 0
    # No fix released: only the exact versions listed in the record are affected.
    return installed in advisory.affected_versions


def find_findings(packages: list[Package], index: dict[str, list[Advisory]]) -> list[Finding]:
    """Match installed packages against advisories.

    Results are grouped per (CVE, source package, installed version), so a source
    package that builds many binaries (like the kernel) is reported once.
    """
    groups: dict[tuple[str, str, str], tuple[Advisory, list[str]]] = {}
    for pkg in packages:
        source = pkg.source_name or pkg.name.split(":")[0]
        installed = pkg.source_version or pkg.version
        for advisory in index.get(source, []):
            if not _is_affected(advisory, installed):
                continue
            key = (advisory.cve_id, source, installed)
            groups.setdefault(key, (advisory, []))[1].append(pkg.name)

    findings = [
        Finding(
            cve_id=cve_id,
            source_package=source,
            packages=tuple(sorted(set(names))),
            installed_version=installed,
            fixed_version=advisory.fixed_version,
            pro_fixed_version=advisory.pro_fixed_version,
            priority=advisory.priority,
            summary=advisory.summary,
        )
        for (cve_id, source, installed), (advisory, names) in groups.items()
    ]
    return sorted(
        findings,
        key=lambda f: (
            PRIORITY_ORDER.get(f.priority, len(PRIORITY_ORDER)),
            f.cve_id,
            f.source_package,
        ),
    )
