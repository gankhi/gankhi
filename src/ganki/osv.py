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
import logging
import os
import re
import tarfile
import tempfile
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

# Ubuntu ships some apps (Firefox, Thunderbird, ...) as a snap and keeps a tiny
# transitional .deb with a version like "2:1snap1-0ubuntu3". That version says
# nothing about the real app, so comparing it with CVE records gives false hits.
_SNAP_STUB = re.compile(r"\dsnap\d")


def is_snap_stub(version: str) -> bool:
    """Is this the placeholder .deb of an app that is really installed as a snap?"""
    return _SNAP_STUB.search(version) is not None


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


INDEX_FORMAT = 1
log = logging.getLogger(__name__)


def _index_path(archive: Path, ecosystem: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9.]+", "-", ecosystem).strip("-")
    return archive.with_name(f"osv-index-{safe}.json")


def _archive_stamp(archive: Path) -> list[int]:
    stat = archive.stat()
    return [INDEX_FORMAT, stat.st_size, stat.st_mtime_ns]


def _advisory_to_list(a: Advisory) -> list[Any]:
    return [
        a.cve_id,
        a.summary,
        a.priority,
        a.source_package,
        a.fixed_version,
        sorted(a.affected_versions),
        a.pro_fixed_version,
    ]


def _advisory_from_list(row: list[Any]) -> Advisory:
    cve_id, summary, priority, source, fixed, versions, pro = row
    if not all(isinstance(x, str) for x in (cve_id, summary, priority, source)):
        raise ValueError("bad advisory")
    if not (fixed is None or isinstance(fixed, str)) or not (pro is None or isinstance(pro, str)):
        raise ValueError("bad advisory")
    if not isinstance(versions, list) or not all(isinstance(v, str) for v in versions):
        raise ValueError("bad advisory")
    return Advisory(cve_id, summary, priority, source, fixed, frozenset(versions), pro)


def _read_index(path: Path, stamp: list[int]) -> dict[str, list[Advisory]] | None:
    """The saved index, or ``None`` if it is missing, stale or damaged (then it is rebuilt)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("stamp") != stamp:
            return None
        return {
            str(name): [_advisory_from_list(row) for row in rows]
            for name, rows in data["advisories"].items()
        }
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None


def _write_index(path: Path, stamp: list[int], index: dict[str, list[Advisory]]) -> None:
    payload = {
        "stamp": stamp,
        "advisories": {n: [_advisory_to_list(a) for a in rows] for n, rows in index.items()},
    }
    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="osv-index-", suffix=".part")  # 600
    except OSError:
        return  # a read-only cache folder only costs speed
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"))
        os.replace(tmp, path)  # atomic: a half-written index is never read
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def load_advisories(archive: Path, ecosystem: str) -> dict[str, list[Advisory]]:
    """Advisories indexed by source package name.

    Reading the whole archive is slow, so the result is saved next to it and reused until
    the archive changes (a new feed is downloaded).
    """
    index_file = _index_path(archive, ecosystem)
    stamp = _archive_stamp(archive)
    saved = _read_index(index_file, stamp)
    if saved is not None:
        return saved
    index = _parse_archive(archive, ecosystem)
    try:
        _write_index(index_file, stamp, index)
    except OSError:
        log.warning("Could not save the advisory index; the next scan will be slower.")
    return index


def _parse_archive(archive: Path, ecosystem: str) -> dict[str, list[Advisory]]:
    """Read the feed archive (slow: decompresses and parses every record)."""
    index: dict[str, list[Advisory]] = defaultdict(list)
    needle = ecosystem.encode()
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
            raw = handle.read()
            if needle not in raw:
                continue  # the record does not mention this release: skip the JSON parse
            try:
                record = json.loads(raw)
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
        if is_snap_stub(installed):
            continue
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
