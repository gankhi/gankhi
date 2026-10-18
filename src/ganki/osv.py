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
import multiprocessing
import os
import re
import sqlite3
import tarfile
import tempfile
from collections import deque
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import Future, ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
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
            return _shorten(line)
    return ""


def _shorten(line: str) -> str:
    """Cut a long line at the last whole word and say that it was cut."""
    if len(line) <= SUMMARY_CHARS:
        return line
    cut = line[:SUMMARY_CHARS]
    if line[SUMMARY_CHARS] != " " and " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut.rstrip(" ,;:") + "…"


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


INDEX_FORMAT = 2
CHUNK_RECORDS = 300  # records handed to one worker at a time
MAX_WORKERS = 4
log = logging.getLogger(__name__)


def _index_path(archive: Path, ecosystem: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9.]+", "-", ecosystem).strip("-")
    return archive.with_name(f"osv-index-{safe}.sqlite")


def _archive_stamp(archive: Path) -> str:
    stat = archive.stat()
    return f"{INDEX_FORMAT}:{stat.st_size}:{stat.st_mtime_ns}"


def _advisory_to_row(a: Advisory) -> tuple[Any, ...]:
    return (
        a.source_package,
        a.cve_id,
        a.summary,
        a.priority,
        a.fixed_version,
        # the exact versions only matter when no fix was published (see _is_affected)
        json.dumps(
            sorted(a.affected_versions) if a.fixed_version is None else [], separators=(",", ":")
        ),
        a.pro_fixed_version,
    )


def _advisory_from_row(row: tuple[Any, ...]) -> Advisory:
    source, cve_id, summary, priority, fixed, versions, pro = row
    return Advisory(
        cve_id=cve_id,
        summary=summary,
        priority=priority,
        source_package=source,
        fixed_version=fixed,
        affected_versions=frozenset(json.loads(versions)),
        pro_fixed_version=pro,
    )


_COLUMNS = "source, cve, summary, priority, fixed, versions, pro"


class AdvisoryIndex(Mapping[str, list[Advisory]]):
    """Advisories by source package, read from the saved index on demand.

    Only the packages that are asked for are read, so opening it is instant and it does
    not hold the whole feed in memory.
    """

    def __init__(self, path: Path) -> None:
        self._db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)

    def __getitem__(self, name: str) -> list[Advisory]:
        rows = self._db.execute(
            f"SELECT {_COLUMNS} FROM adv WHERE source = ? ORDER BY rowid",  # noqa: S608
            (name,),
        ).fetchall()
        if not rows:
            raise KeyError(name)
        return [_advisory_from_row(row) for row in rows]

    def __iter__(self) -> Iterator[str]:
        for (name,) in self._db.execute("SELECT DISTINCT source FROM adv ORDER BY source"):
            yield name

    def __len__(self) -> int:
        return int(self._db.execute("SELECT COUNT(DISTINCT source) FROM adv").fetchone()[0])

    def close(self) -> None:
        self._db.close()


def _open_if_current(path: Path, stamp: str) -> AdvisoryIndex | None:
    """The saved index, or ``None`` if it is missing, stale or damaged (then it is rebuilt)."""
    if not path.is_file():
        return None
    try:
        index = AdvisoryIndex(path)
        row = index._db.execute("SELECT value FROM meta WHERE key = 'stamp'").fetchone()
        if row is None or row[0] != stamp:
            index.close()
            return None
        return index
    except sqlite3.Error:
        return None


def _rows_from_raw(chunk: list[bytes], ecosystem: str) -> list[tuple[Any, ...]]:
    """Parse a batch of raw records into rows. Runs in a worker process (so it is top-level)."""
    rows: list[tuple[Any, ...]] = []
    for raw in chunk:
        try:
            record = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            continue  # one broken record must not stop the scan
        if isinstance(record, dict):
            rows.extend(_advisory_to_row(a) for a in parse_record(record, ecosystem))
    return rows


def _raw_records(
    archive: Path, ecosystem: str, on_progress: Callable[[float], None] | None
) -> Iterator[bytes]:
    """The raw JSON of every record that mentions this release (slow: decompresses it all)."""
    needle = ecosystem.encode()
    total = max(archive.stat().st_size, 1)
    with archive.open("rb") as raw, tarfile.open(fileobj=raw, mode="r:xz") as tar:
        for count, member in enumerate(tar):
            if count >= MAX_MEMBERS:
                break
            if on_progress and count % 500 == 0:
                on_progress(min(raw.tell() / total, 0.99))  # how much of the file was read
            name = Path(member.name).name
            if not (member.isfile() and name.startswith("UBUNTU-CVE-") and name.endswith(".json")):
                continue
            if member.size > MAX_RECORD_BYTES:
                continue
            handle = tar.extractfile(member)  # in-memory read, nothing written to disk
            if handle is None:
                continue
            data = handle.read()
            if needle in data:  # a record that does not mention this release is skipped
                yield data


def _make_pool() -> ProcessPoolExecutor | None:
    workers = min(MAX_WORKERS, os.cpu_count() or 1)
    if workers < 2:
        return None
    try:
        return ProcessPoolExecutor(
            max_workers=workers, mp_context=multiprocessing.get_context("spawn")
        )
    except (OSError, ValueError):
        return None


def _build_index(
    archive: Path,
    ecosystem: str,
    target: Path,
    stamp: str,
    on_progress: Callable[[float], None] | None,
) -> None:
    """Read the archive and save the index to ``target`` (parsing in several processes)."""
    fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix="osv-index-", suffix=".part")
    os.close(fd)  # created as 600
    tmp = Path(tmp_name)
    pool: ProcessPoolExecutor | None = None
    try:
        db = sqlite3.connect(tmp)
        db.execute(
            "CREATE TABLE adv (source TEXT, cve TEXT, summary TEXT, priority TEXT,"
            " fixed TEXT, versions TEXT, pro TEXT)"
        )
        db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        pending: deque[tuple[Future[list[tuple[Any, ...]]], list[bytes]]] = deque()
        broken = False

        def store(rows: list[tuple[Any, ...]]) -> None:
            db.executemany("INSERT INTO adv VALUES (?,?,?,?,?,?,?)", rows)

        def drain(limit: int) -> None:
            nonlocal broken
            while len(pending) > limit:
                future, batch = pending.popleft()
                try:
                    store(future.result())
                except (BrokenProcessPool, OSError):
                    broken = True  # the workers could not run: do this batch here instead
                    store(_rows_from_raw(batch, ecosystem))

        def submit(chunk: list[bytes]) -> None:
            nonlocal pool, broken
            if pool is None and not broken and len(chunk) == CHUNK_RECORDS:
                pool = _make_pool()
                broken = pool is None
            if pool is None or broken:
                store(_rows_from_raw(chunk, ecosystem))
                return
            try:
                pending.append((pool.submit(_rows_from_raw, chunk, ecosystem), chunk))
            except (BrokenProcessPool, OSError, RuntimeError):
                broken = True
                store(_rows_from_raw(chunk, ecosystem))
                return
            drain(MAX_WORKERS * 2)  # keep only a few batches in memory at a time

        chunk: list[bytes] = []
        for data in _raw_records(archive, ecosystem, on_progress):
            chunk.append(data)
            if len(chunk) >= CHUNK_RECORDS:
                submit(chunk)
                chunk = []
        if chunk:
            submit(chunk)
        drain(0)
        db.execute("CREATE INDEX adv_source ON adv (source)")
        db.execute("INSERT INTO meta VALUES ('stamp', ?)", (stamp,))
        db.commit()
        db.close()
        os.replace(tmp, target)  # atomic: a half-written index is never read
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    finally:
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)


def load_advisories(
    archive: Path,
    ecosystem: str,
    on_progress: Callable[[float], None] | None = None,
) -> AdvisoryIndex:
    """Advisories indexed by source package name.

    Reading the whole archive is slow, so the result is saved next to it as a small
    database and reused until the archive changes (a new feed is downloaded).
    """
    target = _index_path(archive, ecosystem)
    stamp = _archive_stamp(archive)
    current = _open_if_current(target, stamp)
    if current is None:
        _build_index(archive, ecosystem, target, stamp, on_progress)
        for old in archive.parent.glob("osv-index-*.json"):  # saved by an earlier version
            old.unlink(missing_ok=True)
        current = AdvisoryIndex(target)
    if on_progress:
        on_progress(1.0)
    return current


def _is_affected(advisory: Advisory, installed: str) -> bool:
    """Is this installed source version vulnerable to the advisory?"""
    if advisory.fixed_version is not None:
        return debversion.compare(installed, advisory.fixed_version) < 0
    # No fix released: only the exact versions listed in the record are affected.
    return installed in advisory.affected_versions


def find_findings(packages: list[Package], index: Mapping[str, list[Advisory]]) -> list[Finding]:
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
