"""Match pip and npm packages against the public OSV lists (PyPI and npm).

Same idea as the Ubuntu check: the list is downloaded (a public file) and compared on this
computer, so the names and versions of what you have installed are never sent anywhere.

How a record is read (the OSV format, https://ossf.github.io/osv-schema/):
- ``withdrawn`` records are skipped.
- An ``affected`` entry names a package and gives ranges of versions (``introduced`` up to,
  not including, ``fixed``; or up to and including ``last_affected``) and sometimes a list
  of exact versions. Only the ``ECOSYSTEM`` and ``SEMVER`` ranges are used.
- ``MAL-`` records are packages that were published to steal or damage; they count as
  critical and the only advice is to remove them.

Safety: the archive is read in memory, never extracted; each record is size-capped; the
number of members is capped; JSON is parsed with the standard library.
"""

from __future__ import annotations

import json
import logging
import math
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ganki import versions
from ganki.collectors.external import NPM_ECOSYSTEM, PYPI, ExternalPackage, normalize_python_name

log = logging.getLogger(__name__)

FEED_URLS = {
    PYPI: "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
    NPM_ECOSYSTEM: "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
}
MAX_RECORD_BYTES = 2 * 1024 * 1024
MAX_MEMBERS = 2_000_000
SUMMARY_CHARS = 240
_LABELS = {
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
}


@dataclass(frozen=True)
class ExternalFinding:
    """One advisory that applies to one installed pip or npm package."""

    ecosystem: str
    name: str
    version: str
    advisory_id: str
    cve_id: str  # "" when the record has no CVE alias
    summary: str
    priority: str  # critical / high / medium / low, or "" when the record gives none
    fixed_version: str | None  # None: no fixed version (or a malicious package: remove it)
    malicious: bool = False

    @property
    def key(self) -> str:
        return self.cve_id or self.advisory_id


# --- severity ------------------------------------------------------------------------------
_CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _round_up(value: float) -> float:
    return math.ceil(value * 10 - 1e-9) / 10


def cvss3_score(vector: str) -> float | None:
    """The base score (0-10) of a CVSS v3.x vector, or ``None`` if it cannot be read."""
    if not vector.startswith("CVSS:3"):
        return None
    parts = dict(item.split(":", 1) for item in vector.split("/")[1:] if ":" in item)
    try:
        changed = parts["S"] == "C"
        privileges = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}
        exploit = (
            8.22
            * _CVSS3_WEIGHTS["AV"][parts["AV"]]
            * _CVSS3_WEIGHTS["AC"][parts["AC"]]
            * privileges[parts["PR"]]
            * _CVSS3_WEIGHTS["UI"][parts["UI"]]
        )
        iss = 1 - (
            (1 - _CVSS3_WEIGHTS["C"][parts["C"]])
            * (1 - _CVSS3_WEIGHTS["I"][parts["I"]])
            * (1 - _CVSS3_WEIGHTS["A"][parts["A"]])
        )
    except KeyError:
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    return _round_up(min((impact + exploit) * (1.08 if changed else 1), 10))


def _score_priority(score: float) -> str:
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def record_priority(record: dict[str, Any]) -> str:
    """critical / high / medium / low from what the record says, or "" if it says nothing."""
    if str(record.get("id", "")).startswith("MAL-"):
        return "critical"
    specific = record.get("database_specific")
    label = specific.get("severity") if isinstance(specific, dict) else None
    if isinstance(label, str) and label.lower() in _LABELS:
        return _LABELS[label.lower()]
    for item in record.get("severity") or []:
        if isinstance(item, dict) and isinstance(item.get("score"), str):
            score = cvss3_score(item["score"])
            if score is not None:
                return _score_priority(score)
    return ""


# --- matching ------------------------------------------------------------------------------
def _summary(record: dict[str, Any]) -> str:
    text = record.get("summary") or record.get("details") or ""
    for line in str(text).splitlines():
        if line.strip():
            return line.strip()[:SUMMARY_CHARS]
    return ""


def _intervals(affected: dict[str, Any]) -> Iterable[tuple[str, str | None, str | None]]:
    """(introduced, fixed, last_affected) for each stretch of versions the entry covers."""
    for version_range in affected.get("ranges") or []:
        if version_range.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        introduced: str | None = None
        for event in version_range.get("events") or []:
            if "introduced" in event:
                introduced = str(event["introduced"])
            elif "fixed" in event and introduced is not None:
                yield introduced, str(event["fixed"]), None
                introduced = None
            elif "last_affected" in event and introduced is not None:
                yield introduced, None, str(event["last_affected"])
                introduced = None
        if introduced is not None:
            yield introduced, None, None


def affected_by(
    affected: dict[str, Any], ecosystem: str, installed: str
) -> tuple[bool, str | None]:
    """Is ``installed`` inside this entry? Also the version that fixes it, if known."""
    if installed in (affected.get("versions") or []):
        # An exact list says the version is affected; look for the fix in the ranges.
        fixes = [fixed for _intro, fixed, _last in _intervals(affected) if fixed]
        return True, _lowest_above(ecosystem, installed, fixes)
    current = versions.parse(ecosystem, installed)
    if current is None:
        return False, None
    for introduced, fixed, last in _intervals(affected):
        start = None if introduced == "0" else versions.parse(ecosystem, introduced)
        if introduced != "0" and start is None:
            continue
        if start is not None and current < start:
            continue
        if fixed is not None:
            end = versions.parse(ecosystem, fixed)
            if end is not None and current < end:
                return True, fixed
        elif last is not None:
            end = versions.parse(ecosystem, last)
            if end is not None and current <= end:
                return True, None
        else:
            return True, None
    return False, None


def _lowest_above(ecosystem: str, installed: str, fixes: list[str]) -> str | None:
    current = versions.parse(ecosystem, installed)
    above = [
        (parsed, text)
        for text in fixes
        if (parsed := versions.parse(ecosystem, text)) is not None
        and (current is None or parsed > current)
    ]
    return min(above, key=lambda pair: pair[0])[1] if above else None


def _record_name_key(ecosystem: str, name: str) -> str:
    return normalize_python_name(name) if ecosystem == PYPI else name


def find_external(
    archive: Path,
    ecosystem: str,
    packages: list[ExternalPackage],
    progress: Callable[[float], None] | None = None,
) -> list[ExternalFinding]:
    """Advisories of ``archive`` (an OSV ``all.zip``) that apply to ``packages``."""
    wanted = {_record_name_key(ecosystem, p.name): p for p in packages if p.ecosystem == ecosystem}
    found: dict[tuple[str, str], ExternalFinding] = {}
    if not wanted:
        return []
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > MAX_MEMBERS:
            raise ValueError("the vulnerability list has too many records")
        for number, member in enumerate(members):
            if progress is not None and number % 2000 == 0:
                progress(number / max(len(members), 1))
            if member.is_dir() or not member.filename.endswith(".json"):
                continue
            if member.file_size > MAX_RECORD_BYTES:
                continue
            try:
                record = json.loads(bundle.read(member))
            except ValueError:
                continue
            if not isinstance(record, dict) or record.get("withdrawn"):
                continue
            _collect(record, ecosystem, wanted, found)
    if progress is not None:
        progress(1.0)
    return sorted(found.values(), key=lambda f: (f.name, f.key))


def _collect(
    record: dict[str, Any],
    ecosystem: str,
    wanted: dict[str, ExternalPackage],
    found: dict[tuple[str, str], ExternalFinding],
) -> None:
    for affected in record.get("affected") or []:
        package = affected.get("package") if isinstance(affected, dict) else None
        if not isinstance(package, dict) or package.get("ecosystem") != ecosystem:
            continue
        installed = wanted.get(_record_name_key(ecosystem, str(package.get("name", ""))))
        if installed is None:
            continue
        hit, fixed = affected_by(affected, ecosystem, installed.version)
        if not hit:
            continue
        advisory_id = str(record.get("id", ""))
        cve = next((a for a in record.get("aliases") or [] if str(a).startswith("CVE-")), "")
        finding = ExternalFinding(
            ecosystem=ecosystem,
            name=installed.name,
            version=installed.version,
            advisory_id=advisory_id,
            cve_id=str(cve),
            summary=_summary(record),
            priority=record_priority(record),
            fixed_version=fixed,
            malicious=advisory_id.startswith("MAL-"),
        )
        slot = (installed.name, finding.key)
        old = found.get(slot)
        if old is None or (old.fixed_version is None and finding.fixed_version is not None):
            found[slot] = finding


# --- keeping the answer, so an unchanged list is not read again -----------------------------
def signature(packages: list[ExternalPackage], stamp: str) -> str:
    """Identifies "this list of packages against this version of the list"."""
    items = sorted(f"{p.ecosystem}\0{p.name}\0{p.version}" for p in packages)
    return stamp + "\n" + "\n".join(items)


def load_cached(path: Path, key: str) -> list[ExternalFinding] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("key") != key:
            return None
        return [ExternalFinding(**item) for item in data["findings"]]
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None


def save_cached(path: Path, key: str, findings: list[ExternalFinding]) -> None:
    data = {"key": key, "findings": [vars(f) for f in findings]}
    try:
        path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        log.info("could not keep the pip/npm answer", exc_info=True)
