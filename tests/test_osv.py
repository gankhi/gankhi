# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for reading the OSV feed and matching it to installed packages.

Fixtures mirror the shape of real records from Canonical's feed (a fixed entry
with ``binaries``, an unfixed entry with a ``versions`` list, a withdrawn record,
the ``severity`` list and the Pro ecosystem). No network is used.
"""

import io
import json
import tarfile

from ganki.collectors.apt import Package
from ganki.osv import MAX_RECORD_BYTES, find_findings, is_snap_stub, load_advisories, parse_record

ECOSYSTEM = "Ubuntu:24.04:LTS"
PRO = "Ubuntu:Pro:24.04:LTS"


def affected_entry(name, ecosystem=ECOSYSTEM, fixed=None, versions=()):
    events = [{"introduced": "0"}]
    if fixed:
        events.append({"fixed": fixed})
    entry = {
        "package": {"ecosystem": ecosystem, "name": name},
        "ranges": [{"type": "ECOSYSTEM", "events": events}],
        "versions": list(versions),
    }
    if fixed:
        entry["ecosystem_specific"] = {"availability": "No subscription required"}
    return entry


def make_record(cve="UBUNTU-CVE-2025-6491", affected=None, priority="medium", **extra):
    record = {
        "id": cve,
        "details": "\nSOAP parsing crash in the XML namespace handling.\n\nMore text here.",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"},
            {"type": "Ubuntu", "score": priority},
        ],
        "affected": affected
        if affected is not None
        else [
            affected_entry(
                "php8.3", fixed="8.3.6-0ubuntu0.24.04.5", versions=["8.3.6-0ubuntu0.24.04.4"]
            )
        ],
    }
    record.update(extra)
    return record


def make_archive(path, members):
    """Build a .tar.xz from ``members``: list of (name, bytes) or (TarInfo, bytes)."""
    with tarfile.open(path, "w:xz") as tar:
        for item in members:
            if isinstance(item[0], tarfile.TarInfo):
                info, data = item
            else:
                info = tarfile.TarInfo(item[0])
                data = item[1]
                info.size = len(data)
            tar.addfile(info, io.BytesIO(data) if info.isfile() else None)


def pkg(name, version, source=None, source_version=None):
    return Package(
        name=name,
        version=version,
        architecture="amd64",
        size_kib=1,
        description="",
        source_name=source or name,
        source_version=source_version or version,
    )


def index_for(record):
    index = {}
    for advisory in parse_record(record, ECOSYSTEM):
        index.setdefault(advisory.source_package, []).append(advisory)
    return index


# ---------- parse_record ----------


def test_parse_record_extracts_fix_priority_and_summary():
    (advisory,) = parse_record(make_record(), ECOSYSTEM)
    assert advisory.cve_id == "CVE-2025-6491"
    assert advisory.source_package == "php8.3"
    assert advisory.fixed_version == "8.3.6-0ubuntu0.24.04.5"
    assert advisory.priority == "medium"
    assert advisory.summary == "SOAP parsing crash in the XML namespace handling."


def test_withdrawn_records_are_skipped():
    assert parse_record(make_record(withdrawn="2025-06-23T15:52:32Z"), ECOSYSTEM) == []


def test_unfixed_entry_keeps_its_affected_versions():
    record = make_record(affected=[affected_entry("wordpress", versions=["6.2+dfsg1-1ubuntu1"])])
    (advisory,) = parse_record(record, ECOSYSTEM)
    assert advisory.fixed_version is None
    assert advisory.affected_versions == {"6.2+dfsg1-1ubuntu1"}


def test_other_ecosystems_are_ignored():
    record = make_record(
        affected=[affected_entry("php8.1", ecosystem="Ubuntu:22.04:LTS", fixed="1")]
    )
    assert parse_record(record, ECOSYSTEM) == []


def test_non_cve_ids_are_ignored():
    assert parse_record(make_record(cve="USN-1234-1"), ECOSYSTEM) == []


def test_missing_priority_is_empty_string():
    record = make_record()
    del record["severity"]
    assert parse_record(record, ECOSYSTEM)[0].priority == ""


def test_pro_fix_is_attached_to_the_plain_entry():
    record = make_record(
        affected=[
            affected_entry("libfoo", versions=["1.0-1"]),
            affected_entry("libfoo", ecosystem=PRO, fixed="1.0-1ubuntu0.1~esm1"),
        ]
    )
    (advisory,) = parse_record(record, ECOSYSTEM)
    assert advisory.fixed_version is None
    assert advisory.pro_fixed_version == "1.0-1ubuntu0.1~esm1"


def test_pro_entry_alone_creates_no_advisory():
    record = make_record(affected=[affected_entry("libfoo", ecosystem=PRO, fixed="1")])
    assert parse_record(record, ECOSYSTEM) == []


def test_parse_record_survives_garbage_fields():
    record = {
        "id": "UBUNTU-CVE-2025-1",
        "severity": "x",
        "affected": [{"package": None}, {"package": {}}],
    }
    assert parse_record(record, ECOSYSTEM) == []


# ---------- load_advisories ----------


def test_load_advisories_indexes_by_source_package(tmp_path):
    archive = tmp_path / "feed.tar.xz"
    other = make_record(
        cve="UBUNTU-CVE-2025-1111", affected=[affected_entry("openssl", fixed="3.0.13-1")]
    )
    make_archive(
        archive,
        [
            ("osv/cve/2025/UBUNTU-CVE-2025-6491.json", json.dumps(make_record()).encode()),
            ("osv/cve/2025/UBUNTU-CVE-2025-1111.json", json.dumps(other).encode()),
        ],
    )
    assert set(load_advisories(archive, ECOSYSTEM)) == {"php8.3", "openssl"}


def test_load_advisories_skips_bad_members_without_failing(tmp_path):
    archive = tmp_path / "feed.tar.xz"
    link = tarfile.TarInfo("osv/cve/2025/UBUNTU-CVE-2025-2222.json")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    make_archive(
        archive,
        [
            ("osv/cve/2025/UBUNTU-CVE-2025-3333.json", b"{ not json"),  # broken JSON
            ("osv/cve/2025/UBUNTU-CVE-2025-4444.json", b" " * (MAX_RECORD_BYTES + 1)),  # too large
            ("osv/cve/2025/UBUNTU-CVE-2025-5555.json", b"[1, 2, 3]"),  # not an object
            ("../../escape/UBUNTU-CVE-2025-6666.json", json.dumps(make_record()).encode()),
            (link, b""),  # symlink: must not be followed
            ("osv/usn/USN-0001-1.json", json.dumps(make_record()).encode()),  # not a CVE file
        ],
    )
    index = load_advisories(archive, ECOSYSTEM)
    # The traversal-looking name is read by basename, in memory; nothing is written to disk.
    assert list(index) == ["php8.3"]
    assert not (tmp_path.parent / "escape").exists()


# ---------- find_findings ----------


def test_older_installed_version_is_affected_with_a_fix():
    installed = pkg("php8.3-cli", "x", "php8.3", "8.3.6-0ubuntu0.24.04.4")
    (finding,) = find_findings([installed], index_for(make_record()))
    assert finding.cve_id == "CVE-2025-6491"
    assert finding.packages == ("php8.3-cli",)
    assert finding.status == "fix_available"


def test_fixed_or_newer_version_is_not_affected():
    for version in ("8.3.6-0ubuntu0.24.04.5", "8.3.6-0ubuntu0.24.04.6"):
        assert find_findings([pkg("php8.3", version)], index_for(make_record())) == []


def test_unfixed_only_affects_versions_listed_in_the_record():
    record = make_record(affected=[affected_entry("wordpress", versions=["6.4.3+dfsg1-1ubuntu1"])])
    listed = find_findings([pkg("wordpress", "6.4.3+dfsg1-1ubuntu1")], index_for(record))
    unlisted = find_findings([pkg("wordpress", "9.9-1")], index_for(record))
    assert [f.status for f in listed] == ["no_fix"]
    assert unlisted == []


def test_unfixed_with_pro_fix_reports_subscription_status():
    record = make_record(
        affected=[
            affected_entry("libfoo", versions=["1.0-1"]),
            affected_entry("libfoo", ecosystem=PRO, fixed="1.0-1ubuntu0.1~esm1"),
        ]
    )
    (finding,) = find_findings([pkg("libfoo", "1.0-1")], index_for(record))
    assert finding.status == "fix_with_pro"


def test_binaries_of_one_source_are_grouped_into_one_finding():
    record = make_record(affected=[affected_entry("linux", fixed="6.8.0-90.91")])
    kernel = [
        pkg("linux-tools-6.8.0-31", "6.8.0-31.31", "linux", "6.8.0-31.31"),
        pkg("linux-tools-6.8.0-31-generic", "6.8.0-31.31", "linux", "6.8.0-31.31"),
        pkg("linux-tools-6.8.0-35", "6.8.0-35.35", "linux", "6.8.0-35.35"),
    ]
    findings = find_findings(kernel, index_for(record))
    # One finding per installed *version* of the source, not one per binary package.
    assert len(findings) == 2
    first = next(f for f in findings if f.installed_version == "6.8.0-31.31")
    assert first.packages == ("linux-tools-6.8.0-31", "linux-tools-6.8.0-31-generic")


def test_unrelated_packages_are_ignored():
    assert find_findings([pkg("bash", "5.2")], index_for(make_record())) == []


def test_matching_uses_source_package_not_binary_name():
    binary = pkg("libphp8.3-embed", "x", source="php8.3", source_version="8.3.6-0ubuntu0.24.04.4")
    assert len(find_findings([binary], index_for(make_record()))) == 1


def test_most_urgent_findings_come_first():
    low = make_record(
        cve="UBUNTU-CVE-2025-0001", priority="low", affected=[affected_entry("a", fixed="2")]
    )
    high = make_record(
        cve="UBUNTU-CVE-2025-0002", priority="high", affected=[affected_entry("b", fixed="2")]
    )
    index = {**index_for(low), **index_for(high)}
    findings = find_findings([pkg("a", "1"), pkg("b", "1")], index)
    assert [f.priority for f in findings] == ["high", "low"]


def test_snap_placeholder_packages_are_not_matched():
    record = make_record(affected=[affected_entry("thunderbird", fixed="2:999-0ubuntu1")])
    stub = pkg("thunderbird", "2:1snap1-0ubuntu3")
    assert find_findings([stub], index_for(record)) == []


def test_is_snap_stub_only_matches_the_placeholder_pattern():
    assert is_snap_stub("2:1snap1-0ubuntu3")
    assert is_snap_stub("1:1snap1-0ubuntu2")
    assert not is_snap_stub("128.0-1ubuntu1")
    assert not is_snap_stub("2.76+ubuntu24.04")
