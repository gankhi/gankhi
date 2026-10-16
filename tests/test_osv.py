# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for reading the OSV feed and matching it to installed packages.

The feed is simulated with small in-memory archives; no network is used.
"""

import io
import json
import tarfile

from ganki.collectors.apt import Package
from ganki.osv import MAX_RECORD_BYTES, find_findings, load_advisories, parse_record

ECOSYSTEM = "Ubuntu:24.04:LTS"


def make_record(
    cve="UBUNTU-CVE-2025-6491",
    ecosystem=ECOSYSTEM,
    name="php8.3",
    fixed="8.3.6-0ubuntu0.24.04.5",
    availability="No subscription required",
):
    events = [{"introduced": "0"}]
    if fixed:
        events.append({"fixed": fixed})
    return {
        "id": cve,
        "summary": "SOAP parsing crash",
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": name},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
                "ecosystem_specific": {"availability": availability},
            }
        ],
    }


def make_archive(path, members):
    """Build a .tar.xz from ``members``: list of (name, bytes) or a TarInfo + bytes."""
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


# ---------- parse_record ----------


def test_parse_record_extracts_fixed_version_and_cve_id():
    (advisory,) = parse_record(make_record(), ECOSYSTEM)
    assert advisory.cve_id == "CVE-2025-6491"
    assert advisory.source_package == "php8.3"
    assert advisory.fixed_version == "8.3.6-0ubuntu0.24.04.5"
    assert advisory.requires_subscription is False


def test_parse_record_without_fix_has_none():
    (advisory,) = parse_record(make_record(fixed=None), ECOSYSTEM)
    assert advisory.fixed_version is None


def test_parse_record_ignores_other_ecosystems():
    assert parse_record(make_record(ecosystem="Ubuntu:22.04:LTS"), ECOSYSTEM) == []


def test_parse_record_ignores_non_cve_ids():
    assert parse_record(make_record(cve="USN-1234-1"), ECOSYSTEM) == []


def test_parse_record_flags_subscription_only_fixes():
    record = make_record(availability="Available with Ubuntu Pro")
    (advisory,) = parse_record(record, ECOSYSTEM)
    assert advisory.requires_subscription is True


def test_parse_record_survives_garbage_fields():
    record = {"id": "UBUNTU-CVE-2025-1", "affected": [{"package": None}, {"package": {}}]}
    assert parse_record(record, ECOSYSTEM) == []


# ---------- load_advisories ----------


def test_load_advisories_indexes_by_source_package(tmp_path):
    archive = tmp_path / "feed.tar.xz"
    make_archive(
        archive,
        [
            ("osv/cve/2025/UBUNTU-CVE-2025-6491.json", json.dumps(make_record()).encode()),
            (
                "osv/cve/2025/UBUNTU-CVE-2025-1111.json",
                json.dumps(make_record(cve="UBUNTU-CVE-2025-1111", name="openssl")).encode(),
            ),
        ],
    )
    index = load_advisories(archive, ECOSYSTEM)
    assert set(index) == {"php8.3", "openssl"}


def test_load_advisories_skips_bad_members_without_failing(tmp_path):
    archive = tmp_path / "feed.tar.xz"
    huge = b" " * (MAX_RECORD_BYTES + 1)
    link = tarfile.TarInfo("osv/cve/2025/UBUNTU-CVE-2025-2222.json")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    make_archive(
        archive,
        [
            ("osv/cve/2025/UBUNTU-CVE-2025-3333.json", b"{ not json"),  # broken JSON
            ("osv/cve/2025/UBUNTU-CVE-2025-4444.json", huge),  # too large
            ("osv/cve/2025/UBUNTU-CVE-2025-5555.json", b"[1, 2, 3]"),  # not an object
            ("../../escape/UBUNTU-CVE-2025-6666.json", json.dumps(make_record()).encode()),
            (link, b""),  # symlink: must not be followed
            ("osv/usn/USN-0001-1.json", json.dumps(make_record()).encode()),  # not a CVE file
        ],
    )
    index = load_advisories(archive, ECOSYSTEM)
    # Only the file with a traversal-looking path is read (by basename, in memory),
    # and nothing is ever written outside the archive.
    assert list(index) == ["php8.3"]
    assert not (tmp_path.parent / "escape").exists()


# ---------- find_findings ----------


def index_for(**kwargs):
    index = {}
    for advisory in parse_record(make_record(**kwargs), ECOSYSTEM):
        index.setdefault(advisory.source_package, []).append(advisory)
    return index


def test_older_installed_version_is_affected():
    installed = pkg("php8.3-cli", "x", "php8.3", "8.3.6-0ubuntu0.24.04.4")
    findings = find_findings([installed], index_for())
    assert [(f.cve_id, f.package) for f in findings] == [("CVE-2025-6491", "php8.3-cli")]
    assert findings[0].fixed_version == "8.3.6-0ubuntu0.24.04.5"


def test_fixed_or_newer_version_is_not_affected():
    for version in ("8.3.6-0ubuntu0.24.04.5", "8.3.6-0ubuntu0.24.04.6"):
        assert find_findings([pkg("php8.3", version)], index_for()) == []


def test_no_fix_released_is_reported_with_none():
    findings = find_findings([pkg("php8.3", "8.3.6-0ubuntu0.24.04.9")], index_for(fixed=None))
    assert len(findings) == 1
    assert findings[0].fixed_version is None


def test_unrelated_packages_are_ignored():
    assert find_findings([pkg("bash", "5.2")], index_for()) == []


def test_matching_uses_source_package_not_binary_name():
    binary = pkg("libphp8.3-embed", "8.3.6-0ubuntu0.24.04.4", source="php8.3")
    assert len(find_findings([binary], index_for())) == 1
