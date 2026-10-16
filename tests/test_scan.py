# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Test the scan command wiring with all I/O replaced by fakes."""

from pathlib import Path

import ganki.scan as scan
from ganki.collectors.apt import Package
from ganki.feed import FeedStatus
from ganki.osv import Advisory
from ganki.release import UnsupportedReleaseError


def test_main_prints_a_summary(monkeypatch, capsys):
    advisory = Advisory("CVE-2025-1", "demo", "demo", "2.0", requires_subscription=False)
    package = Package("demo", "1.0", "amd64", 1, "", source_name="demo", source_version="1.0")
    monkeypatch.setattr(scan, "detect_ecosystem", lambda: "Ubuntu:24.04:LTS")
    monkeypatch.setattr(scan, "refresh", lambda: FeedStatus(Path("x"), "today", downloaded=False))
    monkeypatch.setattr(scan, "load_advisories", lambda path, eco: {"demo": [advisory]})
    monkeypatch.setattr(scan, "collect", lambda: [package])

    assert scan.main() == 0
    output = capsys.readouterr().out
    assert "1 findings" in output
    assert "CVE-2025-1" in output
    assert "feed already up to date" in output


def test_main_reports_unsupported_systems(monkeypatch, capsys):
    def fail():
        raise UnsupportedReleaseError("not ubuntu")

    monkeypatch.setattr(scan, "detect_ecosystem", fail)
    assert scan.main() == 2
    assert "not ubuntu" in capsys.readouterr().out
