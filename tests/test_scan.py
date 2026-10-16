# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Test the scan command wiring with all I/O replaced by fakes."""

from pathlib import Path

import ganki.scan as scan
import ganki.service as service
from ganki.collectors.apt import Package
from ganki.feed import FeedStatus
from ganki.osv import Advisory
from ganki.release import UnsupportedReleaseError


def test_main_prints_a_summary(monkeypatch, capsys):
    advisory = Advisory("CVE-2025-1", "demo bug", "high", "demo", "2.0", frozenset())
    package = Package("demo", "1.0", "amd64", 1, "", source_name="demo", source_version="1.0")
    monkeypatch.setattr(service, "detect_ecosystem", lambda: "Ubuntu:24.04:LTS")
    monkeypatch.setattr(
        service, "refresh", lambda: FeedStatus(Path("x"), "today", downloaded=False)
    )
    monkeypatch.setattr(service, "load_advisories", lambda path, eco: {"demo": [advisory]})
    monkeypatch.setattr(service, "collect", lambda: [package])
    monkeypatch.setattr(service, "collect_updates", lambda: [])

    assert scan.main() == 0
    output = capsys.readouterr().out
    assert "1 findings across 1 different CVEs" in output
    assert "fix available (update it): 1" in output
    assert "[high] demo 1.0 -> 2.0" in output
    assert "1 CVEs (high 1)" in output
    assert "feed already up to date" in output
    assert "Programs you can fix" in output


def test_main_reports_unsupported_systems(monkeypatch, capsys):
    def fail():
        raise UnsupportedReleaseError("not ubuntu")

    monkeypatch.setattr(service, "detect_ecosystem", fail)
    assert scan.main() == 2
    assert "not ubuntu" in capsys.readouterr().out
