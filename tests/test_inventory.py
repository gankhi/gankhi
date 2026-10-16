# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for searching, sorting and paging the package inventory."""

from datetime import datetime, timezone

from ganki.collectors.apt import Package
from ganki.inventory import human_size, paginate, select


def pkg(name, size=10, manual=False, desc="", day=None):
    when = datetime(2026, 1, day, tzinfo=timezone.utc) if day else None
    return Package(name, "1.0", "amd64", size, desc, manual=manual, installed_at=when)


PACKAGES = [
    pkg("zlib", 50, desc="compression library", day=3),
    pkg("vim", 4000, manual=True, desc="text editor", day=1),
    pkg("bash", 1500, desc="shell", day=2),
    pkg("nodate", 5),
]


def names(items):
    return [p.name for p in items]


def test_default_sort_is_biggest_first():
    assert names(select(PACKAGES)) == ["vim", "bash", "zlib", "nodate"]


def test_sort_by_name_and_by_newest_date():
    assert names(select(PACKAGES, sort="name")) == ["bash", "nodate", "vim", "zlib"]
    assert names(select(PACKAGES, sort="date")) == ["zlib", "bash", "vim", "nodate"]


def test_unknown_sort_falls_back_to_size():
    assert names(select(PACKAGES, sort="nonsense"))[0] == "vim"


def test_search_matches_name_or_description_ignoring_case():
    assert names(select(PACKAGES, query="EDITOR")) == ["vim"]
    assert names(select(PACKAGES, query="zl")) == ["zlib"]


def test_manual_only_keeps_what_the_user_installed():
    assert names(select(PACKAGES, manual_only=True)) == ["vim"]


def test_paginate_slices_and_totals_the_whole_selection():
    page = paginate(select(PACKAGES), number=2, size=3)
    assert names(page.items) == ["nodate"]
    assert (page.number, page.pages, page.total) == (2, 2, 4)
    assert page.total_kib == 4000 + 1500 + 50 + 5


def test_paginate_clamps_out_of_range_pages_and_handles_empty():
    assert paginate(PACKAGES, number=99, size=3).number == 2
    assert paginate(PACKAGES, number=-5, size=3).number == 1
    empty = paginate([])
    assert (empty.items, empty.number, empty.pages, empty.total) == ([], 1, 1, 0)


def test_human_size():
    assert human_size(512) == "512 KiB"
    assert human_size(1536) == "1.5 MiB"
    assert human_size(3 * 1024 * 1024) == "3.0 GiB"
