# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for the Debian version comparison, using cases from the Debian policy."""

import pytest

from ganki.debversion import compare

# (older, newer): the first is strictly older than the second.
ORDERED_PAIRS = [
    ("1.0", "1.1"),
    ("1.9", "1.10"),  # numeric, not alphabetical
    ("1.0~rc1", "1.0"),  # tilde sorts before the release
    ("1.0~~", "1.0~"),
    ("1.0~", "1.0"),
    ("1.0", "1.0+dfsg"),
    ("1.0", "1.0a"),
    ("1.0-1", "1.0-2"),
    ("1.0-1", "1.0-1ubuntu1"),
    ("1.0-1ubuntu1", "1.0-1ubuntu2"),
    ("2.0", "1:0.5"),  # epoch wins over everything
    ("5.2.21-2ubuntu4", "5.2.21-2ubuntu4.1"),
    ("8.3.6-0ubuntu0.24.04.4", "8.3.6-0ubuntu0.24.04.5"),
    ("3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.6"),
    ("2.39-0ubuntu8", "2.39-0ubuntu8.1"),
    ("1.0-1~bpo12+1", "1.0-1"),
    ("0.9", "1.0"),
]


@pytest.mark.parametrize(("older", "newer"), ORDERED_PAIRS)
def test_older_is_less_and_symmetry_holds(older, newer):
    assert compare(older, newer) == -1
    assert compare(newer, older) == 1


@pytest.mark.parametrize("version", ["1.0", "1:2.3-4", "5.2.21-2ubuntu4", "1.0~rc1-1"])
def test_equal_versions(version):
    assert compare(version, version) == 0


def test_leading_zeros_are_ignored():
    assert compare("1.01", "1.1") == 0
    assert compare("1.002-1", "1.2-1") == 0


def test_hyphens_inside_upstream_use_last_hyphen_as_revision():
    # "1.0-beta-2": upstream is "1.0-beta", revision is "2".
    assert compare("1.0-beta-2", "1.0-beta-10") == -1


def test_surrounding_whitespace_is_ignored():
    assert compare(" 1.0 ", "1.0") == 0


def test_non_numeric_epoch_is_not_treated_as_epoch():
    # "abc:1" has no valid epoch; must not crash.
    assert compare("abc:1", "abc:2") == -1
