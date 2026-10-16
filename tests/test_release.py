# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for Ubuntu release detection."""

import pytest

from ganki.release import UnsupportedReleaseError, detect_ecosystem, parse_os_release

LINUX_LITE = """NAME="Linux Lite"
VERSION="7.4"
ID=linuxlite
ID_LIKE="ubuntu debian"
VERSION_ID="7.4"
VERSION_CODENAME=noble
UBUNTU_CODENAME=noble
"""

UBUNTU = """NAME="Ubuntu"
ID=ubuntu
VERSION_ID="22.04"
VERSION_CODENAME=jammy
"""

DEBIAN = """ID=debian
VERSION_CODENAME=bookworm
"""


def write(tmp_path, text):
    path = tmp_path / "os-release"
    path.write_text(text)
    return path


def test_parse_os_release_strips_quotes_and_ignores_noise():
    values = parse_os_release('# comment\n\nNAME="Linux Lite"\nID=linuxlite\nbroken line\n')
    assert values == {"NAME": "Linux Lite", "ID": "linuxlite"}


def test_derivative_uses_ubuntu_codename(tmp_path):
    assert detect_ecosystem(write(tmp_path, LINUX_LITE)) == "Ubuntu:24.04:LTS"


def test_plain_ubuntu_uses_version_codename(tmp_path):
    assert detect_ecosystem(write(tmp_path, UBUNTU)) == "Ubuntu:22.04:LTS"


def test_debian_is_unsupported(tmp_path):
    with pytest.raises(UnsupportedReleaseError):
        detect_ecosystem(write(tmp_path, DEBIAN))


def test_missing_file_is_unsupported(tmp_path):
    with pytest.raises(UnsupportedReleaseError):
        detect_ecosystem(tmp_path / "does-not-exist")
