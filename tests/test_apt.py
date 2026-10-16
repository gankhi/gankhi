# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for the apt collector: pure parsing, no access to the real system."""

from ganki.collectors.apt import install_date, parse_dpkg_query, parse_manual


def _row(*fields: str) -> str:
    return "\t".join(fields)


SAMPLE = "\n".join(
    [
        _row("bash", "5.2.21-2ubuntu4", "amd64", "1856", "ii ", "GNU Bourne Again SHell"),
        _row("libc6:i386", "2.39-0ubuntu8", "i386", "12000", "ii ", "GNU C Library"),
        _row("oldpkg", "1.0", "amd64", "10", "rc ", "removed, config left"),
        _row("nosize", "1.0", "all", "", "ii ", "no size reported"),
        "garbage line without tabs",
    ]
)


def test_only_installed_packages_are_kept():
    names = [p.name for p in parse_dpkg_query(SAMPLE)]
    assert names == ["bash", "libc6:i386", "nosize"]


def test_fields_are_parsed():
    bash = parse_dpkg_query(SAMPLE)[0]
    assert bash.version == "5.2.21-2ubuntu4"
    assert bash.architecture == "amd64"
    assert bash.size_kib == 1856
    assert bash.description == "GNU Bourne Again SHell"


def test_missing_size_becomes_zero():
    nosize = parse_dpkg_query(SAMPLE)[-1]
    assert nosize.size_kib == 0


def test_parse_manual_ignores_blank_lines():
    assert parse_manual("bash\nlibc6:i386\n\n") == {"bash", "libc6:i386"}


def test_install_date_uses_list_file_mtime(tmp_path):
    (tmp_path / "bash.list").write_text("/bin/bash\n")
    result = install_date("bash", "amd64", info_dir=tmp_path)
    assert result is not None
    assert result.tzinfo is not None


def test_install_date_missing_file_returns_none(tmp_path):
    assert install_date("nothing", "amd64", info_dir=tmp_path) is None
