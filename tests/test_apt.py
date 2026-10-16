# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for the apt collector: pure parsing, no access to the real system."""

from ganki.collectors import apt
from ganki.collectors.apt import (
    Package,
    install_date,
    menu_packages,
    parse_dpkg_query,
    parse_manual,
)


def _row(*fields: str) -> str:
    # Source package, version, section, priority and essential are optional in tests.
    padded = (*fields, *([""] * (11 - len(fields))))
    return "\t".join(padded)


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


def test_source_package_is_parsed_when_present():
    line = _row(
        "libssl3t64",
        "3.0.13-0ubuntu3.5",
        "amd64",
        "5000",
        "ii ",
        "SSL library",
        "openssl",
        "3.0.13-0ubuntu3.5",
    )
    pkg = parse_dpkg_query(line)[0]
    assert pkg.source_name == "openssl"
    assert pkg.source_version == "3.0.13-0ubuntu3.5"


def test_source_falls_back_to_binary_name_and_version():
    pkg = parse_dpkg_query(_row("bash", "5.2", "amd64", "1", "ii ", "shell"))[0]
    assert pkg.source_name == "bash"
    assert pkg.source_version == "5.2"


def test_section_priority_and_essential_are_parsed():
    row = _row("git", "1", "amd64", "5", "ii ", "vcs", "git", "1", "universe/vcs", "optional", "no")
    package = parse_dpkg_query(row)[0]
    assert (package.section, package.priority, package.essential) == ("vcs", "optional", False)


def _package(**values):
    return Package("x", "1", "amd64", 1, "", **values)


def test_menu_entry_makes_a_program_even_if_it_is_a_dependency():
    assert _package(has_menu_entry=True).is_program


def test_chosen_dev_tools_are_programs_but_libraries_and_system_packages_are_not():
    assert _package(manual=True, section="vcs", priority="optional").is_program
    assert not _package(manual=True, section="libs", priority="optional").is_program
    assert not _package(manual=True, section="interpreters", priority="important").is_program
    assert not _package(manual=True, section="devel", essential=True).is_program
    assert not _package(manual=False, section="vcs").is_program  # pulled in, not chosen
    assert not _package(manual=True, section="admin").is_program


def test_support_packages_in_tool_sections_are_not_programs():
    for name in (
        "libbinutils:amd64",
        "cmake-data",
        "gcc-13",
        "cpp-x86-64-linux-gnu",
        "java-common",
    ):
        assert not Package(name, "1", "amd64", 1, "", manual=True, section="devel").is_program
    assert Package("git", "1", "amd64", 1, "", manual=True, section="vcs").is_program


def test_menu_packages_find_only_visible_launchers(tmp_path, monkeypatch):
    apps = tmp_path / "applications"
    apps.mkdir()
    (apps / "vlc.desktop").write_text("[Desktop Entry]\nType=Application\nName=VLC\n")
    (apps / "helper.desktop").write_text("[Desktop Entry]\nType=Application\nNoDisplay=true\n")
    info = tmp_path / "info"
    info.mkdir()
    (info / "vlc.list").write_text(f"/usr/bin/vlc\n{apps}/vlc.desktop\n")
    (info / "helper.list").write_text(f"{apps}/helper.desktop\n")
    (info / "bash.list").write_text("/bin/bash\n")
    monkeypatch.setattr(apt, "APPLICATIONS_DIR", f"{apps}/")
    assert menu_packages(info) == {"vlc"}
