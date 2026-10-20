# ruff: noqa: S101
"""Previews are parsed from apt simulations; nothing here touches the real system."""

from gankhi import actions
from gankhi.actions import (
    AUTOREMOVE,
    CLEAN,
    REMOVE,
    UPDATE,
    UPDATE_ALL,
    Preview,
    download_total,
    parse,
    preview,
)

SIM = """Inst vim [9.1] (9.2 noble-updates [amd64])
Inst newlib (1.0 noble [amd64])
Remv old [1.0]
Need to get 1,234 kB/5,678 kB of archives.
After this operation, 12.5 MB of additional disk space will be used.
"""


def test_parse_counts_upgrades_installs_and_removals():
    result = parse(UPDATE, "vim", SIM)
    assert (result.upgrades, result.installs, result.removals) == (["vim"], ["newlib"], ["old"])
    assert result.disk_change_bytes == 12_500_000


def test_parse_reads_freed_space_as_negative():
    result = parse(REMOVE, "x", "After this operation, 574 kB disk space will be freed.\n")
    assert result.disk_change_bytes == -574_000


def test_download_total_sums_the_sizes_and_ignores_other_lines():
    output = "'http://a/x.deb' x.deb 100 SHA256:1\nnoise\n'http://a/y.deb' y.deb 250 SHA256:2\n"
    assert download_total(output) == 350


def test_commands_save_the_program_list_before_changing_anything():
    result = Preview(REMOVE, "vlc")
    assert result.commands == [actions.SNAPSHOT_COMMAND, "sudo apt-get remove vlc"]
    assert Preview(UPDATE_ALL, "").commands[-1] == "sudo apt-get full-upgrade"
    assert Preview(REMOVE, "vlc", blocked="blocked_protected").commands == []


def test_removal_without_an_apt_size_line_uses_the_installed_size():
    def simulator(_action, _name, _uris=False):
        return "Remv vlc [3.0]\nRemv vlc-data [3.0]\n"

    result = preview(REMOVE, "vlc", {"vlc"}, set(), simulator, {"vlc": 100, "vlc-data": 200})
    assert result.disk_change_bytes == -300 * 1024


def test_unknown_packages_never_reach_the_simulator():
    def simulator(*_args):
        raise AssertionError("must not run")

    for name in ("missing", "-rf", "a b", ""):
        assert preview(REMOVE, name, {"vlc"}, set(), simulator).blocked == "blocked_unknown"


def test_updating_everything_is_refused_when_it_would_remove_protected_software():
    def simulator(_action, _name, _uris=False):
        return "Inst vim [9.1] (9.2 noble-updates [amd64])\nRemv systemd-sysv [255]\n"

    blocked = preview(UPDATE_ALL, "", {"vim"}, {"systemd-sysv"}, simulator)
    assert blocked.blocked == "blocked_drags_protected"
    assert blocked.commands == []
    # the same update is fine when what it removes is not protected
    assert not preview(UPDATE_ALL, "", {"vim"}, set(), simulator).blocked


def test_the_disk_change_is_unknown_when_apt_does_not_say():
    assert (
        parse(UPDATE_ALL, "", "Inst vim [9.1] (9.2 noble-updates [amd64])\n").disk_change_bytes
        is None
    )
    assert parse(UPDATE, "vim", SIM).disk_change_bytes == 12_500_000


def test_emptying_the_cache_needs_no_simulation_and_shows_what_it_frees():
    def simulator(*_args):
        raise AssertionError("must not run")

    result = preview(CLEAN, "ignored", set(), set(), simulator, cache_kib=2048)
    assert not result.blocked and result.disk_change_bytes == -2048 * 1024
    assert result.commands == ["sudo apt-get clean"]  # nothing to save first
    assert preview(CLEAN, "", set(), set(), simulator, cache_kib=0).blocked == (
        "blocked_nothing_to_clean"
    )


def test_removing_what_is_not_needed_lists_it_and_never_touches_protected_software():
    def simulator(action, _name, uris=False):
        assert not uris, "nothing is downloaded when removing"
        return "Remv linux-image-6.8.0-100-generic [6.8.0-100]\nRemv old-lib [1.0]\n"

    sizes = {"linux-image-6.8.0-100-generic": 300, "old-lib": 10}
    result = preview(AUTOREMOVE, "ignored", set(), set(), simulator, sizes)
    assert result.removals == ["linux-image-6.8.0-100-generic", "old-lib"]
    assert result.disk_change_bytes == -310 * 1024 and not result.warnings
    assert result.commands[-1] == "sudo apt-get autoremove"
    blocked = preview(AUTOREMOVE, "", set(), {"old-lib"}, simulator, sizes)
    assert blocked.blocked == "blocked_drags_protected"
    assert blocked.blocked_names == ("old-lib",)  # the person can see what is behind the refusal
    nothing = preview(AUTOREMOVE, "", set(), set(), lambda *_a, **_k: "")
    assert nothing.blocked == "blocked_nothing_to_remove"
