# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for the per-tool status list and paging helpers."""

from ganki.collectors.apt import Package
from ganki.collectors.updates import Update
from ganki.osv import Finding
from ganki.paging import human_size, paginate
from ganki.tools import OK, OUTDATED, VULNERABLE, build_tools


def pkg(name, manual=True):
    return Package(name, "1.0", "amd64", 10, f"{name} description", has_menu_entry=manual)


def finding(cve, name="a", fixed="2.0", priority="medium"):
    return Finding(cve, name, (name,), "1.0", fixed, None, priority, "text")


def update(name):
    return Update(name, "amd64", "1.0", "1.5", "noble-updates", False)


def test_state_vulnerable_outdated_or_ok():
    tools = {
        t.name: t
        for t in build_tools([pkg("a"), pkg("b"), pkg("c")], [finding("CVE-1", "a")], [update("b")])
    }
    assert tools["a"].state == VULNERABLE
    assert tools["b"].state == OUTDATED and tools["b"].update_to == "1.5"
    assert tools["c"].state == OK


def test_vulnerable_wins_over_outdated():
    (tool,) = build_tools([pkg("a")], [finding("CVE-1", "a")], [update("a")])
    assert tool.state == VULNERABLE and tool.update_to == "1.5"


def test_cve_counts_priority_and_fixed_version():
    findings = [
        finding("CVE-1", priority="low", fixed="2.1"),
        finding("CVE-2", priority="high", fixed="2.10"),
        finding("CVE-3", priority="medium", fixed=None),
        finding("CVE-1", priority="low", fixed="2.1"),  # same CVE again: counted once
    ]
    (tool,) = build_tools([pkg("a")], findings, [])
    assert tool.cve_count == 3
    assert tool.top_priority == "high"
    assert (tool.fixable, tool.unfixable) == (2, 1)
    assert tool.fixed_in == "2.10"  # compared as Debian versions, not text
    assert [c.cve_id for c in tool.cves][0] == "CVE-2"  # most urgent first


def test_most_urgent_tools_come_first_and_cve_lines_are_capped():
    many = [finding(f"CVE-{i}", "a") for i in range(20)]
    tools = build_tools(
        [pkg("z-ok"), pkg("b"), pkg("a")],
        many + [finding("CVE-X", "b", priority="critical")],
        [update("z-ok"), update("a"), update("b")],
    )
    assert [t.name for t in tools] == ["b", "a", "z-ok"]
    assert len(tools[1].cves) == 5


def test_arch_qualified_names_match_updates():
    (tool,) = build_tools([pkg("libc6:amd64")], [], [update("libc6")])
    assert tool.state == OUTDATED


def test_paginate_clamps_and_slices():
    items = list(range(120))
    page = paginate(items, number=3, size=50)
    assert (page.items, page.number, page.pages, page.total) == (items[100:], 3, 3, 120)
    assert paginate(items, number=99, size=50).number == 3
    assert paginate(items, number=-1, size=50).number == 1
    assert paginate([]).pages == 1


def test_human_size():
    assert human_size(512) == "512 KiB"
    assert human_size(1536) == "1.5 MiB"
    assert human_size(3 * 1024 * 1024) == "3.0 GiB"


def test_end_of_support_only_flags_well_known_cases():
    from ganki.tools import end_of_support

    assert end_of_support("nodejs", "18.19.1+dfsg-6ubuntu5")
    assert end_of_support("nodejs", "20.11.0+dfsg-1")
    assert not end_of_support("nodejs", "22.9.0-1")
    assert not end_of_support("git", "1:2.43.0-1")


def test_the_sample_of_notices_keeps_the_ones_without_a_fix():
    # many urgent notices with a fix must not push the few without one out of the list
    findings = [finding(f"CVE-{n}", priority="high") for n in range(8)]
    findings.append(finding("CVE-OPEN", fixed=None, priority="low"))
    (tool,) = build_tools([pkg("a")], findings, [])
    shown = [c.cve_id for c in tool.cves]
    assert "CVE-OPEN" in shown
    assert sum(1 for c in tool.cves if c.status != "no_fix") == 5
    assert tool.cve_count == 9


def test_the_list_starts_with_what_an_update_fully_fixes_and_ends_with_what_cannot_be_fixed():
    findings = [
        finding("CVE-1", "fixable", fixed="2.0", priority="low"),
        finding("CVE-2", "mixed", fixed="2.0", priority="critical"),
        finding("CVE-3", "mixed", fixed=None, priority="critical"),  # this one stays open
        finding("CVE-4", "no-patch", fixed=None, priority="critical"),
        finding("CVE-5", "fix-not-offered", fixed="3.0", priority="high"),  # no update in sources
    ]
    tools = build_tools(
        [
            pkg("up-to-date"),
            pkg("outdated"),
            pkg("fixable"),
            pkg("mixed"),
            pkg("no-patch"),
            pkg("fix-not-offered"),
        ],
        findings,
        [update("outdated"), update("fixable"), update("mixed"), update("no-patch")],
    )
    # an update fully fixes it > fixes only part > outdated > nothing to do > up to date
    assert [t.name for t in tools] == [
        "fixable",
        "mixed",
        "outdated",
        "no-patch",
        "fix-not-offered",
        "up-to-date",
    ]


def test_a_tool_remembers_whether_its_update_is_a_security_one():
    from ganki.collectors.updates import Update

    updates = [
        Update("a", "amd64", "1", "2", "noble-updates,noble-security", True),
        Update("b", "amd64", "1", "2", "noble-updates", False),
    ]
    by_name = {t.name: t for t in build_tools([pkg("a"), pkg("b"), pkg("c")], [], updates)}
    assert by_name["a"].update_security and "noble-security" in by_name["a"].update_origin
    assert not by_name["b"].update_security and not by_name["c"].update_security
