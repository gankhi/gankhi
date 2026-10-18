# ruff: noqa: S101
"""Grouping of packages in the report, and the order and split of its tables."""

from dataclasses import replace

from ganki import families, report
from test_web import make_result


def tool(name, priority="high", fixed="2.0", version="1.0", program=False):
    template = next(t for t in make_result().tools if t.is_program)
    return replace(
        template,
        name=name,
        version=version,
        is_program=program,
        state="vulnerable",
        top_priority=priority,
        fixed_in=fixed,
        end_of_support=False,
    )


def test_kernel_pieces_share_one_family():
    for name in (
        "linux-image-6.8.0-137-generic",
        "linux-headers-6.8.0-137",
        "linux-libc-dev:amd64",
        "linux-tools-common",
        "linux-modules-extra-6.8.0-137-generic",
    ):
        assert families.is_kernel(name), name
    assert not families.is_kernel("linux-firmware")
    assert not families.is_kernel("linuxlite-tools")


def test_families_group_java_virtualbox_zfs_and_lite():
    names = [
        "openjdk-17-jre",
        "openjdk-17-jdk",
        "openjdk-21-jre",
        "virtualbox-qt",
        "virtualbox-dkms",
        "libzfs4linux",
        "zfsutils-linux",
        "lite-tweaks",
        "lite-updates",
        "wireshark",
    ]
    groups = families.group([tool(n) for n in names])
    counts = {g.key: g.count for g in groups}
    assert counts == {
        "openjdk-17": 2,
        "openjdk-21": 1,
        "virtualbox": 2,
        "zfs": 2,
        "lite": 2,
        "wireshark": 1,
    }


def test_groups_come_most_urgent_first():
    groups = families.group([tool("zz", "low"), tool("aa", "critical"), tool("mm", "medium")])
    assert [g.top_priority for g in groups] == ["critical", "medium", "low"]


def test_a_family_with_a_few_members_names_them():
    group = families.group([tool("virtualbox-qt"), tool("virtualbox-dkms")])[0]
    assert group.members() == "virtualbox-dkms, virtualbox-qt"
    assert (
        families.group([tool("linux-image-6.8.0-1"), tool("linux-tools-common")])[0].members() == ""
    )
    big = families.group([tool(f"lite-{i}") for i in range(5)])[0]
    assert big.members() == ""


def test_the_report_splits_fixable_from_waiting_and_counts_minor_ones():
    result = make_result()
    tools = [
        tool("libfix", "high", fixed="2.0"),
        tool("libwait", "high", fixed=None),
        tool("libminor", "low", fixed=None),
    ]
    data = report.build_report(replace(result, tools=tools), "es", "now")
    assert b"Se arreglan actualizando" in data
    assert b"Sin arreglo publicado todav" in data
    assert b"libfix" in data and b"libwait" in data
    assert b"libminor" not in data  # counted, not listed
    assert b"Avisos m" in data


def test_a_family_is_one_row_in_the_report():
    result = make_result()
    tools = [tool(f"openjdk-17-part{i}", "medium") for i in range(6)]
    group = families.group(tools)[0]
    assert (
        report._label(group, "Kernel de Linux", "{n} componentes") == "openjdk-17 (6 componentes)"
    )
    data = report.build_report(replace(result, tools=tools), "es", "now")
    assert b"part5" not in data


def test_a_group_is_named_by_whole_words():
    group = families.group([tool("openjdk-17-jre"), tool("openjdk-17-jdk")])[0]
    assert group.label("k") == "openjdk-17"
    group = families.group([tool("network-manager-vpnc"), tool("network-manager-openvpn")])[0]
    assert group.label("k") == "network-manager"
