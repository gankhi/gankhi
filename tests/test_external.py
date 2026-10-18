# ruff: noqa: S101
"""pip and npm: what is read, how versions compare, how the public lists are matched."""

import json
import zipfile

import pytest

from ganki import osv_external, versions
from ganki.collectors import external
from ganki.collectors.external import ExternalPackage


def test_pip_lists_only_what_pip_installed_and_names_are_normalised():
    output = json.dumps(
        [
            {"name": "Foo_Bar", "version": "1.0", "location": "/home/u/.local/lib/python3.12"},
            {"name": "requests", "version": "2.31", "location": "/usr/lib/python3/dist-packages"},
            {
                "name": "torch",
                "version": "2.1",
                "location": "/usr/local/lib/python3.12/dist-packages",
            },
            {"name": "broken"},
        ]
    )
    names = [(p.name, p.version) for p in external.parse_pip(output)]
    assert names == [("foo-bar", "1.0"), ("torch", "2.1")]
    assert external.parse_pip("not json") == []


def test_npm_lists_global_packages():
    output = json.dumps({"dependencies": {"left-pad": {"version": "1.3.0"}, "x": {}}})
    assert [(p.name, p.version) for p in external.parse_npm(output)] == [("left-pad", "1.3.0")]
    assert external.parse_npm("[]") == []


def test_versions_compare_like_pypi_and_npm():
    assert versions.parse("PyPI", "1.0rc1") < versions.parse("PyPI", "1.0")
    assert versions.parse("PyPI", "2.10") > versions.parse("PyPI", "2.9")
    assert versions.parse("npm", "1.2.3-beta.1") < versions.parse("npm", "1.2.3")
    assert versions.parse("npm", "1.10.0") > versions.parse("npm", "1.9.9")
    assert versions.parse("npm", "1.0.0-alpha.2") > versions.parse("npm", "1.0.0-alpha.1")
    assert versions.parse("npm", "garbage") is None
    assert versions.parse("PyPI", "garbage") is None


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ],
)
def test_cvss3_scores_match_the_published_ones(vector, score):
    assert osv_external.cvss3_score(vector) == score


def test_unreadable_vectors_give_no_score():
    assert osv_external.cvss3_score("CVSS:4.0/AV:N") is None
    assert osv_external.cvss3_score("CVSS:3.1/AV:N") is None


def affected(name, ecosystem="PyPI", events=None, versions_list=None, kind="ECOSYSTEM"):
    entry = {"package": {"ecosystem": ecosystem, "name": name}}
    if events is not None:
        entry["ranges"] = [{"type": kind, "events": events}]
    if versions_list is not None:
        entry["versions"] = versions_list
    return entry


def test_a_version_is_inside_a_range_until_the_fix():
    entry = affected("a", events=[{"introduced": "0"}, {"fixed": "2.0"}])
    assert osv_external.affected_by(entry, "PyPI", "1.9") == (True, "2.0")
    assert osv_external.affected_by(entry, "PyPI", "2.0") == (False, None)
    entry = affected("a", events=[{"introduced": "1.5"}, {"fixed": "2.0"}])
    assert osv_external.affected_by(entry, "PyPI", "1.4") == (False, None)
    entry = affected("a", events=[{"introduced": "0"}, {"last_affected": "3.0"}])
    assert osv_external.affected_by(entry, "PyPI", "3.0") == (True, None)
    assert osv_external.affected_by(entry, "PyPI", "3.1") == (False, None)
    entry = affected("a", events=[{"introduced": "0"}])
    assert osv_external.affected_by(entry, "PyPI", "9") == (True, None)


def test_an_exact_version_list_counts_and_unknown_range_types_are_ignored():
    entry = affected("a", versions_list=["1.0", "1.1"])
    assert osv_external.affected_by(entry, "PyPI", "1.1")[0]
    assert not osv_external.affected_by(entry, "PyPI", "1.2")[0]
    git = affected("a", events=[{"introduced": "0"}], kind="GIT")
    assert osv_external.affected_by(git, "PyPI", "1.0") == (False, None)


def test_priority_comes_from_the_label_the_score_or_malware():
    assert osv_external.record_priority({"database_specific": {"severity": "MODERATE"}}) == "medium"
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert osv_external.record_priority({"severity": [{"type": "CVSS_V3", "score": vector}]}) == (
        "critical"
    )
    assert osv_external.record_priority({"id": "MAL-2024-1"}) == "critical"
    assert osv_external.record_priority({"id": "PYSEC-1"}) == ""


def make_archive(path, records):
    with zipfile.ZipFile(path, "w") as bundle:
        for index, record in enumerate(records):
            bundle.writestr(f"{index}.json", json.dumps(record))


def test_find_external_matches_only_installed_affected_versions(tmp_path):
    records = [
        {
            "id": "GHSA-1",
            "aliases": ["CVE-2024-1"],
            "summary": "Bad thing",
            "database_specific": {"severity": "HIGH"},
            "affected": [affected("Foo_Bar", events=[{"introduced": "0"}, {"fixed": "2.0"}])],
        },
        {"id": "GHSA-2", "withdrawn": "2024-01-01", "affected": [affected("foo-bar")]},
        {"id": "GHSA-3", "affected": [affected("other", events=[{"introduced": "0"}])]},
        {
            "id": "GHSA-4",
            "affected": [affected("foo-bar", events=[{"introduced": "3.0"}, {"fixed": "4.0"}])],
        },
        {
            "id": "MAL-1",
            "summary": "malware",
            "affected": [affected("evil", events=[{"introduced": "0"}])],
        },
    ]
    archive = tmp_path / "pypi.zip"
    make_archive(archive, records)
    installed = [
        ExternalPackage("PyPI", "foo-bar", "1.0", "pip"),
        ExternalPackage("PyPI", "evil", "0.1", "pip"),
    ]
    found = osv_external.find_external(archive, "PyPI", installed)
    by_name = {f.name: f for f in found}
    assert [f.advisory_id for f in found if f.name == "foo-bar"] == ["GHSA-1"]
    assert by_name["foo-bar"].cve_id == "CVE-2024-1"
    assert by_name["foo-bar"].fixed_version == "2.0"
    assert by_name["foo-bar"].priority == "high"
    assert by_name["evil"].malicious and by_name["evil"].priority == "critical"
    assert "other" not in by_name


def test_the_same_cve_is_counted_once(tmp_path):
    base = {"aliases": ["CVE-1"], "affected": [affected("a", events=[{"introduced": "0"}])]}
    fixed = {
        "aliases": ["CVE-1"],
        "affected": [affected("a", events=[{"introduced": "0"}, {"fixed": "2"}])],
    }
    archive = tmp_path / "x.zip"
    make_archive(archive, [{"id": "PYSEC-1", **base}, {"id": "GHSA-1", **fixed}])
    found = osv_external.find_external(archive, "PyPI", [ExternalPackage("PyPI", "a", "1", "pip")])
    assert len(found) == 1 and found[0].fixed_version == "2"


def test_a_corrupt_record_does_not_stop_the_reading(tmp_path):
    archive = tmp_path / "x.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("bad.json", "{not json")
        bundle.writestr(
            "ok.json",
            json.dumps({"id": "G", "affected": [affected("a", events=[{"introduced": "0"}])]}),
        )
    found = osv_external.find_external(archive, "PyPI", [ExternalPackage("PyPI", "a", "1", "pip")])
    assert len(found) == 1


def test_only_the_listing_commands_can_run():
    from ganki import runner

    for command in (
        [runner.PYTHON, "-c", "print(1)"],
        [runner.PYTHON, "-m", "pip", "install", "x"],
        [runner.NPM, "install", "-g", "x"],
        [runner.NPM_LOCAL, "ls", "-g", "--json", "--depth=0", "--extra"],
    ):
        with pytest.raises(runner.CommandNotAllowedError):
            runner.run(command)


def test_scan_external_with_a_failing_download_reports_the_tool_and_goes_on():
    import urllib.error

    from ganki import external_scan

    packages = [ExternalPackage("PyPI", "a", "1", "pip"), ExternalPackage("npm", "b", "1", "npm")]

    def check(ecosystem, pkgs, cache_dir, progress):
        if ecosystem == "PyPI":
            raise urllib.error.URLError("offline")
        return []

    tools, failed = external_scan.scan_external(collect=lambda: packages, check=check)
    assert failed == ["pip"]
    assert [t.name for t in tools] == ["a", "b"]


def test_nothing_is_downloaded_when_pip_and_npm_have_nothing_installed():
    from ganki import external_scan

    def check(*_args):
        raise AssertionError("must not be called")

    assert external_scan.scan_external(collect=list, check=check) == ([], [])


def test_the_last_answer_is_reused_while_the_list_is_unchanged(tmp_path):
    from ganki import external_scan, feed

    archive = tmp_path / "osv-PyPI.zip"
    make_archive(archive, [{"id": "G", "affected": [affected("a", events=[{"introduced": "0"}])]}])
    packages = [ExternalPackage("PyPI", "a", "1", "pip")]
    calls = []

    def refresh(url, **kwargs):
        calls.append(url)
        return feed.FeedStatus(archive, "Mon", downloaded=len(calls) == 1)

    first = external_scan.check_ecosystem("PyPI", packages, tmp_path, refresh=refresh)
    archive.unlink()  # a second read of the archive would now fail
    again = external_scan.check_ecosystem("PyPI", packages, tmp_path, refresh=refresh)
    assert first == again and len(first) == 1


def test_built_tools_put_affected_packages_first_and_keep_the_fix():
    from ganki.external_tools import build_external_tools
    from ganki.osv_external import ExternalFinding

    packages = [
        ExternalPackage("PyPI", "calm", "1", "pip"),
        ExternalPackage("PyPI", "bad", "1", "pip"),
    ]
    findings = [
        ExternalFinding("PyPI", "bad", "1", "G1", "CVE-1", "x", "high", "2.0"),
        ExternalFinding("PyPI", "bad", "1", "G2", "CVE-2", "y", "medium", "2.5"),
    ]
    tools = build_external_tools(packages, findings)
    assert [t.name for t in tools] == ["bad", "calm"]
    assert tools[0].top_priority == "high" and tools[0].fixed_in == "2.5"
    assert tools[0].cve_count == 2 and not tools[1].vulnerable


def with_external(failed=()):
    from dataclasses import replace

    from ganki.external_tools import ExternalTool
    from test_web import make_result

    tools = [
        ExternalTool("evilpkg", "0.1", "pip", "PyPI", True, "critical", 1, None, True),
        ExternalTool("oldlib", "1.0", "pip", "PyPI", True, "high", 2, "2.1"),
        ExternalTool("calm", "1.0", "npm", "npm", False),
    ]
    return replace(make_result(), external=tools, external_failed=list(failed))


@pytest.mark.parametrize("lang", ["en", "es"])
def test_the_voice_reads_python_and_npm(lang):
    from ganki import narration

    segments = [s for s in narration.build(with_external(["npm"]), lang) if s.section == "external"]
    text = " ".join(s.text for s in segments)
    assert "evilpkg" in text and "oldlib" in text and "npm" in text
    assert not any("{" in s.text for s in segments)
    assert segments[0].tone == "bad"


def test_the_voice_says_nothing_when_pip_and_npm_have_nothing():
    from ganki import narration
    from test_web import make_result

    assert not [s for s in narration.build(make_result(), "en") if s.section == "external"]


def test_the_report_has_a_python_and_npm_section():
    from ganki import report

    data = report.build_report(with_external(["npm"]), "es", "now")
    assert b"evilpkg" in data and b"oldlib" in data
    assert b"calm" not in data  # only the affected ones are listed


def test_the_page_lists_the_affected_packages_and_a_failed_check():
    from test_web import BASE, build, login, wait_until_done

    client = login(build(scan=lambda: with_external(["npm"])).test_client())
    wait_until_done(client)
    page = client.get("/", base_url=BASE).get_data(as_text=True)
    assert "evilpkg" in page and "oldlib" in page
    assert "Python and npm packages" in page
    assert "calm" not in page.split('data-explain="external"')[1].split("</section>")[0]
    assert "npm" in page


def test_the_quick_look_finds_names_however_the_json_is_spaced(tmp_path):
    archive = tmp_path / "x.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        text = json.dumps(
            {"id": "G", "affected": [affected("Foo_Bar", events=[{"introduced": "0"}])]}
        )
        bundle.writestr("a.json", text.replace('"name": ', '"name":'))
    found = osv_external.find_external(
        archive, "PyPI", [ExternalPackage("PyPI", "foo-bar", "1", "pip")]
    )
    assert len(found) == 1


def test_reading_in_another_process_gives_the_same_answer(tmp_path):
    archive = tmp_path / "x.zip"
    make_archive(archive, [{"id": "G", "affected": [affected("a", events=[{"introduced": "0"}])]}])
    packages = [ExternalPackage("PyPI", "a", "1", "pip")]
    assert osv_external.find_external_isolated(archive, "PyPI", packages) == (
        osv_external.find_external(archive, "PyPI", packages)
    )


def test_snap_list_skips_runtimes_and_keeps_apps():
    from ganki.collectors.sandboxed import parse_snap

    output = (
        "Name     Version  Rev   Tracking       Publisher  Notes\n"
        "core22   20240111 1380  latest/stable  canonical✓ base\n"
        "firefox  131.0    5187  latest/stable  mozilla✓   -\n"
        "snapd    2.63     21759 latest/stable  canonical✓ snapd\n"
    )
    apps = parse_snap(output)
    assert [(a.name, a.version, a.source) for a in apps] == [("firefox", "131.0", "mozilla")]


def test_flatpak_list_reads_tab_separated_columns():
    from ganki.collectors.sandboxed import parse_flatpak

    output = "org.gimp.GIMP\tGIMP\t2.10.38\tflathub\t245.1 MB\n\nbroken line\n"
    apps = parse_flatpak(output)
    assert [(a.name, a.version, a.tool, a.source) for a in apps] == [
        ("GIMP", "2.10.38", "flatpak", "flathub")
    ]


def test_sandboxed_commands_are_allowlisted_with_exact_arguments():
    import pytest

    from ganki import runner

    with pytest.raises(Exception):  # noqa: B017, PT011
        runner.run([runner.SNAP, "remove", "firefox"])
    with pytest.raises(Exception):  # noqa: B017, PT011
        runner.run([runner.FLATPAK, "uninstall", "org.gimp.GIMP"])


def test_snap_and_flatpak_sizes_are_read_in_the_same_unit(tmp_path):
    from ganki.collectors.sandboxed import parse_flatpak, parse_snap

    (tmp_path / "firefox_5187.snap").write_bytes(b"x" * 3 * 1024 * 1024)
    snap = parse_snap(
        "Name     Version  Rev   Tracking       Publisher  Notes\n"
        "firefox  131.0    5187  latest/stable  mozilla✓   -\n"
        "ghost    1.0      7     latest/stable  someone    -\n",
        tmp_path,
    )
    assert [(a.name, a.size_kib) for a in snap] == [("firefox", 3072), ("ghost", None)]
    flat = parse_flatpak(
        "org.gimp.GIMP\tGIMP\t2.10\tflathub\t245.1\u00a0MB\nx.Y\tY\t1\tflathub\t?\n"
    )
    assert flat[0].size_kib == 245_100_000 // 1024 and flat[1].size_kib is None


def test_the_update_and_remove_commands_are_exact_and_safe():
    from ganki.external_tools import ExternalTool, remove_command, update_command

    pip = ExternalTool("oldlib", "1.0", "pip", "PyPI", True, "high", 2, "2.1")
    npm = ExternalTool("@scope/lib", "1.0", "npm", "npm", True, "high", 1, "3.0.1")
    assert update_command(pip) == "python3 -m pip install --upgrade 'oldlib>=2.1'"
    assert update_command(npm) == "npm install -g '@scope/lib@>=3.0.1'"
    assert remove_command(pip) == "python3 -m pip uninstall oldlib"
    assert remove_command(npm) == "npm uninstall -g @scope/lib"
    no_fix = ExternalTool("oldlib", "1.0", "pip", "PyPI", True, "high", 2, None)
    assert update_command(no_fix) is None
    # a name or version with shell characters is never put into a command
    evil = ExternalTool("x; rm -rf ~", "1.0", "pip", "PyPI", True, "high", 1, "2.0")
    assert update_command(evil) is None and remove_command(evil) is None
    odd_version = ExternalTool("lib", "1.0", "pip", "PyPI", True, "high", 1, "2.0$(id)")
    assert update_command(odd_version) is None


def test_the_python_and_npm_rows_show_the_command_to_copy():
    from test_web import BASE, build, login, wait_until_done

    client = login(build(with_external).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    assert "python3 -m pip install --upgrade &#39;oldlib&gt;=2.1&#39;" in html
    assert "python3 -m pip uninstall evilpkg" in html  # malicious: remove, never update


def test_snap_and_flatpak_commands_are_exact_and_safe():
    from ganki.collectors.sandboxed import (
        SandboxedApp,
        is_shared_runtime,
        parse_flatpak,
        remove_command,
        update_command,
    )

    snap = SandboxedApp("thunderbird", "1", "snap", "canonical", None, "thunderbird")
    assert update_command(snap) == "sudo snap refresh thunderbird"
    assert remove_command(snap) == "sudo snap remove thunderbird"
    (flat,) = parse_flatpak("org.gimp.GIMP\tGIMP\t2.10\tflathub\t245.1 MB\n")
    assert flat.app_id == "org.gimp.GIMP"
    assert update_command(flat) == "flatpak update org.gimp.GIMP"
    assert remove_command(flat) == "flatpak uninstall org.gimp.GIMP"
    odd = SandboxedApp("x", "1", "snap", "me", None, "x; rm -rf ~")
    assert update_command(odd) is None and remove_command(odd) is None
    base = SandboxedApp("mesa-2404", "1", "snap", "canonical", None, "mesa-2404")
    assert is_shared_runtime(base) and not is_shared_runtime(snap)


def test_the_rows_offer_to_remove_as_well_as_update():
    from test_web import BASE, build, login, wait_until_done

    client = login(build(with_external).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    update = html.index("pip install --upgrade")
    assert "python3 -m pip uninstall oldlib" in html[update:]  # both for the same package
    assert "python3 -m pip show NAME" in html  # check what needs it before removing
