# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Known flaws with no fix yet live in their own card, so the main list shows what can be done."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from gankhi.tools import is_parked  # noqa: E402
from test_web import BASE, build, login, make_result, wait_until_done  # noqa: E402


def get(path="/"):
    client = login(build().test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    return client.get(path, base_url=BASE).get_data(as_text=True)


def section(html, marker, end="</section>"):
    part = html[html.index(marker) :]
    return part[: part.index(end)]


def test_a_program_with_no_fix_is_parked_and_one_with_a_fix_is_not():
    tools = {t.name: t for t in make_result().tools}
    assert is_parked(tools["virtualbox"]) and not is_parked(tools["openssl"])
    assert not is_parked(tools["vim"])  # only outdated: nothing to park


def test_the_no_fix_ones_are_in_their_own_card_not_in_the_main_table():
    html = get()
    card = section(html, 'id="parked"')
    assert "<strong>virtualbox</strong>" in card and "<strong>openssl</strong>" not in card
    assert "Known flaws with no fix yet (1)" in card
    main = section(html, 'id="tools"')
    assert "<strong>openssl</strong>" in main and "<strong>virtualbox</strong>" not in main


def test_the_card_is_shown_with_all_and_vulnerable_but_not_with_other_filters():
    assert 'id="parked"' in get("/?f=vulnerable") and 'id="parked"' in get("/")
    assert 'id="parked"' not in get("/?f=outdated") and 'id="parked"' not in get("/?f=ok")


def test_the_vulnerable_chip_counts_all_of_them_and_the_card_opens_in_that_view():
    html = get()
    assert "With vulnerabilities · 2" in html  # openssl (has a fix) and virtualbox (does not)
    assert "<details open>" not in section(html, 'id="parked"', "</summary>")
    view = get("/?f=vulnerable")
    assert "<details open>" in section(view, 'id="parked"', "</summary>")  # shown, not folded
    assert "1 with no fix yet" in html  # virtualbox, said next to the totals
    assert 'href="/?f=vulnerable#parked"' in html


def test_opening_the_cve_list_shows_every_notice_of_the_tool():
    from dataclasses import replace

    from gankhi.tools import CveLine

    lines = tuple(CveLine(f"CVE-2026-{n:04d}", "high", "flaw", None, "no_fix") for n in range(28))

    def scan():
        result = make_result()
        tools = [
            replace(t, cves=lines, cve_count=28) if t.name == "virtualbox" else t
            for t in result.tools
        ]
        return replace(result, tools=tools)

    client = login(build(scan).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    assert all(f"CVE-2026-{n:04d}" in html for n in range(28))
    assert "28 CVEs" in html and "more are not listed" not in html


def test_when_nothing_has_a_fix_the_vulnerable_view_says_where_the_list_is():
    from dataclasses import replace

    def scan():
        result = make_result()
        return replace(
            result,
            tools=[replace(t, fixed_in=None) if t.name == "openssl" else t for t in result.tools],
        )

    client = login(build(scan).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/?f=vulnerable", base_url=BASE).get_data(as_text=True)
    assert "Nothing here can be fixed by updating. The 2 with known flaws" in html
    card = section(html, 'id="parked"')
    assert "<strong>openssl</strong>" in card and "<strong>virtualbox</strong>" in card


def test_the_assistant_starts_minimized_and_the_scan_time_is_local():
    html = get()
    assert '<aside class="assistant" id="assistant" hidden' in html
    assert 'id="assistant-open" class="assistant-open" aria-label' in html  # the icon is visible
    assert "UTC" not in html  # the time of the last scan is shown in the computer's own time
    js = (Path(__file__).parents[1] / "src/gankhi/web/static/assistant.js").read_text()
    assert "gankhi_dock" not in js  # no memory of an earlier open or closed state


def test_state_and_vulnerabilities_are_two_separate_columns():
    html = get("/?f=vulnerable")
    head = section(html, 'id="tools"', "</thead>")
    assert head.index("Repo status") < head.index("Vulnerabilities") < head.index("Actions")
    row = html[html.index("<strong>openssl</strong>") :]
    row = row[: row.index("</tr>")]
    # the state only says if it is outdated, up to date or not checked; the level has its own cell
    assert 'class="sev sev-high">▲ High · CVE-' in row  # a single notice shows which one it is
    assert "Vulnerability ·" not in row
    assert "Latest available" in row  # no newer version is on offer, whatever its flaws


def test_a_program_without_flaws_shows_a_dash_in_the_vulnerabilities_column():
    html = get("/?f=ok")
    row = html[html.index("<strong>git</strong>") :]
    row = row[: row.index("</tr>")]
    assert "sev sev-" not in row and "—" in row


def test_every_level_has_its_own_color_class():
    css = (Path(__file__).parents[1] / "src/gankhi/web/static/style.css").read_text()
    for level in ("critical", "high", "medium", "low", "unknown"):
        assert f".sev-{level}" in css


def test_the_headline_adds_libraries_and_dependencies_and_says_how_it_splits():
    from dataclasses import replace

    def scan():
        result = make_result()
        tools = [replace(t, state="vulnerable") if t.name == "libfoo1" else t for t in result.tools]
        return replace(result, tools=tools)

    client = login(build(scan).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    plain = client.get("/", base_url=BASE).get_data(as_text=True)
    everything = client.get("/?show=all", base_url=BASE).get_data(as_text=True)
    for html in (plain, everything):  # the checkbox changes the list, never the headline
        assert "3 with vulnerabilities" in html
        assert "2 programs + 1 libraries and dependencies" in html


def test_the_ring_legend_splits_the_flaws_by_severity_each_with_its_colour():
    html = get()
    ring = html[html.index('data-explain="programs"') :]
    ring = ring[: ring.index("</ul>")]
    assert "2 vulnerabilities" in ring  # the total first, with its number
    assert '<li class="sub"><a' in ring
    assert "1 high" in ring and "1 medium" in ring  # openssl and virtualbox
    assert 'class="sw sev-high"' in ring and 'class="seg sev-high"' in ring
    assert "critical" not in ring  # nothing critical here, so nothing is listed


def test_the_vulnerable_view_lists_every_flaw_libraries_included():
    from dataclasses import replace

    def scan():
        result = make_result()
        tools = [
            replace(t, state="vulnerable", cve_count=1) if t.name == "libfoo1" else t
            for t in result.tools
        ]
        return replace(result, tools=tools)

    client = login(build(scan).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    listing = client.get("/", base_url=BASE).get_data(as_text=True)
    assert "<strong>libfoo1</strong>" not in listing  # the plain list still hides the libraries
    vulnerable = client.get("/?f=vulnerable", base_url=BASE).get_data(as_text=True)
    assert "<strong>libfoo1</strong>" in vulnerable  # ...but the flaws list has all of them
    assert "With vulnerabilities · 3" in vulnerable


def test_the_support_ring_counts_supported_outdated_and_unsupported_apart_from_the_flaws_ring():
    from dataclasses import replace

    def scan():
        result = make_result()
        tools = [
            replace(t, end_of_support=True) if t.name in ("git", "virtualbox") else t
            for t in result.tools
        ]
        return replace(result, tools=tools)

    client = login(build(scan).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    flaws = html[html.index('data-explain="programs"') :]
    flaws = flaws[: flaws.index("</ul>")]
    assert "<h3>Vulnerabilities</h3>" in flaws and "2 vulnerabilities" in flaws
    assert "outdated" not in flaws and "no support" not in flaws  # those live in the other ring
    support = html[html.index('data-explain="support"') :]
    support = support[: support.index("</ul>")]
    assert "<h3>Updates and support</h3>" in support
    # vim is outdated; git and virtualbox are out of support; openssl and libfoo1 are fine
    assert "2 up to date and supported" in support
    assert "1 outdated, still supported" in support and "2 without support" in support
    only = client.get("/?f=eol", base_url=BASE).get_data(as_text=True)
    assert "<strong>git</strong>" in only and "<strong>vim</strong>" not in only


def test_ring_parts_are_real_arcs_that_close_the_circle():
    from gankhi.web.app import ring_arc

    first = ring_arc(0, 25)
    assert first.startswith("M70.000 18.000A52 52 0 0 1 ")  # starts at 12 o'clock, clockwise
    assert ring_arc(0, 60).split("A52 52 ")[1].startswith("0 1 1 ")  # more than half: the large arc
    whole = ring_arc(0, 100)  # a single part of 100 % is the whole circle, not an empty path
    assert whole.startswith("M70.000 18.000A52 52 0 1 1 ") and not whole.endswith("70.000 18.000")


def test_a_program_out_of_support_is_listed_even_when_its_flaws_have_no_fix_yet():
    from dataclasses import replace

    def scan():
        result = make_result()
        tools = [
            replace(t, end_of_support=True) if t.name == "virtualbox" else t for t in result.tools
        ]
        return replace(result, tools=tools)

    client = login(build(scan).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    page = client.get("/", base_url=BASE).get_data(as_text=True)
    assert "1 without support" in page  # said in the ring...
    listed = client.get("/?f=eol", base_url=BASE).get_data(as_text=True)
    assert "<strong>virtualbox</strong>" in listed  # ...and the link shows which one it is


def test_the_tools_list_has_no_explanatory_sentences_and_the_menu_has_four_tabs():
    from dataclasses import replace

    from gankhi.external_tools import ExternalTool

    def scan():
        fine = [ExternalTool(f"p{i}", "1", "pip", "PyPI", vulnerable=False) for i in range(3)]
        return replace(make_result(), external=fine)

    client = login(build(scan).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    assert "The total at the top also counts" not in html
    assert "tick the box to list them" not in html
    menu = html[html.index('id="sidenav"') : html.index('class="panels"')]
    for tab in ("tools", "apps", "unchecked", "ext", "downloads"):
        assert f'data-tab-link="{tab}"' in menu
    assert "(PDF, .zip, …)" in menu


def test_clicking_a_severity_lists_only_that_severity():
    only_high = get("/?f=vulnerable&sev=high")
    main = section(only_high, 'id="tools"')
    assert "<strong>openssl</strong>" in main
    assert (
        "<strong>virtualbox</strong>" not in section(only_high, 'id="parked"')
        if 'id="parked"' in only_high
        else True
    )
    only_medium = get("/?f=vulnerable&sev=medium")
    assert "<strong>openssl</strong>" not in section(only_medium, 'id="tools"')
    assert "<strong>virtualbox</strong>" in section(only_medium, 'id="parked"')
    # the ring's severity lines link to that filter; an unknown level is ignored
    assert 'href="/?f=vulnerable&amp;sev=high#tools"' in get()
    assert "<strong>openssl</strong>" in section(get("/?f=vulnerable&sev=bogus"), 'id="tools"')


def _kernel_scan():
    from dataclasses import replace

    from gankhi.tools import OK, VULNERABLE, Tool, _update_via

    old = Tool(
        "linux-headers-6.8.0-137", "6.8.0-137.137", 1, "kernel headers", True, VULNERABLE,
        fixed_in="6.8.0-147.147", fixable=3, cve_count=3, top_priority="high",
    )  # fmt: skip
    meta = Tool("linux-generic", "6.8.0-137.137", 1, "kernel", True, OK, update_to="6.8.0-147.147")
    return old, meta, _update_via, replace


def test_a_versioned_kernel_package_is_updated_through_the_kernel_meta_package():
    old, meta, update_via, replace = _kernel_scan()
    assert update_via(old, {old.name: old, meta.name: meta}) == "linux-generic"
    assert update_via(old, {old.name: old}) == ""  # nothing to update it through
    other = replace(old, name="openssl")
    assert update_via(other, {other.name: other, meta.name: meta}) == ""  # not a kernel package


def test_that_row_gets_an_update_button_that_points_at_the_meta_package():
    from dataclasses import replace

    old, meta, update_via, _ = _kernel_scan()
    kernel = replace(old, update_via="linux-generic")
    base = make_result()

    def scan():
        return replace(base, tools=[*base.tools, kernel, meta])

    client = login(build(scan).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/?f=vulnerable", base_url=BASE).get_data(as_text=True)
    row = html[html.index("linux-headers-6.8.0-137") :]
    row = row[: row.index("</tr>")]
    assert "action=update&amp;pkg=linux-generic" in row


def test_the_packages_of_each_kernel_are_one_item_counted_once():
    from gankhi.tools import OK, VULNERABLE, Tool, group_kernels

    def package(name, version, state=VULNERABLE, via=""):
        return Tool(
            name, version, 10, "kernel part", True, state,
            cve_count=5, top_priority="critical", update_via=via,
        )  # fmt: skip

    tools = [
        package("linux-image-6.8.0-137-generic", "6.8.0-137.137", via="linux-generic"),
        package("linux-headers-6.8.0-137", "6.8.0-137.137", via="linux-generic"),
        package("linux-modules-6.8.0-137-generic", "6.8.0-137.137"),
        package("linux-image-6.8.0-147-generic", "6.8.0-147.147"),
        package("linux-headers-6.8.0-147", "6.8.0-147.147", state=OK),
        package("openssl", "1"),
    ]
    grouped = {t.name: t for t in group_kernels(tools, "6.8.0-147-generic")}
    assert sorted(grouped) == ["linux-6.8.0-137", "linux-6.8.0-147", "openssl"]
    old, new = grouped["linux-6.8.0-137"], grouped["linux-6.8.0-147"]
    assert len(old.group) == 3 and old.size_kib == 30 and old.update_via == "linux-generic"
    assert old.state == VULNERABLE and old.cve_count == 5  # the notices are not multiplied
    assert not old.kernel_in_use and new.kernel_in_use
    assert new.state == VULNERABLE  # one package with notices makes the kernel have them
    assert old.protected and old.core and not grouped["openssl"].group


def test_a_grouped_kernel_shows_its_version_and_whether_it_is_in_use():
    from dataclasses import replace

    from gankhi.tools import Tool

    kernel = Tool(
        "linux-6.8.0-137", "6.8.0-137.137", 10, "", True, "vulnerable",
        cve_count=3, top_priority="critical", fixed_in="6.8.0-147.147", fixable=3,
        update_via="linux-generic", protected=True,
        group=("linux-image-6.8.0-137-generic", "linux-headers-6.8.0-137"),
    )  # fmt: skip
    meta = Tool(
        "linux-generic", "6.8.0-137.137", 1, "kernel", True, "ok", update_to="6.8.0-147.147"
    )
    base = make_result()
    client = login(build(lambda: replace(base, tools=[*base.tools, kernel, meta])).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    client.get("/lang/es", base_url=BASE)
    html = client.get("/?f=vulnerable", base_url=BASE).get_data(as_text=True)
    row = html[html.index("Kernel 6.8.0-137") :]
    row = row[: row.index("</tr>")]
    assert "no está en uso (viejo)" in row and "2 paquetes" in row
    assert "pkg=linux-generic" in row


def test_a_development_header_package_says_it_is_better_not_to_remove_it():
    from dataclasses import replace

    from gankhi.tools import KEEP_PACKAGES, Tool

    assert "linux-libc-dev" in KEEP_PACKAGES
    header = Tool(
        "linux-libc-dev", "6.8.0-147.147", 10, "headers", True, "vulnerable",
        cve_count=2, top_priority="critical", keep_hint=True,
    )  # fmt: skip
    base = make_result()
    client = login(build(lambda: replace(base, tools=[*base.tools, header])).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    client.get("/lang/es", base_url=BASE)
    html = client.get("/?f=vulnerable", base_url=BASE).get_data(as_text=True)
    row = html[html.index("<strong>linux-libc-dev</strong>") :]
    row = row[: row.index("</tbody>")]
    assert row.count("Se recomienda no quitarlo") == 1  # said once, in its own tag


def test_the_keep_advice_also_matches_names_with_the_architecture():
    from gankhi.collectors.apt import Package
    from gankhi.tools import build_tools

    packages = [
        Package("linux-libc-dev:amd64", "6.8.0-147.147", "amd64", 10, "headers"),
        Package("libc6-dev:amd64", "2.39", "amd64", 10, "libc headers"),
    ]
    by_name = {t.name: t for t in build_tools(packages, [], [])}
    assert by_name["linux-libc-dev:amd64"].keep_hint  # dpkg reports multi-arch names this way
    assert not by_name["libc6-dev:amd64"].keep_hint  # its notices are not the kernel's
