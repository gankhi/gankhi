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
    assert "1 of them with no fix yet" in html  # virtualbox, said next to the totals
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
    assert 'class="sev sev-high">▲ High · 1 CVE<' in row
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
