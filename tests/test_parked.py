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


def test_the_vulnerable_chip_counts_only_what_can_be_acted_on_and_the_ring_all_of_it():
    html = get()
    assert "With vulnerabilities · 1" in html  # openssl, which has a fix
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
    assert "CVE: 28" in html and "more are not listed" not in html
