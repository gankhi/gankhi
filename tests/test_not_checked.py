# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Programs from outside Ubuntu: found, shown as "not checked", never as up to date."""

import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from gankhi import ask_ai, narration, report  # noqa: E402
from gankhi.collectors.apt import Package  # noqa: E402
from gankhi.collectors.origins import (  # noqa: E402
    is_ubuntu_origin,
    parse_origins,
    resolve_superseded,
    third_party,
)
from gankhi.collectors.sandboxed import SandboxedApp  # noqa: E402
from gankhi.collectors.updates import Update  # noqa: E402
from gankhi.release import codename_for  # noqa: E402
from gankhi.tools import OUTDATED, UNCHECKED, build_tools  # noqa: E402
from test_web import BASE, build, login, make_result, wait_until_done  # noqa: E402

APT_LIST = """Listing...
bash/noble-updates,noble-security,now 5.2.21 amd64 [installed]
vim/noble,now 9.1 amd64 [installed,automatic]
google-cloud-cli/cloud-sdk,now 548.0.0-0 amd64 [installed]
docker-ce/noble,now 5:27.0 amd64 [installed,upgradable to: 5:27.1]
handmade/now 1.0 amd64 [installed,local]
"""


def test_the_origins_of_installed_packages_are_read_from_apt():
    found = parse_origins(APT_LIST)
    assert found["bash"] == "noble-updates,noble-security"
    assert found["google-cloud-cli"] == "cloud-sdk" and found["handmade"] == "local"


def test_only_packages_from_outside_ubuntus_pockets_are_third_party():
    assert third_party(APT_LIST, "noble") == {
        "google-cloud-cli": "cloud-sdk",
        "handmade": "local",
    }
    assert is_ubuntu_origin("noble-updates,noble-security", "noble")
    assert not is_ubuntu_origin("cloud-sdk", "noble")
    assert not is_ubuntu_origin("jammy", "noble")
    assert is_ubuntu_origin("anything", "")  # an unknown release: claim nothing


def test_a_repository_that_reuses_ubuntus_release_name_cannot_be_told_apart():
    """Known limit, written down on purpose: apt only shows the suite, and Docker or a PPA use
    "noble" too. Those are still compared with Ubuntu's list, as before; the README says so."""
    assert "docker-ce" not in third_party(APT_LIST, "noble")


def test_the_codename_comes_from_the_ecosystem():
    assert codename_for("Ubuntu:24.04:LTS") == "noble" and codename_for("nope") == ""


def _tools():
    packages = [
        Package("gcloud", "548.0.0", "amd64", 400_000, "Google Cloud tools", has_menu_entry=True),
        Package("handmade", "1.0", "amd64", 100, "A tool", has_menu_entry=True),
        Package("vim", "9.1", "amd64", 3000, "editor", has_menu_entry=True),
    ]
    updates = [Update("handmade", "amd64", "1.0", "1.1", "mine", False)]
    return build_tools(
        packages, [], updates, third_party={"gcloud": "cloud-sdk", "handmade": "local"}
    )


def test_a_package_from_outside_ubuntu_is_not_checked_and_not_up_to_date():
    by_name = {t.name: t for t in _tools()}
    assert by_name["gcloud"].state == UNCHECKED and by_name["gcloud"].origin == "cloud-sdk"
    assert by_name["handmade"].state == OUTDATED  # apt does know about its newer version
    assert by_name["vim"].state == "ok" and by_name["vim"].origin == ""


def _result():
    sandboxed = [SandboxedApp("firefox", "131.0", "snap", "mozilla**", 1024, "firefox")]
    return replace(make_result(), tools=_tools(), sandboxed=sandboxed)


def test_the_text_for_an_ai_lists_what_was_not_checked_and_asks_for_a_table():
    items = ask_ai.unchecked_items(_result())
    assert [i.name for i in items] == ["gcloud", "handmade", "firefox"]
    text = ask_ai.build_prompt(items, "Ubuntu 24.04 LTS", "en")
    assert "Ubuntu 24.04 LTS" in text and "- gcloud 548.0.0 (apt, repository cloud-sdk)" in text
    assert "installed from a .deb file" in text and "snap, publisher mozilla**" in text
    assert (
        "exactly 3 columns" in text
        and "Command to update" in text
        and "Do not make anything up" in text
    )
    assert "Search the web for each program" in text and "download page" in text
    assert (
        "Never fill the whole column" in text
        and "Not reported yet" in text
        and "OSV.dev, NVD, GitHub" in text
        and "never a search-engine link" in text
    )
    assert "Do not suggest removing" in text and "full plain URL" in text
    assert "remove the program" not in text
    assert "no explanations" in text and "Read each command before running it." in text
    spanish = ask_ai.build_prompt(items, "Ubuntu 24.04 LTS", "es")
    assert "Respondé SOLO con una tabla" in spanish and "No inventes nada" in spanish
    assert "someone" not in text  # the user name of the sample system never goes in


def test_a_long_list_is_cut_for_the_text_and_says_how_many_are_missing():
    many = [ask_ai.Unchecked(f"pkg{i}", "1", "apt", "x") for i in range(ask_ai.MAX_LISTED + 5)]
    text = ask_ai.build_prompt(many, "Linux", "en")
    assert "5 more" in text and f"pkg{ask_ai.MAX_LISTED}" not in text


def test_fields_that_end_up_in_the_text_are_one_short_line():
    messy = ask_ai._clean("line one\nline two " + "x" * 200)
    assert "\n" not in messy and len(messy) <= 60


def test_the_page_shows_not_checked_with_a_button_that_copies_the_text():
    client = login(build(_result).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    assert 'id="unchecked"' in html and "Gankhi sends nothing" in html
    assert 'id="copy" data-target="ai-text"' in html and 'id="ai-text"' in html
    assert "◌ Not checked" in html and "Not from Ubuntu: cloud-sdk" in html
    assert "Not checked · 1" in html  # the filter
    listed = client.get("/?f=unchecked", base_url=BASE).get_data(as_text=True)
    assert "gcloud" in listed and "<strong>vim</strong>" not in listed
    client.get("/lang/es", base_url=BASE)
    spanish = client.get("/", base_url=BASE).get_data(as_text=True)
    assert "Copiar lista y consulta para una IA" in spanish and "◌ Sin revisar" in spanish


def test_the_not_checked_programs_do_not_count_as_up_to_date():
    client = login(build(_result).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    assert "1 not checked" in html  # the legend of the ring
    assert 'class="seg dim"' in html


def test_the_assistant_and_the_report_say_what_was_not_checked():
    text = " ".join(s.text for s in narration.build(_result(), "en"))
    assert "come from outside Ubuntu, so I cannot check them" in text
    data = report.build_report(_result(), "en", "now")
    assert b"Not checked" in data and b"gcloud" in data and b"cloud-sdk" in data
    assert b"snap, publisher mozilla" in data


def test_each_part_of_the_programs_ring_opens_its_own_list():
    client = login(build(_result).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    for filter_name in ("ok", "outdated", "unchecked"):
        assert f'href="/?f={filter_name}#tools"' in html
    only = client.get("/?f=unchecked", base_url=BASE).get_data(as_text=True)
    assert "<strong>gcloud</strong>" in only and "<strong>vim</strong>" not in only


def test_the_up_to_date_list_says_when_python_or_npm_packages_make_up_the_difference():
    from gankhi.external_tools import ExternalTool

    def with_packages():
        fine = [ExternalTool(f"p{i}", "1", "pip", "PyPI", vulnerable=False) for i in range(3)]
        return replace(make_result(), external=fine)

    client = login(build(with_packages).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    listed = client.get("/?f=ok", base_url=BASE).get_data(as_text=True)
    assert "3 more Python or npm packages have no known notices" in listed
    other = client.get("/?f=outdated", base_url=BASE).get_data(as_text=True)
    assert "Python or npm packages have no known notices" not in other


def test_column_titles_stay_in_view_while_the_page_scrolls():
    css = (Path(__file__).parent.parent / "src/gankhi/web/static/style.css").read_text()
    assert "thead th { position: sticky; top: 0;" in css
    assert "@media (min-width: 1040px) { .scroll { overflow-x: clip; } }" in css


def test_the_not_checked_card_lists_only_what_gankhi_cannot_update_for_you():
    client = login(build(_result).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    card = html[html.index('id="unchecked"') :]
    card = card[: card.index("</section>")]
    # no rows repeated here: the snap lives in its own section, the others in the tools list
    for name in ("firefox", "gcloud", "handmade"):
        assert f"<strong>{name}</strong>" not in card
    assert 'href="#sandboxed"' in card and 'id="sandboxed"' in html
    assert "2 programs from other apt repositories or .deb files are in the tools list" in card
    assert 'href="/?f=unchecked#tools"' in card
    # the text to copy has everything Gankhi could not check: being updatable says nothing
    # about whether the program has known vulnerabilities
    assert "- firefox" in card and "- gcloud" in card and "- handmade" in card
    assert "exactly 3 columns" in card and "lists all 3 programs that were not checked" in card


def test_the_text_for_an_ai_names_the_ubuntu_a_derivative_is_built_on():
    one = [ask_ai.Unchecked("gcloud", "1", "apt", "x")]
    text = ask_ai.build_prompt(one, "Linux Lite 7.4", "en", "Ubuntu:24.04:LTS")
    assert "I use Linux Lite 7.4 (based on Ubuntu 24.04 LTS)." in text
    spanish = ask_ai.build_prompt(one, "Linux Lite 7.4", "es", "Ubuntu:24.04:LTS")
    assert "Uso Linux Lite 7.4 (basado en Ubuntu 24.04 LTS)." in spanish
    ubuntu = ask_ai.build_prompt(one, "Ubuntu 24.04.3 LTS", "en", "Ubuntu:24.04:LTS")
    assert "I use Ubuntu 24.04.3 LTS." in ubuntu  # already says it: not repeated
    assert "I use Linux." in ask_ai.build_prompt(one, "", "en", "")


def test_the_header_only_mentions_the_vulnerability_data_when_it_was_just_downloaded():
    def scan(downloaded):
        return lambda: replace(make_result(), feed_downloaded=downloaded)

    for downloaded in (False, True):
        client = login(build(scan(downloaded)).test_client())
        client.get("/", base_url=BASE)
        wait_until_done(client)
        html = client.get("/", base_url=BASE).get_data(as_text=True)
        assert ("Vulnerability data: downloaded just now" in html) is downloaded
        assert "already up to date" not in html


def test_an_ubuntu_package_with_a_newer_version_out_is_not_taken_for_a_loose_file():
    # apt no longer lists the installed version in any repository once a newer one is out, so it
    # reports it as "local"; the newer version tells where the package really comes from
    listing = (
        "Listing...\n"
        "tool/now 2.1 all [installed,upgradable to: 2.2]\n"
        "other/now 1.0 all [installed,upgradable to: 1.1]\n"
        "byhand/now 3.0 all [installed,local]\n"
    )
    outside = third_party(listing, "noble")
    assert set(outside) == {"tool", "other", "byhand"}
    updates = [
        Update("tool", "all", "2.1", "2.2", "noble-updates", False),
        Update("other", "all", "1.0", "1.1", "vendor-repo", False),
    ]
    resolved = resolve_superseded(outside, updates, "noble")
    assert "tool" not in resolved  # Ubuntu's own: its notices apply again
    assert resolved["other"] == "vendor-repo"  # from that repository, not a loose file
    assert resolved["byhand"] == "local"  # nothing newer: really installed by hand


def test_a_newer_version_that_does_not_fix_the_notices_is_not_offered_as_the_fix():
    def with_update(*names):
        base = make_result()
        tools = [replace(t, update_to="9.9") if t.name in names else t for t in base.tools]
        return replace(base, tools=tools)

    def page(result):
        client = login(build(lambda: result).test_client())
        client.get("/", base_url=BASE)
        wait_until_done(client)
        return client.get("/", base_url=BASE).get_data(as_text=True)

    def row(html, name):
        start = html.index(f"<strong>{name}</strong>")
        return html[start : html.index('class="gap"', start)]

    # virtualbox has notices with no patch; a newer version exists but fixes none of them
    html = page(with_update("virtualbox"))
    box = row(html, "virtualbox")
    assert "A newer version exists, but it does not fix these vulnerabilities yet" in box
    assert 'class="btn primary"' not in box and 'class="btn"' in box
    # with no newer version the plain "no fix" tag stays
    plain = row(page(with_update()), "virtualbox")
    assert "No fix yet" in plain and "A newer version exists" not in plain
    # an update that does fix something keeps the highlighted button
    assert 'class="btn primary"' in row(page(with_update("openssl")), "openssl")
    # with nothing to update there is no Update button at all, not a disabled one
    assert "Update</a>" not in plain and 'btn off">Update' not in plain


def test_the_copy_button_goes_back_to_its_label_after_copying():
    script = (Path(__file__).parent.parent / "src/gankhi/web/static/app.js").read_text()
    assert "var original = button.textContent;" in script
    assert "button.textContent = original;" in script and "clearTimeout(restore)" in script
    assert 'querySelectorAll(".ask-row")' in script  # the same behaviour for every row button


def test_every_program_gankhi_could_not_check_has_its_own_button_to_ask_an_ai():
    client = login(build(_result).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    buttons = html.count('class="btn ask-row"')
    # gcloud and handmade in the tools list, firefox (snap) in its own section only
    assert buttons == 3
    row = html[html.index("<strong>gcloud</strong>") :]
    row = row[: row.index("</tr>")]
    assert "Copy question for an AI" in row and "- gcloud 548.0.0" in row
    assert "- handmade" not in row  # each button carries only its own program
    # a program Gankhi did check has no such button
    vim = html[html.index("<strong>vim</strong>") :]
    assert "ask-row" not in vim[: vim.index("</tr>")]


def test_a_change_that_is_running_is_shown_on_the_main_page_with_what_it_does():
    from test_web import FakeExecutor

    class Running(FakeExecutor):
        def status(self):
            return {
                "state": "running",
                "lines": ["Setting up tool (1.0) ..."],
                "command": "apt-get install --only-upgrade tool",
                "returncode": None,
            }

    def main_page(executor):
        client = login(build(_result, executor=executor).test_client())
        client.get("/", base_url=BASE)
        wait_until_done(client)
        return client.get("/", base_url=BASE).get_data(as_text=True)

    html = main_page(Running())
    assert 'id="change-banner"' in html
    assert "A change is running on your system:" in html
    assert "apt-get install --only-upgrade tool" in html
    assert 'id="change-banner"' not in main_page(FakeExecutor())  # nothing running: no banner
    script = (Path(__file__).parent.parent / "src/gankhi/web/static/app.js").read_text()
    assert "function followOther()" in script and 'getElementById("change-banner")' in script
