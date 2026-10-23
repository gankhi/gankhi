# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Marking a program as checked by the person: only for that exact version, kept locally."""

import json
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from gankhi import verified  # noqa: E402
from gankhi.collectors.sandboxed import SandboxedApp  # noqa: E402
from test_not_checked import _result  # noqa: E402
from test_web import BASE, build, login, wait_until_done  # noqa: E402

POST = {"X-Gankhi": "1"}


def page(app):
    client = login(app.test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    return client


def mark(client, how, name, version, checked=True):
    body = {"how": how, "name": name, "version": version, "checked": checked}
    return client.post("/api/verify", json=body, headers=POST, base_url=BASE)


def html_of(client):
    return client.get("/", base_url=BASE).get_data(as_text=True)


def test_the_mark_is_for_one_version_only(tmp_path):
    store = verified.Store(tmp_path / "v.json")
    assert store.add("snap", "firefox", "131.0")
    assert verified.key("snap", "firefox", "131.0") in store.marks()
    assert verified.key("snap", "firefox", "132.0") not in store.marks()


def test_the_marks_are_saved_privately_and_survive_a_restart(tmp_path):
    path = tmp_path / "gankhi" / "v.json"
    verified.Store(path).add("snap", "firefox", "131.0")
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    again = verified.Store(path)
    assert [m.name for m in again.marks().values()] == ["firefox"]
    assert again.remove("snap", "firefox", "131.0") and not again.marks()


def test_a_broken_file_starts_empty_instead_of_crashing(tmp_path):
    path = tmp_path / "v.json"
    path.write_text("{not json", encoding="utf-8")
    assert verified.Store(path).marks() == {}
    path.write_text(json.dumps({"items": [{"how": "snap"}, 5, {"how": "x"}]}), encoding="utf-8")
    assert verified.Store(path).marks() == {}


def test_a_marked_app_leaves_the_lists_and_goes_to_its_own_card(tmp_path):
    client = page(build(_result, verified_store=verified.Store(tmp_path / "v.json")))
    before = html_of(client)
    assert "<strong>firefox</strong>" in before and 'id="verified"' not in before
    assert mark(client, "snap", "firefox", "131.0").status_code == 200
    after = html_of(client)
    sandboxed = after[after.index('id="sandboxed"') :] if 'id="sandboxed"' in after else ""
    assert "firefox" not in sandboxed.split("</section>")[0]  # gone from the apps section
    card = after[after.index('id="verified"') :]
    card = card[: card.index("</section>")]
    assert "<strong>firefox</strong>" in card and "Undo" in card
    assert "- firefox" not in after  # no longer in the text for an AI


def test_a_program_in_the_tools_list_is_tagged_and_not_counted_as_not_checked(tmp_path):
    client = page(build(_result, verified_store=verified.Store(tmp_path / "v.json")))
    assert "Checked by you" not in html_of(client)
    assert mark(client, "apt", "gcloud", "548.0.0").status_code == 200
    after = html_of(client)
    row = after[after.index("<strong>gcloud</strong>") :]
    row = row[: row.index("</tr>")]
    assert "Checked by you" in row and "ask-row" not in row and "verify-row" not in row


def test_a_new_version_comes_back_to_the_list(tmp_path):
    store = verified.Store(tmp_path / "v.json")
    store.add("snap", "firefox", "130.0")  # the version checked before
    html = html_of(page(build(_result, verified_store=store)))
    assert "<strong>firefox</strong>" in html and 'id="verified"' not in html


def test_undo_puts_it_back(tmp_path):
    client = page(build(_result, verified_store=verified.Store(tmp_path / "v.json")))
    mark(client, "snap", "firefox", "131.0")
    assert mark(client, "snap", "firefox", "131.0", checked=False).status_code == 200
    assert 'id="verified"' not in html_of(client)


def test_only_something_listed_as_not_checked_can_be_marked(tmp_path):
    client = page(build(_result, verified_store=verified.Store(tmp_path / "v.json")))
    assert mark(client, "snap", "nothing", "1").status_code == 404
    assert mark(client, "apt", "vim", "9.1").status_code == 404  # checked by Gankhi
    bad = client.post("/api/verify", json={"how": "x"}, headers=POST, base_url=BASE)
    assert bad.status_code == 400
    assert client.post("/api/verify", json={}, base_url=BASE).status_code == 403  # needs the header


def test_every_pending_row_has_the_button_and_it_needs_no_inline_script():
    html = html_of(page(build(_result)))
    assert html.count('class="btn verify-row"') == 3
    assert "onclick" not in html


def test_the_button_script_sends_the_exact_version_with_the_guard_header():
    js = (Path(__file__).parents[1] / "src/gankhi/web/static/app.js").read_text(encoding="utf-8")
    assert '"/api/verify"' in js and '"X-Gankhi": "1"' in js and "dataset.version" in js


def test_snap_and_flatpak_apps_do_not_collide_by_name():
    apps = [SandboxedApp("x", "1", "snap", "a", None, "x"), SandboxedApp("x", "1", "flatpak", "b")]
    assert replace(_result(), sandboxed=apps).sandboxed[0].tool == "snap"
    assert verified.key("snap", "x", "1") != verified.key("flatpak", "x", "1")
