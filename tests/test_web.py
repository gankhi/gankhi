# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for the web dashboard: access control, hardening, rendering."""

import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ganki.cleanup import Reclaimable
from ganki.collectors.apt import Package
from ganki.collectors.updates import Update
from ganki.downloads import DownloadGroup
from ganki.osv import Finding
from ganki.release import UnsupportedReleaseError
from ganki.service import ScanResult
from ganki.summary import summarize
from ganki.system import SystemInfo
from ganki.tools import build_tools
from ganki.web.app import SESSION_COOKIE, create_app, uptime_text
from ganki.web.i18n import pick_language, translate

PORT = 8589
SECRET = "s3cret-token-for-tests"  # noqa: S105 - test value
BASE = f"http://127.0.0.1:{PORT}"


def make_result(summary="plain text"):
    findings = [
        Finding("CVE-1", "openssl", ("openssl",), "1.0", "2.0", None, "high", summary),
        Finding("CVE-2", "virtualbox", ("virtualbox",), "7.0", None, None, "medium", summary),
        Finding("CVE-3", "linux", ("linux-image",), "6.8.0-31.31", "6.8.0-90.91", None, "low", ""),
    ]
    packages = [
        Package("openssl", "1.0", "amd64", 900, "crypto toolkit", has_menu_entry=True),
        Package("virtualbox", "7.0", "amd64", 4000, "virtual machines", has_menu_entry=True),
        Package("vim", "9.1", "amd64", 3000, "text editor", has_menu_entry=True),
        Package("git", "2.43", "amd64", 38000, "version control", has_menu_entry=True),
        Package("libfoo1", "1.0", "amd64", 20, "internal library", manual=False),
    ]
    updates = [Update("vim", "amd64", "9.1", "9.2", "noble-updates", False)]
    system = SystemInfo(
        "Ubuntu 24.04 LTS",
        "6.8.0-137-generic",
        "x86_64",
        "someone",
        93600,
        500 * 1024**3,
        300 * 1024**3,
        16 * 1024**2,
        6 * 1024**2,
        True,
    )
    return ScanResult(
        ecosystem="Ubuntu:24.04:LTS",
        feed_downloaded=False,
        feed_date="today",
        findings=findings,
        risks=summarize(findings, "6.8.0-137-generic"),
        snap_stubs=["thunderbird"],
        pending_updates=5,
        scanned_at=datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc),
        system=system,
        reclaimable=Reclaimable(old_kernel_kib=500_000, apt_cache_kib=2_000_000),
        download_groups=[DownloadGroup("archives", 3, 4 * 1024**3), DownloadGroup("pdf", 5, 10**6)],
        downloads_folder="~/Descargas",
        tools=build_tools(packages, findings, updates),
    )


class FakeExecutor:
    """Stands in for the real one: records what would have been run."""

    def __init__(self, available=True, busy=False):
        self.available = available
        self.busy = busy
        self.started = []

    def start(self, action, package):
        if self.busy:
            return False
        self.started.append((action, package))
        return True

    def status(self):
        return {"state": "idle", "lines": [], "command": "", "returncode": None}


def build(scan=make_result, simulator=None, executor=None):
    simulator = simulator or (lambda action, name, uris=False: "")
    app = create_app(scan, SECRET, PORT, simulator, executor or FakeExecutor(available=False))
    app.testing = True
    return app


def login(client):
    client.set_cookie(SESSION_COOKIE, SECRET, domain="127.0.0.1")
    return client


def wait_until_done(client):
    for _ in range(100):
        if client.get("/api/status", base_url=BASE).get_json()["state"] != "running":
            return
        time.sleep(0.02)
    raise AssertionError("scan did not finish")


# ---------- access control ----------


def test_requests_without_the_secret_are_refused():
    response = build().test_client().get("/", base_url=BASE)
    assert response.status_code == 403


def test_wrong_secret_in_the_address_is_refused():
    response = build().test_client().get("/?access=wrong", base_url=BASE)
    assert response.status_code == 403


def test_correct_secret_sets_a_strict_cookie_and_hides_it_from_the_address():
    response = build().test_client().get(f"/?access={SECRET}", base_url=BASE)
    assert response.status_code == 302
    assert response.headers["Location"] == "/"
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie


def test_foreign_host_header_is_rejected_against_dns_rebinding():
    client = login(build().test_client())
    assert client.get("/", base_url="http://evil.example:8589").status_code == 400
    assert client.get("/", base_url="http://127.0.0.1:9999").status_code == 400


def test_localhost_name_is_accepted():
    client = build().test_client()
    client.set_cookie(SESSION_COOKIE, SECRET, domain="localhost")
    assert client.get("/", base_url=f"http://localhost:{PORT}").status_code == 200


# ---------- state-changing requests ----------


def test_rescan_needs_the_custom_header():
    client = login(build().test_client())
    assert client.post("/api/rescan", base_url=BASE).status_code == 403


def test_rescan_rejects_a_foreign_origin():
    client = login(build().test_client())
    response = client.post(
        "/api/rescan",
        base_url=BASE,
        headers={"X-Ganki": "1", "Origin": "http://evil.example"},
    )
    assert response.status_code == 403


def test_rescan_accepts_same_origin_with_header():
    client = login(build().test_client())
    response = client.post(
        "/api/rescan",
        base_url=BASE,
        headers={"X-Ganki": "1", "Origin": BASE},
    )
    assert response.status_code in (200, 202)


# ---------- hardening ----------


def test_security_headers_are_present_even_on_refusals():
    response = build().test_client().get("/", base_url=BASE)
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"


def test_csp_forbids_inline_scripts_and_external_sources():
    csp = build().test_client().get("/", base_url=BASE).headers["Content-Security-Policy"]
    assert "unsafe-inline" not in csp
    assert "http" not in csp


# ---------- pages ----------


def test_page_shows_the_mockup_sections_after_the_scan():
    client = login(build().test_client())
    client.get("/", base_url=BASE)  # starts the scan
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    assert "Ubuntu 24.04 LTS" in html  # system strip
    assert "60%" in html  # disk used
    assert "restart" in html  # reboot notice
    assert "openssl" in html and "virtualbox" in html and "vim" in html
    assert "libfoo1" not in html  # dependencies are hidden by default
    assert "thunderbird" in html  # snap placeholder note
    assert "~/Descargas" in html
    assert "4.0 GiB" in html  # downloads by type


def test_filters_narrow_the_tools_table():
    client = login(build().test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    vulnerable = client.get("/?f=vulnerable", base_url=BASE).get_data(as_text=True)
    assert "virtualbox" in vulnerable and "<strong>git</strong>" not in vulnerable
    outdated = client.get("/?f=outdated", base_url=BASE).get_data(as_text=True)
    assert "<strong>vim</strong>" in outdated and "<strong>openssl</strong>" not in outdated
    # an outdated program with no notices says whether its update matters
    assert 'class="tag info">Update<' in outdated
    up_to_date = client.get("/?f=ok", base_url=BASE).get_data(as_text=True)
    assert "<strong>git</strong>" in up_to_date and "<strong>vim</strong>" not in up_to_date
    assert "<strong>virtualbox</strong>" not in up_to_date and "Up to date · 1" in up_to_date
    assert "libfoo1" in client.get("/?show=all", base_url=BASE).get_data(as_text=True)
    found = client.get("/?q=version+control", base_url=BASE).get_data(as_text=True)
    assert "<strong>git</strong>" in found and "<strong>vim</strong>" not in found


def test_bad_query_parameters_do_not_break_the_page():
    client = login(build().test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    response = client.get("/?f=evil&page=abc&q=%22%3E%3Cscript%3E", base_url=BASE)
    assert response.status_code == 200
    assert "<script>alert" not in response.get_data(as_text=True)


def test_uptime_text():
    assert uptime_text(93600) == "1 d 2 h"
    assert uptime_text(3900) == "1 h 5 min"


def test_text_from_the_feed_is_escaped():
    client = login(build(lambda: make_result("<script>alert(1)</script>")).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    assert "<script>alert(1)" not in html


def test_unsupported_system_shows_a_message():
    def unsupported():
        raise UnsupportedReleaseError("not ubuntu")

    client = login(build(unsupported).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    assert client.get("/api/status", base_url=BASE).get_json()["state"] == "unsupported"


def test_failed_scan_does_not_leak_details():
    def broken():
        raise RuntimeError("secret path /home/someone/file")

    client = login(build(broken).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    assert "/home/someone" not in html


def test_language_switch_is_remembered():
    client = login(build().test_client())
    response = client.get("/lang/es", base_url=BASE)
    assert response.status_code == 302
    client.get("/", base_url=BASE)
    wait_until_done(client)
    assert "Herramientas instaladas" in client.get("/", base_url=BASE).get_data(as_text=True)
    assert client.get("/lang/xx", base_url=BASE).status_code == 404


# ---------- i18n ----------


def test_pick_language_prefers_cookie_then_browser_then_default():
    assert pick_language("es", "en") == "es"
    assert pick_language(None, "es-AR,es;q=0.9,en;q=0.8") == "es"
    assert pick_language(None, "fr-FR") == "en"
    assert pick_language("zz", None) == "en"


def test_translate_falls_back_to_english_and_to_the_key():
    assert translate("fr", "rescan") == "Scan again"
    assert translate("es", "no-such-key") == "no-such-key"
    assert translate("en", "page_of", n=3, total=9) == "Page 3 of 9"


@pytest.mark.parametrize("key", ["title", "rescan", "kernel", "tools", "reclaim", "downloads"])
def test_every_key_exists_in_both_languages(key):
    assert translate("es", key) != key
    assert translate("en", key) != key


def test_both_languages_have_the_same_keys():
    from ganki.web.i18n import TEXTS

    assert set(TEXTS["es"]) == set(TEXTS["en"])


# ---------- start-up: the secret key is never printed ----------


def run_opening_inline(monkeypatch, listening=True):
    """Make the browser-opening thread run at once and say whether the port is listening."""
    from ganki.web import server

    class Inline:
        def __init__(self, target, args=(), daemon=None):
            self._target, self._args = target, args

        def start(self):
            self._target(*self._args)

    monkeypatch.setattr(server.threading, "Thread", Inline)
    monkeypatch.setattr(server, "wait_until_listening", lambda port, seconds=15.0: listening)


def test_access_url_is_saved_privately_and_not_printed(tmp_path, monkeypatch, capsys):
    import stat

    from ganki.web import server

    opened = []

    class FakeApp:
        def run(self, **_kwargs):
            return None

    monkeypatch.setattr(server, "default_cache_dir", lambda: tmp_path / "cache")
    monkeypatch.setattr(server, "create_app", lambda *_args, **_kwargs: FakeApp())
    monkeypatch.setattr(server.webbrowser, "open", lambda url: opened.append(url) or True)
    run_opening_inline(monkeypatch)

    assert server.main(["--port", "8123"]) == 0

    saved = tmp_path / "cache" / server.ACCESS_FILE
    url = saved.read_text().strip()
    assert url.startswith("http://127.0.0.1:8123/?access=")
    assert opened == [url]
    assert stat.S_IMODE(saved.stat().st_mode) == 0o600
    assert url.split("access=")[1] not in capsys.readouterr().out


def test_when_the_browser_does_not_open_only_the_file_path_is_shown(tmp_path, monkeypatch, capsys):
    from ganki.web import server

    class FakeApp:
        def run(self, **_kwargs):
            return None

    monkeypatch.setattr(server, "default_cache_dir", lambda: tmp_path)
    monkeypatch.setattr(server, "create_app", lambda *_args, **_kwargs: FakeApp())
    monkeypatch.setattr(server.webbrowser, "open", lambda url: False)
    monkeypatch.setattr(server.shutil, "which", lambda name: None)  # no desktop opener either
    run_opening_inline(monkeypatch)

    server.main([])
    saved = (tmp_path / server.ACCESS_FILE).read_text().strip()
    output = capsys.readouterr().out
    assert str(tmp_path / server.ACCESS_FILE) in output
    assert saved.split("access=")[1] not in output


# ---------- a second copy must not disturb the first ----------


def test_second_launch_on_a_busy_port_leaves_the_saved_address_alone(tmp_path, monkeypatch):
    import socket

    from ganki.web import server

    saved = tmp_path / server.ACCESS_FILE
    saved.write_text("original-address\n")
    monkeypatch.setattr(server, "default_cache_dir", lambda: tmp_path)
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        assert server.port_is_free(port) is False
        assert server.main(["--port", str(port), "--no-open"]) == 1
    assert saved.read_text() == "original-address\n"
    assert server.port_is_free(port) is True


def test_request_log_lines_never_show_the_access_key():
    import logging

    from ganki.web.server import HideAccessKey

    record = logging.LogRecord(
        "werkzeug",
        logging.INFO,
        "",
        0,
        '"%s" %s %s',
        ("GET /?access=SECRET123 HTTP/1.1", 302, "-"),
        None,
    )
    assert HideAccessKey().filter(record) is True
    line = record.getMessage()
    assert "SECRET123" not in line
    assert "access=<hidden>" in line
    assert "GET /" in line and "302" in line


def test_page_draws_the_ring_charts_and_folds_extra_rows():
    client = login(build().test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/?show=all", base_url=BASE).get_data(as_text=True)
    assert html.count('class="ring"') == 3  # disk, RAM, programs up to date
    assert "stroke-dasharray" in html and "style=" not in html  # CSP: no inline styles
    assert 'id="more-tools"' in html and 'class="more"' in html  # rows beyond the first few fold


def test_pause_on_error_waits_for_enter_only_when_it_fails(monkeypatch):
    import socket

    from ganki.web import server

    asked = []
    monkeypatch.setattr("builtins.input", lambda prompt="": asked.append(prompt) or "")
    monkeypatch.setattr(server.sys.stdin, "isatty", lambda: True, raising=False)
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        assert server.main(["--port", str(port), "--no-open", "--pause-on-error"]) == 1
    assert len(asked) == 1


def test_fonts_are_served_from_the_app_itself():
    client = login(build().test_client())
    response = client.get("/static/fonts/space-grotesk-latin-400-normal.woff2", base_url=BASE)
    assert response.status_code == 200 and len(response.data) > 1000
    csp = client.get("/", base_url=BASE).headers["Content-Security-Policy"]
    assert "font-src 'self'" in csp and "http" not in csp


def test_install_prompts_accept_a_spanish_yes():
    from pathlib import Path

    for name in ("install.sh", "uninstall.sh"):
        script = (Path(__file__).parent.parent / "scripts" / name).read_text()
        assert "|s|S|" in script


CTX = {"t": lambda key, **_: key, "lang": "en"}


def test_long_ring_labels_use_the_smaller_text():
    app = build()
    template = app.jinja_env.from_string(
        "{% from 'index.html' import ring with context %}{{ ring([(50, 'ok')], center, 'x', 'y') }}"
    )
    with app.test_request_context():
        assert "ring-big long" in template.render(center="42/147", **CTX)
        assert "ring-big long" not in template.render(center="60%", **CTX)
        assert "ring-big xlong" in template.render(center="2097/3097", **CTX)


def test_rows_explain_in_plain_words_what_to_do():
    client = login(build().test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    assert "Fixed in 2.0 with the distribution" in html  # openssl has a fix
    assert "No fix yet" in html and "no patch published for this yet" in html  # virtualbox has none


URIS = (
    "'http://x/vim.deb' vim_9.2.deb 1000000 SHA256:abc\n"
    "'http://x/rt.deb' rt.deb 234000 SHA256:def\n"
)
SIMULATION = """Reading package lists...
Inst vim [9.1] (9.2 noble-updates [amd64])
Inst vim-runtime [9.1] (9.2 noble-updates [all])
Inst brand-new-lib (1.0 noble [amd64])
Remv old-thing [1.0]
Need to get 1,234 kB/5,678 kB of archives.
After this operation, 12.5 MB of additional disk space will be used.
"""


def with_guarded_packages():
    from dataclasses import replace

    result = make_result()
    guarded = [
        Package("bash", "5.2", "amd64", 1800, "shell", priority="required", has_menu_entry=True),
        Package("vim", "9.1", "amd64", 3000, "text editor", has_menu_entry=True),
    ]
    updates = [Update("vim", "amd64", "9.1", "9.2", "noble-updates", False)]
    return replace(result, tools=build_tools(guarded, [], updates, "6.8.0-137-generic"))


def preview_client(simulator=lambda action, name, uris=False: URIS if uris else SIMULATION):
    client = login(build(with_guarded_packages, simulator).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    return client


def test_preview_shows_what_an_update_would_do_and_the_commands_to_copy():
    html = (
        preview_client().get("/preview?action=update&pkg=vim", base_url=BASE).get_data(as_text=True)
    )
    assert "2 updated, 1 new, 1 removed" in html
    assert "Still to download: 1.2 MiB" in html
    assert "sudo apt-get install --only-upgrade vim" in html
    assert "dpkg --get-selections" in html  # the undo list comes first
    assert "style=" not in html


def test_protected_programs_cannot_be_previewed_for_removal():
    client = preview_client(lambda *_: (_ for _ in ()).throw(AssertionError("must not simulate")))
    html = client.get("/preview?action=remove&pkg=bash", base_url=BASE).get_data(as_text=True)
    assert "will not remove it" in html and "sudo apt-get remove" not in html


def test_removal_that_drags_protected_software_is_refused():
    simulation = "Remv vim [9.1]\nRemv bash [5.2]\n"
    client = preview_client(lambda *_a: simulation)
    html = client.get("/preview?action=remove&pkg=vim", base_url=BASE).get_data(as_text=True)
    assert "also remove software the system depends on" in html
    assert "sudo apt-get remove" not in html


def test_preview_rejects_unknown_actions_and_packages():
    client = preview_client(lambda *_: (_ for _ in ()).throw(AssertionError("must not simulate")))
    assert client.get("/preview?action=purge&pkg=vim", base_url=BASE).status_code == 400
    for name in ("nonexistent", "vim;reboot", "-rf", "../etc"):
        html = client.get(f"/preview?action=remove&pkg={name}", base_url=BASE).get_data(
            as_text=True
        )
        assert "not in the list" in html


def test_preview_needs_the_access_cookie():
    assert build().test_client().get("/preview?action=all", base_url=BASE).status_code == 403


def test_a_failed_simulation_shows_a_generic_message():
    def broken(action, name, uris=False):
        raise OSError("/secret/path exploded")

    html = preview_client(broken).get("/preview?action=all", base_url=BASE).get_data(as_text=True)
    assert "could not run" in html and "/secret/path" not in html


def test_table_has_update_and_remove_buttons_and_protected_lock():
    html = preview_client().get("/", base_url=BASE).get_data(as_text=True)
    assert "/preview?action=update&amp;pkg=vim" in html
    assert "/preview?action=remove&amp;pkg=vim" in html
    assert "Protected" in html and "action=remove&amp;pkg=bash" not in html
    assert "action=all" in html  # "Update everything" in the header


def run_client(executor, simulator=lambda action, name, uris=False: URIS if uris else SIMULATION):
    client = login(build(with_guarded_packages, simulator, executor).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    return client


def post_run(client, body, headers=None):
    return client.post(
        "/api/run",
        json=body,
        base_url=BASE,
        headers={"X-Ganki": "1"} if headers is None else headers,
    )


def test_confirmed_removal_is_started_with_the_exact_package():
    executor = FakeExecutor()
    client = run_client(executor, lambda a, n, u=False: "Remv vim [9.1]\n")
    response = post_run(client, {"action": "remove", "pkg": "vim", "confirm": True})
    assert response.status_code == 202 and executor.started == [("remove", "vim")]


def test_running_needs_the_custom_header_and_the_cookie():
    executor = FakeExecutor()
    client = run_client(executor)
    body = {"action": "update", "pkg": "vim", "confirm": True, "understood": True}
    assert post_run(client, body, headers={}).status_code == 403
    assert build().test_client().post("/api/run", json=body, base_url=BASE).status_code == 403
    assert executor.started == []


def test_running_needs_explicit_confirmation_and_valid_input():
    executor = FakeExecutor()
    client = run_client(executor)
    for body in (
        {"action": "update", "pkg": "vim"},  # no confirm
        {"action": "update", "pkg": "vim", "confirm": "yes"},
        {"action": "purge", "pkg": "vim", "confirm": True},
        {"action": "update", "pkg": ["vim"], "confirm": True},
        None,
    ):
        assert post_run(client, body).status_code == 400
    assert executor.started == []


def test_protected_and_unknown_programs_are_never_run():
    executor = FakeExecutor()
    client = run_client(executor)
    for name in ("bash", "nonexistent", "vim;reboot"):
        response = post_run(client, {"action": "remove", "pkg": name, "confirm": True})
        assert response.status_code == 409
    assert executor.started == []


def test_warnings_must_be_acknowledged():
    executor = FakeExecutor()
    simulation = lambda a, n, u=False: "Remv vim [9.1]\nRemv vim-runtime [9.1]\n"  # noqa: E731
    client = run_client(executor, simulation)
    body = {"action": "remove", "pkg": "vim", "confirm": True}
    assert post_run(client, body).status_code == 409
    assert executor.started == []
    assert post_run(client, {**body, "understood": True}).status_code == 202


def test_a_second_action_is_refused_while_one_runs():
    client = run_client(FakeExecutor(busy=True), lambda a, n, u=False: "Remv vim [9.1]\n")
    assert post_run(client, {"action": "remove", "pkg": "vim", "confirm": True}).status_code == 409


def test_confirmation_screen_shows_warnings_and_the_run_button_only_when_it_can_run():
    simulation = lambda a, n, u=False: "Remv vim [9.1]\nRemv vim-runtime [9.1]\n"  # noqa: E731
    html = (
        run_client(FakeExecutor(), simulation)
        .get("/preview?action=remove&pkg=vim", base_url=BASE)
        .get_data(as_text=True)
    )
    assert "Are you sure" in html and "1 more package(s) will also be removed" in html
    assert 'id="run"' in html and 'id="understood"' in html and "style=" not in html
    # which password it is, and what to do if the account cannot give one
    assert "the same one you type with sudo" in html and "use the command shown below" in html
    no_window = run_client(FakeExecutor(available=False), simulation)
    html = no_window.get("/preview?action=remove&pkg=vim", base_url=BASE).get_data(as_text=True)
    assert 'id="run"' not in html and "sudo apt-get remove vim" in html


def test_run_status_is_available_to_the_page():
    client = run_client(FakeExecutor())
    assert client.get("/api/run/status", base_url=BASE).get_json()["state"] == "idle"


def test_logging_in_always_redirects_to_the_home_page():
    client = build().test_client()
    for path in ("/", "/preview", "//example.com", "/\\example.com"):
        response = client.get(f"{path}?access={SECRET}", base_url=BASE)
        if response.status_code == 302:
            assert response.headers["Location"] == "/"


def test_page_width_grows_with_the_screen_instead_of_a_fixed_column():
    css = (Path(__file__).parent.parent / "src/ganki/web/static/style.css").read_text()
    main_rule = next(line for line in css.splitlines() if line.startswith("main {"))
    assert "min(2200px" in main_rule and "100%" in main_rule


def test_times_over_a_minute_are_written_in_minutes_and_dates_in_local_form():
    from ganki.web.app import duration_text, feed_date_text

    assert duration_text(14.3) == "14.3 s"
    assert duration_text(149.5) == "2m 30s"
    assert duration_text(60.0) == "1m 00s"
    text = feed_date_text("Sat, 17 Oct 2026 07:57:02 GMT", "es")
    assert "oct 2026" in text and "GMT" not in text
    assert feed_date_text("garbage", "es") == "garbage"


def test_assistant_has_a_close_cross_and_the_search_has_a_magnifier():
    client = login(build().test_client())
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    assert 'id="assistant-close"' in html and 'id="assistant-open"' in html
    assert 'type="submit" class="lupa"' in html  # the magnifier really searches


def test_the_fix_labels_open_an_explanation_with_what_to_keep_in_mind():
    client = login(build().test_client())
    client.get("/", base_url=BASE)  # starts the scan
    wait_until_done(client)  # the page shows the result only once the scan has finished
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    # each label is the summary of a details element: a keyboard-friendly button, no script
    assert '<details class="note"><summary><span class="tag ok">' in html
    assert '<details class="note"><summary><span class="tag bad">' in html
    assert "A virtual machine isolates another system" in html  # virtualbox, not a generic text
    assert "encrypts the connections of many programs" in html  # openssl


def test_every_explanation_exists_in_both_languages():
    from ganki.web.i18n import TEXTS as STRINGS

    keys = [k for k in STRINGS["en"] if k.startswith("more_")]
    assert keys and all(STRINGS["es"].get(k) for k in keys)


def test_each_snap_or_flatpak_app_explains_how_ganki_treats_it():
    from dataclasses import replace

    from ganki.collectors.sandboxed import SandboxedApp

    def scan():
        return replace(
            make_result(),
            sandboxed=[
                SandboxedApp("firefox", "131.0", "snap", "mozilla**", 3 * 1024, "firefox"),
                SandboxedApp("ghost", "1", "snap", "someone", None, "ghost"),
                SandboxedApp("mesa-2404", "1", "snap", "canonical", None, "mesa-2404"),
            ],
        )

    client = login(build(scan).test_client())
    client.get("/", base_url=BASE)  # starts the scan
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    assert "How Ganki checks it" in html
    assert "cannot tell you whether it has known flaws" in html
    # every table lines up on the same columns: name, origin, version, size
    assert html.count('<table class="aligned">') == 2
    snap = html[html.index("Snap and Flatpak apps") :]
    order = [snap.index(w) for w in ("Package", "Installed with", "Version", "Size", "Source")]
    assert order == sorted(order)
    assert "sudo snap refresh firefox" in html and "sudo snap remove firefox" in html
    assert html.count("looks like a base that other apps") == 1  # only for the shared runtime
    assert "3.0 MiB" in html and '<td class="num mono">—</td>' in html  # size, or a dash


def test_the_hover_option_is_gone_from_the_assistant():
    client = login(build().test_client())
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    assert "voice-hover" not in html and 'id="voice-on"' in html


def test_a_second_click_opens_the_running_copy_instead_of_failing(tmp_path, monkeypatch):
    import threading

    from ganki.web import server

    app = build()
    started = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=PORT, use_reloader=False), daemon=True
    )
    started.start()
    import time

    time.sleep(1)
    url = f"http://127.0.0.1:{PORT}/?access={SECRET}"
    server.save_access_url(url, tmp_path)
    monkeypatch.setattr(server, "default_cache_dir", lambda: tmp_path)
    opened = []
    monkeypatch.setattr(
        server, "open_in_browser", lambda address, *_: opened.append(address) or True
    )
    assert server.looks_like_ganki(url)
    assert not server.looks_like_ganki(f"http://127.0.0.1:{PORT}/?access=wrong")
    assert server.main(["--port", str(PORT)]) == 0
    assert opened == [url]


def test_the_desktop_opener_is_the_fallback_when_no_browser_is_found(monkeypatch):
    from ganki.web import server

    calls = []
    monkeypatch.setattr(server.webbrowser, "open", lambda address: False)
    monkeypatch.setattr(server.shutil, "which", lambda name: "/usr/bin/xdg-open")
    monkeypatch.setattr(server.subprocess, "Popen", lambda cmd, **kw: calls.append(cmd))
    assert server.open_in_browser("http://127.0.0.1:1/") is True
    assert calls == [["/usr/bin/xdg-open", "http://127.0.0.1:1/"]]
    monkeypatch.setattr(server.shutil, "which", lambda name: None)
    assert server.open_in_browser("http://127.0.0.1:1/") is False


def test_any_installed_browser_is_used_when_there_is_no_default(monkeypatch):
    from ganki.web import server

    calls = []
    monkeypatch.setattr(server.webbrowser, "open", lambda address: False)
    installed = {"librewolf": "/usr/bin/librewolf"}  # no xdg-open, no default browser
    monkeypatch.setattr(server.shutil, "which", lambda name: installed.get(name))
    monkeypatch.setattr(server.subprocess, "Popen", lambda cmd, **kw: calls.append(cmd))
    assert server.open_in_browser("http://127.0.0.1:1/") is True
    assert calls == [["/usr/bin/librewolf", "http://127.0.0.1:1/"]]


def test_the_browser_is_not_opened_before_the_server_listens(tmp_path, monkeypatch, capsys):
    from ganki.web import server

    class FakeApp:
        def run(self, **_kwargs):
            return None

    opened = []
    monkeypatch.setattr(server, "default_cache_dir", lambda: tmp_path)
    monkeypatch.setattr(server, "create_app", lambda *_args, **_kwargs: FakeApp())
    monkeypatch.setattr(server.webbrowser, "open", lambda url: opened.append(url) or True)
    run_opening_inline(monkeypatch, listening=False)
    server.main(["--port", "8124"])
    assert opened == []  # it never answered, so the browser was not sent there
    assert str(tmp_path / server.ACCESS_FILE) in capsys.readouterr().out


def test_wait_until_listening_sees_a_real_listener():
    import socket

    from ganki.web import server

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        assert server.wait_until_listening(listener.getsockname()[1], seconds=2)
    assert not server.wait_until_listening(1, seconds=0.2)


def test_opening_without_the_key_explains_how_to_get_in():
    app = build()
    client = app.test_client()
    for path in ("/", "/?access=", "/?access=wrong"):
        reply = client.get(path, base_url=BASE)
        html = reply.get_data(as_text=True)
        assert reply.status_code == 403
        assert "ganki --no-open" in html and "dashboard-url" in html
        assert SECRET not in html and "style=" not in html and "<script" not in html
    # with the key it still works, and a POST without the session is still a plain refusal
    assert login(app.test_client()).get("/", base_url=BASE).status_code == 200
    assert client.post("/api/anything", base_url=BASE).status_code == 403


def _browsers_found(monkeypatch, tmp_path, found, dialog=None, folders=()):
    """Pretend these commands exist; `dialog` is what the choice window answers."""
    from ganki.web import browsers

    monkeypatch.delenv("BROWSER", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(browsers.shutil, "which", lambda name: found.get(name))
    monkeypatch.setattr(browsers, "APPLICATION_FOLDERS", tuple(str(f) for f in folders))
    asked = []

    def fake_run(command):
        asked.append(command)
        if "--list" in command or "--menu" in command or "--file-selection" in command:
            return dialog.pop(0) if isinstance(dialog, list) else (dialog or (1, ""))
        return 0, ""  # "Remember" pressed

    monkeypatch.setattr(browsers, "_run", fake_run)
    return browsers, asked


def _desktop_entry(
    folder, name, label, command, categories="Network;WebBrowser;", mime="x-scheme-handler/http;"
):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(
        f"[Desktop Entry]\nType=Application\nName={label}\nExec={command}\n"
        f"Categories={categories}\nMimeType={mime}\n"
    )


def test_installed_browsers_come_from_known_commands_and_the_desktop_list(monkeypatch, tmp_path):
    apps = tmp_path / "apps"
    _desktop_entry(apps, "wolf.desktop", "LibreWolf", "/opt/wolf/librewolf %u")
    _desktop_entry(apps, "tor.desktop", "Tor Browser", "tor-browser %u")
    _desktop_entry(apps, "game.desktop", "Wolf Game", "/opt/wolf/game", categories="Game;")
    _desktop_entry(apps, "ff.desktop", "Firefox Web Browser", "firefox %u")  # same as command
    found = {
        "firefox": "/usr/bin/firefox",
        "tor-browser": "/usr/bin/tor-browser",
        "/opt/wolf/librewolf": "/opt/wolf/librewolf",
        "chromium": "/usr/bin/chromium",
    }
    browsers, _ = _browsers_found(monkeypatch, tmp_path, found, folders=[apps])
    labels = [b.label for b in browsers.installed_browsers()]
    assert labels == ["Chromium", "Firefox", "LibreWolf", "Tor Browser"]  # no duplicates, no game


def test_a_flatpak_browser_is_started_with_its_own_command(monkeypatch, tmp_path):
    apps = tmp_path / "apps"
    _desktop_entry(
        apps,
        "io.gitlab.librewolf-community.desktop",
        "LibreWolf",
        "/usr/bin/flatpak run --branch=stable --command=librewolf io.gitlab.librewolf-community "
        "@@u %U @@",
    )
    browsers, _ = _browsers_found(
        monkeypatch, tmp_path, {"/usr/bin/flatpak": "/usr/bin/flatpak"}, folders=[apps]
    )
    (entry,) = browsers.installed_browsers()
    assert entry.argv[-1] == "io.gitlab.librewolf-community"
    assert browsers.command_for(entry.key) == list(entry.argv)


def test_the_chosen_browser_is_used_and_can_be_remembered(monkeypatch, tmp_path):
    found = {
        "zenity": "/usr/bin/zenity",
        "firefox": "/usr/bin/firefox",
        "librewolf": "/usr/bin/librewolf",
    }
    browsers, asked = _browsers_found(monkeypatch, tmp_path, found, (0, "/usr/bin/librewolf"))

    assert browsers.choose() == "/usr/bin/librewolf"
    assert browsers.preference_path().read_text().strip() == "/usr/bin/librewolf"

    asked.clear()
    assert browsers.choose() == "/usr/bin/librewolf"  # remembered: no window
    assert asked == []

    browsers.choose(force_ask=True)  # --ask-browser asks again
    assert asked


def test_a_program_picked_from_the_files_is_accepted(monkeypatch, tmp_path):
    mine = tmp_path / "LibreWolf.AppImage"
    mine.write_text("#!/bin/sh\n")
    mine.chmod(0o755)
    found = {"zenity": "/usr/bin/zenity", "firefox": "/f", "chromium": "/c"}
    browsers, _ = _browsers_found(
        monkeypatch, tmp_path, found, [(0, browsers_other()), (0, str(mine))]
    )
    assert browsers.choose() == str(mine)
    assert browsers.command_for(str(mine)) == [str(mine)]


def browsers_other():
    from ganki.web import browsers

    return browsers.OTHER


def test_cancelling_the_window_opens_nothing_and_remembers_nothing(monkeypatch, tmp_path):
    found = {"zenity": "/usr/bin/zenity", "firefox": "/f", "librewolf": "/l"}
    browsers, _ = _browsers_found(monkeypatch, tmp_path, found, (1, ""))
    assert browsers.choose() == browsers.CANCELLED
    assert not browsers.preference_path().exists()


def test_a_single_browser_or_no_dialog_tool_falls_back_to_the_default(monkeypatch, tmp_path):
    browsers, asked = _browsers_found(
        monkeypatch, tmp_path, {"zenity": "/usr/bin/zenity", "firefox": "/f"}
    )
    assert browsers.choose() == browsers.DEFAULT and asked == []
    browsers, asked = _browsers_found(monkeypatch, tmp_path, {"firefox": "/f", "librewolf": "/l"})
    assert browsers.choose() == browsers.DEFAULT and asked == []


def test_the_browser_variable_is_respected_without_asking(monkeypatch, tmp_path):
    browsers, asked = _browsers_found(
        monkeypatch, tmp_path, {"zenity": "/z", "firefox": "/f", "librewolf": "/l"}
    )
    monkeypatch.setenv("BROWSER", "librewolf")
    assert browsers.choose() == browsers.DEFAULT and asked == []


def test_an_unknown_answer_cannot_launch_an_arbitrary_program(monkeypatch, tmp_path):
    found = {"zenity": "/usr/bin/zenity", "firefox": "/f", "librewolf": "/l"}
    browsers, _ = _browsers_found(monkeypatch, tmp_path, found, (0, "/opt/not-a-browser"))
    assert browsers.choose() == browsers.DEFAULT


def test_open_in_browser_starts_the_chosen_one(monkeypatch):
    from ganki.web import server

    started = []
    from ganki.web import browsers

    monkeypatch.setattr(browsers, "command_for", lambda key: ["/usr/bin/librewolf"])
    monkeypatch.setattr(server, "_start", lambda command: started.append(command) or True)
    assert server.open_in_browser("http://127.0.0.1:1/", "/usr/bin/librewolf") is True
    assert started == [["/usr/bin/librewolf", "http://127.0.0.1:1/"]]


def test_asking_again_and_choosing_always_ask_undoes_a_remembered_choice(monkeypatch, tmp_path):
    found = {"zenity": "/usr/bin/zenity", "firefox": "/usr/bin/firefox", "chromium": "/c"}
    browsers, asked = _browsers_found(monkeypatch, tmp_path, found, (0, "/usr/bin/firefox"))
    browsers.remember("/usr/bin/firefox")
    assert browsers.choose() == "/usr/bin/firefox"  # remembered: no window

    def say_no_to_remembering(command):
        asked.append(command)
        if "--list" in command:
            return 0, "/c"
        return 1, ""  # "Always ask" pressed

    monkeypatch.setattr(browsers, "_run", say_no_to_remembering)
    assert browsers.choose(force_ask=True) == "/c"
    assert not browsers.preference_path().exists()  # forgotten: the next start asks again


def test_a_row_with_fixed_and_unfixed_notices_counts_each_kind():
    from dataclasses import replace

    from ganki.web.i18n import TEXTS as STRINGS

    for lang in ("en", "es"):
        text = STRINGS[lang]["hint_fixed_part"].format(n=39, m=3, version="1.2")
        assert "39" in text and "3" in text and "1.2" in text

    def scan():
        result = make_result()
        extra = Finding("CVE-9", "openssl", ("openssl",), "1.0", None, None, "low", "plain text")
        findings = [*result.findings, extra]
        packages = [Package("openssl", "1.0", "amd64", 900, "crypto toolkit", has_menu_entry=True)]
        return replace(result, findings=findings, tools=build_tools(packages, findings, []))

    client = login(build(scan).test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    # openssl has one notice with a fix and one without: each label says how many
    assert 'tag ok">Fix available: 1<' in html
    assert 'tag bad">No fix yet: 1<' in html
    # the summary line no longer suggests that every notice is fixed by the update
    assert "1 fixed in 2.0 · 1 with no fix yet" in html


def test_two_names_for_the_same_program_are_listed_once(monkeypatch, tmp_path):
    program = tmp_path / "opt" / "chrome"
    program.parent.mkdir()
    program.write_text("#!/bin/sh\n")
    program.chmod(0o755)
    short, stable = tmp_path / "google-chrome", tmp_path / "google-chrome-stable"
    short.symlink_to(program)
    stable.symlink_to(program)
    apps = tmp_path / "apps"
    _desktop_entry(apps, "chrome.desktop", "Google Chrome", f"{stable} %U")
    found = {"google-chrome": str(short)}
    browsers, _ = _browsers_found(monkeypatch, tmp_path, found, folders=[apps])
    assert [b.label for b in browsers.installed_browsers()] == ["Google Chrome"]


def test_system_entries_that_only_claim_to_be_browsers_are_left_out(monkeypatch, tmp_path):
    apps = tmp_path / "apps"
    _desktop_entry(apps, "wolf.desktop", "LibreWolf", "/opt/wolf/librewolf %u")
    _desktop_entry(apps, "support.desktop", "Support", "/opt/wolf/support", mime="")
    _desktop_entry(apps, "net.desktop", "Network Connections", "/opt/wolf/net", mime="")
    found = {"/opt/wolf/librewolf": "/opt/wolf/librewolf", "/opt/wolf/support": "/x"}
    found["/opt/wolf/net"] = "/y"
    browsers, _ = _browsers_found(monkeypatch, tmp_path, found, folders=[apps])
    assert [b.label for b in browsers.installed_browsers()] == ["LibreWolf"]


def test_emptying_the_download_cache_has_its_own_preview_and_runs_without_a_package():
    executor = FakeExecutor()
    client = run_client(executor)
    html = client.get("/preview?action=clean", base_url=BASE).get_data(as_text=True)
    assert "Frees 1.9 GiB" in html and "sudo apt-get clean" in html
    assert "dpkg --get-selections" not in html and "updated," not in html
    assert "list of programs" not in html  # nothing is saved when only downloads are deleted
    assert "action=clean" in client.get("/", base_url=BASE).get_data(as_text=True)
    response = post_run(client, {"action": "clean", "pkg": "", "confirm": True})
    assert response.status_code == 202 and executor.started == [("clean", "")]


def test_removing_what_is_not_needed_has_its_preview_and_runs_without_a_package():
    executor = FakeExecutor()
    simulation = "Remv linux-image-6.8.0-100-generic [6.8.0-100]\nRemv old-lib [1.0]\n"
    client = run_client(executor, lambda a, n, u=False: simulation)
    html = client.get("/preview?action=autoremove", base_url=BASE).get_data(as_text=True)
    assert "linux-image-6.8.0-100-generic" in html and "sudo apt-get autoremove" in html
    assert "never removes the kernel in use" in html
    assert "action=autoremove" in client.get("/", base_url=BASE).get_data(as_text=True)
    response = post_run(client, {"action": "autoremove", "pkg": "", "confirm": True})
    assert response.status_code == 202 and executor.started == [("autoremove", "")]


def test_a_refusal_names_the_protected_packages_behind_it():
    simulation = "Remv linux-image-6.8.0-100-generic [6.8.0-100]\nRemv bash [5.2]\n"
    client = run_client(FakeExecutor(), lambda a, n, u=False: simulation)
    html = client.get("/preview?action=autoremove", base_url=BASE).get_data(as_text=True)
    assert "Protected packages it would remove" in html and "bash" in html
    assert "linux-image-6.8.0-100-generic" not in html


def test_autoremove_accepts_a_leftover_library_but_still_refuses_core_packages():
    from dataclasses import replace

    def scan():
        packages = [
            Package("libold1:i386", "1", "i386", 90, "lib", priority="required"),
            Package("coreutils", "9", "amd64", 900, "core", essential=True),
        ]
        return replace(make_result(), tools=build_tools(packages, [], [], "6.8.0-137-generic"))

    def client_for(simulation):
        client = login(build(scan, lambda a, n, u=False: simulation, FakeExecutor()).test_client())
        client.get("/", base_url=BASE)
        wait_until_done(client)
        return client

    page = "/preview?action=autoremove"
    ok = client_for("Remv libold1:i386 [1]\n").get(page, base_url=BASE).get_data(as_text=True)
    assert "libold1:i386" in ok and "sudo apt-get autoremove" in ok
    refused = client_for("Remv coreutils [9]\n").get(page, base_url=BASE).get_data(as_text=True)
    assert (
        "Protected packages it would remove" in refused and "sudo apt-get autoremove" not in refused
    )


def test_a_folder_of_downloads_can_be_opened_but_nothing_else(tmp_path, monkeypatch):
    from ganki import downloads

    base = tmp_path / "Descargas"
    (base / "fotos").mkdir(parents=True)
    (base / "fotos" / "a.jpg").write_text("x")
    monkeypatch.setattr(downloads, "downloads_dir", lambda: base)
    opened = []
    app = create_app(make_result, SECRET, PORT, opener=lambda folder: opened.append(folder) or True)
    app.testing = True
    client = login(app.test_client())
    wait_until_done(client)

    def ask(path, headers=None):
        return client.post(
            "/api/open-folder",
            json={"path": path},
            base_url=BASE,
            headers={"X-Ganki": "1"} if headers is None else headers,
        )

    assert ask("fotos/a.jpg").status_code == 200 and opened == [(base / "fotos").resolve()]
    assert ask("../etc").status_code == 400 and ask("/etc").status_code == 400
    assert (
        client.post(
            "/api/open-folder", json=None, base_url=BASE, headers={"X-Ganki": "1"}
        ).status_code
        == 400
    )
    assert ask("fotos/a.jpg", headers={}).status_code == 403
    assert len(opened) == 1


def test_oversized_request_is_refused() -> None:
    """A huge body is cut off before it is read (the page only sends tiny JSON)."""
    app = create_app(make_result, SECRET, PORT)
    app.testing = True
    client = login(app.test_client())
    response = client.post(
        "/api/run",
        data=b"x" * (200 * 1024),
        base_url=BASE,
        headers={"X-Ganki": "1", "Content-Type": "application/json"},
    )
    assert response.status_code == 413
