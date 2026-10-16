# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for the web dashboard: access control, hardening, rendering."""

import time
from datetime import datetime, timezone

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
        Package("openssl", "1.0", "amd64", 900, "crypto toolkit", manual=True),
        Package("virtualbox", "7.0", "amd64", 4000, "virtual machines", manual=True),
        Package("vim", "9.1", "amd64", 3000, "text editor", manual=True),
        Package("git", "2.43", "amd64", 38000, "version control", manual=True),
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


def build(scan=make_result):
    app = create_app(scan, SECRET, PORT)
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


def test_access_url_is_saved_privately_and_not_printed(tmp_path, monkeypatch, capsys):
    import stat

    from ganki.web import server

    opened = []

    class FakeApp:
        def run(self, **_kwargs):
            return None

    monkeypatch.setattr(server, "default_cache_dir", lambda: tmp_path / "cache")
    monkeypatch.setattr(server, "create_app", lambda *_args: FakeApp())
    monkeypatch.setattr(server.webbrowser, "open", lambda url: opened.append(url) or True)

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
    monkeypatch.setattr(server, "create_app", lambda *_args: FakeApp())
    monkeypatch.setattr(server.webbrowser, "open", lambda url: False)

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
