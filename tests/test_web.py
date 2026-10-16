# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for the web dashboard: access control, hardening, rendering."""

import time
from datetime import datetime, timezone

import pytest

from ganki.osv import Finding
from ganki.release import UnsupportedReleaseError
from ganki.service import ScanResult
from ganki.summary import summarize
from ganki.web.app import SESSION_COOKIE, create_app
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
    return ScanResult(
        ecosystem="Ubuntu:24.04:LTS",
        feed_downloaded=False,
        feed_date="today",
        findings=findings,
        risks=summarize(findings, "6.8.0-137-generic"),
        snap_stubs=["thunderbird"],
        pending_updates=5,
        scanned_at=datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc),
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


def test_page_shows_sections_after_the_scan():
    client = login(build().test_client())
    client.get("/", base_url=BASE)  # starts the scan
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    assert "openssl" in html
    assert "virtualbox" in html
    assert "6.8.0-31.31" in html  # listed as an old kernel
    assert "thunderbird" in html


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
    assert "Programas" in client.get("/", base_url=BASE).get_data(as_text=True)
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
    assert translate("en", "more", n=3) == "and 3 more"


@pytest.mark.parametrize("key", ["title", "rescan", "kernel", "programs_fix", "old_kernels"])
def test_every_key_exists_in_both_languages(key):
    assert translate("es", key) != key
    assert translate("en", key) != key
