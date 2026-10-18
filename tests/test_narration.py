# ruff: noqa: S101
"""The spoken explanation: fixed rules, computed from this machine's numbers."""

import re

import pytest

from ganki import narration
from ganki.service import ScanResult
from test_web import BASE, build, login, make_result, wait_until_done


def texts(result: ScanResult, lang: str) -> str:
    return " ".join(s.text for s in narration.build(result, lang))


@pytest.mark.parametrize("lang", ["en", "es"])
def test_no_placeholder_is_left_in_the_text(lang):
    for segment in narration.build(make_result(), lang):
        assert not re.search(r"[{}]", segment.text), segment.text


@pytest.mark.parametrize("lang", ["en", "es"])
def test_every_segment_points_at_a_section_of_the_page(lang):
    sections = {s.section for s in narration.build(make_result(), lang)}
    assert sections <= {"system", "disk", "ram", "programs", "tools", "reclaim", "downloads"}
    assert {"system", "disk", "ram", "programs", "tools"} <= sections


def test_spoken_sizes_are_written_for_a_voice():
    assert narration.spoken_size(2 * 1024**2, "es") == "2 gigas"
    assert narration.spoken_size(1536 * 1024, "es") == "1,5 gigas"
    assert narration.spoken_size(512, "en") == "512 kilobytes"


def test_scanning_message_asks_to_wait():
    assert "wait" in narration.scanning_message("en").lower()
    assert "esper" in narration.scanning_message("es").lower()


def test_advice_covers_fixable_expired_and_virtual_machines():
    result = make_result()
    text = texts(result, "en")
    assert "update" in text.lower()
    if any(t.name == "virtualbox" for t in result.tools):
        assert "do not browse the web" in text


def test_no_advice_when_nothing_is_vulnerable():
    result = make_result()
    for tool in result.tools:
        object.__setattr__(tool, "state", "ok")
    text = texts(result, "en")
    assert "My advice" not in text
    assert "None of your programs" in text


def test_endpoint_is_empty_until_the_scan_is_done():
    client = login(build().test_client())
    data = client.get("/api/narration", base_url=BASE).get_json()
    assert data["segments"] == []
    assert data["scanning"]
    client.get("/", base_url=BASE)
    wait_until_done(client)
    data = client.get("/api/narration", base_url=BASE).get_json()
    assert data["segments"]


def test_endpoint_needs_the_session():
    client = build().test_client()
    assert client.get("/api/narration", base_url=BASE).status_code in (401, 403)


def test_page_marks_sections_and_has_the_dock_without_loosening_the_csp():
    client = login(build().test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    response = client.get("/", base_url=BASE)
    html = response.get_data(as_text=True)
    assert html.count("data-explain=") >= 6
    assert 'id="assistant"' in html
    assert "assistant.js" in html
    csp = response.headers["Content-Security-Policy"]
    assert "unsafe" not in csp and "script-src 'self'" in csp
