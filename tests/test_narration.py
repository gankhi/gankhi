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
    assert sections <= {"system", "disk", "ram", "tools", "reclaim", "downloads", "external"}
    assert {"system", "disk", "ram", "tools"} <= sections


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
    assert "Everything is up to date" in text


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


def test_only_the_most_urgent_programs_are_named():
    result = make_result()
    names = [t.name for t in result.tools if t.is_program and t.state == "vulnerable"]
    urgent = narration._most_urgent([t for t in result.tools if t.state == "vulnerable"])
    assert len(urgent) <= narration.MOST_URGENT
    text = texts(result, "en")
    for tool in result.tools:
        if tool.state == "vulnerable" and tool not in urgent:
            assert tool.name not in text
    assert names  # the sample machine has vulnerable programs


def test_highest_priority_comes_first():
    from types import SimpleNamespace as T

    items = [
        T(name="b", top_priority="medium", fixed_in="1", cve_count=1),
        T(name="a", top_priority="high", fixed_in=None, cve_count=1),
        T(name="c", top_priority="high", fixed_in="2", cve_count=1),
    ]
    assert [t.name for t in narration._most_urgent(items)] == ["c", "a", "b"]


def test_the_summary_is_short_and_follows_the_requested_order():
    sections = [s.section for s in narration.build(make_result(), "es")]
    assert sections.index("disk") < sections.index("ram") < sections.index("tools")
    assert "programs" not in sections


def _with_library(result, priority="critical", name="libfoo1"):
    from dataclasses import replace

    template = next(t for t in result.tools if t.is_program)
    library = replace(
        template,
        name=name,
        is_program=False,
        state="vulnerable",
        top_priority=priority,
        fixed_in="2.0",
        end_of_support=False,
    )
    return replace(result, tools=[*result.tools, library])


@pytest.mark.parametrize("lang", ["en", "es"])
def test_memory_reading_includes_the_total(lang):
    result = make_result()
    ram = next(s for s in narration.build(result, lang) if s.section == "ram")
    assert narration.spoken_size(result.system.ram_total_kib, lang) in ram.text


@pytest.mark.parametrize("lang", ["en", "es"])
def test_critical_libraries_are_counted_and_named(lang):
    result = _with_library(make_result(), "critical", "libcritical9")
    text = texts(result, lang)
    assert "libcritical9" in text
    assert re.search(r"\b1\b", text)


def test_libraries_alone_do_not_read_as_clean():
    result = make_result()
    for tool in result.tools:
        object.__setattr__(tool, "state", "ok")
    result = _with_library(result, "low", "libquiet1")
    text = texts(result, "en")
    assert "Everything is up to date" not in text
    assert "none critical" in text


def test_old_kernels_never_take_the_place_of_what_is_urgent():
    from dataclasses import replace

    result = make_result()
    result = _with_library(result, "critical", "linux-headers-6.8.0-90")
    result = _with_library(result, "high", "libreal1")
    result = replace(
        result,
        reclaimable=replace(result.reclaimable, old_kernel_packages=["linux-headers-6.8.0-90"]),
    )
    text = texts(result, "en")
    advice = text.split("My advice")[1]
    assert "linux-headers-6.8.0-90" not in advice
    assert "libreal1" in advice
    assert "old kernels" in text


def test_thousands_are_written_with_separators():
    assert narration.thousands(108995, "es") == "108.995"
    assert narration.thousands(108995, "en") == "108,995"


def test_the_pieces_of_one_kernel_are_one_entry_and_a_restart_is_advised():
    result = make_result()
    for name in ("linux-image-6.8.0-137-generic", "linux-modules-6.8.0-137-generic"):
        result = _with_library(result, "critical", name)
    text = texts(result, "en")
    advice = text.split("My advice")[1]
    assert "the system kernel" in advice
    assert "linux-image" not in advice and "linux-modules" not in advice
    assert "restart the computer" in advice


def test_with_a_full_disk_the_advice_is_to_clean_before_updating():
    from dataclasses import replace

    from ganki import cleanup

    result = make_result()
    roomy = replace(result.system, disk_used=10, disk_total=1010)
    full = replace(result.system, disk_used=900, disk_total=1000)
    reclaim = cleanup.Reclaimable(apt_cache_kib=4_000_000)
    base = replace(result, reclaimable=reclaim, pending_updates=5)
    assert "clean first" not in texts(replace(base, system=roomy), "en")
    assert "clean first" in texts(replace(base, system=full), "en")


@pytest.mark.parametrize("lang", ["en", "es"])
def test_end_of_support_wording_does_not_overstate(lang):
    from ganki.web import i18n

    for key in ("say_advice_expired", "hint_eol", "report_act_eol"):
        assert "Ubuntu Pro" in i18n.translate(lang, key, names="x")


def test_snap_and_flatpak_apps_are_counted_and_said_not_to_be_checked():
    import dataclasses

    from ganki.collectors.sandboxed import SandboxedApp

    result = dataclasses.replace(
        make_result(),
        sandboxed=[
            SandboxedApp("firefox", "131", "snap", "mozilla"),
            SandboxedApp("GIMP", "2.10", "flatpak", "flathub"),
            SandboxedApp("Inkscape", "1.3", "flatpak", "flathub"),
        ],
    )
    text = " ".join(s.text for s in narration.build(result, "es"))
    assert "1 apps snap y 2 flatpak" in text and "no las reviso" in text
    data = __import__("ganki.report", fromlist=["x"]).build_report(result, "es", "now")
    assert data.startswith(b"%PDF")
