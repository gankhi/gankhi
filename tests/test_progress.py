# ruff: noqa: S101
"""The live view of a running scan."""

import threading
import time

from ganki.progress import STEPS, Progress
from ganki.web.app import create_app
from test_web import BASE, PORT, SECRET, login, make_result


def test_steps_move_from_pending_to_running_to_done():
    progress = Progress()
    assert {s["state"] for s in progress.snapshot()["steps"]} == {"pending"}
    progress.begin("system")
    assert progress.snapshot()["steps"][0]["state"] == "running"
    progress.finish("system", os_name="Ubuntu")
    snap = progress.snapshot()
    assert snap["steps"][0]["state"] == "done"
    assert snap["facts"]["os_name"] == "Ubuntu"
    assert [s["key"] for s in snap["steps"]] == list(STEPS)


def test_fraction_is_kept_between_zero_and_one():
    progress = Progress()
    progress.begin("index")
    progress.fraction("index", 7.5)
    assert progress.snapshot()["steps"][5]["fraction"] == 1.0
    progress.fraction("index", -1)
    assert progress.snapshot()["steps"][5]["fraction"] == 0.0


def test_reset_forgets_the_previous_scan():
    progress = Progress()
    progress.begin("system")
    progress.finish("system", packages=3)
    progress.reset()
    snap = progress.snapshot()
    assert snap["facts"] == {} and snap["steps"][0]["state"] == "pending"


def slow_app():
    progress = Progress()
    release = threading.Event()

    def scan():
        progress.begin("system")
        progress.finish(
            "system",
            os_name="Ubuntu 24.04",
            disk_total=100 * 1024**3,
            disk_used=60 * 1024**3,
            ram_total_kib=1000,
            ram_used_kib=380,
        )
        progress.begin("programs")
        progress.finish("programs", packages=1234)
        progress.begin("index")
        progress.fraction("index", 0.5)
        release.wait(5)
        return make_result()

    return create_app(scan, SECRET, PORT, progress=progress), release


def test_the_running_page_shows_the_progress_panel():
    app, release = slow_app()
    client = login(app.test_client())
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    assert 'id="progress"' in html and 'id="steps"' in html
    release.set()


def test_progress_endpoint_describes_steps_and_first_facts():
    app, release = slow_app()
    client = login(app.test_client())
    client.get("/", base_url=BASE)
    time.sleep(0.3)
    data = client.get("/api/progress", base_url=BASE).get_json()
    states = {s["key"]: s["state"] for s in data["steps"]}
    assert states["system"] == "done" and states["index"] == "running"
    assert any("1234 packages" in line for line in data["facts"])
    assert any("60% used" in line for line in data["facts"])
    index = next(s for s in data["steps"] if s["key"] == "index")
    assert index["detail"] == "50 %"
    assert 0 < data["percent"] < 100
    assert data["state"] == "running"
    release.set()


def test_progress_text_follows_the_language():
    app, release = slow_app()
    client = login(app.test_client())
    client.get("/", base_url=BASE)
    time.sleep(0.3)
    client.set_cookie("ganki_lang", "es", domain="127.0.0.1")
    data = client.get("/api/progress", base_url=BASE).get_json()
    assert any("paquetes instalados" in line for line in data["facts"])
    release.set()


def test_progress_needs_the_session():
    app, release = slow_app()
    assert app.test_client().get("/api/progress", base_url=BASE).status_code == 403
    release.set()
