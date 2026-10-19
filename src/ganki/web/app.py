"""The Flask application: a read-only view of the scan, reachable only from this machine.

Defences, in order of what they stop:
- The server listens on 127.0.0.1 only (see ``server.py``).
- Every request needs the secret token printed at start-up (kept in an HttpOnly,
  SameSite=Strict cookie afterwards), so another local user or a web page cannot read it.
- The ``Host`` header must be the loopback address, which blocks DNS-rebinding attacks.
- State-changing requests need a custom header plus a same-origin ``Origin`` (no CSRF).
- A strict Content-Security-Policy and other headers; no external resources at all.
"""

from __future__ import annotations

import hmac
import subprocess
import threading
from collections.abc import Callable
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, make_response, redirect, render_template, request
from werkzeug.wrappers import Response

from ganki import (
    actions,
    advice,
    downloads,
    external_tools,
    folders,
    narration,
    paging,
    report,
    speech,
)
from ganki.collectors import sandboxed
from ganki.executor import ActionJob
from ganki.progress import RUNNING as STEP_RUNNING
from ganki.progress import Progress
from ganki.runner import CommandNotAllowedError
from ganki.service import ScanResult
from ganki.summary import RUNNING_KERNEL
from ganki.tools import OK, OUTDATED, VULNERABLE
from ganki.web import i18n
from ganki.web.jobs import DONE, IDLE, RUNNING, ScanJob

SESSION_COOKIE = "ganki_session"
LANG_COOKIE = "ganki_lang"
WARM_SEGMENTS = 4
MONTHS = {
    "es": "ene feb mar abr may jun jul ago sep oct nov dic".split(),
    "en": "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(),
}


def level_tone(value: int, busy: int, tight: int) -> str:
    """bad / warn / ok, with the same limits the spoken summary uses."""
    return "bad" if value >= tight else "warn" if value >= busy else "ok"


def duration_text(seconds: float) -> str:
    """``14.3`` -> ``14.3 s``; from one minute on, ``149.5`` -> ``2m 29s``."""
    if seconds < 60:
        return f"{seconds} s"
    whole = round(seconds)
    return f"{whole // 60}m {whole % 60:02d}s"


def feed_date_text(text: str, lang: str) -> str:
    """The server's ``Sat, 17 Oct 2026 07:57:02 GMT`` as ``17 oct 2026, 04:57`` (local time)."""
    try:
        moment = parsedate_to_datetime(text).astimezone()
    except (TypeError, ValueError):
        return text[:40]
    months = MONTHS.get(lang, MONTHS["en"])
    return f"{moment.day} {months[moment.month - 1]} {moment.year}, {moment:%H:%M}"


STEP_WEIGHTS = {
    "system": 4,
    "programs": 8,
    "updates": 6,
    "downloads": 4,
    "feed": 4,
    "index": 60,
    "external": 4,
    "analysis": 10,
}
FILTERS = ("all", "ok", "outdated", "vulnerable")
MAX_QUERY_CHARS = 100
MAX_REQUEST_BYTES = 64 * 1024  # the page only ever sends tiny JSON bodies
CSP = (
    "default-src 'none'; style-src 'self'; font-src 'self'; script-src 'self'; connect-src 'self'; "
    "img-src 'self'; media-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


def uptime_text(seconds: int) -> str:
    """``273600`` -> ``3 d 4 h``."""
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    return f"{days} d {hours} h" if days else f"{hours} h {rest // 60} min"


NEEDS_KEY_PAGE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta name="color-scheme" content="dark light"><title>Ganki</title></head>
<body>
<h1>Ganki</h1>
<p><b>Falta la clave de acceso.</b> Abrí Ganki con su ícono del escritorio o desde el menú de
aplicaciones. Si querés usar otro navegador: en una consola ejecutá <code>ganki --no-open</code>,
y pegá en tu navegador la dirección completa que está en el archivo
<code>~/.cache/ganki/dashboard-url</code> (empieza con <code>http://127.0.0.1</code> y termina con
la clave). La clave cambia cada vez que Ganki arranca.</p>
<hr>
<p><b>The access key is missing.</b> Open Ganki from its desktop icon or the applications menu.
To use another browser: run <code>ganki --no-open</code> in a terminal, then paste into your
browser the full address found in <code>~/.cache/ganki/dashboard-url</code> (it starts with
<code>http://127.0.0.1</code> and ends with the key). The key changes every time Ganki starts.</p>
</body></html>
"""


def create_app(
    scan: Callable[[], ScanResult],
    secret: str,
    port: int,
    simulator: actions.Simulator = actions.simulate,
    executor: ActionJob | None = None,
    speaker: speech.Speaker | None = None,
    progress: Progress | None = None,
    opener: Callable[[Path], bool] = folders.open_folder,
) -> Flask:
    """Build the app. ``scan`` produces a ``ScanResult``; ``secret`` is the access token.

    ``simulator`` runs the apt simulations behind the previews and ``executor`` runs a
    confirmed action for real (both replaced in tests).
    """
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES
    voice = speaker or speech.Speaker()

    def warm_voice(result: ScanResult) -> None:
        """Speak-ahead: make the first parts of the narration while the page is still loading.

        Synthesis takes a few seconds, so doing it only when the browser asks made the voice
        start late. The audio goes to the same cache the browser's request reads from.
        """

        def work() -> None:
            for lang in i18n.LANGUAGES:
                if not voice.available(lang):
                    continue
                for segment in narration.build(result, lang)[:WARM_SEGMENTS]:
                    voice.speak(lang, segment.text)

        threading.Thread(target=work, daemon=True).start()

    job = ScanJob(scan, progress, on_done=warm_voice)
    runner_job = executor or ActionJob(on_done=job.start)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    app.jinja_env.filters["size"] = paging.human_size
    app.jinja_env.filters["bytes"] = lambda n: paging.human_size(int(n) // 1024)
    app.jinja_env.filters["uptime"] = uptime_text

    def authorized() -> bool:
        cookie = request.cookies.get(SESSION_COOKIE, "")
        return hmac.compare_digest(cookie.encode(), secret.encode())

    @app.before_request
    def guard() -> Response | None:
        if request.host not in allowed_hosts:
            abort(400)
        offered = request.args.get("access", "")
        if offered and hmac.compare_digest(offered.encode(), secret.encode()):
            response = redirect("/")  # a fixed address: drops the token, never follows the request
            response.set_cookie(
                SESSION_COOKIE, secret, httponly=True, secure=True, samesite="Strict", path="/"
            )
            return response
        if not authorized():
            abort(403)
        if request.method not in ("GET", "HEAD"):
            origin = request.headers.get("Origin")
            if request.headers.get("X-Ganki") != "1" or (
                origin is not None and origin.split("://", 1)[-1] not in allowed_hosts
            ):
                abort(403)
        return None

    @app.errorhandler(403)
    def forbidden(error: Exception) -> Response | tuple[str, int, dict[str, str]]:
        """Someone opened the page without the key: say how to get in, instead of a blank page.

        No styles or scripts are used: without the key the page cannot even load its own files.
        """
        if request.method not in ("GET", "HEAD") or authorized():
            return error  # type: ignore[return-value]
        return NEEDS_KEY_PAGE, 403, {"Content-Type": "text/html; charset=utf-8"}

    @app.after_request
    def harden(response: Response) -> Response:
        if response.headers.pop("X-Ganki-No-CSP", None) is None:
            response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def current_language() -> str:
        return i18n.pick_language(
            request.cookies.get(LANG_COOKIE), request.headers.get("Accept-Language")
        )

    @app.route("/lang/<code>")
    def set_language(code: str) -> Response:
        if code not in i18n.LANGUAGES:
            abort(404)
        response = redirect("/")
        response.set_cookie(
            LANG_COOKIE, code, httponly=True, secure=True, samesite="Strict", path="/"
        )
        return response

    def tool_view(result: ScanResult) -> dict[str, object]:
        """Everything the tools table needs, taken from the query string."""
        show_all = request.args.get("show") == "all"
        chosen = request.args.get("f", "all")
        chosen = chosen if chosen in FILTERS else "all"
        query = request.args.get("q", "")[:MAX_QUERY_CHARS]
        universe = [t for t in result.tools if t.is_program or show_all]
        wanted = {"ok": OK, "outdated": OUTDATED, "vulnerable": VULNERABLE}.get(chosen)
        text = query.strip().lower()
        shown = [
            t
            for t in universe
            if (wanted is None or t.state == wanted)
            and (not text or text in t.name.lower() or text in t.description.lower())
        ]
        kernel = [r for r in result.risks if r.kind == RUNNING_KERNEL]
        # The headline numbers add up everything Ganki checked: system programs and also the
        # Python and npm packages. (Snap and Flatpak apps are not checked, so they are not
        # counted as "up to date".) The filter chips keep counting the programs table only.
        outside = len(result.external)
        outside_bad = sum(1 for p in result.external if p.vulnerable)
        total_all = len(universe) + outside
        total_bad = sum(1 for t in universe if t.state == VULNERABLE) + outside_bad
        total_old = sum(1 for t in universe if t.state == OUTDATED)
        return {
            "totals": {
                "all": total_all,
                "outdated": total_old,
                "vulnerable": total_bad,
                "ok": total_all - total_old - total_bad,
                "outside": outside,
            },
            "page": paging.paginate(shown, request.args.get("page", 1, type=int)),
            "counts": {
                "all": len(universe),
                "outdated": sum(1 for t in universe if t.state == OUTDATED),
                "vulnerable": sum(1 for t in universe if t.state == VULNERABLE),
                "ok": sum(1 for t in universe if t.state == OK),
            },
            "filter": chosen,
            "filters": FILTERS,
            "q": query,
            "show_all": show_all,
            "kernel": kernel[0] if kernel else None,
        }

    @app.route("/")
    def index() -> str:
        if job.state == IDLE:
            job.start()
        lang = current_language()
        result = job.result
        context: dict[str, object] = {
            "lang": lang,
            "t": lambda key, **values: i18n.translate(lang, key, **values),
            "advise": lambda tool, kind, generic: advice.paragraphs(
                tool,
                kind,
                lang,
                lambda priority: i18n.translate(lang, priority or "unknown"),
                i18n.translate(lang, generic),
            ),
            "advise_app": lambda app: advice.sandboxed_paragraphs(app, lang),
            "update_info": lambda tool: advice.update_info(tool, lang),
            "sandboxed_update": sandboxed.update_command,
            "sandboxed_remove": sandboxed.remove_command,
            "sandboxed_shared": sandboxed.is_shared_runtime,
            "update_command": external_tools.update_command,
            "remove_command": external_tools.remove_command,
            "pip_managed": external_tools.externally_managed(),
            "state": job.state,
            "result": result,
            "now": datetime.now(),
            "natural_voice": voice.available(lang),
        }
        if result is not None and job.state in (DONE, RUNNING):
            context.update(tool_view(result))
        return render_template("index.html", **context)

    def build_preview(result: ScanResult, action: str, package: str) -> actions.Preview:
        try:
            return actions.preview(
                action,
                package,
                {t.name for t in result.tools},
                {
                    t.name
                    for t in result.tools
                    if (t.core if action == "autoremove" else t.protected)
                },
                simulator,
                {t.name: t.size_kib for t in result.tools},
                result.reclaimable.apt_cache_kib,
            )
        except (CommandNotAllowedError, subprocess.SubprocessError, OSError):
            return actions.Preview(action, package, blocked="blocked_failed")

    @app.route("/preview")
    def preview_page() -> str:
        """What an update or removal would do, from a simulation. Nothing is changed."""
        result = job.result
        action = request.args.get("action", "")
        package = request.args.get("pkg", "")[:100]
        if action not in actions.ACTIONS:
            abort(400)
        if result is None or job.state not in (DONE, RUNNING):
            return redirect("/")  # type: ignore[return-value]
        lang = current_language()
        view = build_preview(result, action, package)
        return render_template(
            "preview.html",
            lang=lang,
            t=lambda key, **values: i18n.translate(lang, key, **values),
            state=job.state,
            view=view,
            can_run=runner_job.available and not view.blocked,
            needs_ack=bool(view.warnings),
            warning_text=lambda key, value: i18n.translate(lang, key, n=value, name=value),
        )

    @app.route("/api/narration")
    def narration_data() -> Response:
        """The spoken explanation, built from the scan with fixed rules (no AI, no network)."""
        lang = current_language()
        result = job.result
        ready = result is not None and job.state == DONE
        segments = narration.build(result, lang) if ready and result is not None else []
        return jsonify(
            lang=lang,
            scanning=narration.scanning_message(lang),
            segments=[
                {"section": i.section, "text": i.text, "framing": i.framing} for i in segments
            ],
        )

    @app.route("/api/speak")
    def speak() -> Response:
        """Audio of one part of the narration. The text is built here, never taken from the page."""
        lang = current_language()
        result = job.result
        if request.args.get("scanning") == "1":
            text = narration.scanning_message(lang)
        elif result is None or job.state != DONE:
            abort(404)
        else:
            segments = narration.build(result, lang)
            section = request.args.get("section", "")
            index = request.args.get("seg", "")
            if index.isdigit() and int(index) < len(segments):
                text = segments[int(index)].text
            elif section:
                text = " ".join(s.text for s in segments if s.section == section and not s.framing)
            else:
                abort(400)
        if not text:
            abort(404)
        audio = voice.speak(lang, text)
        if audio is None:
            abort(503)
        return Response(audio, mimetype="audio/wav")

    @app.route("/api/progress")
    def scan_progress() -> Response:
        """What the scan is doing now, with short texts the page can show as they are."""
        lang = current_language()

        def say(key: str, **values: object) -> str:
            return i18n.translate(lang, key, **values)

        snap = job.progress.snapshot()
        facts: dict[str, Any] = snap["facts"]
        steps = []
        done_weight = 0.0
        for item in snap["steps"]:
            fraction = item["fraction"] or 0.0
            done_weight += STEP_WEIGHTS[item["key"]] * (
                1.0 if item["state"] == "done" else fraction
            )
            if item["state"] == "pending":
                detail = ""
            elif item["state"] == STEP_RUNNING and item["fraction"]:
                detail = f"{int(item['fraction'] * 100)} %"
            else:
                detail = duration_text(item["seconds"]) if item["seconds"] is not None else ""
            steps.append(
                {
                    "key": item["key"],
                    "label": say(f"step_{item['key']}"),
                    "state": item["state"],
                    "detail": detail,
                }
            )
        lines = []
        cards = []
        if "os_name" in facts:
            disk_pct = (
                round(100 * facts["disk_used"] / facts["disk_total"]) if facts["disk_total"] else 0
            )
            ram_pct = (
                round(100 * facts["ram_used_kib"] / facts["ram_total_kib"])
                if facts["ram_total_kib"]
                else 0
            )
            free = paging.human_size((facts["disk_total"] - facts["disk_used"]) // 1024)
            cards += [
                {
                    "key": "system",
                    "title": say("card_system"),
                    "value": str(facts["os_name"])[:40],
                    "sub": "",
                    "tone": "",
                    "meter": None,
                },
                {
                    "key": "disk",
                    "title": say("disk"),
                    "value": f"{disk_pct}%",
                    "sub": say("card_free", free=free),
                    "tone": level_tone(disk_pct, narration.DISK_BUSY, narration.DISK_TIGHT),
                    "meter": disk_pct,
                },
                {
                    "key": "ram",
                    "title": say("ram"),
                    "value": f"{ram_pct}%",
                    "sub": say(
                        "card_ram_sub",
                        used=paging.human_size(facts["ram_used_kib"]),
                        total=paging.human_size(facts["ram_total_kib"]),
                    ),
                    "tone": level_tone(ram_pct, narration.RAM_BUSY, narration.RAM_HIGH),
                    "meter": ram_pct,
                },
            ]
        if "updates" in facts:
            cards.append(
                {
                    "key": "updates",
                    "title": say("card_updates"),
                    "value": str(facts["updates"]),
                    "sub": say("card_updates_sub"),
                    "tone": "warn" if facts["updates"] else "ok",
                    "meter": None,
                }
            )
        if "packages" in facts:
            lines.append(say("fact_packages", n=facts["packages"]))
        if "download_files" in facts:
            size = paging.human_size(int(facts["download_bytes"]) // 1024)
            lines.append(say("fact_downloads", files=facts["download_files"], size=size))
        if facts.get("feed_date"):
            lines.append(say("fact_feed", date=feed_date_text(str(facts["feed_date"]), lang)))
        if "external_packages" in facts and facts["external_packages"]:
            lines.append(say("fact_external", n=facts["external_packages"]))
        if "findings" in facts:
            lines.append(say("fact_findings", n=facts["findings"]))
        return jsonify(
            state=job.state,
            steps=steps,
            cards=cards,
            facts=lines,
            percent=min(100, round(done_weight)),
        )

    @app.route("/report.pdf")
    def report_pdf() -> Response:
        """The scan as a PDF, made on the spot from the latest result."""
        result = job.result
        if result is None or job.state != DONE:
            abort(404)
        lang = current_language()
        document = report.build_report(result, lang, datetime.now().strftime("%Y-%m-%d %H:%M"))
        response = Response(document, mimetype="application/pdf")
        response.headers["Content-Disposition"] = 'inline; filename="ganki-report.pdf"'
        response.headers["X-Ganki-No-CSP"] = "1"  # see harden(): the PDF viewer needs this
        return response

    @app.route("/downloads/<key>")
    def downloads_detail(key: str) -> str:
        """What is inside one kind of download (read-only; names relative to Downloads)."""
        if key not in downloads.known_keys():
            abort(404)
        lang = current_language()
        folder = downloads.downloads_dir()
        return render_template(
            "downloads.html",
            lang=lang,
            t=lambda k, **values: i18n.translate(lang, k, **values),
            state=job.state,
            detail=downloads.group_detail(folder, key),
            folder_name="~/" + folder.name,
        )

    @app.route("/api/open-folder", methods=["POST"])
    def open_downloads_folder() -> Response:
        """Show a folder of Downloads in the file manager. Only a folder, only inside Downloads."""
        data = request.get_json(silent=True)
        relative = data.get("path") if isinstance(data, dict) else None
        folder = (
            folders.folder_to_open(downloads.downloads_dir(), relative)
            if isinstance(relative, str)
            else None
        )
        if folder is None:
            return make_response(jsonify(error="invalid"), 400)
        if not opener(folder):
            return make_response(jsonify(error="unavailable"), 503)
        return jsonify(opened=True)

    @app.route("/api/status")
    def status() -> Response:
        return jsonify(state=job.state)

    @app.route("/api/rescan", methods=["POST"])
    def rescan() -> Response:
        started = job.start()
        return make_response(jsonify(started=started), 202 if started else 200)

    @app.route("/api/run", methods=["POST"])
    def run_action() -> Response:
        """Run a confirmed action. Everything is checked again here, not trusted from the page."""
        data = request.get_json(silent=True)
        data = data if isinstance(data, dict) else {}
        action = data.get("action")
        package = data.get("pkg", "")
        result = job.result
        if (
            action not in actions.ACTIONS
            or not isinstance(package, str)
            or data.get("confirm") is not True
            or result is None
            or job.state != DONE
        ):
            return make_response(jsonify(error="invalid"), 400)
        view = build_preview(result, action, package)
        if view.blocked:
            return make_response(jsonify(error=view.blocked), 409)
        if view.warnings and data.get("understood") is not True:
            return make_response(jsonify(error="needs_ack"), 409)
        if not runner_job.start(action, package):
            return make_response(jsonify(error="busy"), 409)
        return make_response(jsonify(started=True), 202)

    @app.route("/api/run/status")
    def run_status() -> Response:
        return jsonify(runner_job.status())

    return app
