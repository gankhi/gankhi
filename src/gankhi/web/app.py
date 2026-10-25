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
import math
import subprocess
from collections.abc import Callable
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, make_response, redirect, render_template, request
from werkzeug.wrappers import Response

from gankhi import (
    actions,
    advice,
    ask_ai,
    downloads,
    external_tools,
    folders,
    narration,
    paging,
    report,
    verified,
)
from gankhi.collectors import sandboxed
from gankhi.collectors.origins import LOCAL
from gankhi.executor import RUNNING as CHANGE_RUNNING
from gankhi.executor import ActionJob
from gankhi.progress import RUNNING as STEP_RUNNING
from gankhi.progress import Progress
from gankhi.runner import CommandNotAllowedError
from gankhi.service import ScanResult
from gankhi.summary import RUNNING_KERNEL
from gankhi.tools import OK, OUTDATED, UNCHECKED, VULNERABLE, is_parked
from gankhi.web import i18n
from gankhi.web.jobs import DONE, IDLE, RUNNING, ScanJob

SESSION_COOKIE = "gankhi_session"
LANG_COOKIE = "gankhi_lang"
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


SEVERITY_LEVELS = ("critical", "high", "medium", "low", "unknown")


def severity_level(item: Any) -> str:
    """The bucket the severity ring counts an item in (negligible counts as low)."""
    priority = item.top_priority
    if priority == "negligible":
        return "low"
    return priority if priority in SEVERITY_LEVELS else "unknown"


def origin_label(origin: str) -> str:
    """The repository an item comes from, without the placeholders apt reports for unknown parts."""
    seen: list[str] = []
    for part in (origin or "").split(","):
        part = part.strip()
        if part and part.lower() != "unknown" and part not in seen:
            seen.append(part)
    return ", ".join(seen)


def ring_arc(start: float, end: float) -> str:
    """SVG path of the arc of the ring from ``start`` to ``end`` (percent, from 12 o'clock).

    Drawn as a real arc: dashes on a circle left a one pixel gap at the seam between two parts.
    """
    end = min(end, 99.999)

    def point(percent: float) -> str:
        angle = 2 * math.pi * percent / 100 - math.pi / 2
        return f"{70 + 52 * math.cos(angle):.3f} {70 + 52 * math.sin(angle):.3f}"

    large = 1 if end - start > 50 else 0
    return f"M{point(start)}A52 52 0 {large} 1 {point(end)}"


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
FILTERS = ("all", "ok", "outdated", "vulnerable", "unchecked", "eol")
MAX_QUERY_CHARS = 100
MAX_REQUEST_BYTES = 64 * 1024  # the page only ever sends tiny JSON bodies
CSP = (
    "default-src 'none'; style-src 'self'; font-src 'self'; script-src 'self'; connect-src 'self'; "
    "img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


def uptime_text(seconds: int) -> str:
    """``273600`` -> ``3 d 4 h``."""
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    return f"{days} d {hours} h" if days else f"{hours} h {rest // 60} min"


NEEDS_KEY_PAGE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta name="color-scheme" content="dark light"><title>Gankhi</title></head>
<body>
<h1>Gankhi</h1>
<p><b>Falta la clave de acceso.</b> Abrí Gankhi con su ícono del escritorio o desde el menú de
aplicaciones. Si querés usar otro navegador: en una consola ejecutá <code>gankhi --no-open</code>,
y pegá en tu navegador la dirección completa que está en el archivo
<code>~/.cache/gankhi/dashboard-url</code> (empieza con <code>http://127.0.0.1</code> y termina con
la clave). La clave cambia cada vez que Gankhi arranca.</p>
<hr>
<p><b>The access key is missing.</b> Open Gankhi from its desktop icon or the applications menu.
To use another browser: run <code>gankhi --no-open</code> in a terminal, then paste into your
browser the full address found in <code>~/.cache/gankhi/dashboard-url</code> (it starts with
<code>http://127.0.0.1</code> and ends with the key). The key changes every time Gankhi starts.</p>
</body></html>
"""


def create_app(
    scan: Callable[[], ScanResult],
    secret: str,
    port: int,
    simulator: actions.Simulator = actions.simulate,
    executor: ActionJob | None = None,
    progress: Progress | None = None,
    opener: Callable[[Path], bool] = folders.show_in_file_manager,
    verified_store: verified.Store | None = None,
) -> Flask:
    """Build the app. ``scan`` produces a ``ScanResult``; ``secret`` is the access token.

    ``simulator`` runs the apt simulations behind the previews and ``executor`` runs a
    confirmed action for real (both replaced in tests).
    """
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES

    job = ScanJob(scan, progress)
    marks_store = verified_store if verified_store is not None else verified.Store()
    runner_job = executor or ActionJob(on_done=job.start)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    app.jinja_env.globals["ring_arc"] = ring_arc
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
            if request.headers.get("X-Gankhi") != "1" or (
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
        if response.headers.pop("X-Gankhi-No-CSP", None) is None:
            response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        chosen = request.args.get("lang", "")
        if chosen in i18n.LANGUAGES:  # the switch on the detail pages: remember it, no redirect
            response.set_cookie(
                LANG_COOKIE, chosen, httponly=True, secure=True, samesite="Strict", path="/"
            )
        return response

    def current_language() -> str:
        asked = request.args.get("lang", "")
        return i18n.pick_language(
            asked if asked in i18n.LANGUAGES else request.cookies.get(LANG_COOKIE),
            request.headers.get("Accept-Language"),
        )

    @app.route("/lang/<code>")
    def set_language(code: str) -> Response:
        if code not in i18n.LANGUAGES:
            abort(404)
        response = redirect("/")  # a fixed address, never taken from the request
        response.set_cookie(
            LANG_COOKIE, code, httponly=True, secure=True, samesite="Strict", path="/"
        )
        return response

    def checked_by_user(tool: Any, marks: dict[str, verified.Mark]) -> bool:
        """A program Gankhi cannot check that the person marked as checked, in this version."""
        if tool.state != UNCHECKED or not tool.is_program or not tool.origin:
            return False
        how = "deb" if tool.origin == LOCAL else "apt"
        return verified.key(how, ask_ai.clean(tool.name), ask_ai.clean(tool.version)) in marks

    def tool_view(result: ScanResult, marks: dict[str, verified.Mark]) -> dict[str, object]:
        """Everything the tools table needs, taken from the query string."""
        chosen = request.args.get("f", "all")
        chosen = chosen if chosen in FILTERS else "all"
        # The list of flaws always has all of them, libraries and dependencies included.
        ticked = request.args.get("show") == "all"
        show_all = ticked or chosen in ("vulnerable", "outdated", "eol", "unchecked", "ok")
        query = request.args.get("q", "")[:MAX_QUERY_CHARS]
        universe = [t for t in result.tools if t.is_program or show_all]
        wanted = {
            "ok": OK,
            "outdated": OUTDATED,
            "vulnerable": VULNERABLE,
            "unchecked": UNCHECKED,
        }.get(chosen)
        text = query.strip().lower()
        severity_wanted = request.args.get("sev", "")
        if chosen != "vulnerable" or severity_wanted not in SEVERITY_LEVELS:
            severity_wanted = ""
        shown = [
            t
            for t in universe
            if (wanted is None or t.state == wanted)
            and (chosen != "eol" or t.end_of_support)
            and not (wanted == UNCHECKED and checked_by_user(t, marks))
            and (not text or text in t.name.lower() or text in t.description.lower())
            # parked ones have their own card in the views that show it; in the others (for
            # example out of support) they must be listed here, or the list would come up empty
            and not (is_parked(t) and chosen in ("all", "vulnerable"))
            and (not severity_wanted or severity_level(t) == severity_wanted)
        ]
        parked = [
            t
            for t in universe
            if is_parked(t) and (not severity_wanted or severity_level(t) == severity_wanted)
        ]
        kernel = [r for r in result.risks if r.kind == RUNNING_KERNEL]
        # The headline numbers add up everything Gankhi checked: system programs and also the
        # Python and npm packages. (Snap and Flatpak apps are not checked, so they are not
        # counted as "up to date".) The filter chips keep counting the programs table only.
        outside = len(result.external)
        outside_bad = sum(1 for p in result.external if p.vulnerable)
        # The headline always counts the libraries and dependencies too, whatever the table shows:
        # the checkbox only changes the list, never how many flaws the computer has.
        everything = result.tools
        by_user = sum(1 for t in everything if checked_by_user(t, marks))
        total_all = (
            len(everything) + outside - by_user
        )  # the ones checked by hand have their own card
        eol_total = sum(1 for t in everything if t.end_of_support)
        problems = (
            sum(1 for t in everything if t.state in (VULNERABLE, OUTDATED) or t.end_of_support)
            + outside_bad
        )
        parked_total = sum(1 for t in everything if is_parked(t))
        support = {"fine": outside, "outdated": 0, "eol": 0, "unchecked": 0}
        for item in everything:
            if checked_by_user(item, marks):
                continue  # these have their own card
            if item.end_of_support:
                support["eol"] += 1
            elif item.state == OUTDATED:
                support["outdated"] += 1
            elif item.state == UNCHECKED:
                support["unchecked"] += 1
            else:
                support["fine"] += 1
        severity = {key: 0 for key in ("critical", "high", "medium", "low", "unknown")}
        flawed = [t for t in everything if t.state == VULNERABLE]
        flawed += [p for p in result.external if p.vulnerable]
        for item in flawed:
            severity[severity_level(item)] += 1
        bad_programs = sum(1 for t in everything if t.state == VULNERABLE and t.is_program)
        bad_libraries = sum(1 for t in everything if t.state == VULNERABLE and not t.is_program)
        total_bad = bad_programs + bad_libraries + outside_bad
        total_old = sum(1 for t in everything if t.state == OUTDATED)
        total_unchecked = sum(1 for t in everything if t.state == UNCHECKED) - by_user
        return {
            "severity_filter": severity_wanted,
            "parked": parked,
            "parked_shown": parked if chosen in ("all", "vulnerable") else [],
            "totals": {
                "all": total_all,
                "outdated": total_old,
                "vulnerable": total_bad,
                "severity": severity,
                "support": support,
                "eol": eol_total,
                "hidden_libraries": len(everything) - len(universe),
                "problems": problems,
                "parked_all": parked_total,
                "vuln_programs": bad_programs,
                "vuln_libraries": bad_libraries,
                "vuln_outside": outside_bad,
                "ok_outside": outside - outside_bad,
                "ok": total_all - total_old - total_bad - total_unchecked,
                "unchecked": total_unchecked,
                "outside": outside,
            },
            "page": paging.paginate(shown, request.args.get("page", 1, type=int)),
            # each chip counts what its list shows, so they match the numbers in the rings
            "counts": {
                "all": len([t for t in everything if t.is_program or ticked]),
                "outdated": total_old,
                "vulnerable": bad_programs + bad_libraries,
                "ok": sum(1 for t in everything if t.state == OK),
                "unchecked": total_unchecked,
                "eol": sum(1 for t in universe if t.end_of_support),
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
        change = runner_job.status()
        marks = marks_store.marks()
        everything = ask_ai.unchecked_items(result) if result is not None else []
        pending = [i for i in everything if verified.key(i.how, i.name, i.version) not in marks]
        checked_items = [
            (i, marks[verified.key(i.how, i.name, i.version)].day)
            for i in everything
            if verified.key(i.how, i.name, i.version) in marks
        ]
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
            "sandboxed_uses": sandboxed.uses_command,
            "sandboxed_shared": sandboxed.is_shared_runtime,
            "update_command": external_tools.update_command,
            "remove_command": external_tools.remove_command,
            "pip_managed": external_tools.externally_managed(),
            "EXT_OTHERS_MAX": external_tools.MAX_LISTED_OTHERS,
            "state": job.state,
            "result": result,
            "unchecked": pending,
            "verified_items": checked_items,
            "sandboxed_shown": [
                a
                for a in (result.sandboxed if result is not None else [])
                if verified.key(a.tool, ask_ai.clean(a.name), ask_ai.clean(a.version)) not in marks
            ],
            "tool_checked": lambda tool: checked_by_user(tool, marks),
            "clean": ask_ai.clean,
            "origin_label": origin_label,
            "pending_how": {i.name: i.how for i in pending},
            "change_running": change.get("state") == CHANGE_RUNNING,
            "change_command": change.get("command", ""),
            "now": datetime.now(),
        }
        if result is not None and job.state in (DONE, RUNNING):
            context.update(tool_view(result, marks))
        items = context["unchecked"]
        if items:
            os_name = result.system.os_name if result is not None and result.system else ""
            ecosystem = result.ecosystem if result is not None else ""
            context["ai_prompt"] = ask_ai.build_prompt(items, os_name, lang, ecosystem)  # type: ignore[arg-type]
            # one question per program, for the button in its own row
            context["ai_prompts"] = {
                i.name: ask_ai.build_prompt([i], os_name, lang, ecosystem)
                for i in items  # type: ignore[attr-defined]
            }
        if result is not None:
            # one question per Python or npm package, for the button in its own row
            context["ext_prompts"] = {
                (p.tool, p.name): ask_ai.build_package_prompt(p.name, p.version, p.tool, lang)
                for p in result.external
                if not p.vulnerable
            }
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
        response.headers["Content-Disposition"] = 'inline; filename="gankhi-report.pdf"'
        response.headers["X-Gankhi-No-CSP"] = "1"  # see harden(): the PDF viewer needs this
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
        """Show a file or folder of Downloads in the file manager. Only inside Downloads."""
        data = request.get_json(silent=True)
        relative = data.get("path") if isinstance(data, dict) else None
        folder = (
            folders.inside_downloads(downloads.downloads_dir(), relative)
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

    @app.route("/api/verify", methods=["POST"])
    def verify() -> Response:
        """Mark (or unmark) a program or app as checked by the person, in its exact version.

        Only something that is really listed as not checked right now can be marked.
        """
        data = request.get_json(silent=True)
        data = data if isinstance(data, dict) else {}
        how, name, version = data.get("how"), data.get("name"), data.get("version")
        result = job.result
        if (
            not all(isinstance(v, str) for v in (how, name, version))
            or how not in verified.HOWS
            or not isinstance(data.get("checked"), bool)
            or result is None
        ):
            return make_response(jsonify(error="invalid"), 400)
        listed = {(i.how, i.name, i.version) for i in ask_ai.unchecked_items(result)}
        if (how, name, version) not in listed:
            return make_response(jsonify(error="unknown"), 404)
        if data["checked"]:
            done = marks_store.add(how, name, version)  # type: ignore[arg-type]
        else:
            done = marks_store.remove(how, name, version)  # type: ignore[arg-type]
        return make_response(jsonify(ok=done), 200)

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
