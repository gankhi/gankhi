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
from collections.abc import Callable

from flask import Flask, abort, jsonify, make_response, redirect, render_template, request
from werkzeug.wrappers import Response

from ganki import inventory
from ganki.collectors.apt import Package, collect
from ganki.service import ScanResult
from ganki.summary import OLD_KERNEL, PROGRAM, RUNNING_KERNEL
from ganki.web import i18n
from ganki.web.jobs import DONE, IDLE, RUNNING, ScanJob

SESSION_COOKIE = "ganki_session"
LANG_COOKIE = "ganki_lang"
ROW_LIMIT = 60  # rows shown per table; the rest is summarised as "and N more"
CSP = (
    "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; "
    "img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


def create_app(
    scan: Callable[[], ScanResult],
    secret: str,
    port: int,
    packages: Callable[[], list[Package]] = collect,
) -> Flask:
    """Build the app.

    ``scan`` produces a ``ScanResult``; ``packages`` lists installed packages;
    ``secret`` is the access token.
    """
    app = Flask(__name__)
    job = ScanJob(scan)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    def authorized() -> bool:
        cookie = request.cookies.get(SESSION_COOKIE, "")
        return hmac.compare_digest(cookie.encode(), secret.encode())

    @app.before_request
    def guard() -> Response | None:
        if request.host not in allowed_hosts:
            abort(400)
        offered = request.args.get("access", "")
        if offered and hmac.compare_digest(offered.encode(), secret.encode()):
            response = redirect(request.path)  # drop the token from the address bar
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

    @app.after_request
    def harden(response: Response) -> Response:
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

    @app.route("/")
    def index() -> str:
        if job.state == IDLE:
            job.start()
        lang = current_language()
        result = job.result
        context: dict[str, object] = {
            "lang": lang,
            "t": lambda key, **values: i18n.translate(lang, key, **values),
            "state": job.state,
            "result": result,
            "limit": ROW_LIMIT,
        }
        if result is not None and job.state in (DONE, RUNNING):
            risks = result.risks
            context.update(
                fixable=[r for r in risks if r.kind == PROGRAM and r.has_fix],
                unfixable=[r for r in risks if r.kind == PROGRAM and not r.has_fix],
                kernel=[r for r in risks if r.kind == RUNNING_KERNEL],
                old_kernels=[r for r in risks if r.kind == OLD_KERNEL],
                total_fixable=sum(1 for f in result.findings if f.status == "fix_available"),
                total_nofix=sum(1 for f in result.findings if f.status == "no_fix"),
                total_cves=len({f.cve_id for f in result.findings}),
            )
        return render_template("index.html", **context)

    app.jinja_env.filters["size"] = inventory.human_size

    @app.route("/inventory")
    def inventory_page() -> str:
        lang = current_language()
        sort = request.args.get("sort", "size")
        sort = sort if sort in inventory.SORTS else "size"
        query = request.args.get("q", "")[: inventory.MAX_QUERY_CHARS]
        manual_only = request.args.get("manual") == "1"
        number = request.args.get("page", 1, type=int)
        selected = inventory.select(packages(), query, manual_only, sort)
        return render_template(
            "inventory.html",
            lang=lang,
            t=lambda key, **values: i18n.translate(lang, key, **values),
            state="idle",
            page=inventory.paginate(selected, number),
            q=query,
            sort=sort,
            manual=manual_only,
            sorts=inventory.SORTS,
        )

    @app.route("/api/status")
    def status() -> Response:
        return jsonify(state=job.state)

    @app.route("/api/rescan", methods=["POST"])
    def rescan() -> Response:
        started = job.start()
        return make_response(jsonify(started=started), 202 if started else 200)

    return app
