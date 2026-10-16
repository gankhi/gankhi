"""Start the dashboard: ``python -m ganki.web``.

Binds to 127.0.0.1 only. There is deliberately no option to listen on other
addresses: the dashboard shows what is installed on this machine.
"""

from __future__ import annotations

import argparse
import secrets
import webbrowser

from ganki.service import run_scan
from ganki.web.app import create_app

HOST = "127.0.0.1"
DEFAULT_PORT = 8589


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ganki", description="Ganki local dashboard")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--open", action="store_true", help="open the dashboard in the browser")
    args = parser.parse_args(argv)

    secret = secrets.token_urlsafe(32)
    app = create_app(run_scan, secret, args.port)
    url = f"http://{HOST}:{args.port}/?access={secret}"
    print(f"Ganki is running. Open this address (it contains a one-time secret):\n  {url}")
    if args.open:
        webbrowser.open(url)
    app.run(host=HOST, port=args.port, debug=False, use_reloader=False, threaded=True)
    return 0
