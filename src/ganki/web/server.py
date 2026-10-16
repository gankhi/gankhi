"""Start the dashboard: ``python -m ganki.web``.

Binds to 127.0.0.1 only. There is deliberately no option to listen on other
addresses: the dashboard shows what is installed on this machine.

The access address contains a secret key. It is never printed: Ganki opens it
in the browser directly and also saves it to a file only the current user can
read, so it does not end up in terminal scrollback or logs.
"""

from __future__ import annotations

import argparse
import os
import secrets
import tempfile
import webbrowser
from pathlib import Path

from ganki.feed import default_cache_dir
from ganki.service import run_scan
from ganki.web.app import create_app

HOST = "127.0.0.1"
DEFAULT_PORT = 8589
ACCESS_FILE = "dashboard-url"


def save_access_url(url: str, directory: Path) -> Path:
    """Write the address to a file readable only by this user (mode 600) and return its path."""
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix="url-", suffix=".part")  # created as 600
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(url + "\n")
        target = directory / ACCESS_FILE
        os.replace(tmp_name, target)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ganki", description="Ganki local dashboard")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--no-open", action="store_true", help="do not open the dashboard in the browser"
    )
    args = parser.parse_args(argv)

    access_key = secrets.token_urlsafe(32)
    app = create_app(run_scan, access_key, args.port)
    url = f"http://{HOST}:{args.port}/?access={access_key}"
    saved = save_access_url(url, default_cache_dir())

    opened = False if args.no_open else webbrowser.open(url)
    if opened:
        print(f"Ganki is running on http://{HOST}:{args.port}/ and opened in your browser.")
    else:
        print(f"Ganki is running on http://{HOST}:{args.port}/")
        print(f"To open it, copy the address from this file (only you can read it):\n  {saved}")
    print("Press Ctrl+C to stop.")
    app.run(host=HOST, port=args.port, debug=False, use_reloader=False, threaded=True)
    return 0
