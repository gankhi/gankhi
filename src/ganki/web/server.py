"""Start the dashboard: ``python -m ganki.web``.

Binds to 127.0.0.1 only. There is deliberately no option to listen on other
addresses: the dashboard shows what is installed on this machine.

The access address contains a secret key. It is never printed: Ganki opens it
in the browser directly and also saves it to a file only the current user can
read, so it does not end up in terminal scrollback or logs.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import secrets
import shutil
import socket
import subprocess  # noqa: S404  (only to hand the address to the desktop's own opener)
import sys
import tempfile
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

from ganki.feed import default_cache_dir
from ganki.progress import Progress
from ganki.service import run_scan
from ganki.web.app import create_app

HOST = "127.0.0.1"
DEFAULT_PORT = 8589
ACCESS_FILE = "dashboard-url"


class HideAccessKey(logging.Filter):
    """Replace the access key in request log lines (``GET /?access=KEY``) before they print."""

    _KEY = re.compile(r"access=[^\s&\"']+")

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._KEY.sub("access=<hidden>", record.getMessage())
        record.args = ()
        return True


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


def port_is_free(port: int) -> bool:
    """Can we listen on this port? Checked first so a second copy never touches the first."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((HOST, port))
        except OSError:
            return False
    return True


def open_in_browser(url: str) -> bool:
    """Open the address in the person's own browser, whichever it is.

    The standard opener goes first (it honours the BROWSER variable and the desktop's default).
    If it finds nothing, the desktop's own ``xdg-open`` is tried before giving up.
    """
    if webbrowser.open(url):
        return True
    opener = shutil.which("xdg-open")
    if opener is None:
        return False
    try:
        subprocess.Popen(  # noqa: S603  (absolute path from which(), fixed arguments, no shell)
            [opener, url],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return False
    return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow the redirect: the redirect itself is the answer we are looking for."""

    def redirect_request(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        return None


def looks_like_ganki(url: str) -> bool:
    """Does a copy of Ganki accept this very address? A valid key is answered with a redirect."""
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(url, timeout=2) as reply:  # noqa: S310  (127.0.0.1 only)
            return reply.status in (301, 302, 303, 307, 308)
    except urllib.error.HTTPError as error:
        return error.code in (301, 302, 303, 307, 308)
    except (OSError, ValueError):
        return False


def open_running_copy(port: int) -> bool:
    """A second click on the icon: open the copy that is already running instead of failing."""
    saved = default_cache_dir() / ACCESS_FILE
    try:
        url = saved.read_text().strip()
    except OSError:
        return False
    if not url.startswith(f"http://{HOST}:{port}/") or not looks_like_ganki(url):
        return False
    print("Ganki is already running. Opening it in your browser.")
    if not open_in_browser(url):
        print(f"Open this file's address in your browser (only you can read it):\n  {saved}")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ganki", description="Ganki local dashboard")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--no-open", action="store_true", help="do not open the dashboard in the browser"
    )
    parser.add_argument(
        "--pause-on-error",
        action="store_true",
        help="wait for Enter before exiting after an error (for launchers that close the window)",
    )
    args = parser.parse_args(argv)
    code = _serve(args)
    if code != 0 and args.pause_on_error and sys.stdin.isatty():
        input("Press Enter to close this window...")
    return code


def _serve(args: argparse.Namespace) -> int:
    if not port_is_free(args.port):
        if not args.no_open and open_running_copy(args.port):
            return 0
        print(f"Port {args.port} is already in use. Is Ganki already running?")
        print("Close the other one, or choose another port with --port.")
        return 1

    access_key = secrets.token_urlsafe(32)
    progress = Progress()
    app = create_app(lambda: run_scan(progress), access_key, args.port, progress=progress)
    url = f"http://{HOST}:{args.port}/?access={access_key}"
    saved = save_access_url(url, default_cache_dir())

    opened = False if args.no_open else open_in_browser(url)
    if opened:
        print(f"Ganki is running on http://{HOST}:{args.port}/ and opened in your browser.")
    else:
        print(f"Ganki is running on http://{HOST}:{args.port}/")
        print(f"To open it, copy the address from this file (only you can read it):\n  {saved}")
    print("Press Ctrl+C to stop.")
    logging.getLogger("werkzeug").addFilter(HideAccessKey())
    try:
        app.run(host=HOST, port=args.port, debug=False, use_reloader=False, threaded=True)
    except OSError as error:
        print(f"Could not start on port {args.port}: {error}.")
        print("Is Ganki already running? Close it, or choose another port with --port.")
        return 1
    return 0


def run() -> None:
    """Entry point of the installed ``ganki`` command."""
    raise SystemExit(main())
