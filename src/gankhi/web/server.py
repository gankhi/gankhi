"""Start the dashboard: ``python -m gankhi.web``.

Binds to 127.0.0.1 only. There is deliberately no option to listen on other
addresses: the dashboard shows what is installed on this machine.

The access address contains a secret key. It is never printed: Gankhi opens it
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
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

from flask import cli as flask_cli

from gankhi import verified
from gankhi.feed import default_cache_dir
from gankhi.progress import Progress
from gankhi.service import run_scan
from gankhi.web import browsers
from gankhi.web.app import create_app

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


# Browsers tried by name when the system has no default one (or cannot open links).
KNOWN_BROWSERS = tuple(command for command, _label in browsers.KNOWN)


def _start(command: list[str], settle: float = 2.0) -> bool:
    """Start a program on its own and say whether it really started.

    A program that fails right away (a missing library, a refused profile) used to count as
    opened, because starting it worked. Now a quick failure is a failure, so the next way of
    opening the browser is tried. One that is still running after ``settle`` seconds is a
    browser that stays in front: that is a success.
    """
    print(f"Opening with: {command[0]}")
    try:
        process = subprocess.Popen(  # noqa: S603  (absolute path from which(), fixed arguments, no shell)
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return False
    try:
        code = process.wait(timeout=settle)
    except subprocess.TimeoutExpired:
        return True
    if code != 0:
        print(f"{Path(command[0]).name} stopped with code {code}; trying another way.")
    return code == 0


def open_in_browser(url: str, browser: str = browsers.DEFAULT) -> bool:
    """Open the address in the person's own browser, whichever it is.

    0. The browser the person picked in the choice window, if any.
    1. The standard opener (honours the BROWSER variable and the desktop's default).
    2. The desktop's own ``xdg-open``.
    3. Any well-known browser that is installed, even if none is the default.
    """
    if browser not in (browsers.DEFAULT, browsers.CANCELLED):
        command = browsers.command_for(browser)
        if command is not None and _start([*command, url]):
            return True
    if webbrowser.open(url):
        return True
    opener = shutil.which("xdg-open")
    if opener is not None and _start([opener, url]):
        return True
    for name in KNOWN_BROWSERS:
        path = shutil.which(name)
        if path is not None and _start([path, url]):
            return True
    return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow the redirect: the redirect itself is the answer we are looking for."""

    def redirect_request(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        return None


def wait_until_listening(port: int, seconds: float = 15.0) -> bool:
    """Wait until the server accepts connections, so the browser never arrives too early."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            socket.create_connection((HOST, port), timeout=0.2).close()
        except OSError:
            time.sleep(0.03)
        else:
            return True
    return False


def open_when_ready(url: str, port: int, saved: Path, ask: bool = False) -> None:
    """Open the browser as soon as the server is listening (runs beside the server)."""
    browser = browsers.choose(force_ask=ask)  # the person may take a while to choose
    if browser == browsers.CANCELLED:
        print(f"Not opened. To open it later, use the address in this file:\n  {saved}")
    elif wait_until_listening(port) and open_in_browser(url, browser):
        print("Gankhi opened in your browser.")
    else:
        print(f"To open it, copy the address from this file (only you can read it):\n  {saved}")


def looks_like_gankhi(url: str) -> bool:
    """Does a copy of Gankhi accept this very address? A valid key is answered with a redirect."""
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(url, timeout=2) as reply:  # noqa: S310  (127.0.0.1 only)
            return reply.status in (301, 302, 303, 307, 308)
    except urllib.error.HTTPError as error:
        return error.code in (301, 302, 303, 307, 308)
    except (OSError, ValueError):
        return False


def open_running_copy(port: int, ask: bool = False) -> bool:
    """A second click on the icon: open the copy that is already running instead of failing."""
    saved = default_cache_dir() / ACCESS_FILE
    try:
        url = saved.read_text().strip()
    except OSError:
        return False
    if not url.startswith(f"http://{HOST}:{port}/") or not looks_like_gankhi(url):
        return False
    print("Gankhi is already running. Opening it in your browser.")
    browser = browsers.choose(force_ask=ask)
    if browser == browsers.CANCELLED:
        return True
    if not open_in_browser(url, browser):
        print(f"Open this file's address in your browser (only you can read it):\n  {saved}")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gankhi", description="Gankhi local dashboard")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--no-open", action="store_true", help="do not open the dashboard in the browser"
    )
    parser.add_argument(
        "--ask-browser",
        action="store_true",
        help="ask which installed browser to open Gankhi in, even if a choice was remembered",
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
        if not args.no_open and open_running_copy(args.port, args.ask_browser):
            return 0
        print(f"Port {args.port} is already in use. Is Gankhi already running?")
        print("Close the other one, or choose another port with --port.")
        return 1

    access_key = secrets.token_urlsafe(32)
    progress = Progress()
    app = create_app(
        lambda: run_scan(progress),
        access_key,
        args.port,
        progress=progress,
        verified_store=verified.Store(verified.default_path()),
    )
    url = f"http://{HOST}:{args.port}/?access={access_key}"
    saved = save_access_url(url, default_cache_dir())

    print(f"Gankhi is running on http://{HOST}:{args.port}/")
    if args.no_open:
        print(f"To open it, copy the address from this file (only you can read it):\n  {saved}")
    else:
        # The server must be listening before the browser asks, or the first request fails.
        threading.Thread(
            target=open_when_ready, args=(url, args.port, saved, args.ask_browser), daemon=True
        ).start()
    print("Press Ctrl+C to stop.")
    werkzeug_log = logging.getLogger("werkzeug")
    werkzeug_log.addFilter(HideAccessKey())
    # Flask's start-up banner and its "development server" warning are for programmers; they
    # only worry the person who double-clicked the icon. Real errors are still shown.
    werkzeug_log.setLevel(logging.ERROR)
    flask_cli.show_server_banner = lambda *_args, **_kwargs: None
    try:
        app.run(host=HOST, port=args.port, debug=False, use_reloader=False, threaded=True)
    except OSError as error:
        print(f"Could not start on port {args.port}: {error}.")
        print("Is Gankhi already running? Close it, or choose another port with --port.")
        return 1
    return 0


def run() -> None:
    """Entry point of the installed ``gankhi`` command."""
    raise SystemExit(main())
