"""The single place where Ganki runs external commands.

Every command goes through ``run()``, which enforces three rules:

1. Only executables on the ``ALLOWED_COMMANDS`` list can run.
2. No shell is involved: arguments are passed as a list.
3. The environment is minimal and fixed (C locale so output is parseable).

Keeping this in one module makes it easy to audit what Ganki can execute.

``run()`` is read-only. The only code path that can change the system is
``run_privileged()``, which accepts nothing but the exact lists built by
``privileged_apt()`` (remove, update one package, update all) and goes through the
system's own password window (pkexec).
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable, Sequence

DPKG_QUERY = "/usr/bin/dpkg-query"
APT_MARK = "/usr/bin/apt-mark"
APT = "/usr/bin/apt"
APT_GET = "/usr/bin/apt-get"
PKEXEC = "/usr/bin/pkexec"  # asks for the password in the system's own window
ENV = "/usr/bin/env"

# Read-only commands only. Anything that changes the system must be added
# deliberately, in its own reviewed change, never here by accident.
ALLOWED_COMMANDS = frozenset({DPKG_QUERY, APT_MARK, APT, APT_GET})

# Some executables can change the system, so they are allowed with exact arguments
# only. ``apt-get`` may only *simulate* (-s) a few operations; Ganki never runs them
# for real. Package names are checked so an argument can never turn into an option.
RESTRICTED_ARGUMENTS = {
    APT_GET: frozenset(
        {
            ("-s", "autoremove"),
            ("-s", "full-upgrade"),
            # Prints the download addresses and sizes, then stops: nothing is downloaded.
            ("--print-uris", "-y", "-qq", "full-upgrade"),
        }
    ),
}
PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9+.\-]{0,99}(:[a-z0-9]{1,20})?$")
_SIMULATIONS_WITH_PACKAGE = (
    ("-s", "remove"),
    ("-s", "install", "--only-upgrade"),
    ("--print-uris", "-y", "-qq", "install", "--only-upgrade"),
)

_ENV = {"LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin:/bin"}
# What pkexec needs to find the password window of the running desktop session.
_SESSION_VARIABLES = ("DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR")
_KEEP_CONFIG = ["-o", "Dpkg::Options::=--force-confold"]  # never overwrite the person's settings


class CommandNotAllowedError(ValueError):
    """Raised when something tries to run a command that is not allowlisted."""


def _arguments_allowed(
    command: str, arguments: tuple[str, ...], exact: frozenset[tuple[str, ...]]
) -> bool:
    if arguments in exact:
        return True
    if command != APT_GET:
        return False
    for prefix in _SIMULATIONS_WITH_PACKAGE:
        if (
            len(arguments) == len(prefix) + 1
            and arguments[: len(prefix)] == prefix
            and PACKAGE_NAME.match(arguments[-1])
        ):
            return True
    return False


def privileged_apt(action: str, package: str = "") -> list[str]:
    """The only commands that may change the system, written out exactly.

    ``action`` is "remove", "update" (one package) or "all". Nothing else is built
    here, and ``run_privileged`` refuses any list that differs from these.
    """
    head = [PKEXEC, ENV, "DEBIAN_FRONTEND=noninteractive", APT_GET]
    if action == "remove":
        return [*head, "remove", "-y", package]
    if action == "update":
        return [*head, "install", "--only-upgrade", "-y", *_KEEP_CONFIG, package]
    return [*head, "full-upgrade", "-y", *_KEEP_CONFIG]


def _privileged_allowed(args: Sequence[str]) -> bool:
    candidate = list(args)
    if candidate == privileged_apt("all"):
        return True
    name = candidate[-1] if candidate else ""
    return bool(PACKAGE_NAME.match(name)) and any(
        candidate == privileged_apt(action, name) for action in ("remove", "update")
    )


def run_privileged(args: Sequence[str], on_line: Callable[[str], None], timeout: int = 7200) -> int:
    """Run one of the ``privileged_apt`` commands, passing each output line to ``on_line``.

    Returns the exit code. The password is asked by the system's own window; Ganki never
    sees it. stdin is closed so nothing can wait for typed input.
    """
    if not _privileged_allowed(args):
        raise CommandNotAllowedError(f"not an allowed privileged command: {list(args)[:6]}")
    env = dict(_ENV)
    env.update({key: os.environ[key] for key in _SESSION_VARIABLES if key in os.environ})
    process = subprocess.Popen(  # noqa: S603  (exact allowlisted list, absolute paths, no shell)
        list(args),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    try:
        assert process.stdout is not None  # noqa: S101 (PIPE was requested above)
        for line in process.stdout:
            on_line(line.rstrip("\n"))
        return process.wait(timeout=timeout)
    finally:
        if process.poll() is None:
            process.kill()


def run(args: Sequence[str], timeout: int = 60) -> str:
    """Run an allowlisted command (no shell) and return its stdout."""
    if not args or args[0] not in ALLOWED_COMMANDS:
        raise CommandNotAllowedError(f"command not allowed: {args[:1]}")
    exact = RESTRICTED_ARGUMENTS.get(args[0])
    if exact is not None and not _arguments_allowed(args[0], tuple(args[1:]), exact):
        raise CommandNotAllowedError(f"arguments not allowed for {args[0]}: {list(args[1:])}")
    result = subprocess.run(  # noqa: S603  (allowlisted absolute path, no shell)
        list(args),
        capture_output=True,
        text=True,
        check=True,
        timeout=timeout,
        env=_ENV,
    )
    return result.stdout
