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
PYTHON = "/usr/bin/python3"  # only to ask pip what is installed (see RESTRICTED_ARGUMENTS)
NPM = "/usr/bin/npm"
NPM_LOCAL = "/usr/local/bin/npm"
SNAP = "/usr/bin/snap"
FLATPAK = "/usr/bin/flatpak"

# Read-only commands only. Anything that changes the system must be added
# deliberately, in its own reviewed change, never here by accident.
ALLOWED_COMMANDS = frozenset(
    {DPKG_QUERY, APT_MARK, APT, APT_GET, PYTHON, NPM, NPM_LOCAL, SNAP, FLATPAK}
)

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
    # Lists what pip and npm have installed; both only read.
    PYTHON: frozenset(
        {("-m", "pip", "list", "-v", "--format=json", "--disable-pip-version-check")}
    ),
    NPM: frozenset({("ls", "-g", "--json", "--depth=0")}),
    NPM_LOCAL: frozenset({("ls", "-g", "--json", "--depth=0")}),
    # Only what is installed; neither is asked about updates (that would use the network).
    SNAP: frozenset({("list",)}),
    FLATPAK: frozenset({("list", "--app", "--columns=application,name,version,origin,size")}),
}
# These two look in the person's own folders (~/.local, ~/.npm-global), so they need HOME.
_NEEDS_HOME = frozenset({PYTHON, NPM, NPM_LOCAL, FLATPAK})  # flatpak reads ~/.local/share/flatpak
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.\-]{0,99}(:[a-z0-9]{1,20})?")  # use fullmatch
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


def valid_package(name: str) -> str | None:
    """The package name if it is a plain Debian package name, else ``None``.

    ``fullmatch`` (not ``match`` with ``$``) so a trailing newline cannot slip through.
    The returned text is built from the match itself, not handed on from the caller.
    """
    found = PACKAGE_NAME.fullmatch(name)
    # apt reads a trailing "-" as "remove this" inside an install, so such a name is refused.
    if found is None or found.group(0).endswith("-"):
        return None
    return found.group(0)


def _checked_arguments(
    command: str, arguments: tuple[str, ...], exact: frozenset[tuple[str, ...]]
) -> tuple[str, ...] | None:
    """The arguments to use, rebuilt from the allowlist; ``None`` if they are not allowed.

    An exact match returns Ganki's own constant. A simulation with one package returns the
    fixed prefix plus the validated package name. Whatever the caller passed is never
    forwarded as it came.
    """
    for allowed in exact:
        if arguments == allowed:
            return allowed
    if command != APT_GET:
        return None
    for prefix in _SIMULATIONS_WITH_PACKAGE:
        if len(arguments) == len(prefix) + 1 and arguments[: len(prefix)] == prefix:
            name = valid_package(arguments[-1])
            if name is not None:
                return (*prefix, name)
    return None


def privileged_apt(action: str, package: str = "") -> list[str]:
    """The only commands that may change the system, written out exactly.

    ``action`` is "remove", "update" (one package), "all", "clean" (empty apt's download
    cache) or "autoremove" (what nothing needs any more, old kernels included). Nothing else
    is built here, and ``run_privileged`` refuses any list that differs from these.
    """
    head = [PKEXEC, ENV, "DEBIAN_FRONTEND=noninteractive", APT_GET]
    if action == "remove":
        return [*head, "remove", "-y", package]
    if action == "update":
        return [*head, "install", "--only-upgrade", "-y", *_KEEP_CONFIG, package]
    if action == "clean":
        return [*head, "clean"]
    if action == "autoremove":
        return [*head, "autoremove", "-y"]
    return [*head, "full-upgrade", "-y", *_KEEP_CONFIG]


def _privileged_command(args: Sequence[str]) -> list[str] | None:
    """The allowlisted command equal to ``args``, rebuilt from Ganki's own pieces."""
    candidate = list(args)
    for action in ("all", "clean", "autoremove"):
        if candidate == privileged_apt(action):
            return privileged_apt(action)
    name = valid_package(candidate[-1]) if candidate else None
    if name is None:
        return None
    for action in ("remove", "update"):
        if candidate == privileged_apt(action, name):
            return privileged_apt(action, name)
    return None


def run_privileged(args: Sequence[str], on_line: Callable[[str], None], timeout: int = 7200) -> int:
    """Run one of the ``privileged_apt`` commands, passing each output line to ``on_line``.

    Returns the exit code. The password is asked by the system's own window; Ganki never
    sees it. stdin is closed so nothing can wait for typed input.
    """
    command = _privileged_command(args)
    if command is None:
        raise CommandNotAllowedError(f"not an allowed privileged command: {list(args)[:6]}")
    env = dict(_ENV)
    env.update({key: os.environ[key] for key in _SESSION_VARIABLES if key in os.environ})
    process = subprocess.Popen(  # noqa: S603  (rebuilt allowlisted list, absolute paths, no shell)
        command,
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


def _environment(command: str) -> dict[str, str]:
    environment = dict(_ENV)
    if command in _NEEDS_HOME:
        environment["PATH"] = "/usr/local/bin:/usr/bin:/bin"  # npm finds its node next to it
        if os.environ.get("HOME"):
            environment["HOME"] = os.environ["HOME"]
    return environment


def run(args: Sequence[str], timeout: int = 60) -> str:
    """Run an allowlisted command (no shell) and return its stdout."""
    command = next((known for known in ALLOWED_COMMANDS if args and args[0] == known), None)
    if command is None:
        raise CommandNotAllowedError(f"command not allowed: {list(args)[:1]}")
    rest: tuple[str, ...] = tuple(args[1:])
    exact = RESTRICTED_ARGUMENTS.get(command)
    if exact is not None:
        checked = _checked_arguments(command, rest, exact)
        if checked is None:
            raise CommandNotAllowedError(f"arguments not allowed for {command}: {list(rest)}")
        rest = checked
    result = subprocess.run(  # noqa: S603  (allowlisted absolute path, checked arguments, no shell)
        [command, *rest],
        capture_output=True,
        text=True,
        check=True,
        timeout=timeout,
        env=_environment(command),
        cwd="/",  # `python -m` would otherwise import from the current folder
    )
    return result.stdout
