"""The single place where Ganki runs external commands.

Every command goes through ``run()``, which enforces three rules:

1. Only executables on the ``ALLOWED_COMMANDS`` list can run.
2. No shell is involved: arguments are passed as a list.
3. The environment is minimal and fixed (C locale so output is parseable).

Keeping this in one module makes it easy to audit what Ganki can execute.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Sequence

DPKG_QUERY = "/usr/bin/dpkg-query"
APT_MARK = "/usr/bin/apt-mark"
APT = "/usr/bin/apt"
APT_GET = "/usr/bin/apt-get"

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
