"""Show a file or folder of the Downloads folder in the person's file manager.

This is the safe way to let someone look at a file before deleting it by hand: Ganki only
*shows* it (the file manager opens its folder with the file selected; the file is never
opened, so nothing can start running), and only when it is inside the Downloads folder. The
page sends a path relative to Downloads; it is resolved and checked here, never trusted as
it came.
"""

from __future__ import annotations

import os
import subprocess
import threading
from pathlib import Path

XDG_OPEN = "/usr/bin/xdg-open"
DBUS_SEND = "/usr/bin/dbus-send"  # asks the file manager to select a file (FileManager1)
SESSION_VARIABLES = ("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "DISPLAY", "XAUTHORITY")
MAX_PATH_CHARS = 4096


def inside_downloads(base: Path, relative: str) -> Path | None:
    """The existing file or folder ``relative`` points to inside ``base``, else ``None``.

    Refused: empty or absolute paths, ``..`` that leaves ``base``, and symlinks that point
    outside it (the path is resolved first). ``base`` itself is not "inside" ``base``.
    """
    if not relative or len(relative) > MAX_PATH_CHARS or "\x00" in relative:
        return None
    if os.path.isabs(relative):
        return None
    try:
        root = os.path.realpath(base, strict=True)
    except (OSError, RuntimeError, ValueError):
        return None
    inside = root.rstrip(os.sep) + os.sep
    # First the plain (lexical) check, then the same check again once symlinks are resolved.
    # Something that is the root itself is not a file or folder "inside" it, so it is refused.
    lexical = os.path.normpath(os.path.join(root, relative))
    if not lexical.startswith(inside):
        return None
    try:
        target = os.path.realpath(lexical, strict=True)
    except (OSError, RuntimeError, ValueError):
        return None
    if not target.startswith(inside):
        return None
    return Path(target)


def folder_to_open(base: Path, relative: str) -> Path | None:
    """The folder to show for ``relative`` (a file or folder inside ``base``), else ``None``.

    A file shows the folder that holds it.
    """
    target = inside_downloads(base, relative)
    if target is None:
        return None
    return target if target.is_dir() else target.parent


def open_folder(folder: Path) -> bool:
    """Ask the desktop to show ``folder``. Returns whether the request could be made."""
    if not folder.is_dir() or not os.access(XDG_OPEN, os.X_OK):
        return False
    try:
        process = subprocess.Popen(  # noqa: S603  (absolute path, a list, a checked folder)
            [XDG_OPEN, str(folder)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return False
    threading.Thread(target=process.wait, daemon=True).start()  # do not leave a zombie
    return True


def _select_in_file_manager(target: Path) -> bool:
    """Ask the file manager to open the folder with ``target`` selected (FileManager1).

    The address is built by ``Path.as_uri``, which encodes commas and colons, so it is always
    one plain item. Returns whether the file manager answered.
    """
    if not os.access(DBUS_SEND, os.X_OK):
        return False
    env = {"PATH": "/usr/bin:/bin"}
    env.update({key: os.environ[key] for key in SESSION_VARIABLES if key in os.environ})
    try:
        done = subprocess.run(  # noqa: S603  (absolute path, a fixed list, an encoded address)
            [
                DBUS_SEND,
                "--session",
                "--print-reply",
                "--reply-timeout=3000",
                "--dest=org.freedesktop.FileManager1",
                "--type=method_call",
                "/org/freedesktop/FileManager1",
                "org.freedesktop.FileManager1.ShowItems",
                f"array:string:{target.as_uri()}",
                "string:",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
            env=env,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


def show_in_file_manager(target: Path) -> bool:
    """Show ``target``: a folder opens; a file is selected inside its folder.

    If the file manager cannot select it, the folder that holds it is opened instead.
    """
    if target.is_dir():
        return open_folder(target)
    if target.is_file() and _select_in_file_manager(target):
        return True
    return open_folder(target.parent)
