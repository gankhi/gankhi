"""Open a folder of the Downloads folder in the person's file manager.

This is the safe way to let someone look at a file before deleting it by hand: Ganki only
opens the *folder* (never a file, so nothing can start running), and only when it is inside
the Downloads folder. The page sends a path relative to Downloads; it is resolved and checked
here, never trusted as it came.
"""

from __future__ import annotations

import os
import subprocess
import threading
from pathlib import Path

XDG_OPEN = "/usr/bin/xdg-open"
MAX_PATH_CHARS = 4096


def folder_to_open(base: Path, relative: str) -> Path | None:
    """The folder to show for ``relative`` (a file or folder inside ``base``), else ``None``.

    Refused: empty or absolute paths, ``..`` that leaves ``base``, and symlinks that point
    outside it (the path is resolved first). A file shows the folder that holds it.
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
    folder = target if os.path.isdir(target) else os.path.dirname(target)
    return Path(folder)


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
