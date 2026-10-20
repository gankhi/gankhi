"""Run an update or a removal for real, after the person confirmed it on the preview page.

Order of events, always the same:
1. save the list of installed programs (a temporary record of what was there),
2. ask the system for permission (its own password window),
3. run the one allowlisted ``apt-get`` command and keep its output for the screen.

Only one action runs at a time. Nothing here decides *what* is allowed: the web layer
validates the request first and ``runner.run_privileged`` refuses anything unexpected.
"""

from __future__ import annotations

import logging
import os
import tempfile
import threading
from collections import deque
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from gankhi import runner
from gankhi.runner import DPKG_QUERY, PKEXEC

log = logging.getLogger(__name__)

IDLE, RUNNING, DONE, FAILED = "idle", "running", "done", "failed"
MAX_LINES = 400
KEEP_SNAPSHOTS = 20
_STATUS_FORMAT = "${binary:Package}\t${db:Status-Abbrev}\n"

Runner = Callable[[list[str], Callable[[str], None]], int]


_fallback_dir: Path | None = None


def snapshot_dir() -> Path:
    """Where the temporary copy of the program list is kept: a place the system empties by itself.

    ``$XDG_RUNTIME_DIR`` (``/run/user/<id>``) is memory-backed and private to the person; it is
    emptied when the session ends or the computer is turned off. If it does not exist, a private
    temporary folder is used (emptied at the next start). Nothing is kept in the home folder.
    """
    global _fallback_dir  # noqa: PLW0603
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime and os.path.isabs(runtime) and os.path.isdir(runtime):
        return Path(runtime) / "gankhi" / "snapshots"
    if _fallback_dir is None or not _fallback_dir.is_dir():
        _fallback_dir = Path(tempfile.mkdtemp(prefix="gankhi-"))  # private: mode 0700, ours
    return _fallback_dir / "snapshots"


def write_snapshot(directory: Path, now: datetime | None = None) -> Path:
    """Save installed packages as ``name<TAB>install`` lines (``dpkg --set-selections`` format)."""
    output = runner.run([DPKG_QUERY, "--show", f"--showformat={_STATUS_FORMAT}"])
    lines = []
    for row in output.splitlines():
        name, _, status = row.partition("\t")
        if name and status.startswith("ii"):
            lines.append(f"{name}\tinstall")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S")
    path = directory / f"programas-{stamp}.txt"
    path.write_text("\n".join(sorted(lines)) + "\n")
    path.chmod(0o600)
    prune_snapshots(directory)
    return path


def prune_snapshots(directory: Path, keep: int = KEEP_SNAPSHOTS) -> None:
    """Keep only the newest ``keep`` snapshots. Only files named like ours are touched."""
    old = sorted(directory.glob("programas-*.txt"), key=lambda f: f.name, reverse=True)[keep:]
    for path in old:
        if path.is_file() and not path.is_symlink():
            path.unlink(missing_ok=True)


def available() -> bool:
    """Is the system's password window tool installed?"""
    return os.access(PKEXEC, os.X_OK)


class ActionJob:
    """At most one real action at a time; its output is kept for the page to show."""

    def __init__(
        self,
        run_command: Runner | None = None,
        directory: Path | None = None,
        on_done: Callable[[], None] | None = None,
        is_available: Callable[[], bool] = available,
    ) -> None:
        self._run = run_command or runner.run_privileged
        self._directory = directory
        self._on_done = on_done
        self._is_available = is_available
        self._lock = threading.Lock()
        self.state = IDLE
        self.lines: deque[str] = deque(maxlen=MAX_LINES)
        self.command = ""
        self.returncode: int | None = None
        self.snapshot = ""
        self.message = ""  # message key when something went wrong before apt ran

    @property
    def available(self) -> bool:
        return self._is_available()

    def start(self, action: str, package: str) -> bool:
        """Begin the action unless another one is running. Returns whether it started."""
        with self._lock:
            if self.state == RUNNING or not self.available:
                return False
            self.state = RUNNING
            self.lines.clear()
            self.returncode = None
            self.snapshot = ""
            self.message = ""
            args = runner.privileged_apt(action, package)
            self.command = " ".join(args)
        threading.Thread(target=self._work, args=(args, action != "clean"), daemon=True).start()
        return True

    def _work(self, args: list[str], save_list: bool = True) -> None:
        try:
            if save_list:  # cleaning only deletes downloaded files: there is nothing to record
                self.snapshot = str(write_snapshot(self._directory or snapshot_dir()))
            code = self._run(args, self.lines.append)
        except Exception:  # details go to the log, the screen gets a generic message
            log.exception("action failed")
            self.message = "run_failed"
            self.state = FAILED
        else:
            self.returncode = code
            self.state = DONE if code == 0 else FAILED
        finally:
            if self._on_done is not None:
                self._on_done()

    def status(self) -> dict[str, object]:
        return {
            "state": self.state,
            "command": self.command,
            "lines": list(self.lines),
            "returncode": self.returncode,
            "snapshot": self.snapshot,
            "message": self.message,
        }
