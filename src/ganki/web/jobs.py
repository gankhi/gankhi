"""Runs the scan in a background thread so the page never blocks."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

from ganki.release import UnsupportedReleaseError
from ganki.service import ScanResult

log = logging.getLogger(__name__)

IDLE, RUNNING, DONE, ERROR, UNSUPPORTED = "idle", "running", "done", "error", "unsupported"


class ScanJob:
    """At most one scan at a time; the latest result is kept in memory."""

    def __init__(self, scan: Callable[[], ScanResult]) -> None:
        self._scan = scan
        self._lock = threading.Lock()
        self.state = IDLE
        self.result: ScanResult | None = None

    def start(self) -> bool:
        """Start a scan unless one is already running. Returns whether one was started."""
        with self._lock:
            if self.state == RUNNING:
                return False
            self.state = RUNNING
        threading.Thread(target=self._run, daemon=True).start()
        return True

    def _run(self) -> None:
        try:
            result = self._scan()
        except UnsupportedReleaseError:
            self.state = UNSUPPORTED
        except Exception:  # any failure must end the job; details go to the log
            log.exception("scan failed")
            self.state = ERROR
        else:
            self.result = result
            self.state = DONE
