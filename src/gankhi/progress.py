"""What the scan is doing right now, so the page can show it while it works.

The scan reports each step (started, finished) and the first facts it learns. The page
reads this through ``/api/progress``. It holds only numbers and short names, never any
text that comes from outside this computer.
"""

from __future__ import annotations

import threading
import time
from typing import Any

PENDING, RUNNING, DONE = "pending", "running", "done"
STEPS = ("system", "programs", "updates", "downloads", "feed", "index", "external", "analysis")


class Progress:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._steps: dict[str, dict[str, Any]] = {
                key: {"state": PENDING, "started": None, "seconds": None, "fraction": None}
                for key in STEPS
            }
            self._facts: dict[str, Any] = {}

    def begin(self, step: str) -> None:
        with self._lock:
            self._steps[step].update(state=RUNNING, started=time.monotonic())

    def fraction(self, step: str, value: float) -> None:
        with self._lock:
            self._steps[step]["fraction"] = max(0.0, min(1.0, value))

    def finish(self, step: str, **facts: Any) -> None:
        with self._lock:
            item = self._steps[step]
            started = item["started"]
            item.update(
                state=DONE,
                fraction=1.0,
                seconds=round(time.monotonic() - started, 1) if started else 0.0,
            )
            self._facts.update(facts)

    def snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            steps = []
            for key in STEPS:
                item = self._steps[key]
                seconds = item["seconds"]
                if item["state"] == RUNNING and item["started"] is not None:
                    seconds = round(now - item["started"], 1)
                steps.append(
                    {
                        "key": key,
                        "state": item["state"],
                        "seconds": seconds,
                        "fraction": item["fraction"],
                    }
                )
            return {"steps": steps, "facts": dict(self._facts)}
