"""What the user has checked by hand: a mark per program or app *and its exact version*.

Gankhi cannot compare snap, flatpak or third-party programs with any list of notices. After
the person checked one (for example by asking an AI) and updated or removed it, they can mark
it. The mark is theirs: Gankhi only stops listing it as "not checked". It is kept on this
computer only, and it stops counting as soon as the version changes.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass
from datetime import date
from pathlib import Path

log = logging.getLogger(__name__)

MAX_MARKS = 5000
MAX_TEXT = 200
HOWS = ("apt", "deb", "snap", "flatpak")


@dataclass(frozen=True)
class Mark:
    how: str
    name: str
    version: str
    day: str  # year-month-day

    @property
    def key(self) -> str:
        return key(self.how, self.name, self.version)


def key(how: str, name: str, version: str) -> str:
    """The same app in another version is another key: a new version is not checked yet."""
    return f"{how}\t{name}\t{version}"


def default_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "gankhi" / "verified.json"


class Store:
    """The marks, in memory and (when given a path) in a small file only the user can read."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._marks: dict[str, Mark] = {}
        self._load()

    def _load(self) -> None:
        if self._path is None:
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            rows = data["items"] if isinstance(data, dict) else []
        except (OSError, ValueError, KeyError):
            return  # no file yet, or one we cannot read: start empty, never crash
        for row in rows[:MAX_MARKS] if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            parts = [row.get(f) for f in ("how", "name", "version", "day")]
            if all(isinstance(p, str) and len(p) <= MAX_TEXT for p in parts) and parts[0] in HOWS:
                mark = Mark(*parts)  # type: ignore[arg-type]
                self._marks[mark.key] = mark

    def _save(self) -> None:
        if self._path is None:
            return
        rows = [
            {"how": m.how, "name": m.name, "version": m.version, "day": m.day}
            for m in self._marks.values()
        ]
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            temp = self._path.with_suffix(".tmp")
            descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump({"version": 1, "items": rows}, handle, indent=1)
            temp.replace(self._path)
        except OSError:
            log.warning("could not save the verified marks", exc_info=True)

    def marks(self) -> dict[str, Mark]:
        with self._lock:
            return dict(self._marks)

    def add(self, how: str, name: str, version: str) -> bool:
        with self._lock:
            if len(self._marks) >= MAX_MARKS and key(how, name, version) not in self._marks:
                return False
            mark = Mark(how, name, version, date.today().isoformat())
            self._marks[mark.key] = mark
            self._save()
            return True

    def remove(self, how: str, name: str, version: str) -> bool:
        with self._lock:
            removed = self._marks.pop(key(how, name, version), None) is not None
            if removed:
                self._save()
            return removed
