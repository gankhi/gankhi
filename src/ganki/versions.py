"""Compare versions the way PyPI (PEP 440) and npm (semantic versioning) do."""

from __future__ import annotations

import re
from functools import total_ordering

from packaging.version import InvalidVersion, Version

_SEMVER = re.compile(
    r"^v?(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\.(?P<patch>\d+))?"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


@total_ordering
class SemVer:
    """npm versions: ``1.2.3``, ``1.2.3-beta.1``. A release is newer than its pre-releases."""

    def __init__(self, text: str) -> None:
        match = _SEMVER.match(text.strip())
        if match is None:
            raise ValueError(f"not a semantic version: {text!r}")
        self.core = (int(match["major"]), int(match["minor"] or 0), int(match["patch"] or 0))
        self.pre = tuple(match["pre"].split(".")) if match["pre"] else ()

    @staticmethod
    def _part(item: str) -> tuple[int, int, str]:
        # numbers sort before words, and by value
        return (0, int(item), "") if item.isdigit() else (1, 0, item)

    def _key(self) -> tuple:  # type: ignore[type-arg]
        pre = tuple(self._part(i) for i in self.pre)
        return (self.core, 1 if not self.pre else 0, pre)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SemVer) and self._key() == other._key()

    def __lt__(self, other: SemVer) -> bool:
        return self._key() < other._key()

    def __hash__(self) -> int:
        return hash(self._key())


def parse(ecosystem: str, text: str):  # type: ignore[no-untyped-def]
    """A comparable version, or ``None`` if the text is not a valid version."""
    try:
        return Version(text) if ecosystem == "PyPI" else SemVer(text)
    except (InvalidVersion, ValueError):
        return None
