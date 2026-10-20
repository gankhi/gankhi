"""Summarise the Downloads folder by kind of file. Read-only: names and sizes only."""

from __future__ import annotations

import heapq
import os
from dataclasses import dataclass, field
from pathlib import Path

MAX_ENTRIES = 200_000  # stop on absurdly large folders instead of freezing

# (key, suffixes). Order matters: the first matching group wins.
GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("archives", (".zip", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".tar", ".7z", ".rar", ".gz")),
    ("images", (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".heic")),
    ("installers", (".deb", ".appimage", ".rpm", ".run", ".snap", ".flatpakref")),
    ("pdf", (".pdf",)),
    (
        "documents",
        (".doc", ".docx", ".odt", ".xls", ".xlsx", ".ods", ".ppt", ".pptx", ".odp", ".txt", ".csv"),
    ),
)


@dataclass(frozen=True)
class DownloadGroup:
    key: str  # one of GROUPS' keys, or "other"
    files: int
    size_bytes: int


def classify(filename: str) -> str:
    lower = filename.lower()
    for key, suffixes in GROUPS:
        if lower.endswith(suffixes):
            return key
    return "other"


def downloads_dir(home: Path | None = None) -> Path:
    """The user's Downloads folder (from ``user-dirs.dirs``), else ``~/Downloads``."""
    base = home or Path.home()
    try:
        for line in (base / ".config" / "user-dirs.dirs").read_text().splitlines():
            if line.startswith("XDG_DOWNLOAD_DIR="):
                value = line.split("=", 1)[1].strip().strip('"').replace("$HOME", str(base))
                path = Path(value)
                if path.is_absolute() and path.is_relative_to(base):
                    return path
    except OSError:
        pass
    return base / "Downloads"


def scan_downloads(folder: Path) -> list[DownloadGroup]:
    """Count files and bytes per kind, biggest first. Symlinks are never followed."""
    counts: dict[str, list[int]] = {}
    seen = 0
    for root, _dirs, names in os.walk(folder, followlinks=False):
        for name in names:
            seen += 1
            if seen > MAX_ENTRIES:
                break
            try:
                info = os.lstat(os.path.join(root, name))
            except OSError:
                continue
            if not os.path.isfile(os.path.join(root, name)) or os.path.islink(
                os.path.join(root, name)
            ):
                continue
            entry = counts.setdefault(classify(name), [0, 0])
            entry[0] += 1
            entry[1] += info.st_size
        if seen > MAX_ENTRIES:
            break
    groups = [DownloadGroup(key, files, size) for key, (files, size) in counts.items()]
    return sorted(groups, key=lambda g: -g.size_bytes)


TOP_ITEMS = 30
TOP_KINDS = 12
MAX_NAME_CHARS = 120


@dataclass(frozen=True)
class FolderUse:
    name: str  # first folder under Downloads (or the file itself, if it is loose)
    is_folder: bool
    files: int
    size_bytes: int
    full: str = ""  # the same name, not shortened (used to open its folder)


@dataclass(frozen=True)
class BigFile:
    path: str  # relative to Downloads, never the full path
    size_bytes: int
    full: str = ""  # the same path, not shortened (used to open its folder)


@dataclass(frozen=True)
class KindUse:
    extension: str  # ".mp4", or "" for files without one
    files: int
    size_bytes: int


@dataclass(frozen=True)
class GroupDetail:
    key: str
    files: int
    size_bytes: int
    folders: list[FolderUse] = field(default_factory=list)
    biggest: list[BigFile] = field(default_factory=list)
    kinds: list[KindUse] = field(default_factory=list)
    truncated: bool = False  # the folder was too large to read completely


def _short(text: str) -> str:
    return text if len(text) <= MAX_NAME_CHARS else text[: MAX_NAME_CHARS - 1] + "\u2026"


def group_detail(folder: Path, key: str) -> GroupDetail:
    """What is inside one kind of download: where the space is, the biggest files, the types.

    Read-only. Names are shown relative to the Downloads folder. Symlinks are never followed.
    """
    by_folder: dict[tuple[str, bool], list[int]] = {}
    by_kind: dict[str, list[int]] = {}
    biggest: list[tuple[int, str]] = []
    files = total = seen = 0
    truncated = False
    for root, _dirs, names in os.walk(folder, followlinks=False):
        for name in names:
            seen += 1
            if seen > MAX_ENTRIES:
                truncated = True
                break
            if classify(name) != key:
                continue
            path = os.path.join(root, name)
            try:
                info = os.lstat(path)
            except OSError:
                continue
            if not os.path.isfile(path) or os.path.islink(path):
                continue
            relative = os.path.relpath(path, folder)
            top = relative.split(os.sep, 1)
            slot = by_folder.setdefault((top[0], len(top) > 1), [0, 0])
            slot[0] += 1
            slot[1] += info.st_size
            extension = os.path.splitext(name)[1].lower()
            kind = by_kind.setdefault(extension, [0, 0])
            kind[0] += 1
            kind[1] += info.st_size
            files += 1
            total += info.st_size
            heapq.heappush(biggest, (info.st_size, relative))
            if len(biggest) > TOP_ITEMS:
                heapq.heappop(biggest)
        if truncated:
            break
    folders = sorted(by_folder.items(), key=lambda item: -item[1][1])[:TOP_ITEMS]
    kinds = sorted(by_kind.items(), key=lambda item: -item[1][1])[:TOP_KINDS]
    return GroupDetail(
        key=key,
        files=files,
        size_bytes=total,
        folders=[FolderUse(_short(n), is_dir, c, b, n) for (n, is_dir), (c, b) in folders],
        biggest=[BigFile(_short(p), s, p) for s, p in sorted(biggest, reverse=True)],
        kinds=[KindUse(ext, c, b) for ext, (c, b) in kinds],
        truncated=truncated,
    )


def known_keys() -> set[str]:
    return {key for key, _ in GROUPS} | {"other"}
