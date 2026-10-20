"""Download Canonical's vulnerability feed, only when it has changed.

Every scan asks the server "has the feed changed since my copy?" using the
standard ``If-None-Match`` / ``If-Modified-Since`` headers. If not (HTTP 304) the
cached copy is reused, so the data is always current without re-downloading
~46 MB each time.

This is the only network access in Gankhi. It downloads a public file; it sends
nothing about your system except the normal HTTP request.
"""

from __future__ import annotations

import json
import os
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

OSV_URL = "https://security-metadata.canonical.com/osv/osv-all.tar.xz"
MAX_DOWNLOAD_BYTES = 300 * 1024 * 1024  # refuse absurdly large downloads
MAX_EXTERNAL_BYTES = 600 * 1024 * 1024  # the npm list is much bigger than Ubuntu's
TIMEOUT_SECONDS = 60
_CHUNK = 1024 * 256


@dataclass(frozen=True)
class FeedStatus:
    """Result of a refresh."""

    path: Path
    last_modified: str | None  # as reported by the server, shown to the user
    downloaded: bool  # False when the cached copy was already current


def default_cache_dir() -> Path:
    """``$XDG_CACHE_HOME/gankhi`` or ``~/.cache/gankhi``."""
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "gankhi"


def _read_meta(meta_path: Path) -> dict[str, str]:
    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str)} if isinstance(data, dict) else {}


def refresh(
    url: str = OSV_URL,
    cache_dir: Path | None = None,
    opener: Callable[..., object] = urllib.request.urlopen,
    name: str = "osv-all",
    suffix: str = ".tar.xz",
    max_bytes: int | None = None,
) -> FeedStatus:
    """Make sure the cached feed is current; download it if the server has a newer one."""
    if not url.startswith("https://"):
        raise ValueError("the feed must be downloaded over HTTPS")
    limit = max_bytes or MAX_DOWNLOAD_BYTES
    cache = cache_dir or default_cache_dir()
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / f"{name}{suffix}"
    meta_path = cache / f"{name}.meta.json"
    meta = _read_meta(meta_path) if target.exists() else {}

    headers = {"User-Agent": "gankhi"}
    if meta.get("etag"):
        headers["If-None-Match"] = meta["etag"]
    if meta.get("last_modified"):
        headers["If-Modified-Since"] = meta["last_modified"]
    request = urllib.request.Request(url, headers=headers)  # noqa: S310  (https checked above)

    try:
        response = opener(request, timeout=TIMEOUT_SECONDS)
    except urllib.error.HTTPError as error:
        if error.code == 304 and target.exists():
            return FeedStatus(target, meta.get("last_modified"), downloaded=False)
        raise

    with response as resp:  # type: ignore[attr-defined]
        declared = int(resp.headers.get("Content-Length") or 0)
        if declared > limit:
            raise ValueError("the feed is larger than the allowed maximum")
        fd, tmp_name = tempfile.mkstemp(dir=cache, prefix="osv-", suffix=".part")
        total = 0
        try:
            with os.fdopen(fd, "wb") as out:
                while chunk := resp.read(_CHUNK):
                    total += len(chunk)
                    if total > limit:
                        raise ValueError("the feed exceeded the allowed maximum while downloading")
                    out.write(chunk)
            os.replace(tmp_name, target)  # atomic: never leaves a half-written feed
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise
        new_meta = {
            "etag": resp.headers.get("ETag") or "",
            "last_modified": resp.headers.get("Last-Modified") or "",
        }
    meta_path.write_text(json.dumps(new_meta), encoding="utf-8")
    return FeedStatus(target, new_meta["last_modified"] or None, downloaded=True)
