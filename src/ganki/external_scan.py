"""The pip and npm part of a scan: what is installed, and which of it is affected."""

from __future__ import annotations

import logging
import urllib.error
import zipfile
from collections.abc import Callable
from pathlib import Path

from ganki import feed, osv_external
from ganki.collectors.external import NPM_ECOSYSTEM, PYPI, ExternalPackage, collect_external
from ganki.external_tools import ExternalTool, build_external_tools

log = logging.getLogger(__name__)

TOOL_OF = {PYPI: "pip", NPM_ECOSYSTEM: "npm"}


def check_ecosystem(
    ecosystem: str,
    packages: list[ExternalPackage],
    cache_dir: Path | None = None,
    progress: Callable[[float], None] | None = None,
    refresh: Callable[..., feed.FeedStatus] = feed.refresh,
) -> list[osv_external.ExternalFinding]:
    """Download the list (only if it changed) and match it; reuse the last answer if nothing
    changed since."""
    folder = cache_dir or feed.default_cache_dir()
    status = refresh(
        osv_external.FEED_URLS[ecosystem],
        cache_dir=folder,
        name=f"osv-{ecosystem}",
        suffix=".zip",
        max_bytes=feed.MAX_EXTERNAL_BYTES,
    )
    key = osv_external.signature(packages, status.last_modified or "")
    kept = folder / f"external-{ecosystem}.json"
    cached = None if status.downloaded else osv_external.load_cached(kept, key)
    if cached is not None:
        return cached
    findings = osv_external.find_external(status.path, ecosystem, packages, progress)
    osv_external.save_cached(kept, key, findings)
    return findings


def scan_external(
    progress: Callable[[float], None] | None = None,
    collect: Callable[[], list[ExternalPackage]] = collect_external,
    check: Callable[..., list[osv_external.ExternalFinding]] = check_ecosystem,
) -> tuple[list[ExternalTool], list[str]]:
    """Every pip and npm package with its notices, and the tools that could not be checked.

    A failure here (no network, a bad download) never stops the rest of the scan: the tool
    is reported as not checked.
    """
    packages = collect()
    findings: list[osv_external.ExternalFinding] = []
    failed: list[str] = []
    ecosystems = [e for e in (PYPI, NPM_ECOSYSTEM) if any(p.ecosystem == e for p in packages)]
    for number, ecosystem in enumerate(ecosystems):

        def part(value: float, number: int = number) -> None:
            if progress is not None:
                progress((number + value) / len(ecosystems))

        try:
            findings += check(
                ecosystem, [p for p in packages if p.ecosystem == ecosystem], None, part
            )
        except (OSError, ValueError, urllib.error.URLError, zipfile.BadZipFile):
            log.warning("could not check %s packages", TOOL_OF[ecosystem], exc_info=True)
            failed.append(TOOL_OF[ecosystem])
    return build_external_tools(packages, findings), failed
