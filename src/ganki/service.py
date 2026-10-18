"""One full scan of this machine: what is installed, what is affected, what can be updated.

Shared by the command-line scan and the web dashboard so both show the same data.
Everything is read-only and local; the only network access is the public
vulnerability feed download in ``feed.refresh``.
"""

from __future__ import annotations

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ganki import cleanup
from ganki import downloads as downloads_mod
from ganki.collectors.apt import collect
from ganki.collectors.updates import collect_updates
from ganki.feed import refresh
from ganki.osv import Finding, find_findings, is_snap_stub, load_advisories
from ganki.progress import Progress
from ganki.release import detect_ecosystem
from ganki.summary import PackageRisk, summarize
from ganki.system import SystemInfo, read_system
from ganki.tools import Tool, build_tools

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanResult:
    """Everything one scan found."""

    ecosystem: str
    feed_downloaded: bool  # True when a newer feed was downloaded for this scan
    feed_date: str  # the feed's Last-Modified, as the server reported it ("" if unknown)
    findings: list[Finding]
    risks: list[PackageRisk]
    snap_stubs: list[str]  # placeholder packages whose real app is a snap (not checked)
    pending_updates: int
    scanned_at: datetime
    system: SystemInfo | None = None
    reclaimable: cleanup.Reclaimable = field(default_factory=cleanup.Reclaimable)
    download_groups: list[downloads_mod.DownloadGroup] = field(default_factory=list)
    downloads_folder: str = ""  # shown as "~/Descargas", never the full home path
    tools: list[Tool] = field(default_factory=list)


def run_scan(progress: Progress | None = None) -> ScanResult:
    """Download the feed if it changed, then match it against the installed packages.

    Raises ``UnsupportedReleaseError`` on systems the feed does not cover.
    """
    ecosystem = detect_ecosystem()
    progress = progress or Progress()
    started = time.monotonic()

    def step(name: str, work, facts=lambda _result: {}):  # type: ignore[no-untyped-def]
        progress.begin(name)
        result = work()
        progress.finish(name, **facts(result))
        return result

    # The slow parts do not depend on each other, so they run side by side: the system
    # commands (dpkg, apt) wait on other processes while the feed is being read.
    folder = downloads_mod.downloads_dir()
    with ThreadPoolExecutor(max_workers=4) as pool:
        system_job = pool.submit(
            step,
            "system",
            read_system,
            lambda s: {
                "os_name": s.os_name,
                "disk_total": s.disk_total,
                "disk_used": s.disk_used,
                "ram_total_kib": s.ram_total_kib,
                "ram_used_kib": s.ram_used_kib,
            },
        )
        packages_job = pool.submit(step, "programs", collect, lambda r: {"packages": len(r)})
        updates_job = pool.submit(step, "updates", collect_updates, lambda r: {"updates": len(r)})
        downloads_job = pool.submit(
            step,
            "downloads",
            lambda: downloads_mod.scan_downloads(folder),
            lambda r: {
                "download_files": sum(g.files for g in r),
                "download_bytes": sum(g.size_bytes for g in r),
            },
        )
        status = step(
            "feed",
            refresh,
            lambda r: {"feed_downloaded": r.downloaded, "feed_date": r.last_modified or ""},
        )
        index = step(
            "index",
            lambda: load_advisories(
                status.path, ecosystem, lambda value: progress.fraction("index", value)
            ),
        )
        packages = packages_job.result()
        updates = updates_job.result()
        system = system_job.result()
        download_groups = downloads_job.result()
    progress.begin("analysis")
    findings = find_findings(packages, index)
    log.info("scan finished in %.1f s", time.monotonic() - started)
    result = ScanResult(
        ecosystem=ecosystem,
        feed_downloaded=status.downloaded,
        feed_date=status.last_modified or "",
        findings=findings,
        risks=summarize(findings, os.uname().release),
        snap_stubs=sorted(
            {p.name for p in packages if is_snap_stub(p.source_version or p.version)}
        ),
        pending_updates=len(updates),
        scanned_at=datetime.now(timezone.utc),
        system=system,
        reclaimable=cleanup.estimate(packages, system.kernel),
        download_groups=download_groups,
        downloads_folder="~/" + folder.name,
        tools=build_tools(packages, findings, updates, system.kernel),
    )
    progress.finish("analysis", findings=len(findings))
    return result
