"""Command-line vulnerability scan: ``python -m ganki.scan``.

Temporary entry point to check the pipeline end to end before the web
dashboard exists. Read-only: it downloads the public feed (only when it has
changed), then compares it with your installed packages locally.
"""

from __future__ import annotations

import os
from collections import Counter

from ganki.collectors.apt import collect
from ganki.feed import refresh
from ganki.osv import find_findings, load_advisories
from ganki.release import UnsupportedReleaseError, detect_ecosystem
from ganki.summary import OLD_KERNEL, PROGRAM, RUNNING_KERNEL, PackageRisk, summarize

SHOWN = 15
STATUS_TEXT = {
    "fix_available": "fix available (update it)",
    "fix_with_pro": "fix needs Ubuntu Pro",
    "no_fix": "no fix released yet",
}


def print_section(title: str, risks: list[PackageRisk]) -> None:
    """Print the most urgent packages of one kind, one line each."""
    print(f"\n{title}: {len(risks)} package(s)")
    for risk in risks[:SHOWN]:
        priorities = ", ".join(f"{p} {n}" for p, n in risk.by_priority.items())
        fix = f" -> {risk.target_version}" if risk.target_version else ""
        state = f"fixable {risk.fix_available}, needs Pro {risk.fix_with_pro}, no fix {risk.no_fix}"
        print(
            f"  [{risk.top_priority or '?'}] {risk.source_package} "
            f"{risk.installed_version}{fix} | {risk.cve_count} CVEs ({priorities}) | {state}"
        )
    if len(risks) > SHOWN:
        print(f"  ... and {len(risks) - SHOWN} more")


def main() -> int:
    """Run the scan and print a short summary. Returns a process exit code."""
    try:
        ecosystem = detect_ecosystem()
    except UnsupportedReleaseError as error:
        print(f"Cannot check vulnerabilities on this system: {error}")
        return 2

    status = refresh()
    state = "downloaded a newer feed" if status.downloaded else "feed already up to date"
    print(f"Release: {ecosystem} | {state} | server date: {status.last_modified or 'unknown'}")

    index = load_advisories(status.path, ecosystem)
    findings = find_findings(collect(), index)

    print(
        f"{len(findings)} findings across {len({f.cve_id for f in findings})} different CVEs "
        f"in {len({f.source_package for f in findings})} source packages"
    )
    for key, text in STATUS_TEXT.items():
        print(f"  {text}: {sum(1 for f in findings if f.status == key)}")
    by_priority = Counter(f.priority or "unknown" for f in findings)
    print("  by priority: " + ", ".join(f"{p}={n}" for p, n in by_priority.most_common()))

    risks = summarize(findings, os.uname().release)
    print_section("Programs (grouped by package)", [r for r in risks if r.kind == PROGRAM])
    print_section("Running kernel", [r for r in risks if r.kind == RUNNING_KERNEL])
    old = [r for r in risks if r.kind == OLD_KERNEL]
    if old:
        total = sum(r.cve_count for r in old)
        print(f"\nOld kernels, installed but not running: {len(old)} ({total} CVEs). Removing them")
        print("clears these findings; they are not an exposure while you boot the newer kernel.")
        for risk in old:
            print(f"  {risk.source_package} {risk.installed_version}: {risk.cve_count} CVEs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
