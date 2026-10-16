"""Command-line vulnerability scan: ``python -m ganki.scan``.

Temporary entry point to check the pipeline end to end before the web
dashboard exists. Read-only: it downloads the public feed (only when it has
changed), then compares it with your installed packages locally.
"""

from __future__ import annotations

from collections import Counter

from ganki.collectors.apt import collect
from ganki.feed import refresh
from ganki.osv import find_findings, load_advisories
from ganki.release import UnsupportedReleaseError, detect_ecosystem

SHOWN = 15
STATUS_TEXT = {
    "fix_available": "fix available (update it)",
    "fix_with_pro": "fix needs Ubuntu Pro",
    "no_fix": "no fix released yet",
}


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

    for finding in findings[:SHOWN]:
        fixed = finding.fixed_version or finding.pro_fixed_version or "-"
        print(
            f"  [{finding.priority or '?'}] {finding.cve_id}  {finding.source_package} "
            f"{finding.installed_version} -> {fixed}  ({STATUS_TEXT[finding.status]}; "
            f"{len(finding.packages)} package(s))"
        )
    if len(findings) > SHOWN:
        print(f"  ... and {len(findings) - SHOWN} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
