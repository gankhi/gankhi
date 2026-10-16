"""Command-line vulnerability scan: ``python -m ganki.scan``.

Temporary entry point to check the pipeline end to end before the web
dashboard exists. Read-only: it downloads the public feed (only when it has
changed), then compares it with your installed packages locally.
"""

from __future__ import annotations

from ganki.collectors.apt import collect
from ganki.feed import refresh
from ganki.osv import find_findings, load_advisories
from ganki.release import UnsupportedReleaseError, detect_ecosystem

SHOWN = 15


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
    unfixed = [f for f in findings if f.fixed_version is None]
    pro_only = [f for f in findings if f.requires_subscription]
    print(
        f"{len(findings)} findings | {len(unfixed)} with no fix released yet "
        f"| {len(pro_only)} whose fix needs a subscription"
    )
    for finding in findings[:SHOWN]:
        fixed = finding.fixed_version or "no fix yet"
        print(f"  {finding.cve_id}  {finding.package} {finding.installed_version} -> {fixed}")
    if len(findings) > SHOWN:
        print(f"  ... and {len(findings) - SHOWN} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
