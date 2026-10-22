"""Which installed apt packages come from outside Ubuntu's own archive.

Reads ``apt list --installed`` (read-only). Ubuntu's vulnerability list only covers what Ubuntu
publishes, so a package from another repository (Google, Docker, a PPA...) or installed by hand
from a ``.deb`` cannot be checked against it. Those are reported as "not checked", never as safe.
"""

from __future__ import annotations

import re

from gankhi.collectors.updates import Update
from gankhi.runner import APT, run

# Example lines (C locale):
#   bash/noble-updates,noble-security,now 5.2.21-2ubuntu4.1 amd64 [installed]
#   google-cloud-cli/cloud-sdk,now 548.0.0-0 amd64 [installed]
#   some-tool/now 1.0 amd64 [installed,local]
_LINE = re.compile(r"^(?P<name>[^/\s]+)/(?P<origins>\S+)\s+\S+\s+\S+\s+\[installed")
LOCAL = "local"  # installed from a file, no repository behind it


def parse_origins(output: str) -> dict[str, str]:
    """Package name -> its origins as apt reports them ("noble-updates,noble-security")."""
    found: dict[str, str] = {}
    for line in output.splitlines():
        match = _LINE.match(line.strip())
        if match is None:
            continue  # the "Listing..." header, warnings, anything unexpected
        suites = [part for part in match["origins"].split(",") if part and part != "now"]
        found.setdefault(match["name"], ",".join(suites) or LOCAL)
    return found


def is_ubuntu_origin(origins: str, codename: str) -> bool:
    """True when any origin is one of Ubuntu's own pockets for this release."""
    if not codename:
        return True  # an unknown release cannot be told apart: do not claim anything
    own = re.compile(rf"{re.escape(codename)}(-security|-updates|-backports|-proposed)?")
    return any(own.fullmatch(part) for part in origins.split(","))


def third_party(output: str, codename: str) -> dict[str, str]:
    """The packages that do not come from Ubuntu, with where they come from."""
    return {
        name: origins
        for name, origins in parse_origins(output).items()
        if not is_ubuntu_origin(origins, codename)
    }


def resolve_superseded(
    outside: dict[str, str], updates: list[Update], codename: str
) -> dict[str, str]:
    """Settle the packages whose installed version is no longer in any repository.

    When a newer version is out, apt no longer lists the one installed in any repository and
    reports it as "local". Where the newer version comes from tells what the package really is:
    if it is one of Ubuntu's own pockets it is an Ubuntu package that is only out of date (and
    Ubuntu's notices apply to it); otherwise it comes from that other repository.
    """
    newer = {u.name.split(":")[0]: u.origin for u in updates}
    resolved: dict[str, str] = {}
    for name, origins in outside.items():
        source = newer.get(name)
        if origins != LOCAL or source is None:
            resolved[name] = origins
        elif not is_ubuntu_origin(source, codename):
            resolved[name] = source
    return resolved


def collect_third_party(codename: str) -> dict[str, str]:
    return third_party(run([APT, "list", "--installed"], timeout=120), codename)
