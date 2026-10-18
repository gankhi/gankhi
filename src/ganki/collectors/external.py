"""What pip and npm have installed (read-only), apart from what apt manages.

Ubuntu's own Python and Node packages (``python3-requests``, ``node-*``) are apt packages:
the Ubuntu feed already covers them, including fixes Ubuntu applies without changing the
version number. Checking them again against the public PyPI/npm lists would only give false
alarms, so only what pip or npm installed by themselves is listed here.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess  # noqa: S404  (only to catch the errors that runner.run raises)
from dataclasses import dataclass
from pathlib import Path

from ganki.runner import NPM, NPM_LOCAL, PYTHON, run

log = logging.getLogger(__name__)

PYPI, NPM_ECOSYSTEM = "PyPI", "npm"
_APT_PYTHON = re.compile(r"^/usr/lib/python3(\.\d+)?/(dist|site)-packages")
MAX_PACKAGES = 5000


@dataclass(frozen=True)
class ExternalPackage:
    ecosystem: str  # "PyPI" or "npm", the names the OSV lists use
    name: str
    version: str
    tool: str  # "pip" or "npm": what the person would use to update it


def normalize_python_name(name: str) -> str:
    """PEP 503: ``Foo_Bar.baz`` -> ``foo-bar-baz``."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_pip(output: str) -> list[ExternalPackage]:
    """``pip list -v --format=json`` -> the packages pip itself put on this computer."""
    try:
        data = json.loads(output)
    except ValueError:
        return []
    found: dict[str, ExternalPackage] = {}
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        name, version = item.get("name"), item.get("version")
        location = str(item.get("location") or "")
        if not isinstance(name, str) or not isinstance(version, str) or not version:
            continue
        if _APT_PYTHON.match(location):
            continue  # installed by apt: covered by the Ubuntu list
        key = normalize_python_name(name)
        found.setdefault(key, ExternalPackage(PYPI, key, version, "pip"))
    return sorted(found.values(), key=lambda p: p.name)[:MAX_PACKAGES]


def parse_npm(output: str) -> list[ExternalPackage]:
    """``npm ls -g --json --depth=0`` -> the global npm packages."""
    try:
        data = json.loads(output)
    except ValueError:
        return []
    dependencies = data.get("dependencies") if isinstance(data, dict) else None
    found = []
    for name, info in (dependencies or {}).items() if isinstance(dependencies, dict) else []:
        version = info.get("version") if isinstance(info, dict) else None
        if isinstance(name, str) and isinstance(version, str) and version:
            found.append(ExternalPackage(NPM_ECOSYSTEM, name, version, "npm"))
    return sorted(found, key=lambda p: p.name)[:MAX_PACKAGES]


def collect_pip() -> list[ExternalPackage]:
    if not Path(PYTHON).is_file():
        return []
    try:
        output = run(
            [PYTHON, "-m", "pip", "list", "-v", "--format=json", "--disable-pip-version-check"],
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        log.info("pip could not list its packages", exc_info=True)
        return []
    return parse_pip(output)


def collect_npm() -> list[ExternalPackage]:
    command = next((c for c in (NPM, NPM_LOCAL) if Path(c).is_file()), None)
    if command is None:
        return []
    try:
        output = run([command, "ls", "-g", "--json", "--depth=0"], timeout=120)
    except (OSError, subprocess.SubprocessError):
        log.info("npm could not list its packages", exc_info=True)
        return []
    return parse_npm(output)


def collect_external() -> list[ExternalPackage]:
    return [*collect_pip(), *collect_npm()]
