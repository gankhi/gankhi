# ruff: noqa: S101, S603, S607
# (pytest tests rely on bare asserts; the scripts run are the repository's own)
"""Tests for the install and uninstall scripts and the launcher files."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
INSTALL = ROOT / "scripts" / "install.sh"
UNINSTALL = ROOT / "scripts" / "uninstall.sh"

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


@needs_bash
@pytest.mark.parametrize("script", [INSTALL, UNINSTALL])
def test_scripts_have_valid_bash_syntax(script):
    assert subprocess.run(["bash", "-n", str(script)], check=False).returncode == 0


@needs_bash
def test_uninstall_refuses_to_touch_anything_outside_the_home_folder(tmp_path):
    victim = tmp_path / "outside" / "ganki"
    victim.mkdir(parents=True)
    home = tmp_path / "home"
    home.mkdir()
    result = subprocess.run(
        ["bash", str(UNINSTALL), "--yes"],
        env={
            "HOME": str(home),
            "XDG_DATA_HOME": str(tmp_path / "outside"),
            "PATH": "/usr/bin:/bin",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "refusing" in result.stderr
    assert victim.exists()


@needs_bash
def test_uninstall_without_confirmation_changes_nothing(tmp_path):
    app = tmp_path / ".local" / "share" / "ganki"
    app.mkdir(parents=True)
    result = subprocess.run(
        ["bash", str(UNINSTALL)],
        env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
        input="n\n",
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert app.exists()
    assert "Nothing was changed" in result.stdout


def test_launcher_template_has_the_required_entries():
    text = (ROOT / "packaging" / "ganki.desktop.in").read_text()
    assert "Exec=@EXEC@ --pause-on-error" in text
    assert "Terminal=true" in text  # a terminal window is how the user stops it (Ctrl+C)
    assert "Icon=@ICON@" in text
    assert (ROOT / "packaging" / "ganki.svg").read_text().lstrip().startswith("<svg")


def test_the_installed_command_points_at_a_real_function():
    from ganki.web import server

    assert callable(server.run)
    assert 'ganki = "ganki.web.server:run"' in (ROOT / "pyproject.toml").read_text()
