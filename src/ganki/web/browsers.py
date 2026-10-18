"""Let the person choose which installed browser opens Ganki.

Ganki looks for well-known browsers and, when there is more than one, shows a small
window (zenity or kdialog, whichever the desktop has) to choose from. Without such a
window, or if the person set ``BROWSER`` themselves, nothing is asked and the desktop's
default browser is used. The choice can be remembered; ``ganki --ask-browser`` asks again.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # noqa: S404  (fixed argument lists, no shell, only the desktop's dialog tools)
from pathlib import Path

# command name -> label shown in the window. The first name found for a label wins.
KNOWN = (
    ("firefox", "Firefox"),
    ("librewolf", "LibreWolf"),
    ("google-chrome", "Google Chrome"),
    ("google-chrome-stable", "Google Chrome"),
    ("chromium", "Chromium"),
    ("chromium-browser", "Chromium"),
    ("brave-browser", "Brave"),
    ("vivaldi", "Vivaldi"),
    ("microsoft-edge", "Microsoft Edge"),
    ("opera", "Opera"),
    ("epiphany", "Web (GNOME)"),
    ("falkon", "Falkon"),
    ("midori", "Midori"),
)
DEFAULT = "default"
CANCELLED = "cancelled"
PREFERENCE_FILE = "browser"

_TEXT = {
    "es": {
        "title": "Ganki",
        "ask": "¿En qué navegador querés abrir Ganki?",
        "column": "Navegador",
        "default": "Navegador predeterminado del sistema",
        "open": "Abrir",
        "cancel": "Cancelar",
        "remember": "¿Querés que Ganki recuerde esta elección?",
        "yes": "Recordar",
        "no": "Preguntar siempre",
    },
    "en": {
        "title": "Ganki",
        "ask": "Which browser should open Ganki?",
        "column": "Browser",
        "default": "System default browser",
        "open": "Open",
        "cancel": "Cancel",
        "remember": "Should Ganki remember this choice?",
        "yes": "Remember",
        "no": "Always ask",
    },
}


def _words() -> dict[str, str]:
    language = (os.environ.get("LC_ALL") or os.environ.get("LANG") or "").lower()
    return _TEXT["es" if language.startswith("es") else "en"]


def installed_browsers() -> list[tuple[str, str]]:
    """(label, full path) of each well-known browser found, one per label."""
    found: dict[str, str] = {}
    for command, label in KNOWN:
        path = shutil.which(command)
        if path is not None and label not in found:
            found[label] = path
    return [(label, path) for label, path in found.items()]


def preference_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "ganki" / PREFERENCE_FILE


def remembered(options: list[tuple[str, str]]) -> str | None:
    """The remembered choice, only if it is still installed (or the default)."""
    try:
        value = preference_path().read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if value == DEFAULT or value in {path for _label, path in options}:
        return value
    return None


def remember(choice: str) -> None:
    path = preference_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(choice + "\n", encoding="utf-8")
    except OSError:
        pass  # not remembering is harmless: it will simply ask again


def _run(command: list[str]) -> tuple[int, str]:
    try:
        done = subprocess.run(  # noqa: S603  (absolute path from which(), fixed arguments)
            command, capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL
        )
    except OSError:
        return 127, ""
    return done.returncode, done.stdout.strip()


def _zenity(tool: str, options: list[tuple[str, str]]) -> tuple[str, bool] | None:
    words = _words()
    code, out = _run(
        [
            tool, "--list", f"--title={words['title']}", f"--text={words['ask']}",
            f"--column={words['column']}", "--column=path", "--hide-column=2",
            "--print-column=2", "--width=380", "--height=360",
            f"--ok-label={words['open']}", f"--cancel-label={words['cancel']}",
            words["default"], DEFAULT,
            *[item for label, path in options for item in (label, path)],
        ]
    )  # fmt: skip
    if code != 0 or not out:
        return (CANCELLED, False)
    ask_code, _ = _run(
        [
            tool, "--question", f"--title={words['title']}", f"--text={words['remember']}",
            f"--ok-label={words['yes']}", f"--cancel-label={words['no']}",
        ]
    )  # fmt: skip
    return (out, ask_code == 0)


def _kdialog(tool: str, options: list[tuple[str, str]]) -> tuple[str, bool] | None:
    words = _words()
    code, out = _run(
        [
            tool, "--title", words["title"], "--menu", words["ask"],
            DEFAULT, words["default"],
            *[item for label, path in options for item in (path, label)],
        ]
    )  # fmt: skip
    if code != 0 or not out:
        return (CANCELLED, False)
    ask_code, _ = _run([tool, "--title", words["title"], "--yesno", words["remember"]])
    return (out, ask_code == 0)


def choose(force_ask: bool = False) -> str:
    """Return a browser path, ``DEFAULT`` (use the system's) or ``CANCELLED``."""
    if os.environ.get("BROWSER") and not force_ask:
        return DEFAULT  # the person chose already, in the way Linux programs usually do
    options = installed_browsers()
    if not force_ask:
        saved = remembered(options)
        if saved is not None:
            return saved
    if len(options) < 2:
        return DEFAULT
    for tool_name, ask in (("zenity", _zenity), ("kdialog", _kdialog)):
        tool = shutil.which(tool_name)
        if tool is None:
            continue
        answer = ask(tool, options)
        if answer is None:
            continue
        choice, keep = answer
        if choice != DEFAULT and choice not in {path for _label, path in options}:
            choice = CANCELLED if choice == CANCELLED else DEFAULT
        if keep and choice != CANCELLED:
            remember(choice)
        return choice
    return DEFAULT
