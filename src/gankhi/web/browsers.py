"""Let the person choose which installed browser opens Gankhi.

Gankhi looks for well-known browsers and, when there is more than one, shows a small
window (zenity or kdialog, whichever the desktop has) to choose from. Without such a
window, or if the person set ``BROWSER`` themselves, nothing is asked and the desktop's
default browser is used. The choice can be remembered; ``gankhi --ask-browser`` asks again.
"""

from __future__ import annotations

import configparser
import os
import re
import shlex
import shutil
import subprocess  # noqa: S404  (fixed argument lists, no shell, only the desktop's dialog tools)
from pathlib import Path
from typing import NamedTuple

# command name -> label shown in the window. The first name found for a label wins.
KNOWN = (
    ("firefox", "Firefox"),
    ("firefox-esr", "Firefox ESR"),
    ("librewolf", "LibreWolf"),
    ("waterfox", "Waterfox"),
    ("floorp", "Floorp"),
    ("zen-browser", "Zen"),
    ("mullvad-browser", "Mullvad Browser"),
    ("tor-browser", "Tor Browser"),
    ("torbrowser-launcher", "Tor Browser"),
    ("palemoon", "Pale Moon"),
    ("google-chrome", "Google Chrome"),
    ("google-chrome-stable", "Google Chrome"),
    ("chromium", "Chromium"),
    ("chromium-browser", "Chromium"),
    ("ungoogled-chromium", "Ungoogled Chromium"),
    ("brave-browser", "Brave"),
    ("brave", "Brave"),
    ("vivaldi", "Vivaldi"),
    ("vivaldi-stable", "Vivaldi"),
    ("microsoft-edge", "Microsoft Edge"),
    ("microsoft-edge-stable", "Microsoft Edge"),
    ("opera", "Opera"),
    ("thorium-browser", "Thorium"),
    ("yandex-browser", "Yandex Browser"),
    ("duckduckgo", "DuckDuckGo"),
    ("epiphany", "Web (GNOME)"),
    ("falkon", "Falkon"),
    ("konqueror", "Konqueror"),
    ("qutebrowser", "qutebrowser"),
    ("min", "Min"),
    ("midori", "Midori"),
)
# Where desktops list their applications (snap and flatpak keep their own folders).
APPLICATION_FOLDERS = (
    "/usr/share/applications",
    "/usr/local/share/applications",
    "/var/lib/snapd/desktop/applications",
    "/var/lib/flatpak/exports/share/applications",
    "~/.local/share/flatpak/exports/share/applications",
    "~/.local/share/applications",
)
OTHER = "other"
DEFAULT = "default"
CANCELLED = "cancelled"
PREFERENCE_FILE = "browser"

_TEXT = {
    "es": {
        "title": "Gankhi",
        "ask": "¿En qué navegador querés abrir Gankhi?",
        "column": "Navegador",
        "default": "Navegador predeterminado del sistema",
        "other": "Otro (buscar el programa en mis archivos)...",
        "pick": "Elegí el programa del navegador",
        "open": "Abrir",
        "cancel": "Cancelar",
        "remember": "¿Querés que Gankhi recuerde esta elección?",
        "yes": "Recordar",
        "no": "Preguntar siempre",
    },
    "en": {
        "title": "Gankhi",
        "ask": "Which browser should open Gankhi?",
        "column": "Browser",
        "default": "System default browser",
        "other": "Another one (find the program in my files)...",
        "pick": "Choose the browser program",
        "open": "Open",
        "cancel": "Cancel",
        "remember": "Should Gankhi remember this choice?",
        "yes": "Remember",
        "no": "Always ask",
    },
}


def _words() -> dict[str, str]:
    language = (os.environ.get("LC_ALL") or os.environ.get("LANG") or "").lower()
    return _TEXT["es" if language.startswith("es") else "en"]


class Browser(NamedTuple):
    label: str
    key: str  # what is remembered: a program path, or "desktop:<file name>"
    argv: tuple[str, ...]  # command to run; the address is added at the end


_FIELD_CODES = re.compile(r"%[a-zA-Z%]")


def _identity(argv: tuple[str, ...]) -> str:
    """A name for the program behind a command, so one browser is not listed twice."""
    if Path(argv[0]).name == "flatpak":
        for word in reversed(argv):
            if "." in word and not word.startswith(("-", "@", "/")):
                return word.lower()
    # google-chrome and google-chrome-stable are the same program behind two names
    try:
        real = Path(shutil.which(argv[0]) or argv[0]).resolve()
    except (OSError, RuntimeError):
        real = Path(argv[0])
    return str(real).lower()


def _from_desktop_entry(path: Path) -> Browser | None:
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    try:
        parser.read(path, encoding="utf-8")
        entry = parser["Desktop Entry"]
    except (OSError, UnicodeDecodeError, configparser.Error, KeyError):
        return None
    if entry.get("Type") != "Application" or entry.get("Hidden", "").lower() == "true":
        return None
    if "WebBrowser" not in entry.get("Categories", "").split(";"):
        return None
    # Some system entries (network settings, support pages) claim the category without being
    # browsers. A real one also says it opens web addresses or pages.
    opens = entry.get("MimeType", "").split(";")
    if not {"x-scheme-handler/http", "x-scheme-handler/https", "text/html"} & set(opens):
        return None
    name, command = entry.get("Name", "").strip(), entry.get("Exec", "")
    try:
        words = [w for w in shlex.split(command) if not w.startswith("@@")]
    except ValueError:
        return None
    argv = tuple(w for w in (_FIELD_CODES.sub("", word) for word in words) if w)
    if not name or not argv or (shutil.which(argv[0]) is None):
        return None
    return Browser(name, f"desktop:{path.name}", argv)


def installed_browsers() -> list[Browser]:
    """Every browser that can be found: well-known commands and the desktop's own list."""
    found: dict[str, Browser] = {}
    for command, label in KNOWN:
        path = shutil.which(command)
        if path is not None:
            found.setdefault(_identity((path,)), Browser(label, path, (path,)))
    for folder in APPLICATION_FOLDERS:
        directory = Path(folder).expanduser()
        try:
            files = sorted(directory.glob("*.desktop"))
        except OSError:
            continue
        for file in files:
            entry = _from_desktop_entry(file)
            if entry is not None:
                found.setdefault(_identity(entry.argv), entry)
    return sorted(found.values(), key=lambda browser: browser.label.lower())


def command_for(key: str) -> list[str] | None:
    """The command that starts the browser with this key, if it is still there."""
    for browser in installed_browsers():
        if browser.key == key:
            return list(browser.argv)
    path = Path(key)
    if path.is_absolute() and path.is_file() and os.access(path, os.X_OK):
        return [str(path)]  # a program the person picked themselves
    return None


def preference_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "gankhi" / PREFERENCE_FILE


def remembered() -> str | None:
    """The remembered choice, only if it still works (or is the default)."""
    try:
        value = preference_path().read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if value == DEFAULT or (value and command_for(value) is not None):
        return value
    return None


def remember(choice: str) -> None:
    path = preference_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(choice + "\n", encoding="utf-8")
    except OSError:
        pass  # not remembering is harmless: it will simply ask again


def forget() -> None:
    """Remove the remembered choice, so the next start asks again."""
    preference_path().unlink(missing_ok=True)


def _run(command: list[str]) -> tuple[int, str]:
    try:
        done = subprocess.run(  # noqa: S603  (absolute path from which(), fixed arguments)
            command, capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL
        )
    except OSError:
        return 127, ""
    return done.returncode, done.stdout.strip()


def _rows(options: list[Browser]) -> list[tuple[str, str]]:
    words = _words()
    return [
        (words["default"], DEFAULT),
        *[(browser.label, browser.key) for browser in options],
        (words["other"], OTHER),
    ]


def _zenity(tool: str, options: list[Browser]) -> tuple[str, bool]:
    words = _words()
    code, out = _run(
        [
            tool, "--list", f"--title={words['title']}", f"--text={words['ask']}",
            f"--column={words['column']}", "--column=key", "--hide-column=2",
            "--print-column=2", "--width=420", "--height=420",
            f"--ok-label={words['open']}", f"--cancel-label={words['cancel']}",
            *[item for row in _rows(options) for item in row],
        ]
    )  # fmt: skip
    if code != 0 or not out:
        return (CANCELLED, False)
    if out == OTHER:
        code, out = _run(
            [tool, "--file-selection", f"--title={words['pick']}", "--filename=/usr/bin/"]
        )
        if code != 0 or not out:
            return (CANCELLED, False)
    ask_code, _ = _run(
        [
            tool, "--question", f"--title={words['title']}", f"--text={words['remember']}",
            f"--ok-label={words['yes']}", f"--cancel-label={words['no']}",
        ]
    )  # fmt: skip
    return (out, ask_code == 0)


def _kdialog(tool: str, options: list[Browser]) -> tuple[str, bool]:
    words = _words()
    code, out = _run(
        [
            tool, "--title", words["title"], "--menu", words["ask"],
            *[item for label, key in _rows(options) for item in (key, label)],
        ]
    )  # fmt: skip
    if code != 0 or not out:
        return (CANCELLED, False)
    if out == OTHER:
        code, out = _run([tool, "--title", words["pick"], "--getopenfilename", "/usr/bin/"])
        if code != 0 or not out:
            return (CANCELLED, False)
    ask_code, _ = _run([tool, "--title", words["title"], "--yesno", words["remember"]])
    return (out, ask_code == 0)


def choose(force_ask: bool = False) -> str:
    """Return a browser key, ``DEFAULT`` (use the system's) or ``CANCELLED``."""
    if os.environ.get("BROWSER") and not force_ask:
        return DEFAULT  # the person chose already, in the way Linux programs usually do
    if not force_ask:
        saved = remembered()
        if saved is not None:
            return saved
    options = installed_browsers()
    if len(options) < 2 and not force_ask:
        return DEFAULT
    for tool_name, ask in (("zenity", _zenity), ("kdialog", _kdialog)):
        tool = shutil.which(tool_name)
        if tool is None:
            continue
        choice, keep = ask(tool, options)
        if choice not in (DEFAULT, CANCELLED) and command_for(choice) is None:
            choice = DEFAULT  # not something we can start: use the system's browser
        if keep and choice != CANCELLED:
            remember(choice)
        elif force_ask and choice != CANCELLED:
            forget()  # asking again and choosing "always ask" undoes a remembered choice
        return choice
    return DEFAULT
