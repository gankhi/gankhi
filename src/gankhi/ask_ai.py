"""What Gankhi cannot check, and a question the person can paste into an AI of their choice.

Gankhi compares against Ubuntu's list of notices, so programs that come from somewhere else (another
apt repository, a ``.deb`` installed by hand, snap, flatpak) are not checked. This module lists them
and builds the text to copy. Nothing is sent anywhere: the person decides whether to paste it.
Only names, versions and where each one comes from go in the text: no user name, no host name.
"""

from __future__ import annotations

from dataclasses import dataclass

from gankhi.collectors.origins import LOCAL
from gankhi.service import ScanResult

MAX_LISTED = 100  # a longer list makes a text too long to paste anywhere


@dataclass(frozen=True)
class Unchecked:
    name: str
    version: str
    how: str  # "apt" | "deb" | "snap" | "flatpak"
    source: str = ""  # the repository, the publisher or the remote


def _clean(text: str) -> str:
    """One line, no control characters, short: these words end up inside a text for an AI."""
    return " ".join(str(text).split())[:60]


def unchecked_items(result: ScanResult) -> list[Unchecked]:
    """Programs and apps Gankhi cannot compare with any list, in a stable order."""
    items = [
        Unchecked(
            _clean(t.name),
            _clean(t.version),
            "deb" if t.origin == LOCAL else "apt",
            "" if t.origin == LOCAL else _clean(t.origin),
        )
        for t in result.tools
        if t.is_program and t.origin
    ]
    items += [
        Unchecked(_clean(a.name), _clean(a.version), a.tool, _clean(a.source))
        for a in result.sandboxed
    ]
    return sorted(items, key=lambda i: (i.how, i.name.lower()))


_TEXT = {
    "en": {
        "how": {
            "apt": "apt, repository {source}",
            "deb": "installed from a .deb file",
            "snap": "snap, publisher {source}",
            "flatpak": "flatpak, remote {source}",
        },
        "intro": (
            "I use {os}. I want to know if these programs have known security vulnerabilities "
            "in the versions I have installed. A local tool could not check them because they "
            "do not come from Ubuntu's own archive."
        ),
        "more": "...and {n} more that are not listed here.",
        "ask": (
            "Answer with a table, one row per program, with these columns: Program | Version | "
            "Known vulnerabilities (CVE numbers, each with a link to the official source: "
            "vendor advisory, OSV.dev or NVD) | Fixed in | Command to update.\n"
            '- In "Command to update", give the exact command for the way I installed it '
            "(shown in brackets: apt repository, snap, flatpak or .deb file) and tell me to read "
            "it before running it.\n"
            '- If you cannot verify something, write "not verified". Do not make anything up '
            "and do not guess version numbers."
        ),
    },
    "es": {
        "how": {
            "apt": "apt, repositorio {source}",
            "deb": "instalado desde un archivo .deb",
            "snap": "snap, publicado por {source}",
            "flatpak": "flatpak, origen {source}",
        },
        "intro": (
            "Uso {os}. Quiero saber si estos programas tienen vulnerabilidades de seguridad "
            "conocidas en las versiones que tengo instaladas. Una herramienta local no pudo "
            "revisarlos porque no vienen del archivo propio de Ubuntu."
        ),
        "more": "...y {n} más que no se listan acá.",
        "ask": (
            "Respondé con una tabla, una fila por programa, con estas columnas: Programa | "
            "Versión | Vulnerabilidades conocidas (números CVE, cada uno con un enlace a la "
            "fuente oficial: aviso del fabricante, OSV.dev o NVD) | Se arregla en | Comando "
            "para actualizar.\n"
            '- En "Comando para actualizar", dame el comando exacto para la forma en que lo '
            "instalé (figura entre paréntesis: repositorio de apt, snap, flatpak o archivo .deb) "
            "y decime que lo lea antes de ejecutarlo.\n"
            '- Si no podés verificar algo, escribí "no verificado". No inventes nada y no '
            "adivines números de versión."
        ),
    },
}


def how_text(item: Unchecked, lang: str) -> str:
    texts = _TEXT.get(lang, _TEXT["en"])["how"]
    return texts[item.how].format(source=item.source or "?").replace(" ?", "").replace(", ?", "")


def build_prompt(items: list[Unchecked], os_name: str, lang: str) -> str:
    """The text to copy: the question, the list and how to answer."""
    texts = _TEXT.get(lang, _TEXT["en"])
    lines = [f"- {i.name} {i.version} ({how_text(i, lang)})" for i in items[:MAX_LISTED]]
    if len(items) > MAX_LISTED:
        lines.append(texts["more"].format(n=len(items) - MAX_LISTED))
    intro = texts["intro"].format(os=os_name or "Linux")
    return intro + "\n\n" + "\n".join(lines) + "\n\n" + texts["ask"]
