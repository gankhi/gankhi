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
            "Answer ONLY with a table of exactly 3 columns, one row per program, in the same "
            "order as my list, and nothing else:\n"
            "| Program | Vulnerable in my version? | Command to update |\n"
            '- "Vulnerable in my version?": write only "Yes", "No" or "Not verified". If "Yes", '
            "add the CVE numbers, each with a link to the official source.\n"
            '- "Command to update": the exact command for the way I installed it (shown in '
            "brackets).\n"
            "- After the table, add the command to remove the program ONLY for the ones marked "
            '"Yes", one line each.\n'
            "- Search the web for each program (OSV.dev, NVD and the vendor's security page) "
            "before answering. Do not answer from memory.\n"
            '- If I installed it from a .deb file, in "Command to update" write the link to the '
            "vendor's download page instead of an apt command.\n"
            "- No introduction, no explanations, no notes, no advice, no headings, no "
            "paragraphs. Keep every cell short.\n"
            '- If you cannot verify something, write "Not verified". Do not make anything up '
            "and do not guess version numbers.\n"
            "- Last line, exactly: Read each command before running it."
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
            "Respondé SOLO con una tabla de exactamente 3 columnas, una fila por programa, en "
            "el mismo orden que mi lista, y nada más:\n"
            "| Programa | ¿Vulnerable en mi versión? | Comando para actualizar |\n"
            '- "¿Vulnerable en mi versión?": escribí solo "Sí", "No" o "No verificado". Si es '
            '"Sí", sumá los números CVE, cada uno con un enlace a la fuente oficial.\n'
            '- "Comando para actualizar": el comando exacto para la forma en que lo instalé '
            "(figura entre paréntesis).\n"
            "- Debajo de la tabla, poné el comando para eliminar el programa SOLO de los que "
            'marcaste "Sí", una línea cada uno.\n'
            "- Buscá en la web cada programa (OSV.dev, NVD y la página de seguridad del "
            "fabricante) antes de responder. No respondas de memoria.\n"
            '- Si lo instalé desde un archivo .deb, en "Comando para actualizar" poné el enlace '
            "a la página de descarga del fabricante en lugar de un comando de apt.\n"
            "- Sin introducción, sin explicaciones, sin notas, sin consejos, sin títulos, sin "
            "párrafos. Cada celda, corta.\n"
            '- Si no podés verificar algo, escribí "No verificado". No inventes nada y no '
            "adivines números de versión.\n"
            "- Última línea, exactamente: Leé cada comando antes de ejecutarlo."
        ),
    },
}


def how_text(item: Unchecked, lang: str) -> str:
    texts = _TEXT.get(lang, _TEXT["en"])["how"]
    return texts[item.how].format(source=item.source or "?").replace(" ?", "").replace(", ?", "")


def system_phrase(os_name: str, ecosystem: str, lang: str) -> str:
    """The system as the AI needs to know it: its own name and the Ubuntu it is built on.

    A derivative reports its own name and version ("Linux Lite 7.4"), which says nothing about
    the Ubuntu release the packages come from: that is what a command or a fixed version depends on.
    """
    base = (
        ecosystem.removeprefix("Ubuntu:").replace(":", " ")
        if ecosystem.startswith("Ubuntu:")
        else ""
    )
    name = os_name or "Linux"
    if not base or name.startswith("Ubuntu"):
        return name
    joiner = {"es": "basado en Ubuntu"}.get(lang, "based on Ubuntu")
    return f"{name} ({joiner} {base})"


def build_prompt(items: list[Unchecked], os_name: str, lang: str, ecosystem: str = "") -> str:
    """The text to copy: the question, the list and how to answer."""
    texts = _TEXT.get(lang, _TEXT["en"])
    lines = [f"- {i.name} {i.version} ({how_text(i, lang)})" for i in items[:MAX_LISTED]]
    if len(items) > MAX_LISTED:
        lines.append(texts["more"].format(n=len(items) - MAX_LISTED))
    intro = texts["intro"].format(os=system_phrase(os_name, ecosystem, lang))
    return intro + "\n\n" + "\n".join(lines) + "\n\n" + texts["ask"]
