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


clean = _clean  # the form in which names and versions are compared and marked


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
            "| Program and version | Vulnerable in my version? | Command to update |\n"
            '- "Vulnerable in my version?": write only "Yes", "Not reported yet" or '
            '"Not verified". "Yes" only if an advisory says my exact version is affected; add '
            "the CVE numbers, each with a direct link to the advisory (OSV.dev, NVD or the "
            'vendor), never a search-engine link. If you found nothing, do not write "No": '
            'write "Not reported yet".\n'
            '- "Command to update": the exact command for the way I installed it (shown in '
            "brackets).\n"
            "- Do not suggest removing, uninstalling or disabling anything: many of these are "
            "components other programs depend on. Do not add advice of any kind.\n"
            "- Write every link as the full plain URL (https://...), never shortened and never "
            "wrapped in a search or redirect address.\n"
            "- Search the web for each program by name and exact version, in: OSV.dev, NVD, GitHub "
            "Security Advisories, CISA's known exploited list, the Ubuntu and Debian security "
            "trackers and the vendor's own security page. Do not answer from memory.\n"
            '- Search each program one by one. Write "Not reported yet" only for a program you '
            'actually searched and found nothing for; for any you did not search, write "Not '
            'verified". Never fill the whole column with the same answer.\n'
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
            "| Programa y versión | ¿Vulnerable en mi versión? | Comando para actualizar |\n"
            '- "¿Vulnerable en mi versión?": escribí solo "Sí", "Aún no reportado" o '
            '"No verificado". "Sí" solo si un aviso dice que mi versión exacta está afectada; '
            "sumá los números CVE, cada uno con un enlace directo al aviso (OSV.dev, NVD o el "
            'fabricante), nunca un enlace de buscador. Si no encontraste nada, no escribas "No": '
            'escribí "Aún no reportado".\n'
            '- "Comando para actualizar": el comando exacto para la forma en que lo instalé '
            "(figura entre paréntesis).\n"
            "- No sugieras quitar, desinstalar ni desactivar nada: muchos de estos son "
            "componentes de los que dependen otros programas. No agregues consejos de ningún "
            "tipo.\n"
            "- Escribí cada enlace como la URL completa y sin adornos (https://...), nunca "
            "acortada ni envuelta en una dirección de búsqueda o de redirección.\n"
            "- Buscá en la web cada programa por nombre y versión exacta, en: OSV.dev, NVD, GitHub "
            "Security Advisories, la lista de vulnerabilidades explotadas de CISA, los "
            "seguimientos de seguridad de Ubuntu y Debian y la página de seguridad del "
            "fabricante. No respondas de memoria.\n"
            '- Buscá cada programa uno por uno. Escribí "Aún no reportado" solo si lo buscaste '
            'de verdad y no encontraste nada; si no lo buscaste, escribí "No verificado". Nunca '
            "llenes toda la columna con la misma respuesta.\n"
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


_PACKAGE_TEXT = {
    "en": {
        "intro": (
            "I have this package installed. I want to know if this exact version has known "
            "security vulnerabilities, and which is the latest version published."
        ),
        "ask": (
            "Answer ONLY with a table of exactly 3 columns, one row per package, and nothing "
            "else:\n"
            "| Package and version | Vulnerable in my version? | Latest published version |\n"
            '- "Vulnerable in my version?": write only "Yes", "Not reported yet" or "Not '
            'verified". "Yes" only if an advisory says my exact version is affected; add the CVE '
            "numbers, each with a direct link to the advisory (OSV.dev, GitHub Security "
            "Advisories, NVD or the maintainers), never a search-engine link. If you found "
            'nothing, do not write "No": write "Not reported yet".\n'
            '- "Latest published version": the version number, as the package registry shows it, '
            'with the full link to its page there. Add "(deprecated)" if the registry marks the '
            "package as deprecated or abandoned.\n"
            "- Search the web for the package by name and exact version, in: the package "
            "registry, OSV.dev, GitHub Security Advisories, NVD and the project's own security "
            "page. Do not answer from memory.\n"
            "- Write every link as the full plain URL (https://...), never shortened and never "
            "wrapped in a search or redirect address.\n"
            "- Do not suggest removing, updating or changing anything. No advice of any kind.\n"
            "- No introduction, no explanations, no notes, no headings, no paragraphs. Keep "
            "every cell short.\n"
            '- If you cannot verify something, write "Not verified". Do not make anything up '
            "and do not guess version numbers."
        ),
    },
    "es": {
        "intro": (
            "Tengo instalado este paquete. Quiero saber si esta versión exacta tiene "
            "vulnerabilidades de seguridad conocidas, y cuál es la última versión publicada."
        ),
        "ask": (
            "Respondé SOLO con una tabla de exactamente 3 columnas, una fila por paquete, y "
            "nada más:\n"
            "| Paquete y versión | ¿Vulnerable en mi versión? | Última versión publicada |\n"
            '- "¿Vulnerable en mi versión?": escribí solo "Sí", "Aún no reportado" o "No '
            'verificado". "Sí" solo si un aviso dice que mi versión exacta está afectada; sumá '
            "los números CVE, cada uno con un enlace directo al aviso (OSV.dev, GitHub Security "
            "Advisories, NVD o los mantenedores), nunca un enlace de buscador. Si no encontraste "
            'nada, no escribas "No": escribí "Aún no reportado".\n'
            '- "Última versión publicada": el número de versión, como lo muestra el registro '
            'del paquete, con el enlace completo a su página ahí. Sumá "(obsoleto)" si el '
            "registro marca el paquete como obsoleto (deprecated) o abandonado.\n"
            "- Buscá en la web el paquete por nombre y versión exacta, en: el registro del "
            "paquete, OSV.dev, GitHub Security Advisories, NVD y la página de seguridad del "
            "propio proyecto. No respondas de memoria.\n"
            "- Escribí cada enlace como la URL completa y sin adornos (https://...), nunca "
            "acortada ni envuelta en una dirección de búsqueda o de redirección.\n"
            "- No sugieras quitar, actualizar ni cambiar nada. Sin consejos de ningún tipo.\n"
            "- Sin introducción, sin explicaciones, sin notas, sin títulos, sin párrafos. Cada "
            "celda, corta.\n"
            '- Si no podés verificar algo, escribí "No verificado". No inventes nada y no '
            "adivines números de versión."
        ),
    },
}
_PACKAGE_KIND = {"pip": "Python (PyPI)", "npm": "Node (npm)"}


def build_package_prompt(name: str, version: str, tool: str, lang: str) -> str:
    """The text to copy for one Python or npm package: whether its version has known flaws and
    which version is the latest. It asks for no update or removal command: Gankhi has them."""
    texts = _PACKAGE_TEXT.get(lang, _PACKAGE_TEXT["en"])
    kind = _PACKAGE_KIND.get(tool, tool)
    return (
        f"{texts['intro']}\n\n- {_clean(name)} {_clean(version)} ({_clean(kind)})\n\n{texts['ask']}"
    )
