"""Interface texts in Spanish and English."""

from __future__ import annotations

LANGUAGES = ("es", "en")
DEFAULT_LANGUAGE = "en"

TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "title": "Vulnerabilities and updates",
        "scanning": "Scanning this machine... this can take a minute.",
        "rescan": "Scan again",
        "error": "The scan could not finish. Details are in the terminal where Ganki runs.",
        "unsupported": "This system is not supported: vulnerability data covers Ubuntu releases.",
        "findings": "Findings",
        "cves": "Different CVEs",
        "fixable": "Fixed by updating",
        "no_fix": "No fix published",
        "pending": "Updates pending",
        "feed": "Vulnerability data",
        "feed_new": "downloaded just now",
        "feed_cached": "already up to date",
        "scanned": "Last scan",
        "programs_fix": "Programs you can fix",
        "programs_fix_hint": "Updating these removes the listed vulnerabilities.",
        "programs_nofix": "Programs with no fix published",
        "programs_nofix_hint": "Nothing to do yet: the distribution has not released a fix.",
        "kernel": "Running kernel",
        "kernel_hint": "The kernel in use right now. Updating it needs a restart.",
        "old_kernels": "Old kernels (installed, not running)",
        "old_kernels_hint": "Not a risk while a newer kernel runs. Remove them to clear these.",
        "snaps": "Not checked: the real app is a snap",
        "col_package": "Package",
        "col_installed": "Installed",
        "col_fixed_in": "Fixed in",
        "col_cves": "CVEs",
        "col_priority": "Worst priority",
        "col_fixable": "Fixable",
        "col_nofix": "No fix",
        "more": "and {n} more",
        "none": "Nothing here.",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "negligible": "negligible",
        "unknown": "unknown",
        "nav_security": "Vulnerabilities",
        "nav_inventory": "Programs",
        "inv_title": "Installed programs",
        "inv_search": "Search by name or description",
        "inv_sort": "Sort by",
        "sort_size": "Size",
        "sort_name": "Name",
        "sort_date": "Install date",
        "inv_manual_only": "Only ones I installed",
        "inv_apply": "Apply",
        "inv_total": "{n} programs, {size} in total",
        "col_version": "Version",
        "col_size": "Size",
        "col_date": "Installed or updated",
        "col_origin": "Origin",
        "origin_manual": "installed by you",
        "origin_auto": "dependency",
        "prev": "Previous",
        "next": "Next",
        "page_of": "Page {n} of {total}",
    },
    "es": {
        "title": "Vulnerabilidades y actualizaciones",
        "scanning": "Analizando esta máquina... puede tardar un minuto.",
        "rescan": "Analizar de nuevo",
        "error": "El análisis no pudo terminar. Los detalles están en la terminal de Ganki.",
        "unsupported": "Este sistema no es compatible: los datos cubren versiones de Ubuntu.",
        "findings": "Hallazgos",
        "cves": "CVEs distintos",
        "fixable": "Se arreglan actualizando",
        "no_fix": "Sin arreglo publicado",
        "pending": "Actualizaciones pendientes",
        "feed": "Datos de vulnerabilidades",
        "feed_new": "descargados recién",
        "feed_cached": "ya estaban al día",
        "scanned": "Último análisis",
        "programs_fix": "Programas que podés arreglar",
        "programs_fix_hint": "Actualizarlos elimina las vulnerabilidades listadas.",
        "programs_nofix": "Programas sin arreglo publicado",
        "programs_nofix_hint": "Nada para hacer todavía: la distribución no publicó un arreglo.",
        "kernel": "Kernel en uso",
        "kernel_hint": "El kernel que se está usando ahora. Actualizarlo requiere reiniciar.",
        "old_kernels": "Kernels viejos (instalados, sin usar)",
        "old_kernels_hint": "No son un riesgo mientras corra uno más nuevo. Quitarlos los borra.",
        "snaps": "No revisados: la aplicación real es un snap",
        "col_package": "Paquete",
        "col_installed": "Instalado",
        "col_fixed_in": "Arreglado en",
        "col_cves": "CVEs",
        "col_priority": "Peor prioridad",
        "col_fixable": "Arreglables",
        "col_nofix": "Sin arreglo",
        "more": "y {n} más",
        "none": "Nada por acá.",
        "critical": "crítica",
        "high": "alta",
        "medium": "media",
        "low": "baja",
        "negligible": "despreciable",
        "unknown": "desconocida",
        "nav_security": "Vulnerabilidades",
        "nav_inventory": "Programas",
        "inv_title": "Programas instalados",
        "inv_search": "Buscar por nombre o descripción",
        "inv_sort": "Ordenar por",
        "sort_size": "Tamaño",
        "sort_name": "Nombre",
        "sort_date": "Fecha de instalación",
        "inv_manual_only": "Solo los que instalé yo",
        "inv_apply": "Aplicar",
        "inv_total": "{n} programas, {size} en total",
        "col_version": "Versión",
        "col_size": "Tamaño",
        "col_date": "Instalado o actualizado",
        "col_origin": "Origen",
        "origin_manual": "instalado por vos",
        "origin_auto": "dependencia",
        "prev": "Anterior",
        "next": "Siguiente",
        "page_of": "Página {n} de {total}",
    },
}


def pick_language(cookie: str | None, accept_language: str | None) -> str:
    """Language from the saved choice, else the browser's preference, else the default."""
    if cookie in LANGUAGES:
        return str(cookie)
    for part in (accept_language or "").split(","):
        code = part.split(";")[0].strip().lower()[:2]
        if code in LANGUAGES:
            return code
    return DEFAULT_LANGUAGE


def translate(lang: str, key: str, **values: object) -> str:
    """Text for ``key``; falls back to English, then to the key itself."""
    table = TEXTS.get(lang, TEXTS[DEFAULT_LANGUAGE])
    text = table.get(key) or TEXTS[DEFAULT_LANGUAGE].get(key, key)
    return text.format(**values) if values else text
