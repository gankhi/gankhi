"""Turn the scan into a spoken explanation, with fixed rules and no AI model.

Everything is computed from numbers Ganki already has, on this machine. The text
comes from ``i18n`` templates; it is shown as text.
Each segment is tied to a part of the page (``section``) so the page can highlight it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ganki import families
from ganki.service import ScanResult
from ganki.web import i18n

DISK_TIGHT, DISK_BUSY = 85, 70
RAM_HIGH, RAM_BUSY = 85, 60


@dataclass(frozen=True)
class Segment:
    section: str  # matches a data-explain attribute on the page
    text: str
    tone: str = ""  # bad / warn / ok: how the report colours it (never spoken)
    framing: bool = False  # intro/outro: read in the tour, skipped when hovering a section


def thousands(number: int, lang: str) -> str:
    """``108995`` -> ``108.995`` (``108,995`` in English)."""
    text = f"{number:,}"
    return text.replace(",", ".") if lang == "es" else text


def spoken_size(kib: int, lang: str) -> str:
    """``2097152`` -> ``2 gigas`` (written the way a person would say it)."""
    units = (
        ("gigas", "gigabytes", 1024**2),
        ("megas", "megabytes", 1024),
        ("kilos", "kilobytes", 1),
    )
    for es, en, factor in units:
        if kib >= factor or factor == 1:
            value = kib / factor
            number = f"{value:.1f}".rstrip("0").rstrip(".")
            if lang == "es":
                number = number.replace(".", ",")
            return f"{number} {es if lang == 'es' else en}"
    return "0"


def _spoken_duration(seconds: int, lang: str) -> str:
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    if lang == "es":
        return f"{days} días y {hours} horas" if days else f"{hours} horas y {rest // 60} minutos"
    return f"{days} days and {hours} hours" if days else f"{hours} hours and {rest // 60} minutes"


def scanning_message(lang: str) -> str:
    return i18n.translate(lang, "say_scanning")


def build(result: ScanResult, lang: str) -> list[Segment]:
    """The explanation, in the order it is spoken: a short summary, then what is most urgent."""

    def say(key: str, **values: object) -> str:
        return i18n.translate(lang, key, **values)

    segments = [Segment("system", say("say_intro"), framing=True)]
    system = result.system
    disk_full = system is not None and system.disk_percent >= DISK_BUSY
    if system is not None:
        free = spoken_size(system.disk_free // 1024, lang)
        level = (
            "tight"
            if system.disk_percent >= DISK_TIGHT
            else "busy"
            if system.disk_percent >= DISK_BUSY
            else "ok"
        )
        tones = {"tight": "bad", "busy": "warn", "ok": "ok"}
        segments.append(
            Segment(
                "disk",
                say(f"say_disk_{level}", percent=system.disk_percent, free=free),
                tones[level],
            )
        )
        level = (
            "high"
            if system.ram_percent >= RAM_HIGH
            else "busy"
            if system.ram_percent >= RAM_BUSY
            else "ok"
        )
        segments.append(
            Segment(
                "ram",
                say(
                    f"say_ram_{level}",
                    percent=system.ram_percent,
                    used=spoken_size(system.ram_used_kib, lang),
                    total=spoken_size(system.ram_total_kib, lang),
                ),
                {"high": "bad", "busy": "warn", "ok": "ok"}[level],
            )
        )

    reclaim = result.reclaimable
    text = ""
    if reclaim.total_kib:
        text = say("say_reclaim_brief", total=spoken_size(reclaim.total_kib, lang))
    if result.pending_updates:
        text = (text + " " + say("say_reclaim_updates", n=result.pending_updates)).strip()
    if text and disk_full and reclaim.total_kib and result.pending_updates:
        text += " " + say("say_clean_first")
    if text:
        segments.append(Segment("reclaim", text))

    programs = [t for t in result.tools if t.is_program]
    vulnerable = [t for t in programs if t.state == "vulnerable"]
    outdated = [t for t in programs if t.state == "outdated"]
    libraries, old_kernels = vulnerable_libraries(result)
    everything = vulnerable + libraries
    if vulnerable:
        summary = say("say_tools_summary", vulnerable=len(vulnerable), outdated=len(outdated))
    elif libraries:
        summary = say("say_tools_programs_ok", outdated=len(outdated))
    elif outdated:
        summary = say("say_tools_outdated_only", outdated=len(outdated))
    else:
        summary = say("say_tools_clean")
    serious_any = any(t.top_priority in SERIOUS for t in everything)
    tone = "bad" if serious_any else "warn" if everything else "ok"
    segments.append(Segment("tools", summary, tone))
    if libraries:
        serious = sum(1 for t in libraries if t.top_priority in SERIOUS)
        key = "say_tools_libs_serious" if serious else "say_tools_libs_mild"
        segments.append(
            Segment(
                "tools", say(key, n=len(libraries), serious=serious), "bad" if serious else "warn"
            )
        )
    if old_kernels:
        segments.append(Segment("tools", say("say_tools_old_kernels", n=len(old_kernels))))
    if everything:
        segments.append(Segment("tools", say("say_tools_urgent")))
    for text in _advice(_most_urgent(everything), say):
        segments.append(Segment("tools", text, "bad" if serious_any else "warn"))

    segments.extend(_external_segments(result, say))
    segments.extend(_sandboxed_segments(result, say))

    if result.download_groups:
        total_bytes = sum(g.size_bytes for g in result.download_groups)
        files = sum(g.files for g in result.download_groups)
        biggest = result.download_groups[0]
        segments.append(
            Segment(
                "downloads",
                say(
                    "say_downloads",
                    files=thousands(files, lang),
                    size=spoken_size(total_bytes // 1024, lang),
                    kind=say(f"dl_{biggest.key}").split(" (")[0].lower(),
                ),
            )
        )

    if system is not None and system.reboot_required:
        segments.append(Segment("system", say("say_reboot"), "warn"))
    segments.append(Segment("tools", say("say_outro"), framing=True))
    return segments


MOST_URGENT = 3


def _external_segments(result: ScanResult, say) -> list[Segment]:  # type: ignore[no-untyped-def]
    """Python and npm packages: how many, how many have notices, which are most urgent."""
    segments: list[Segment] = []
    bad = [t for t in result.external if t.vulnerable]
    if result.external and not bad:
        segments.append(Segment("external", say("say_external_ok", n=len(result.external)), "ok"))
    elif bad:
        serious = sum(1 for t in bad if t.top_priority in SERIOUS)
        names = _names(bad, say("say_and_more"), "")
        text = say(
            "say_external_bad",
            n=len(result.external),
            bad=len(bad),
            serious=serious,
            names=names,
        )
        segments.append(Segment("external", text, "bad" if serious else "warn"))
        malware = [t for t in bad if t.malicious]
        if malware:
            segments.append(
                Segment(
                    "external",
                    say("say_external_malware", names=_names(malware, say("say_and_more"), "")),
                    "bad",
                )
            )
    if result.external_failed:
        text = say("say_external_failed", tools=", ".join(result.external_failed))
        segments.append(Segment("external", text, "warn"))
    return segments


def _sandboxed_segments(result: ScanResult, say) -> list[Segment]:  # type: ignore[no-untyped-def]
    """Snap and flatpak apps: only counted, because they carry their own libraries."""
    if not result.sandboxed:
        return []
    snaps = sum(1 for a in result.sandboxed if a.tool == "snap")
    flatpaks = len(result.sandboxed) - snaps
    return [Segment("external", say("say_sandboxed", snaps=snaps, flatpaks=flatpaks))]


def vulnerable_libraries(result: ScanResult) -> tuple[list, list]:  # type: ignore[type-arg]
    """Libraries and system packages with notices, and apart from them the old kernels.

    Old kernels are not running, so their notices are solved by removing them, not by
    updating; they must not take the place of what is really urgent.
    """
    old = set(result.reclaimable.old_kernel_packages)
    found = [t for t in result.tools if not t.is_program and t.state == "vulnerable"]
    return [t for t in found if t.name not in old], [t for t in found if t.name in old]


SERIOUS = ("critical", "high")


def _most_urgent(vulnerable: list) -> list:  # type: ignore[type-arg]
    """The few programs worth naming: highest Ubuntu priority first, then the ones with a fix.

    The pieces of one kernel (image, modules, headers...) count as a single entry.
    """
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4}
    ranked = sorted(
        vulnerable,
        key=lambda t: (order.get(t.top_priority, 5), 0 if t.fixed_in else 1, -t.cve_count, t.name),
    )
    chosen: list = []  # type: ignore[type-arg]
    kernel_seen = False
    for tool in ranked:
        if not tool.fixed_in and tool.top_priority in ("low", "negligible"):
            continue  # nothing to do about it and little risk: not worth a spoken warning
        if families.is_kernel(tool.name):
            if kernel_seen:
                continue
            kernel_seen = True
        chosen.append(tool)
    return chosen[:MOST_URGENT]


_VIRTUAL_MACHINES = re.compile(r"virtualbox|qemu|vmware|virt-manager|gnome-boxes")
MAX_NAMES = 3


def _names(tools: list, lang_and: str, kernel: str) -> str:  # type: ignore[type-arg]
    names = [kernel if families.is_kernel(t.name) else t.name for t in tools[:MAX_NAMES]]
    extra = len(tools) - len(names)
    text = ", ".join(names)
    return f"{text} {lang_and}" if extra > 0 else text


def _advice(vulnerable: list, say) -> list[str]:  # type: ignore[no-untyped-def]
    """What to do about each kind of problem. Plain rules, evaluated on this machine's data."""
    texts: list[str] = []
    fixable = [t for t in vulnerable if t.fixed_in and not t.end_of_support]
    expired = [t for t in vulnerable if t.end_of_support]
    waiting = [t for t in vulnerable if not t.fixed_in and not t.end_of_support]
    machines = [t for t in waiting if _VIRTUAL_MACHINES.search(t.name)]
    waiting = [t for t in waiting if t not in machines]
    more = say("say_and_more")
    kernel = say("say_kernel_name")

    if fixable:
        texts.append(say("say_advice_update", names=_names(fixable, more, kernel)))
        if any(families.is_kernel(t.name) for t in fixable):
            texts.append(say("say_advice_restart"))
    if expired:
        texts.append(say("say_advice_expired", names=_names(expired, more, kernel)))
    if machines:
        texts.append(say("say_advice_vm", names=_names(machines, more, kernel)))
    if waiting:
        texts.append(say("say_advice_waiting", names=_names(waiting, more, kernel)))
    return texts
