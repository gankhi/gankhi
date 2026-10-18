"""Turn the scan into a spoken explanation, with fixed rules and no AI model.

Everything is computed from numbers Ganki already has, on this machine. The text
comes from ``i18n`` templates; the voice is the browser's own (local voices only).
Each segment is tied to a part of the page (``section``) so the page can highlight it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ganki.service import ScanResult
from ganki.web import i18n

DISK_TIGHT, DISK_BUSY = 85, 70
RAM_HIGH, RAM_BUSY = 85, 60


@dataclass(frozen=True)
class Segment:
    section: str  # matches a data-explain attribute on the page
    text: str
    framing: bool = False  # intro/outro: read in the tour, skipped when hovering a section


def spoken_size(kib: int, lang: str) -> str:
    """``2097152`` -> ``2 gigas`` (written the way a voice should read it)."""
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
    """The explanation, in the order it is spoken."""

    def say(key: str, **values: object) -> str:
        return i18n.translate(lang, key, **values)

    segments = [Segment("system", say("say_intro"), framing=True)]
    system = result.system
    if system is not None:
        text = say(
            "say_system",
            os=system.os_name,
            user=system.user,
            uptime=_spoken_duration(system.uptime_seconds, lang),
        )
        if system.reboot_required:
            text += " " + say("say_reboot")
        segments.append(Segment("system", text))

        free = spoken_size(system.disk_free // 1024, lang)
        level = (
            "tight"
            if system.disk_percent >= DISK_TIGHT
            else "busy"
            if system.disk_percent >= DISK_BUSY
            else "ok"
        )
        segments.append(
            Segment("disk", say(f"say_disk_{level}", percent=system.disk_percent, free=free))
        )

        level = (
            "high"
            if system.ram_percent >= RAM_HIGH
            else "busy"
            if system.ram_percent >= RAM_BUSY
            else "ok"
        )
        segments.append(Segment("ram", say(f"say_ram_{level}", percent=system.ram_percent)))

    programs = [t for t in result.tools if t.is_program]
    vulnerable = [t for t in programs if t.state == "vulnerable"]
    outdated = [t for t in programs if t.state == "outdated"]
    ok_count = len(programs) - len(vulnerable) - len(outdated)
    segments.append(
        Segment(
            "programs",
            say(
                "say_programs",
                total=len(programs),
                ok=ok_count,
                outdated=len(outdated),
                vulnerable=len(vulnerable),
            ),
        )
    )

    segments.append(Segment("tools", _vulnerability_text(result, vulnerable, say)))

    reclaim = result.reclaimable
    if reclaim.total_kib:
        parts = []
        if reclaim.old_kernel_kib:
            parts.append(say("say_reclaim_kernels", size=spoken_size(reclaim.old_kernel_kib, lang)))
        if reclaim.apt_cache_kib:
            parts.append(say("say_reclaim_cache", size=spoken_size(reclaim.apt_cache_kib, lang)))
        if reclaim.orphan_kib:
            parts.append(say("say_reclaim_orphans", size=spoken_size(reclaim.orphan_kib, lang)))
        segments.append(
            Segment(
                "reclaim",
                say(
                    "say_reclaim",
                    total=spoken_size(reclaim.total_kib, lang),
                    parts=", ".join(parts),
                ),
            )
        )

    if result.download_groups:
        total_bytes = sum(g.size_bytes for g in result.download_groups)
        files = sum(g.files for g in result.download_groups)
        biggest = result.download_groups[0]
        segments.append(
            Segment(
                "downloads",
                say(
                    "say_downloads",
                    files=files,
                    size=spoken_size(total_bytes // 1024, lang),
                    kind=say(f"dl_{biggest.key}").split(" (")[0].lower(),
                ),
            )
        )

    for text in _advice(vulnerable, say):
        segments.append(Segment("tools", text))

    segments.append(Segment("tools", say("say_outro"), framing=True))
    return segments


def _vulnerability_text(result: ScanResult, vulnerable: list, say) -> str:  # type: ignore[no-untyped-def]
    everything = sum(1 for t in result.tools if t.state == "vulnerable")
    hidden = everything - len(vulnerable)
    if not vulnerable:
        text = say("say_vuln_none")
    else:
        fixable = sum(1 for t in vulnerable if t.fixed_in)
        unfixable = len(vulnerable) - fixable
        text = say("say_vuln", n=len(vulnerable), fixable=fixable, unfixable=unfixable)
        if any(t.end_of_support for t in vulnerable):
            text += " " + say("say_vuln_eol")
    if hidden > 0:
        text += " " + say("say_vuln_hidden", n=hidden)
    return text


_VIRTUAL_MACHINES = re.compile(r"virtualbox|qemu|vmware|virt-manager|gnome-boxes")
MAX_NAMES = 3


def _names(tools: list, lang_and: str) -> str:  # type: ignore[type-arg]
    names = [t.name for t in tools[:MAX_NAMES]]
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

    if fixable:
        texts.append(say("say_advice_update", names=_names(fixable, more)))
    if expired:
        texts.append(say("say_advice_expired", names=_names(expired, more)))
    if machines:
        texts.append(say("say_advice_vm", names=_names(machines, more)))
    if waiting:
        texts.append(say("say_advice_waiting", names=_names(waiting, more)))
    return texts
