"""The report: what the scan found, written as a PDF to read, keep or print.

Built on this computer from the scan result; nothing is sent anywhere. The summary uses
the same sentences the assistant speaks, then adds the details in tables.
"""

from __future__ import annotations

from ganki import narration, paging
from ganki.pdfwriter import Pdf
from ganki.service import ScanResult
from ganki.tools import Tool
from ganki.web import i18n

MAX_ROWS = 40
FONT_SIZE = 12.0


def _priority(tool: Tool, lang: str) -> str:
    return i18n.translate(lang, tool.top_priority) if tool.top_priority else "-"


def _action(tool: Tool, lang: str) -> str:
    say = lambda key, **kw: i18n.translate(lang, key, **kw)  # noqa: E731
    if tool.end_of_support:
        return say("report_act_eol")
    if tool.fixed_in:
        return say("report_act_fix", version=tool.fixed_in)
    return say("report_act_nofix")


def build_report(result: ScanResult, lang: str, generated: str) -> bytes:
    def say(key: str, **values: object) -> str:
        return i18n.translate(lang, key, **values)

    pdf = Pdf(say("report_title"), footer="Ganki", size=FONT_SIZE)
    pdf.heading(say("report_title"), size=20)
    pdf.paragraph(f"{say('report_generated', date=generated)} {say('report_private')}")
    pdf.rule()

    pdf.heading(say("report_summary"))
    for segment in narration.build(result, lang):
        if not segment.framing:
            pdf.paragraph(segment.text)

    system = result.system
    if system is not None:
        pdf.heading(say("report_computer"))
        pdf.table(
            [say("report_item"), say("report_value")],
            [
                [say("lbl_system"), f"{system.os_name} ({system.architecture})"],
                ["Kernel", system.kernel],
                [say("lbl_user"), system.user],
                [
                    say("disk"),
                    say(
                        "report_disk",
                        percent=system.disk_percent,
                        used=paging.human_size(system.disk_used // 1024),
                        free=paging.human_size(system.disk_free // 1024),
                    ),
                ],
                [
                    say("ram"),
                    say(
                        "report_ram",
                        percent=system.ram_percent,
                        used=paging.human_size(system.ram_used_kib),
                        total=paging.human_size(system.ram_total_kib),
                    ),
                ],
            ],
            [0.28, 0.72],
        )

    programs = [t for t in result.tools if t.is_program]
    vulnerable = [t for t in programs if t.state == "vulnerable"]
    outdated = [t for t in programs if t.state == "outdated"]
    headers = [say("report_program"), say("report_version"), say("report_priority")]

    pdf.heading(say("report_security"))
    if vulnerable:
        pdf.table(
            [*headers, say("report_action")],
            [
                [t.name, t.version, _priority(t, lang), _action(t, lang)]
                for t in vulnerable[:MAX_ROWS]
            ],
            [0.24, 0.16, 0.12, 0.48],
        )
        if len(vulnerable) > MAX_ROWS:
            pdf.paragraph(say("report_more", n=len(vulnerable) - MAX_ROWS))
    else:
        pdf.paragraph(say("report_none"))

    pdf.heading(say("report_outdated"))
    if outdated:
        pdf.table(
            [say("report_program"), say("report_version"), say("report_new_version")],
            [[t.name, t.version, t.update_to or "-"] for t in outdated[:MAX_ROWS]],
            [0.4, 0.3, 0.3],
        )
        if len(outdated) > MAX_ROWS:
            pdf.paragraph(say("report_more", n=len(outdated) - MAX_ROWS))
    else:
        pdf.paragraph(say("report_none"))

    libraries = [t for t in result.tools if not t.is_program and t.state == "vulnerable"]
    pdf.heading(say("report_libs"))
    if libraries:
        pdf.table(
            [
                say("report_package"),
                say("report_version"),
                say("report_priority"),
                say("report_action"),
            ],
            [
                [t.name, t.version, _priority(t, lang), _action(t, lang)]
                for t in libraries[:MAX_ROWS]
            ],
            [0.24, 0.16, 0.12, 0.48],
        )
        if len(libraries) > MAX_ROWS:
            pdf.paragraph(say("report_more", n=len(libraries) - MAX_ROWS))
    else:
        pdf.paragraph(say("report_none"))
    waiting = sum(1 for t in result.tools if not t.is_program and t.state == "outdated")
    if waiting:
        pdf.paragraph(say("report_libs_outdated", n=waiting))

    reclaim = result.reclaimable
    if reclaim.total_kib:
        pdf.heading(say("report_reclaim"))
        pdf.table(
            [say("report_item"), say("report_value")],
            [
                [say("reclaim_kernels"), paging.human_size(reclaim.old_kernel_kib)],
                [say("reclaim_cache"), paging.human_size(reclaim.apt_cache_kib)],
                [say("reclaim_orphans"), paging.human_size(reclaim.orphan_kib)],
                [say("report_total"), paging.human_size(reclaim.total_kib)],
            ],
            [0.6, 0.4],
        )
    pdf.paragraph(say("report_caution"), size=FONT_SIZE - 1)
    return pdf.build()
