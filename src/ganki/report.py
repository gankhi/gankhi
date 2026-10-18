"""The report: what the scan found, written as a PDF to read, keep or print.

Built on this computer from the scan result; nothing is sent anywhere. The summary uses
the same sentences the assistant speaks, then adds the details in tables.
"""

from __future__ import annotations

from ganki import families, narration, paging
from ganki.pdfwriter import Pdf
from ganki.service import ScanResult
from ganki.tools import Tool
from ganki.web import i18n

MAX_ROWS = 40
MINOR = ("low", "negligible")
FONT_SIZE = 12.0


def _priority(tool: Tool, lang: str) -> str:
    return i18n.translate(lang, tool.top_priority) if tool.top_priority else "-"


def _rows(groups: list[families.Group]) -> list[families.Group]:
    """All critical or high notices, then the rest up to MAX_ROWS (most urgent come first)."""
    serious = [g for g in groups if g.top_priority in narration.SERIOUS]
    rest = [g for g in groups if g.top_priority not in narration.SERIOUS]
    return serious + rest[: max(0, MAX_ROWS - len(serious))]


PRIORITY_TONE = {
    "critical": "bad",
    "high": "bad",
    "medium": "warn",
    "low": "ok",
    "negligible": "ok",
}


def _tones(groups: list[families.Group], columns: int, at: int) -> list[list[str]]:
    """Colour for the priority cell (column ``at``) of each row; the other cells stay plain."""
    out = []
    for item in groups:
        row = [""] * columns
        row[at] = PRIORITY_TONE.get(item.top_priority, "")
        out.append(row)
    return out


def _action(tool: Tool, lang: str) -> str:
    say = lambda key, **kw: i18n.translate(lang, key, **kw)  # noqa: E731
    if tool.end_of_support:
        return say("report_act_eol")
    if tool.fixed_in:
        return say("report_act_fix", version=tool.fixed_in)
    return say("report_act_nofix")


def _security_tables(pdf: Pdf, tools: list[Tool], first_header: str, lang: str) -> None:
    """Two tables: what updating fixes, and what has no fix yet (low risk ones only counted)."""

    def say(key: str, **values: object) -> str:
        return i18n.translate(lang, key, **values)

    fixable = [t for t in tools if t.fixed_in and not t.end_of_support]
    waiting = [t for t in tools if not (t.fixed_in and not t.end_of_support)]
    minor = [t for t in waiting if t.top_priority in MINOR and not t.end_of_support]
    waiting = [t for t in waiting if t not in minor]
    headers = [first_header, say("report_version"), say("report_priority"), say("report_action")]
    kernel = say("report_kernel_name")

    for title, part in ((say("report_fixable"), fixable), (say("report_nofix"), waiting)):
        if not part:
            continue
        groups = families.group(part)
        shown = _rows(groups)
        pdf.heading(title, size=13, keep_with=70)
        pdf.table(
            headers,
            [
                [
                    _label(g, kernel, say("report_components")),
                    g.version or say("report_versions"),
                    _priority(g.top, lang),
                    _action(g.top, lang),
                ]
                for g in shown
            ],
            [0.30, 0.22, 0.16, 0.32],
            _tones(shown, 4, 2),
        )
        if len(shown) < len(groups):
            hidden = sum(g.count for g in groups) - sum(g.count for g in shown)
            pdf.paragraph(say("report_more", n=hidden))
    if minor:
        pdf.paragraph(say("report_minor", n=len(minor)))


def _label(item: families.Group, kernel: str, components: str) -> str:
    name = item.label(kernel)
    if item.count == 1:
        return name
    listed = item.members()
    return f"{name} ({components.format(n=item.count)})" + (f": {listed}" if listed else "")


def _external_section(pdf: Pdf, result: ScanResult, lang: str) -> None:
    """Python and npm packages that have notices (the rest are only counted in the summary)."""

    def say(key: str, **values: object) -> str:
        return i18n.translate(lang, key, **values)

    bad = [t for t in result.external if t.vulnerable]
    if not (bad or result.external_failed):
        return
    pdf.heading(say("report_external"))
    if bad:
        rows, tones = [], []
        for tool in bad[:MAX_ROWS]:
            if tool.malicious:
                action = say("ext_malware")
            elif tool.fixed_in:
                action = say("ext_fix", version=tool.fixed_in, tool=tool.tool)
            else:
                action = say("ext_nofix")
            priority = say(tool.top_priority) if tool.top_priority else "-"
            rows.append([tool.name, tool.version, priority, action])
            tones.append(["", "", PRIORITY_TONE.get(tool.top_priority, ""), ""])
        pdf.table(
            [
                say("ext_col_package"),
                say("report_version"),
                say("report_priority"),
                say("report_action"),
            ],
            rows,
            [0.26, 0.14, 0.16, 0.44],
            tones,
        )
        if len(bad) > MAX_ROWS:
            pdf.paragraph(say("report_more", n=len(bad) - MAX_ROWS))
    if result.external_failed:
        pdf.paragraph(say("ext_failed", tools=", ".join(result.external_failed)), tone="warn")


def build_report(result: ScanResult, lang: str, generated: str) -> bytes:
    def say(key: str, **values: object) -> str:
        return i18n.translate(lang, key, **values)

    pdf = Pdf(say("report_title"), footer="Ganki", size=FONT_SIZE)
    pdf.heading(say("report_title"), size=20)
    pdf.paragraph(f"{say('report_generated', date=generated)} {say('report_private')}")
    pdf.rule()

    pdf.heading(say("report_summary"))
    pdf.paragraph(say("report_legend"), size=FONT_SIZE - 1)
    for segment in narration.build(result, lang):
        if not segment.framing:
            pdf.paragraph(segment.text, tone=segment.tone)

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

    pdf.heading(say("report_security"))
    if vulnerable:
        _security_tables(pdf, vulnerable, say("report_program"), lang)
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

    libraries, old_kernels = narration.vulnerable_libraries(result)
    pdf.heading(say("report_libs"))
    if libraries:
        _security_tables(pdf, libraries, say("report_package"), lang)
    else:
        pdf.paragraph(say("report_none"))
    if old_kernels:
        pdf.paragraph(say("say_tools_old_kernels", n=len(old_kernels)))
    waiting = sum(1 for t in result.tools if not t.is_program and t.state == "outdated")
    if waiting:
        pdf.paragraph(say("report_libs_outdated", n=waiting))

    _external_section(pdf, result, lang)

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
