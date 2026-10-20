"""A small PDF writer for the report: text and tables only, in Helvetica (Arial's PDF twin).

Why not a library: the report is plain text, so a few dozen lines of PDF cover it and
Gankhi keeps no extra dependency. Only the standard Helvetica fonts are used, so no font
file is embedded; text is written in WinAnsi (Windows-1252), which covers Spanish and
English. Anything outside it is replaced by ``?``. Nothing here reads files or runs code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

PAGE_WIDTH, PAGE_HEIGHT = 595.28, 841.89  # A4, in points
MARGIN = 56.0
LEADING = 1.4  # line height as a multiple of the font size

# Glyph widths (1000 units per em) for characters 32..255 in Windows-1252.
_HELVETICA = (
    278,
    278,
    355,
    556,
    556,
    889,
    667,
    191,
    333,
    333,
    389,
    584,
    278,
    333,
    278,
    278,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    278,
    278,
    584,
    584,
    584,
    556,
    1015,
    667,
    667,
    722,
    722,
    667,
    611,
    778,
    722,
    278,
    500,
    667,
    556,
    833,
    722,
    778,
    667,
    778,
    722,
    667,
    611,
    722,
    667,
    944,
    667,
    667,
    611,
    278,
    278,
    278,
    469,
    556,
    333,
    556,
    556,
    500,
    556,
    556,
    278,
    556,
    556,
    222,
    222,
    500,
    222,
    833,
    556,
    556,
    556,
    556,
    333,
    500,
    278,
    556,
    500,
    722,
    500,
    500,
    500,
    334,
    260,
    334,
    584,
    761,
    556,
    0,
    222,
    556,
    333,
    1000,
    556,
    556,
    333,
    1000,
    667,
    333,
    1000,
    0,
    611,
    0,
    0,
    222,
    222,
    333,
    333,
    350,
    556,
    1000,
    333,
    1000,
    500,
    333,
    944,
    0,
    500,
    667,
    278,
    333,
    556,
    556,
    556,
    556,
    260,
    556,
    333,
    737,
    370,
    556,
    584,
    333,
    737,
    333,
    400,
    584,
    333,
    333,
    333,
    556,
    537,
    278,
    333,
    333,
    365,
    556,
    834,
    834,
    834,
    611,
    667,
    667,
    667,
    667,
    667,
    667,
    1000,
    722,
    667,
    667,
    667,
    667,
    278,
    278,
    278,
    278,
    722,
    722,
    778,
    778,
    778,
    778,
    778,
    584,
    778,
    722,
    722,
    722,
    722,
    667,
    667,
    611,
    556,
    556,
    556,
    556,
    556,
    556,
    889,
    500,
    556,
    556,
    556,
    556,
    278,
    278,
    278,
    278,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    584,
    611,
    556,
    556,
    556,
    556,
    500,
    556,
    500,
)
_HELVETICA_BOLD = (
    278,
    333,
    474,
    556,
    556,
    889,
    722,
    238,
    333,
    333,
    389,
    584,
    278,
    333,
    278,
    278,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    333,
    333,
    584,
    584,
    584,
    611,
    975,
    722,
    722,
    722,
    722,
    667,
    611,
    778,
    722,
    278,
    556,
    722,
    611,
    833,
    722,
    778,
    667,
    778,
    722,
    667,
    611,
    722,
    667,
    944,
    667,
    667,
    611,
    333,
    278,
    333,
    584,
    556,
    333,
    556,
    611,
    556,
    611,
    556,
    333,
    611,
    611,
    278,
    278,
    556,
    278,
    889,
    611,
    611,
    611,
    611,
    389,
    556,
    333,
    611,
    556,
    778,
    556,
    556,
    500,
    389,
    280,
    389,
    584,
    761,
    556,
    0,
    278,
    556,
    500,
    1000,
    556,
    556,
    333,
    1000,
    667,
    333,
    1000,
    0,
    611,
    0,
    0,
    278,
    278,
    500,
    500,
    350,
    556,
    1000,
    333,
    1000,
    556,
    333,
    944,
    0,
    500,
    667,
    278,
    333,
    556,
    556,
    556,
    556,
    280,
    556,
    333,
    737,
    370,
    556,
    584,
    333,
    737,
    333,
    400,
    584,
    333,
    333,
    333,
    611,
    556,
    278,
    333,
    333,
    365,
    556,
    834,
    834,
    834,
    611,
    722,
    722,
    722,
    722,
    722,
    722,
    1000,
    722,
    667,
    667,
    667,
    667,
    278,
    278,
    278,
    278,
    722,
    722,
    778,
    778,
    778,
    778,
    778,
    584,
    778,
    722,
    722,
    722,
    722,
    667,
    667,
    611,
    556,
    556,
    556,
    556,
    556,
    556,
    889,
    556,
    556,
    556,
    556,
    556,
    278,
    278,
    278,
    278,
    611,
    611,
    611,
    611,
    611,
    611,
    611,
    584,
    611,
    611,
    611,
    611,
    611,
    556,
    611,
    556,
)

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean(text: str) -> str:
    """Text that can be written in WinAnsi: control characters and unknown symbols removed."""
    text = _CONTROL.sub("", str(text)).replace("\t", " ")
    return text.encode("cp1252", errors="replace").decode("cp1252")


def text_width(text: str, size: float, bold: bool = False) -> float:
    widths = _HELVETICA_BOLD if bold else _HELVETICA
    total = 0
    for char in clean(text):
        code = ord(char.encode("cp1252", errors="replace")) if char else 63
        total += widths[code - 32] if 32 <= code <= 255 else 556
    return total * size / 1000


BREAK_AFTER = "-.+~:_/"


def wrap(text: str, size: float, width: float, bold: bool = False) -> list[str]:
    """Break ``text`` into lines that fit ``width`` (long words are cut)."""
    lines: list[str] = []
    for paragraph in clean(text).split("\n"):
        current = ""
        for word in paragraph.split(" "):
            candidate = f"{current} {word}".strip() if current else word
            if text_width(candidate, size, bold) <= width:
                current = candidate
                continue
            if current:
                lines.append(current)
            while text_width(word, size, bold) > width and len(word) > 1:
                cut = len(word)
                while cut > 1 and text_width(word[:cut], size, bold) > width:
                    cut -= 1
                # Prefer to break after a dash, dot or similar, as a person would.
                nice = max((word.rfind(c, 0, cut) for c in BREAK_AFTER), default=-1)
                if nice >= cut // 2:
                    cut = nice + 1
                lines.append(word[:cut])
                word = word[cut:]
            current = word
        lines.append(current)
    return lines


def _escape(text: str) -> bytes:
    raw = clean(text).encode("cp1252", errors="replace")
    return raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


# Print-friendly tones: (background, text). Meaning never depends on colour alone: the words stay.
TONES = {
    "bad": ((1.0, 0.86, 0.87), (0.62, 0.0, 0.12)),
    "warn": ((1.0, 0.93, 0.74), (0.5, 0.32, 0.0)),
    "ok": ((0.84, 0.95, 0.88), (0.04, 0.38, 0.2)),
}
ROW_TINT = {"bad": (1.0, 0.95, 0.95)}


def _rgb(color: tuple[float, float, float]) -> bytes:
    return b"%.3f %.3f %.3f" % color


@dataclass
class _Page:
    ops: list[bytes]


class Pdf:
    """Collects text page by page and writes the file with ``build()``."""

    def __init__(self, title: str, footer: str = "", size: float = 11.0) -> None:
        self.title = clean(title)
        self.footer = clean(footer)
        self.size = size
        self.width = PAGE_WIDTH - 2 * MARGIN
        self._pages = [_Page([])]
        self._y = PAGE_HEIGHT - MARGIN

    # -- layout -------------------------------------------------------------------------
    def _room(self, height: float) -> None:
        if self._y - height < MARGIN + 18:  # keep space for the footer
            self._pages.append(_Page([]))
            self._y = PAGE_HEIGHT - MARGIN

    def _line(self, x: float, text: str, size: float, bold: bool = False, tone: str = "") -> None:
        font = b"/F2" if bold else b"/F1"
        color = _rgb(TONES[tone][1]) + b" rg " if tone in TONES else b""
        op = color + b"BT " + font + b" %.1f Tf %.2f %.2f Td (" % (size, x, self._y - size)
        self._pages[-1].ops.append(op + _escape(text) + b") Tj ET" + (b" 0 g" if color else b""))

    def space(self, points: float) -> None:
        self._y -= points

    def heading(self, text: str, size: float = 15.0, keep_with: float = 0.0) -> None:
        """A heading; ``keep_with`` is the room that must follow it on the same page."""
        lines = wrap(text, size, self.width, bold=True)
        self._room(size * LEADING * len(lines) + 14 + keep_with)
        self._y -= 10
        for line in lines:
            self._line(MARGIN, line, size, bold=True)
            self._y -= size * LEADING
        self._y -= 2

    def paragraph(
        self, text: str, size: float | None = None, indent: float = 0.0, tone: str = ""
    ) -> None:
        """A paragraph; with a tone it gets a coloured bar at its side and bold text."""
        size = size or self.size
        lines = wrap(text, size, self.width - indent - (8 if tone in TONES else 0), bold=bool(tone))
        for line in lines:
            self._room(size * LEADING)
            if tone in TONES:
                bar = _rgb(TONES[tone][1])
                self._pages[-1].ops.append(
                    bar
                    + b" rg %.2f %.2f 3 %.2f re f 0 g"
                    % (MARGIN, self._y - size * LEADING, size * LEADING)
                )
            left = MARGIN + indent + (8 if tone in TONES else 0)
            self._line(left, line, size, bold=bool(tone), tone=tone)
            self._y -= size * LEADING
        self._y -= size * 0.5

    def rule(self) -> None:
        self._room(8)
        y = self._y - 3
        self._pages[-1].ops.append(
            b"0.75 G 0.6 w %.2f %.2f m %.2f %.2f l S 0 G" % (MARGIN, y, MARGIN + self.width, y)
        )
        self._y -= 8

    def table(
        self,
        headers: list[str],
        rows: list[list[str]],
        fractions: list[float],
        tones: list[list[str]] | None = None,
    ) -> None:
        """A table whose columns take the given fractions of the page width.

        ``tones`` (optional) gives each cell "bad", "warn", "ok" or "": coloured cells are
        written in bold, and a row with a "bad" cell gets a faint red band.
        """
        size = self.size - 1
        widths = [self.width * f for f in fractions]
        pad = 4.0

        def cells(values: list[str], bold: bool, marks: list[str] | None = None) -> None:
            marks = marks or [""] * len(values)
            wrapped = [
                wrap(v, size, w - 2 * pad, bold=bold or m in TONES)
                for v, w, m in zip(values, widths, marks, strict=True)
            ]
            height = max(len(w) for w in wrapped) * size * LEADING + 2 * pad
            self._room(height)
            if bold:
                self._pages[-1].ops.append(
                    b"0.92 g %.2f %.2f %.2f %.2f re f 0 g"
                    % (MARGIN, self._y - height, self.width, height)
                )
            if "bad" in marks:
                self._pages[-1].ops.append(
                    _rgb(ROW_TINT["bad"])
                    + b" rg %.2f %.2f %.2f %.2f re f 0 g"
                    % (MARGIN, self._y - height, self.width, height)
                )
            x = MARGIN
            for lines, width, mark in zip(wrapped, widths, marks, strict=True):
                top = self._y
                if mark in TONES:
                    self._pages[-1].ops.append(
                        _rgb(TONES[mark][0])
                        + b" rg %.2f %.2f %.2f %.2f re f 0 g" % (x, self._y - height, width, height)
                    )
                self._y -= pad
                for line in lines:
                    self._line(x + pad, line, size, bold=bold or mark in TONES, tone=mark)
                    self._y -= size * LEADING
                self._y = top
                x += width
            self._y -= height
            self._pages[-1].ops.append(
                b"0.85 G 0.4 w %.2f %.2f m %.2f %.2f l S 0 G"
                % (MARGIN, self._y, MARGIN + self.width, self._y)
            )

        cells(headers, True)
        for number, row in enumerate(rows):
            cells(row, False, tones[number] if tones else None)
        self._y -= 8

    # -- file ---------------------------------------------------------------------------
    def build(self) -> bytes:
        total = len(self._pages)
        objects: list[bytes] = [b"", b""]  # catalog and page tree are filled in below
        objects.append(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
        )
        objects.append(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold"
            b" /Encoding /WinAnsiEncoding >>"
        )
        page_ids = []
        for number, page in enumerate(self._pages, start=1):
            ops = list(page.ops)
            label = (
                f"{self.footer}  -  {number} / {total}" if self.footer else f"{number} / {total}"
            )
            ops.append(
                b"BT /F1 9 Tf 0.4 g %.2f %.2f Td (" % (MARGIN, MARGIN - 6)
                + _escape(label)
                + b") Tj ET 0 g"
            )
            stream = b"\n".join(ops)
            objects.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
            content_id = len(objects)
            objects.append(
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] "
                b"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>"
                % (PAGE_WIDTH, PAGE_HEIGHT, content_id)
            )
            page_ids.append(len(objects))
        objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
        kids = b" ".join(b"%d 0 R" % number for number in page_ids)
        objects[1] = b"<< /Type /Pages /Kids [" + kids + b"] /Count %d >>" % total
        objects.append(b"<< /Title (" + _escape(self.title) + b") /Producer (Gankhi) >>")
        info_id = len(objects)

        out = bytearray(b"%PDF-1.4\n")
        offsets = []
        for number, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
        for offset in offsets:
            out += b"%010d 00000 n \n" % offset
        out += b"trailer\n<< /Size %d /Root 1 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
            len(objects) + 1,
            info_id,
            xref,
        )
        return bytes(out)
