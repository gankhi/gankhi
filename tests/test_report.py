# ruff: noqa: S101
"""The PDF report and the writer behind it."""

import re

from ganki import pdfwriter, report
from ganki.pdfwriter import MARGIN, PAGE_WIDTH, Pdf
from test_web import BASE, build, login, make_result, wait_until_done


def objects_of(data: bytes) -> dict[int, int]:
    """Object number -> byte offset, read from the xref table."""
    start = int(re.search(rb"startxref\n(\d+)\n%%EOF", data).group(1))
    assert data[start : start + 4] == b"xref"
    count = int(re.match(rb"xref\n0 (\d+)\n", data[start:]).group(1))
    rows = data[start:].split(b"\n")[2 : 2 + count]
    return {n: int(row[:10]) for n, row in enumerate(rows) if n > 0}


def test_the_file_is_a_well_formed_pdf():
    pdf = Pdf("Title", "Ganki")
    pdf.heading("Hello")
    pdf.paragraph("Some text.")
    data = pdf.build()
    assert data.startswith(b"%PDF-1.4") and data.rstrip().endswith(b"%%EOF")
    for number, offset in objects_of(data).items():
        assert data[offset:].startswith(b"%d 0 obj" % number)


def test_long_text_goes_over_several_pages():
    pdf = Pdf("Title")
    for number in range(120):
        pdf.paragraph(f"Line {number}")
    data = pdf.build()
    assert data.count(b"/Type /Page ") >= 2
    assert b"/Count %d" % data.count(b"/Type /Page ") in data


def test_wrapped_lines_fit_the_text_area():
    width = PAGE_WIDTH - 2 * MARGIN
    for line in pdfwriter.wrap("palabra " * 80 + "x" * 300, 12, width):
        assert pdfwriter.text_width(line, 12) <= width + 0.01


def test_special_characters_cannot_break_the_file():
    pdf = Pdf("a (b) \\ c")
    pdf.paragraph("close ) open ( backslash \\ euro € emoji \U0001f600 tab\tend \x00 \x1b")
    data = pdf.build()
    assert b"\\)" in data and b"\\(" in data and b"\\\\" in data
    assert b"\x00" not in data.split(b"stream")[1] and b"\x1b" not in data
    for number, offset in objects_of(data).items():
        assert data[offset:].startswith(b"%d 0 obj" % number)


def test_accents_are_written_in_winansi():
    pdf = Pdf("t")
    pdf.paragraph("áéíóúñ¿¡")
    assert "áéíóúñ¿¡".encode("cp1252") in pdf.build()


def test_the_report_in_spanish_and_english():
    for lang, word in (("es", b"Resumen"), ("en", b"Summary")):
        data = report.build_report(make_result(), lang, "2026-10-18 10:00")
        assert data.startswith(b"%PDF") and word in data
        assert b"openssl" in data and b"virtualbox" in data


def test_the_report_uses_a_readable_size():
    data = report.build_report(make_result(), "en", "now")
    sizes = {float(s) for s in re.findall(rb"/F1 ([\d.]+) Tf", data)}
    assert 12.0 in sizes and 11.0 in sizes
    body = [s for s in sizes if s < 11]
    assert body == [9.0]  # only the page footer is smaller


def test_a_long_list_is_cut_and_says_so():
    result = make_result()
    template = next(t for t in result.tools if t.state == "vulnerable" and t.is_program)
    from dataclasses import replace

    many = [replace(template, name=f"prog{i}") for i in range(report.MAX_ROWS + 5)]
    result = replace(result, tools=many)
    data = report.build_report(result, "en", "now")
    assert b"prog0" in data and b"and 5 more" in data


def test_report_endpoint():
    client = login(build().test_client())
    assert client.get("/report.pdf", base_url=BASE).status_code == 404  # no scan yet
    client.get("/", base_url=BASE)
    wait_until_done(client)
    response = client.get("/report.pdf", base_url=BASE)
    assert response.status_code == 200 and response.mimetype == "application/pdf"
    assert response.data.startswith(b"%PDF")
    assert response.headers["Content-Disposition"].startswith("inline")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "X-Ganki-No-CSP" not in response.headers


def test_report_needs_the_session():
    assert build().test_client().get("/report.pdf", base_url=BASE).status_code == 403


def test_the_page_links_to_the_report_in_a_new_tab():
    client = login(build().test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    assert 'href="/report.pdf"' in html and 'target="_blank"' in html and "noopener" in html
    other = client.get("/", base_url=BASE)
    assert "Content-Security-Policy" in other.headers  # every other page keeps the policy
