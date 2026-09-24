"""Convert the AIPEN markdown document to a styled PDF via ReportLab."""
import re
import sys
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Preformatted, PageBreak, KeepTogether,
)

SRC = Path(sys.argv[1])
OUT = Path(sys.argv[2])

BODY = HexColor("#333333")
ACCENT = HexColor("#1a3a5c")
GRAY_BG = HexColor("#f5f5f5")
RULE = HexColor("#000000")

styles = {
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=22,
                            leading=28, textColor=ACCENT, spaceAfter=10),
    "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=13,
                               leading=18, textColor=BODY, spaceAfter=24),
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=15, leading=19,
                         textColor=ACCENT, spaceBefore=18, spaceAfter=8,
                         keepWithNext=1),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=12.5, leading=16,
                         textColor=ACCENT, spaceBefore=14, spaceAfter=6,
                         keepWithNext=1),
    "h3": ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=11, leading=14,
                         textColor=BODY, spaceBefore=10, spaceAfter=4,
                         keepWithNext=1),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=10, leading=14.5,
                           textColor=BODY, spaceAfter=6),
    "li": ParagraphStyle("li", fontName="Helvetica", fontSize=10, leading=14.5,
                         textColor=BODY, spaceAfter=3, leftIndent=16),
    "code": ParagraphStyle("code", fontName="Courier", fontSize=8, leading=10.5,
                           textColor=BODY),
    "caption": ParagraphStyle("caption", fontName="Helvetica", fontSize=9,
                              leading=12, textColor=HexColor("#666666")),
}

def inline(text: str) -> str:
    """Minimal markdown inline -> reportlab markup."""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"`([^`]+)`", r'<font face="Courier" size="9">\1</font>', text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<!\w)\*([^*\n]+)\*(?!\w)", r"<i>\1</i>", text)
    return text

def code_block(lines):
    pf = Preformatted("\n".join(lines), styles["code"], maxLineLength=95)
    t = Table([[pf]], colWidths=[16.2 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), GRAY_BG),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return [Spacer(1, 4), t, Spacer(1, 8)]

def md_table(rows):
    """rows: list of list[str]; first row header."""
    ncols = max(len(r) for r in rows)
    rows = [r + [""] * (ncols - len(r)) for r in rows]
    data = [[Paragraph(inline(c.strip()), ParagraphStyle(
        "cell", fontName="Helvetica-Bold" if i == 0 else "Helvetica",
        fontSize=8.5, leading=11.5, textColor=BODY)) for c in r]
        for i, r in enumerate(rows)]
    total = 16.2 * cm
    # weight columns: first column wider when 2-3 cols
    if ncols <= 3:
        w0 = total * 0.38
        widths = [w0] + [(total - w0) / (ncols - 1)] * (ncols - 1)
    else:
        widths = [total / ncols] * ncols
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("LINEABOVE", (0, 0), (-1, 0), 1.2, RULE),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, RULE),
        ("LINEBELOW", (0, -1), (-1, -1), 1.2, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    return [Spacer(1, 2), t, Spacer(1, 8)]

def flush_par(buf, story):
    if buf:
        story.append(Paragraph(inline(" ".join(buf)), styles["body"]))
        buf.clear()

def build(md_text: str):
    story = []
    lines = md_text.split("\n")
    i, buf, in_code = 0, [], False
    code_lines, table_rows = [], []
    first_h1_done = False

    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("```"):
            flush_par(buf, story)
            if not in_code:
                in_code = True
                code_lines = []
            else:
                in_code = False
                story.extend(code_block(code_lines))
            i += 1
            continue
        if in_code:
            code_lines.append(line.rstrip("\n"))
            i += 1
            continue
        if line.strip().startswith("|"):
            flush_par(buf, story)
            row = [c for c in line.strip().strip("|").split("|")]
            if not all(re.fullmatch(r"\s*:?-+:?\s*", c) for c in row):
                table_rows.append(row)
            i += 1
            continue
        elif table_rows:
            story.extend(md_table(table_rows))
            table_rows = []
        s = line.strip()
        if not s:
            flush_par(buf, story)
        elif s == "---":
            flush_par(buf, story)
            story.append(Spacer(1, 10))
        elif s.startswith("### "):
            flush_par(buf, story)
            story.append(Paragraph(inline(s[4:]), styles["h3"]))
        elif s.startswith("## "):
            flush_par(buf, story)
            if first_h1_done:
                story.append(PageBreak())
            story.append(Paragraph(inline(s[3:]), styles["h1"]))
        elif s.startswith("# "):
            flush_par(buf, story)
            story.append(Paragraph(inline(s[2:]), styles["title"]))
            first_h1_done = True
        elif re.match(r"^[-*] ", s):
            flush_par(buf, story)
            story.append(Paragraph("• " + inline(s[2:]), styles["li"]))
        elif re.match(r"^\d+\. ", s):
            flush_par(buf, story)
            story.append(Paragraph(inline(s), styles["li"]))
        elif s.startswith(">"):
            flush_par(buf, story)
            story.append(Paragraph("<i>" + inline(s.lstrip("> ").strip()) + "</i>", styles["body"]))
        else:
            buf.append(s)
        i += 1
    flush_par(buf, story)
    if table_rows:
        story.extend(md_table(table_rows))
    return story

def header_footer(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setFont("Helvetica", 8.5)
    canvas.setFillColor(HexColor("#666666"))
    canvas.drawString(2 * cm, h - 1.4 * cm, "AIPEN — Project Requirements, Design & SDLC Plan")
    canvas.drawRightString(w - 2 * cm, h - 1.4 * cm, "v1.0")
    canvas.setStrokeColor(HexColor("#cccccc"))
    canvas.setLineWidth(0.5)
    canvas.line(2 * cm, h - 1.6 * cm, w - 2 * cm, h - 1.6 * cm)
    canvas.drawCentredString(w / 2, 1.3 * cm, f"Page {doc.page}")
    canvas.restoreState()

def first_page(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setStrokeColor(ACCENT)
    canvas.setLineWidth(2)
    canvas.line(2 * cm, h - 3 * cm, 6 * cm, h - 3 * cm)
    canvas.restoreState()

doc = SimpleDocTemplate(str(OUT), pagesize=A4, title="AIPEN — Project Requirements, Design & SDLC Plan",
                        author="AIPEN Project", subject="SDLC planning and design document",
                        topMargin=2.2 * cm, bottomMargin=2.2 * cm,
                        leftMargin=2 * cm, rightMargin=2 * cm)
story = build(SRC.read_text(encoding="utf-8"))
doc.build(story, onFirstPage=first_page, onLaterPages=header_footer)
print(f"OK -> {OUT}")
