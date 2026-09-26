"""Resumes as PDFs, and everything a parser finds in them.

A PDF can carry text that nobody looking at the page sees: white on white, too small
to read, or placed off the page. It also carries metadata fields. parse() separates
the text a person would see from the rest by tracking the fill colour, font size and
position of every piece of text as pypdf walks each page's drawing commands.

The first version called text hidden when its fill was brighter than 92% white or its
size under 4 points. Text at 90% grey and 4.2 points passed both tests while nobody
could read it (bench.py --bypass shows it), so text is now judged by its contrast
against the white page, the measure accessibility guidelines use for legibility.
"""
import io
import textwrap
from dataclasses import dataclass

from pypdf import PdfReader
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

MIN_POINTS = 4.0   # smaller than this is not meant to be read; resume footers use 6 to 8
WHITE = 0.92       # the first rule: a fill this bright on a white page cannot be seen
FAINT = 1.6        # contrast against white below which text cannot be read at any size
SMALL = (6.0, 3.0) # below 6 points, text needs at least 3:1 contrast to be read


@dataclass
class Parsed:
    visible: str
    hidden: list     # [(why, text)] with why in white, tiny, off-page
    metadata: dict


def render(text, *, meta=None, hidden=(), grey_lines=(), footer=None) -> bytes:
    """A4 pages of 10pt Helvetica. hidden: [(style, text)], style one of white, tiny, off-page, near-white.
    grey_lines are drawn in mid grey and footer in 7pt, the way real resumes format dates and small print."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4, invariant=1)
    for key, value in (meta or {}).items():
        getattr(c, f"set{key.title()}")(value)
    width, height = A4
    y = height - 50

    def line(s, size=10, grey=0.0, x=50):
        nonlocal y
        if y < 60:
            c.showPage()
            y = height - 50
        c.setFont("Helvetica", size)
        c.setFillGray(grey)
        c.drawString(x, y, s)
        y -= size + 3

    grey = {g.strip() for g in grey_lines}
    for para in text.split("\n"):
        for s in textwrap.wrap(para, 95) or [""]:
            line(s, grey=0.45 if s.strip() in grey else 0.0)
    if footer:
        line(footer, size=7)
    for style, payload in hidden:
        for s in textwrap.wrap(payload, 95):
            if style == "white":
                c.setFont("Helvetica", 10)
                c.setFillColorRGB(1, 1, 1)
                c.drawString(50, 40, s)
            elif style == "tiny":
                c.setFont("Helvetica", 1)
                c.setFillGray(0)
                c.drawString(50, 30, s)
            elif style == "off-page":
                c.setFont("Helvetica", 10)
                c.setFillGray(0)
                c.drawString(-3000, 300, s)
            elif style == "near-white":   # 90% grey at 4.2pt: under the first rule's limits, unreadable all the same
                c.setFont("Helvetica", 4.2)
                c.setFillGray(0.9)
                c.drawString(50, 20, s)
    c.save()
    return buf.getvalue()


def _fill(op, args):
    v = [float(a) for a in args if isinstance(a, (int, float))]
    if op == b"g" and len(v) == 1:
        return (v[0],) * 3
    if op == b"rg" and len(v) == 3:
        return tuple(v)
    if op == b"k" and len(v) == 4:
        cy, m, ye, k = v
        return ((1 - cy) * (1 - k), (1 - m) * (1 - k), (1 - ye) * (1 - k))
    if op in (b"sc", b"scn") and len(v) in (1, 3):
        return tuple(v) * (3 if len(v) == 1 else 1)
    return None


def contrast(fill):
    """WCAG contrast ratio of a fill colour against a white page, from 1 (invisible) to 21."""
    lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in fill]
    lum = 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]
    return 1.05 / (lum + 0.05)


def hidden_why(fill, size, on_page, rule="contrast"):
    """Why a person would not see this text, or None if they would."""
    if rule == "contrast":
        c = contrast(fill)
        if c < FAINT:
            return "low contrast"
        if size < MIN_POINTS:
            return "tiny"
        if size < SMALL[0] and c < SMALL[1]:
            return "small and faint"
    else:
        if min(fill) > WHITE:
            return "white"
        if size < MIN_POINTS:
            return "tiny"
    return None if on_page else "off-page"


def parse(data: bytes, rule="contrast") -> Parsed:
    """rule: "contrast" (current) or "first" (the original white-and-size test, kept for the bypass demo)."""
    reader = PdfReader(io.BytesIO(data))
    visible, hidden = [], []
    for page in reader.pages:
        x0, y0, x1, y1 = (float(v) for v in page.mediabox)
        state, stack = {"fill": (0.0, 0.0, 0.0)}, []

        def before(op, args, cm, tm):
            if op == b"q":
                stack.append(dict(state))
            elif op == b"Q" and stack:
                state.update(stack.pop())
            elif (fill := _fill(op, args)) is not None:
                state["fill"] = fill

        def on_text(text, cm, tm, font, size):
            if not text.strip():
                if text:
                    visible.append(text)
                return
            scale = (abs(tm[0] * cm[0]) or 1.0)
            x = cm[0] * tm[4] + cm[2] * tm[5] + cm[4]
            y = cm[1] * tm[4] + cm[3] * tm[5] + cm[5]
            why = hidden_why(state["fill"], (size or 0) * scale, x0 - 5 <= x <= x1 and y0 - 5 <= y <= y1, rule)
            if why:
                hidden.append((why, text))
            else:
                visible.append(text)

        page.extract_text(visitor_operand_before=before, visitor_text=on_text)
        visible.append("\n")
    meta = {k.lstrip("/").lower(): str(v) for k, v in (reader.metadata or {}).items()}
    return Parsed("".join(visible).strip(), hidden, meta)
