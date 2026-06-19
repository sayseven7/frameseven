import json
import sys
from datetime import datetime

try:
    from fpdf import FPDF
    from fpdf.enums import MethodReturnValue
except ModuleNotFoundError:
    sys.stderr.write("fpdf2 is required to generate PDF reports. Install it with: python3 -m pip install fpdf2\n")
    raise


# Backgrounds
BG = (7, 10, 16)
SURFACE = (13, 18, 28)
SURFACE_SOFT = (23, 31, 45)

# Borders
BORDER = (38, 50, 68)
BORDER_STR = (53, 68, 91)

# Text
TEXT = (237, 242, 247)
MUTED = (145, 160, 181)
SUBTLE = (100, 116, 139)

# Accent
ACCENT = (103, 232, 249)

# Severities
CRITICAL = (251, 113, 133)
HIGH = (251, 146, 60)
MEDIUM = (250, 204, 21)
LOW = (56, 189, 248)
INFO = (167, 139, 250)

# Status indicator
GREEN = (74, 222, 128)

SEVERITY_COLORS = {
    "CRITICAL": CRITICAL,
    "HIGH": HIGH,
    "MEDIUM": MEDIUM,
    "LOW": LOW,
    "INFO": INFO,
}

WHITE = (255, 255, 255)

REPLACEMENTS = {
    "—": "-",
    "–": "-",
    "…": "...",
    "“": '"',
    "”": '"',
    "‘": "'",
    "’": "'",
    "→": "->",
}


def main():
    report = json.load(sys.stdin)
    pdf = SecurityReportPDF(report)
    pdf.render()
    sys.stdout.buffer.write(bytes(pdf.output()))


def clean(text):
    if text is None:
        return ""

    text = str(text)
    for old, new in REPLACEMENTS.items():
        text = text.replace(old, new)

    return text.encode("latin-1", "replace").decode("latin-1")


def pretty_date(value):
    if not value:
        return "Unknown"

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%B %d, %Y at %H:%M UTC")
    except ValueError:
        return value


def count_by_severity(findings):
    counts = {name: 0 for name in SEVERITY_COLORS}
    for finding in list_value(findings):
        severity = finding.get("severity", "INFO")
        counts[severity] = counts.get(severity, 0) + 1

    return counts


def list_value(value):
    return value if isinstance(value, list) else []


def dict_value(value):
    return value if isinstance(value, dict) else {}


class SecurityReportPDF(FPDF):
    def __init__(self, report):
        super().__init__(format="A4")
        self.report = report
        self.counts = count_by_severity(report.get("findings"))
        self.badge_left = 16.0
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(16, 16, 16)

    def header(self):
        self.set_fill_color(*BG)
        self.rect(0, 0, self.w, self.h, style="F")
        self.set_draw_color(*BORDER)
        self.set_text_color(*TEXT)
        self.set_xy(self.l_margin, self.t_margin)

    def footer(self):
        if self.page_no() == 1:
            return

        self.set_y(-12)
        self.set_font("Helvetica", size=7)
        self.set_text_color(*SUBTLE)
        self.set_x(self.l_margin)
        self.cell(self.epw / 2, 6, clean("frameseven CLI v1 - confidential security report"), align="L")
        self.cell(self.epw / 2, 6, clean(f"Page {self.page_no()} / {{nb}}"), align="R")

    def render(self):
        self.alias_nb_pages()
        self.add_page()
        self.hero()
        self.executive_overview()
        self.assessment_scope()
        self.attack_surface()
        self.security_findings()

    # ------------------------------------------------------------------
    # Primitives and helpers
    # ------------------------------------------------------------------

    def card(self, x, y, w, h, fill, border=None, radius=4):
        self.set_fill_color(*fill)

        if border:
            self.set_draw_color(*border)
            self.rect(x, y, w, h, style="DF", round_corners=True, corner_radius=radius)
        else:
            self.rect(x, y, w, h, style="F", round_corners=True, corner_radius=radius)

    def text_height(self, w, line_h, text, family="Helvetica", style="", size=10):
        self.set_font(family, style, size)

        return self.multi_cell(
            w,
            line_h,
            clean(text),
            dry_run=True,
            output=MethodReturnValue.HEIGHT,
            new_x="LMARGIN",
            new_y="NEXT",
        )

    def ensure_space(self, needed):
        if self.get_y() + needed > self.h - self.b_margin:
            self.add_page()

    def section_heading(self, title, subtitle=""):
        self.ensure_space(20)
        self.ln(2)

        self.set_font("Helvetica", "B", 15)
        self.set_text_color(*TEXT)
        self.cell(0, 8, clean(title), new_x="LMARGIN", new_y="NEXT")

        if subtitle:
            self.set_font("Helvetica", size=9)
            self.set_text_color(*MUTED)
            self.cell(0, 5, clean(subtitle), new_x="LMARGIN", new_y="NEXT")

        self.ln(1)
        self.set_draw_color(*BORDER)
        y = self.get_y()
        self.line(self.l_margin, y, self.w - self.r_margin, y)
        self.ln(4)

    def panel_header(self, title):
        self.ensure_space(16)

        x = self.l_margin
        y = self.get_y()
        w = self.epw
        h = 10

        self.card(x, y, w, h, SURFACE, BORDER, radius=4)

        self.set_xy(x + 5, y + 0.5)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*TEXT)
        self.cell(w - 10, h - 1, clean(title))

        self.set_draw_color(*BORDER)
        self.line(x, y + h, x + w, y + h)
        self.set_y(y + h)

    def badge(self, text, fg, bg, border_color=None):
        if not text:
            return 0

        text = clean(text)
        self.set_font("Helvetica", "B", 6)

        pad = 2.4
        width = self.get_string_width(text) + pad * 2
        height = 4.6

        x = self.get_x()
        y = self.get_y()

        if x + width > self.w - self.r_margin:
            x = self.badge_left
            y += height + 1.6
            self.set_xy(x, y)

        self.set_fill_color(*bg)
        if border_color:
            self.set_draw_color(*border_color)
            style = "DF"
        else:
            style = "F"

        self.rect(x, y, width, height, style=style, round_corners=True, corner_radius=2.3)

        self.set_text_color(*fg)
        self.set_xy(x, y + 0.1)
        self.cell(width, height - 0.2, text, align="C")
        self.set_xy(x + width + 2, y)

        return width

    def code_block(self, label, text, max_lines=80):
        self.ensure_space(16)
        self.ln(1)

        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*ACCENT)
        self.cell(0, 4.5, clean(label.upper()), new_x="LMARGIN", new_y="NEXT")

        lines = str(text).split("\n")
        if len(lines) > max_lines:
            lines = lines[:max_lines] + ["... [truncated]"]

        body = "\n".join(lines)

        self.set_font("Courier", size=7)
        self.set_fill_color(*BG)
        self.set_draw_color(*BORDER)
        self.set_text_color(*TEXT)
        self.multi_cell(0, 3.6, clean(body), fill=True, border=1, padding=4, new_x="LMARGIN", new_y="NEXT")

        self.ln(2)

    def severity_bar(self, severity, count, total):
        color = SEVERITY_COLORS.get(severity, MUTED)

        label_w = 22
        num_w = 10
        gap = 3
        row_h = 6

        self.ensure_space(row_h + 2)
        y = self.get_y()

        bar_x = self.l_margin + label_w + gap
        bar_w = self.w - self.r_margin - num_w - gap - bar_x

        self.set_xy(self.l_margin, y)
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*MUTED)
        self.cell(label_w, row_h, clean(severity.upper()))

        track_h = 1.5
        track_y = y + row_h / 2 - track_h / 2
        self.set_fill_color(*SURFACE_SOFT)
        self.rect(bar_x, track_y, bar_w, track_h, style="F")

        if total > 0 and count > 0:
            fill_w = max(0.8, bar_w * count / total)
            self.set_fill_color(*color)
            self.rect(bar_x, track_y, fill_w, track_h, style="F")

        self.set_xy(self.w - self.r_margin - num_w, y)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*TEXT)
        self.cell(num_w, row_h, str(count), align="R", new_x="LMARGIN", new_y="NEXT")

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def hero(self):
        report = self.report
        target = report.get("target", "")
        errors = list_value(report.get("errors"))
        complete = not errors

        subtitle = report.get("subtitle", "")
        if not subtitle:
            subtitle = "Includes sensitive extracted data (credentials, cards, schema) - CONFIDENTIAL"

        x = self.l_margin
        y = self.get_y()
        w = self.epw
        h = 66

        self.card(x, y, w, h, SURFACE, BORDER_STR, radius=6)

        with self.rect_clip(x, y, w, h):
            self.set_draw_color(*BORDER_STR)
            self.ellipse(x + w - 36, y + h - 16, 72, 72, style="D")
            self.ellipse(x + w - 48, y + h - 28, 96, 96, style="D")

        inner_left = 10
        ix = x + inner_left
        iw = w - inner_left * 2
        cy = y + 9

        self.set_xy(ix, cy)
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*ACCENT)
        self.cell(iw, 4, clean("OFFENSIVE SECURITY ASSESSMENT"))
        cy += 7

        self.set_xy(ix, cy)
        self.set_font("Helvetica", "B", 22)
        self.set_text_color(*TEXT)
        self.cell(iw, 10, clean("Web application security report"))
        cy += 12

        self.set_xy(ix, cy)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*CRITICAL)
        self.cell(iw, 4.4, clean(subtitle))
        cy += 6

        self.set_xy(ix, cy)
        self.set_font("Courier", size=8)
        self.set_text_color(*MUTED)
        self.cell(iw, 4.4, clean(target))
        cy += 8

        self.hero_meta(ix, cy, complete)

        self.set_y(y + h)
        self.ln(6)

    def hero_meta(self, x, y, complete):
        report = self.report

        dot_color = GREEN if complete else HIGH
        self.set_fill_color(*dot_color)
        self.ellipse(x, y + 1.4, 1.8, 1.8, style="F")

        status_text = "Complete" if complete else "Incomplete"
        self.set_xy(x + 3, y)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*TEXT)
        self.cell(self.get_string_width(clean(status_text)) + 8, 4.5, clean(status_text))

        items = [
            "Started " + pretty_date(report.get("started_at", "")),
            "Duration " + str(report.get("duration", "")),
            "Schema " + str(report.get("schema_version", "v1")),
        ]

        self.set_font("Helvetica", size=8)
        self.set_text_color(*MUTED)
        for item in items:
            text = clean(item)
            self.cell(self.get_string_width(text) + 8, 4.5, text)

    def executive_overview(self):
        findings = list_value(self.report.get("findings"))
        endpoints = list_value(dict_value(self.report.get("surface")).get("endpoints"))
        errors = list_value(self.report.get("errors"))

        total = len(findings)
        critical = self.counts.get("CRITICAL", 0)
        high = self.counts.get("HIGH", 0)

        self.section_heading("Executive overview", "Assessment outcome and risk distribution.")

        cards = [
            ("Total findings", total, "Across all completed tools"),
            ("Critical and high", critical + high, "Combined urgent findings"),
            ("Mapped endpoints", len(endpoints), "Discovered during reconnaissance"),
            ("Tool errors", len(errors), "May affect report completeness"),
        ]
        self.metric_cards(cards)

        self.ln(5)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*TEXT)
        self.cell(0, 6, clean("Severity distribution"), new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.severity_bar(severity, self.counts.get(severity, 0), total)

    def metric_cards(self, cards):
        gap = 5
        card_w = (self.epw - gap) / 2
        card_h = 24

        self.ensure_space(card_h * 2 + gap + 4)
        top = self.get_y()

        for index, (label, value, note) in enumerate(cards):
            col = index % 2
            row = index // 2
            x = self.l_margin + col * (card_w + gap)
            y = top + row * (card_h + gap)

            self.card(x, y, card_w, card_h, SURFACE, BORDER, radius=4)

            self.set_xy(x + 5, y + 4)
            self.set_font("Helvetica", size=8)
            self.set_text_color(*MUTED)
            self.cell(card_w - 10, 4, clean(label))

            self.set_xy(x + 5, y + 9)
            self.set_font("Helvetica", "B", 20)
            self.set_text_color(*TEXT)
            self.cell(card_w - 10, 8, clean(str(value)))

            self.set_xy(x + 5, y + 18)
            self.set_font("Helvetica", size=8)
            self.set_text_color(*SUBTLE)
            self.cell(card_w - 10, 4, clean(note))

        self.set_y(top + card_h * 2 + gap)

    def assessment_scope(self):
        surface = dict_value(self.report.get("surface"))

        self.section_heading("Assessment scope", "Key facts about the assessed target.")
        self.panel_header("Assessment scope")
        self.ln(3)

        cells = [
            ("HOST", surface.get("host", "") or "-"),
            ("TECHNOLOGIES", str(len(list_value(surface.get("technologies"))))),
            ("PARAMETERS", str(len(list_value(surface.get("params"))))),
            ("SENSITIVE FILES", str(len(list_value(surface.get("sensitive_files"))))),
        ]

        col_w = self.epw / 2
        row_h = 16
        top = self.get_y()

        for index, (label, value) in enumerate(cells):
            col = index % 2
            row = index // 2
            x = self.l_margin + col * col_w
            y = top + row * row_h

            self.set_fill_color(*SURFACE)
            self.set_draw_color(*BORDER)
            self.rect(x, y, col_w, row_h, style="DF")

            self.set_xy(x + 5, y + 3)
            self.set_font("Helvetica", "B", 7)
            self.set_text_color(*MUTED)
            self.cell(col_w - 10, 4, clean(label))

            self.set_xy(x + 5, y + 8)
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*TEXT)
            self.cell(col_w - 10, 5, clean(value))

        self.set_y(top + row_h * 2)
        self.ln(2)

    def attack_surface(self):
        surface = dict_value(self.report.get("surface"))

        self.section_heading("Attack surface", "Assets and input points observed during reconnaissance.")

        self.panel_list("Technologies", list_value(surface.get("technologies")), self.tech_item)
        self.panel_list("Endpoints", list_value(surface.get("endpoints"))[:12], self.path_item)
        self.panel_list("Parameters", list_value(surface.get("params"))[:12], self.param_item)
        self.panel_list("Sensitive files", list_value(surface.get("sensitive_files"))[:12], self.path_item)

    def panel_list(self, title, items, render_item):
        self.panel_header(title)
        self.ln(2)

        if not items:
            self.set_xy(self.l_margin + 5, self.get_y() + 2)
            self.set_font("Helvetica", "I", 8.5)
            self.set_text_color(*SUBTLE)
            self.cell(0, 5, clean("None identified."), new_x="LMARGIN", new_y="NEXT")
            self.ln(2)
            return

        for item in items:
            self.ensure_space(10)
            render_item(item)

            self.set_draw_color(*BORDER)
            y = self.get_y()
            self.line(self.l_margin, y, self.w - self.r_margin, y)

        self.ln(3)

    def tech_item(self, item):
        name = item.get("name", "")
        version = item.get("version", "")
        if version:
            name = f"{name} {version}".strip()

        self.set_xy(self.l_margin + 5, self.get_y() + 2)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*TEXT)
        self.cell(0, 4.5, clean(name), new_x="LMARGIN", new_y="NEXT")

        source = item.get("source", "")
        if source:
            self.set_x(self.l_margin + 5)
            self.set_font("Helvetica", size=8)
            self.set_text_color(*MUTED)
            self.cell(0, 4, clean(source), new_x="LMARGIN", new_y="NEXT")

        self.ln(1.5)

    def path_item(self, value):
        self.set_xy(self.l_margin + 5, self.get_y() + 2)
        self.set_font("Courier", size=8)
        self.set_text_color(*ACCENT)
        self.multi_cell(0, 4, clean(value), new_x="LMARGIN", new_y="NEXT")
        self.ln(1.5)

    def param_item(self, item):
        name = item.get("name", "")
        method = item.get("method", "")
        endpoint = item.get("endpoint", "")

        self.set_xy(self.l_margin + 5, self.get_y() + 2)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*TEXT)
        self.cell(self.get_string_width(clean(name)) + 2, 4.5, clean(name))

        if method:
            self.set_font("Helvetica", size=8)
            self.set_text_color(*MUTED)
            self.cell(0, 4.5, clean(method), new_x="LMARGIN", new_y="NEXT")
        else:
            self.ln(4.5)

        if endpoint:
            self.set_x(self.l_margin + 5)
            self.set_font("Courier", size=8)
            self.set_text_color(*ACCENT)
            self.multi_cell(0, 4, clean(endpoint), new_x="LMARGIN", new_y="NEXT")

        self.ln(1.5)

    def security_findings(self):
        findings = list_value(self.report.get("findings"))

        self.section_heading("Security findings", "Technical evidence and recommended remediation steps.")

        if not findings:
            self.set_font("Helvetica", "I", 9)
            self.set_text_color(*MUTED)
            self.cell(0, 6, clean("No findings were recorded during this scan."), new_x="LMARGIN", new_y="NEXT")
            return

        for index, finding in enumerate(findings, start=1):
            self.finding(index, finding)

    def finding(self, index, finding):
        severity = finding.get("severity", "INFO")
        color = SEVERITY_COLORS.get(severity, MUTED)
        evidence = dict_value(finding.get("evidence"))

        inner_left = 6
        inner_right = 4
        inner_w = self.epw - inner_left - inner_right

        title = f"{index}. {finding.get('title', '')}"
        description = finding.get("description", "")

        title_h = self.text_height(inner_w, 5.2, title, "Helvetica", "B", 11)
        desc_h = self.text_height(inner_w, 4.6, description, "Helvetica", "", 8.5) if description else 0

        head_h = 4 + 5.5 + 2 + title_h + 4
        if description:
            head_h += 2 + desc_h

        self.ensure_space(head_h + 12)

        x = self.l_margin
        y = self.get_y()

        self.card(x, y, self.epw, head_h, SURFACE, BORDER, radius=4)
        self.set_fill_color(*color)
        self.rect(x + 0.8, y + 1, 1.0, head_h - 2, style="F")

        cy = y + 4
        self.set_xy(x + inner_left, cy)
        self.badge_left = x + inner_left
        self.badge(severity, color, BG, color)
        self.badge(finding.get("module", ""), MUTED, SURFACE_SOFT, BORDER)

        cvss = finding.get("cvss")
        if cvss:
            self.badge(f"CVSS {float(cvss):.1f}", MUTED, SURFACE_SOFT, BORDER)

        if evidence.get("extracted"):
            self.badge("EXPLOITED - EXTRACTED DATA", ACCENT, SURFACE_SOFT, BORDER)

        cy += 5.5 + 2

        self.set_xy(x + inner_left, cy)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*TEXT)
        self.multi_cell(inner_w, 5.2, clean(title), new_x="LMARGIN", new_y="NEXT")
        cy += title_h

        if description:
            cy += 2
            self.set_xy(x + inner_left, cy)
            self.set_font("Helvetica", size=8.5)
            self.set_text_color(*MUTED)
            self.multi_cell(inner_w, 4.6, clean(description), new_x="LMARGIN", new_y="NEXT")

        self.set_y(y + head_h)
        self.ln(2)

        self.finding_body(finding, evidence)
        self.ln(5)

    def finding_body(self, finding, evidence):
        cwe = finding.get("cwe", "")
        owasp = finding.get("owasp", "")

        if cwe or owasp:
            self.set_xy(self.l_margin, self.get_y())
            self.badge_left = self.l_margin
            if cwe:
                self.badge(cwe, MUTED, SURFACE_SOFT)
            if owasp:
                self.badge(owasp, MUTED, SURFACE_SOFT)
            self.ln(7)

        if evidence.get("extracted"):
            self.code_block("Extracted evidence", evidence.get("extracted", ""), max_lines=80)

        if evidence.get("request"):
            self.code_block("HTTP request", evidence.get("request", ""), max_lines=20)

        if evidence.get("response"):
            self.code_block("HTTP response", evidence.get("response", ""), max_lines=20)

        steps = list_value(finding.get("next_steps"))
        if steps:
            self.ln(1)
            self.set_x(self.l_margin)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*TEXT)
            self.cell(0, 5, clean("Recommended next steps"), new_x="LMARGIN", new_y="NEXT")

            for step in steps:
                self.ensure_space(8)
                y = self.get_y()
                self.set_fill_color(*ACCENT)
                self.ellipse(self.l_margin + 1, y + 1.7, 1.3, 1.3, style="F")

                self.set_xy(self.l_margin + 5, y)
                self.set_font("Helvetica", size=8.5)
                self.set_text_color(*TEXT)
                self.multi_cell(0, 4.8, clean(step), new_x="LMARGIN", new_y="NEXT")


if __name__ == "__main__":
    main()
