"""PDF report generation with Unicode font support."""

from collections.abc import Sequence
from pathlib import Path

from fpdf import FPDF

from core.models import Finding, Severity

from .base import BaseReporter

FONT_CANDIDATES = (
    Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    Path("/System/Library/Fonts/Supplemental/Arial Unicode.ttf"),
    Path("/Library/Fonts/Arial Unicode.ttf"),
)


class PDFReporter(BaseReporter):
    """Write findings to a PDF using a Unicode-capable TrueType font."""

    def generate(
        self,
        findings: Sequence[Finding],
        output_dir: Path,
        timestamp: str,
    ) -> Path:
        report_path = output_dir / f"reporte_seguridad_{timestamp}.pdf"
        pdf = FPDF()
        pdf.add_page()
        font_path = self._font_path()
        pdf.add_font("CSPMUnicode", fname=str(font_path))
        pdf.add_font("CSPMUnicode", style="B", fname=str(font_path))
        pdf.set_font("CSPMUnicode", size=16)
        pdf.cell(
            0,
            10,
            "Auditoría de Seguridad CSPM",
            new_x="LMARGIN",
            new_y="NEXT",
            align="C",
        )
        pdf.ln(5)

        for index, finding in enumerate(findings, 1):
            if finding.severity == Severity.CRITICAL:
                pdf.set_text_color(220, 53, 69)
            elif finding.severity == Severity.HIGH:
                pdf.set_text_color(253, 126, 20)
            else:
                pdf.set_text_color(0, 0, 0)
            pdf.set_font("CSPMUnicode", style="B", size=12)
            pdf.cell(
                0,
                8,
                f"{index}. [{finding.severity.value}] "
                f"{finding.service} - {finding.resource}",
                new_x="LMARGIN",
                new_y="NEXT",
            )
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("CSPMUnicode", size=11)
            pdf.multi_cell(
                0,
                6,
                f"Detalle: {finding.description}",
                new_x="LMARGIN",
                new_y="NEXT",
            )
            if finding.remediation:
                pdf.multi_cell(
                    0,
                    6,
                    f"Remediación: {finding.remediation}",
                    new_x="LMARGIN",
                    new_y="NEXT",
                )
            pdf.ln(4)

        pdf.output(str(report_path))
        return report_path

    @staticmethod
    def _font_path() -> Path:
        for candidate in FONT_CANDIDATES:
            if candidate.is_file():
                return candidate
        raise RuntimeError("No se encontró una fuente TrueType compatible con Unicode.")
