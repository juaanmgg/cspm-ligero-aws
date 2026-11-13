import argparse
import csv
import os
from datetime import datetime
from pathlib import Path
from collections.abc import Mapping, Sequence

from fpdf import FPDF

from azure_auditor import AzureSecurityAuditor
from core.models import Finding
from cspm_auditor import AWSSecurityAuditor


SEVERITY_LEVELS = {"Crítico": 2, "Alto": 1, "Todos": 0}
FINDING_FIELDS = ["Servicio", "Recurso", "Riesgo", "Descripción"]


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser de argumentos de la CLI."""
    parser = argparse.ArgumentParser(
        description="Auditoría de seguridad CSPM para AWS y Azure."
    )
    parser.add_argument(
        "--provider",
        choices=("aws", "azure", "all"),
        default="aws",
        help="Proveedor que se auditará (por defecto: aws).",
    )
    parser.add_argument(
        "--format",
        dest="report_format",
        choices=("csv", "pdf", "both"),
        default="both",
        help="Formato de los reportes (por defecto: both).",
    )
    parser.add_argument(
        "--min-severity",
        choices=tuple(SEVERITY_LEVELS),
        default="Todos",
        help="Severidad mínima incluida (por defecto: Todos).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        help="Directorio de destino de los reportes (por defecto: .).",
    )
    return parser


def collect_findings(provider: str) -> list[Finding]:
    """Ejecuta las auditorías seleccionadas y devuelve sus hallazgos."""
    findings: list[Finding] = []

    if provider in ("aws", "all"):
        findings.extend(AWSSecurityAuditor().audit())

    if provider in ("azure", "all"):
        storage_account_url = os.getenv("AZURE_STORAGE_ACCOUNT_URL")
        if not storage_account_url:
            raise ValueError(
                "AZURE_STORAGE_ACCOUNT_URL es obligatorio para auditar Azure."
            )
        findings.extend(AzureSecurityAuditor(storage_account_url).audit())

    return findings


def filter_findings(
    findings: Sequence[Finding | Mapping[str, str]], minimum_severity: str
) -> list[dict[str, str]]:
    """Filtra hallazgos conservando la severidad mínima solicitada."""
    minimum_level = SEVERITY_LEVELS[minimum_severity]
    filtered: list[dict[str, str]] = []
    for finding in findings:
        legacy_finding = finding.to_dict() if isinstance(finding, Finding) else dict(finding)
        if SEVERITY_LEVELS.get(legacy_finding.get("Riesgo", ""), 0) >= minimum_level:
            filtered.append(legacy_finding)
    return filtered


def write_csv_report(findings: Sequence[dict[str, str]], output_dir: Path, timestamp: str) -> Path:
    """Escribe los hallazgos en un reporte CSV."""
    report_path = output_dir / f"reporte_seguridad_{timestamp}.csv"
    with report_path.open("w", newline="", encoding="utf-8") as report_file:
        writer = csv.DictWriter(report_file, fieldnames=FINDING_FIELDS)
        writer.writeheader()
        writer.writerows(findings)
    return report_path


def write_pdf_report(findings: Sequence[dict[str, str]], output_dir: Path, timestamp: str) -> Path:
    """Escribe los hallazgos en un reporte PDF."""
    report_path = output_dir / f"reporte_seguridad_{timestamp}.pdf"
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "Auditoria de Seguridad CSPM", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(5)

    for index, finding in enumerate(findings, 1):
        if finding["Riesgo"] == "Crítico":
            pdf.set_text_color(220, 53, 69)
        elif finding["Riesgo"] == "Alto":
            pdf.set_text_color(253, 126, 20)

        pdf.set_font("helvetica", "B", 12)
        title = (
            f"{index}. [{finding['Riesgo']}] "
            f"{finding['Servicio']} - {finding['Recurso']}"
        )
        pdf.cell(0, 8, _pdf_safe_text(title), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("helvetica", "", 11)
        pdf.multi_cell(0, 6, _pdf_safe_text(f"Detalle: {finding['Descripción']}"))
        pdf.ln(4)

    pdf.output(str(report_path))
    return report_path


def _pdf_safe_text(value: str) -> str:
    """Convierte texto Unicode a una representación compatible con Helvetica."""
    return value.encode("latin-1", errors="replace").decode("latin-1")


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada de la CLI."""
    args = build_parser().parse_args(argv)
    findings = filter_findings(
        collect_findings(args.provider),
        args.min_severity,
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    if not findings:
        print("No se encontraron hallazgos para los filtros seleccionados.")
        return 0

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    generated_reports: list[Path] = []
    if args.report_format in ("csv", "both"):
        generated_reports.append(write_csv_report(findings, args.output_dir, timestamp))
    if args.report_format in ("pdf", "both"):
        generated_reports.append(write_pdf_report(findings, args.output_dir, timestamp))

    for report in generated_reports:
        print(f"Reporte generado: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
