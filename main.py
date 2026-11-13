"""Command-line interface for the multi-cloud CSPM auditor."""

import argparse
from collections.abc import Sequence
from datetime import datetime
import logging
import os
from pathlib import Path

from azure_auditor import AzureSecurityAuditor
from core.exceptions import AuthenticationError
from core.logger import setup_logging
from core.models import Finding, Severity
from cspm_auditor import AWSSecurityAuditor
from reporters import CSVReporter, JSONReporter, PDFReporter
from reporters.base import BaseReporter

SEVERITY_LEVELS = {"Crítico": 4, "Alto": 3, "Medio": 2, "Bajo": 1, "Todos": 0}
SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
REPORTERS: dict[str, BaseReporter] = {
    "csv": CSVReporter(),
    "json": JSONReporter(),
    "pdf": PDFReporter(),
}
LOGGER = logging.getLogger(__name__)


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
        choices=("csv", "pdf", "json", "all"),
        default="all",
        help="Formato de los reportes (por defecto: all).",
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
    parser.add_argument(
        "--fail-on-severity",
        choices=tuple(severity.value for severity in Severity),
        default=None,
        help="Devuelve código 1 si aparece esta severidad o una superior.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Valida credenciales sin auditar recursos ni generar reportes.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Habilita logging detallado.",
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


def validate_credentials(provider: str) -> None:
    """Validate credentials for the selected providers without auditing."""
    if provider in ("aws", "all"):
        AWSSecurityAuditor().check_credentials()
    if provider in ("azure", "all"):
        storage_account_url = os.getenv("AZURE_STORAGE_ACCOUNT_URL")
        if not storage_account_url:
            raise ValueError(
                "AZURE_STORAGE_ACCOUNT_URL es obligatorio para validar Azure."
            )
        AzureSecurityAuditor(storage_account_url).check_credentials()


def filter_findings(
    findings: Sequence[Finding], minimum_severity: str
) -> list[Finding]:
    """Filtra hallazgos sin convertirlos a diccionarios intermedios."""
    minimum_level = SEVERITY_LEVELS[minimum_severity]
    return [
        finding
        for finding in findings
        if SEVERITY_RANK[finding.severity] >= minimum_level
    ]


def generate_reports(
    findings: Sequence[Finding],
    report_format: str,
    output_dir: Path,
    timestamp: str,
) -> list[Path]:
    """Dispatch findings to the selected report generators."""
    formats = ("csv", "pdf", "json") if report_format == "all" else (report_format,)
    return [
        REPORTERS[format_name].generate(findings, output_dir, timestamp)
        for format_name in formats
    ]


def _severity_at_least(findings: Sequence[Finding], threshold: str) -> bool:
    threshold_level = SEVERITY_RANK[Severity(threshold)]
    return any(
        SEVERITY_RANK[finding.severity] >= threshold_level for finding in findings
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada de la CLI."""
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)
    try:
        if args.dry_run:
            validate_credentials(args.provider)
            print("Credenciales válidas")
            return 0
        collected_findings = collect_findings(args.provider)
    except AuthenticationError as error:
        LOGGER.error("%s", error)
        return 2

    should_fail = bool(
        args.fail_on_severity
        and _severity_at_least(collected_findings, args.fail_on_severity)
    )
    findings = filter_findings(collected_findings, args.min_severity)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if not findings:
        print("No se encontraron hallazgos para los filtros seleccionados.")
        return 1 if should_fail else 0

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for report in generate_reports(
        findings, args.report_format, args.output_dir, timestamp
    ):
        print(f"Reporte generado: {report}")
    return 1 if should_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
