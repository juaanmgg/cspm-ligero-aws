from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import main
from core.exceptions import AuthenticationError
from core.models import CloudProvider, Finding, Severity


def test_build_parser_uses_expected_defaults():
    """Usa AWS, ambos formatos y todas las severidades por defecto."""
    args = main.build_parser().parse_args([])

    assert args.provider == "aws"
    assert args.report_format == "both"
    assert args.min_severity == "Todos"
    assert args.output_dir == Path(".")
    assert args.fail_on_severity is None
    assert args.dry_run is False
    assert args.verbose is False


def test_main_provider_flag_selects_requested_provider():
    """Pasa el proveedor indicado a la recolección de hallazgos."""
    with patch("main.collect_findings", return_value=[]) as collect_findings:
        assert main.main(["--provider", "azure"]) == 0

    collect_findings.assert_called_once_with("azure")


def test_main_format_flag_generates_only_csv_report(tmp_path):
    """El flag csv genera CSV y no genera PDF."""
    findings = [
        {
            "Servicio": "Azure Blob",
            "Recurso": "container",
            "Riesgo": "Alto",
            "Descripción": "Acceso público",
        }
    ]
    with (
        patch("main.collect_findings", return_value=findings),
        patch("main.write_csv_report") as write_csv_report,
        patch("main.write_pdf_report") as write_pdf_report,
    ):
        assert main.main(
            ["--format", "csv", "--output-dir", str(tmp_path)]
        ) == 0

    write_csv_report.assert_called_once()
    write_pdf_report.assert_not_called()


def test_main_min_severity_flag_filters_findings(tmp_path):
    """El flag min-severity excluye hallazgos de severidad inferior."""
    findings = [
        {
            "Servicio": "AWS",
            "Recurso": "critical",
            "Riesgo": "Crítico",
            "Descripción": "critical finding",
        },
        {
            "Servicio": "AWS",
            "Recurso": "high",
            "Riesgo": "Alto",
            "Descripción": "high finding",
        },
    ]
    with (
        patch("main.collect_findings", return_value=findings),
        patch("main.write_csv_report") as write_csv_report,
    ):
        assert main.main(
            [
                "--format",
                "csv",
                "--min-severity",
                "Crítico",
                "--output-dir",
                str(tmp_path),
            ]
        ) == 0

    report_findings = write_csv_report.call_args.args[0]
    assert report_findings == [findings[0]]


def test_write_pdf_report_applies_severity_colors(tmp_path):
    """Usa rojo para Crítico, naranja para Alto y negro en las descripciones."""
    findings = [
        {
            "Servicio": "AWS",
            "Recurso": "critical",
            "Riesgo": "Crítico",
            "Descripción": "critical finding",
        },
        {
            "Servicio": "Azure Blob",
            "Recurso": "high",
            "Riesgo": "Alto",
            "Descripción": "high finding",
        },
    ]

    with patch("main.FPDF") as pdf_class:
        pdf = pdf_class.return_value
        main.write_pdf_report(findings, tmp_path, "20261110_000000")

    assert pdf.set_text_color.call_args_list == [
        ((220, 53, 69),),
        ((0, 0, 0),),
        ((253, 126, 20),),
        ((0, 0, 0),),
    ]


def test_fail_on_severity_returns_one_when_threshold_is_reached(tmp_path):
    """Falla el pipeline cuando aparece un finding de severidad crítica."""
    finding = Finding(
        id="finding-1",
        provider=CloudProvider.AWS,
        service="IAM",
        resource="user",
        severity=Severity.CRITICAL,
        description="critical",
        timestamp=datetime.now(),
    )
    with (
        patch("main.collect_findings", return_value=[finding]),
        patch("main.write_csv_report"),
    ):
        assert main.main(
            [
                "--format",
                "csv",
                "--fail-on-severity",
                "HIGH",
                "--output-dir",
                str(tmp_path),
            ]
        ) == 1


def test_dry_run_validates_credentials_without_auditing():
    """El dry-run valida credenciales y no ejecuta auditorías de recursos."""
    with (
        patch("main.validate_credentials") as validate_credentials,
        patch("main.collect_findings") as collect_findings,
    ):
        assert main.main(["--dry-run", "--verbose"]) == 0

    validate_credentials.assert_called_once_with("aws")
    collect_findings.assert_not_called()


def test_authentication_error_returns_two():
    """Los errores de autenticación detienen la CLI con código 2."""
    with patch(
        "main.collect_findings",
        side_effect=AuthenticationError("credenciales inválidas"),
    ):
        assert main.main([]) == 2
