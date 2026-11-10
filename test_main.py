from pathlib import Path
from unittest.mock import patch

import main


def test_build_parser_uses_expected_defaults():
    """Usa AWS, ambos formatos y todas las severidades por defecto."""
    args = main.build_parser().parse_args([])

    assert args.provider == "aws"
    assert args.report_format == "both"
    assert args.min_severity == "Todos"
    assert args.output_dir == Path(".")


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
