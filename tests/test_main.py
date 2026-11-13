from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import main
from core.exceptions import AuthenticationError
from core.models import CloudProvider, Finding, Severity


def make_finding(severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id="finding-1",
        provider=CloudProvider.AWS,
        service="IAM",
        resource="user",
        severity=severity,
        description="description",
        timestamp=datetime.now(),
        remediation="remediation",
    )


def test_build_parser_uses_phase_three_defaults():
    args = main.build_parser().parse_args([])

    assert args.provider == "aws"
    assert args.report_format == "all"
    assert args.min_severity == "Todos"
    assert args.output_dir == Path(".")
    assert args.fail_on_severity is None
    assert args.dry_run is False
    assert args.verbose is False


def test_main_provider_flag_selects_requested_provider():
    with patch("main.collect_findings", return_value=[]) as collect_findings:
        assert main.main(["--provider", "azure"]) == 0

    collect_findings.assert_called_once_with("azure")


def test_main_dispatches_only_csv_report(tmp_path):
    with (
        patch("main.collect_findings", return_value=[make_finding()]),
        patch("main.generate_reports") as generate_reports,
    ):
        assert main.main(["--format", "csv", "--output-dir", str(tmp_path)]) == 0

    generate_reports.assert_called_once()
    assert generate_reports.call_args.args[1] == "csv"


def test_filter_findings_keeps_finding_objects():
    findings = [make_finding(Severity.CRITICAL), make_finding(Severity.LOW)]

    filtered = main.filter_findings(findings, "Crítico")

    assert filtered == findings[:1]
    assert all(isinstance(finding, Finding) for finding in filtered)


def test_fail_on_severity_returns_one_when_threshold_is_reached(tmp_path):
    with (
        patch("main.collect_findings", return_value=[make_finding(Severity.CRITICAL)]),
        patch("main.generate_reports"),
    ):
        assert (
            main.main(
                [
                    "--format",
                    "csv",
                    "--fail-on-severity",
                    "HIGH",
                    "--output-dir",
                    str(tmp_path),
                ]
            )
            == 1
        )


def test_dry_run_validates_credentials_without_auditing():
    with (
        patch("main.validate_credentials") as validate_credentials,
        patch("main.collect_findings") as collect_findings,
    ):
        assert main.main(["--dry-run", "--verbose"]) == 0

    validate_credentials.assert_called_once_with("aws")
    collect_findings.assert_not_called()


def test_authentication_error_returns_two():
    with patch(
        "main.collect_findings",
        side_effect=AuthenticationError("credenciales inválidas"),
    ):
        assert main.main([]) == 2
