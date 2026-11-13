import csv
from datetime import datetime, timezone
import json

from core.models import CloudProvider, Finding, Severity
from reporters import CSVReporter, JSONReporter, PDFReporter


def sample_findings() -> list[Finding]:
    return [
        Finding(
            id="finding-1",
            provider=CloudProvider.AWS,
            service="IAM",
            resource="Usuario: ágil",
            severity=Severity.HIGH,
            description="Descripción con tilde",
            timestamp=datetime(2026, 11, 13, tzinfo=timezone.utc),
            remediation="Activa MFA",
        )
    ]


def test_csv_reporter_writes_typed_finding_fields(tmp_path):
    report_path = CSVReporter().generate(
        sample_findings(), tmp_path, "20261113_000000"
    )

    with report_path.open(encoding="utf-8", newline="") as report_file:
        rows = list(csv.DictReader(report_file))

    assert rows[0]["id"] == "finding-1"
    assert rows[0]["provider"] == "AWS"
    assert rows[0]["severity"] == "HIGH"
    assert rows[0]["remediation"] == "Activa MFA"
    assert rows[0]["timestamp"] == "2026-11-13T00:00:00+00:00"


def test_json_reporter_writes_schema_fields_and_iso_timestamp(tmp_path):
    report_path = JSONReporter().generate(
        sample_findings(), tmp_path, "20261113_000000"
    )

    payload = json.loads(report_path.read_text(encoding="utf-8"))

    assert payload[0]["provider"] == "AWS"
    assert payload[0]["severity"] == "HIGH"
    assert payload[0]["description"] == "Descripción con tilde"
    assert payload[0]["timestamp"] == "2026-11-13T00:00:00+00:00"


def test_pdf_reporter_supports_unicode_text(tmp_path):
    report_path = PDFReporter().generate(
        sample_findings(), tmp_path, "20261113_000000"
    )

    assert report_path.exists()
    assert report_path.read_bytes().startswith(b"%PDF")
