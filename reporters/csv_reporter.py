"""CSV report generation."""

import csv
from collections.abc import Sequence
from pathlib import Path

from core.models import Finding

from .base import BaseReporter

FIELDS = [
    "id",
    "provider",
    "service",
    "resource",
    "severity",
    "description",
    "remediation",
    "timestamp",
]


class CSVReporter(BaseReporter):
    """Write findings as a typed, UTF-8 CSV document."""

    def generate(
        self,
        findings: Sequence[Finding],
        output_dir: Path,
        timestamp: str,
    ) -> Path:
        report_path = output_dir / f"reporte_seguridad_{timestamp}.csv"
        with report_path.open("w", newline="", encoding="utf-8") as report_file:
            writer = csv.DictWriter(report_file, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(self._row(finding) for finding in findings)
        return report_path

    @staticmethod
    def _row(finding: Finding) -> dict[str, str]:
        return {
            "id": finding.id,
            "provider": finding.provider.value,
            "service": finding.service,
            "resource": finding.resource,
            "severity": finding.severity.value,
            "description": finding.description,
            "remediation": finding.remediation,
            "timestamp": finding.timestamp.isoformat(),
        }
