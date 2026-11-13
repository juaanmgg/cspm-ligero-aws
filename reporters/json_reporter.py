"""JSON report generation."""

import json
from collections.abc import Sequence
from pathlib import Path
from dataclasses import asdict
from enum import Enum

from core.models import Finding

from .base import BaseReporter


class JSONReporter(BaseReporter):
    """Write findings using the architecture JSON schema."""

    def generate(
        self,
        findings: Sequence[Finding],
        output_dir: Path,
        timestamp: str,
    ) -> Path:
        report_path = output_dir / f"reporte_seguridad_{timestamp}.json"
        with report_path.open("w", encoding="utf-8") as report_file:
            json.dump(
                [self._serialize(finding) for finding in findings],
                report_file,
                indent=2,
                ensure_ascii=False,
            )
            report_file.write("\n")
        return report_path

    @staticmethod
    def _serialize(finding: Finding) -> dict[str, str]:
        serialized = asdict(finding)
        for key, value in serialized.items():
            if isinstance(value, Enum):
                serialized[key] = value.value
            elif hasattr(value, "isoformat"):
                serialized[key] = value.isoformat()
        return serialized
