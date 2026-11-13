"""Immutable domain models shared by cloud auditors."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CloudProvider(str, Enum):
    """Supported cloud providers."""

    AWS = "AWS"
    AZURE = "AZURE"


@dataclass(frozen=True, slots=True)
class Finding:
    """A security finding produced by an auditor."""

    id: str
    provider: CloudProvider
    service: str
    resource: str
    severity: Severity
    description: str
    timestamp: datetime
    remediation: str = ""

    def to_dict(self) -> dict[str, str]:
        """Return the legacy Spanish keys used by the report writers."""
        severity_labels = {
            Severity.CRITICAL: "Crítico",
            Severity.HIGH: "Alto",
            Severity.MEDIUM: "Medio",
            Severity.LOW: "Bajo",
            Severity.INFO: "Info",
        }
        return {
            "Servicio": self.service,
            "Recurso": self.resource,
            "Riesgo": severity_labels[self.severity],
            "Descripción": self.description,
        }
