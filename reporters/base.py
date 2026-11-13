"""Contracts for report generators."""

from abc import ABC, abstractmethod
from collections.abc import Sequence
from pathlib import Path

from core.models import Finding


class BaseReporter(ABC):
    """Contract implemented by each report format."""

    @abstractmethod
    def generate(
        self,
        findings: Sequence[Finding],
        output_dir: Path,
        timestamp: str,
    ) -> Path:
        """Generate a report and return its path."""
