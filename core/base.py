"""Base contracts for cloud auditors."""

from abc import ABC, abstractmethod
from collections.abc import Iterator

from .models import Finding


class BaseAuditor(ABC):
    """Contract implemented by every cloud security auditor."""

    @abstractmethod
    def audit(self) -> Iterator[Finding]:
        """Yield all findings discovered by the auditor."""
