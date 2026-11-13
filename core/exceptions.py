"""Domain exceptions raised by CSPM auditors."""


class CSPMError(Exception):
    """Base exception for expected CSPM failures."""


class AuthenticationError(CSPMError):
    """Raised when cloud credentials cannot authenticate."""


class ResourceAccessError(CSPMError):
    """Raised when a cloud resource cannot be read."""
