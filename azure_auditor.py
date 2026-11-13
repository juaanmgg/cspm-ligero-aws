"""Azure Blob Storage security posture auditor."""

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import logging
from typing import Any
from urllib.parse import urlsplit

from azure.core.exceptions import AzureError, ClientAuthenticationError
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

from core.base import BaseAuditor
from core.exceptions import AuthenticationError, ResourceAccessError
from core.models import CloudProvider, Finding, Severity

LOGGER = logging.getLogger(__name__)


class AzureSecurityAuditor(BaseAuditor):
    """Audit public access settings in an Azure Blob Storage account."""

    def __init__(
        self,
        storage_account_url: str,
        credential: Any | None = None,
        blob_service_client: Any | None = None,
    ) -> None:
        if not self._is_valid_storage_url(storage_account_url):
            raise ValueError("storage_account_url debe ser una URL HTTPS válida.")
        self.storage_account_url = storage_account_url
        self.credential = credential
        if blob_service_client is None:
            try:
                self.credential = (
                    credential if credential is not None else DefaultAzureCredential()
                )
                self.blob_service_client = BlobServiceClient(
                    account_url=storage_account_url,
                    credential=self.credential,
                    connection_timeout=5,
                    read_timeout=10,
                )
            except ClientAuthenticationError as error:
                raise AuthenticationError(
                    f"No se pudieron validar las credenciales de Azure: {error}"
                ) from error
        else:
            self.blob_service_client = blob_service_client

    def audit(self) -> Iterator[Finding]:
        """Yield findings for public account and container access."""
        try:
            yield from self.check_public_storage_accounts()
        except ClientAuthenticationError as error:
            raise AuthenticationError(
                f"No se pudieron validar las credenciales de Azure: {error}"
            ) from error
        except AzureError as error:
            LOGGER.error("Error leyendo Azure Blob Storage: %s", error)
            raise ResourceAccessError(
                f"Error leyendo Azure Blob Storage: {error}"
            ) from error

    def check_credentials(self) -> None:
        """Validate Azure credentials without enumerating containers."""
        try:
            self.blob_service_client.get_service_properties()
        except ClientAuthenticationError as error:
            raise AuthenticationError(
                f"No se pudieron validar las credenciales de Azure: {error}"
            ) from error
        except AzureError as error:
            raise ResourceAccessError(
                f"No se pudo validar el cliente de Azure: {error}"
            ) from error

    def check_public_storage_accounts(self) -> Iterator[Finding]:
        """Yield account and container public-access findings."""
        service_properties = self.blob_service_client.get_service_properties()
        if self._get_property(service_properties, "allow_blob_public_access") is True:
            yield self._finding(
                "account-public",
                Severity.CRITICAL,
                self.storage_account_url,
                "La cuenta de almacenamiento permite acceso público anónimo a blobs.",
                "Deshabilita el acceso público anónimo en la cuenta de almacenamiento.",
            )

        containers = self.blob_service_client.list_containers()
        with ThreadPoolExecutor(max_workers=10) as executor:
            findings = executor.map(self._check_container, containers)
            for finding in findings:
                if finding is not None:
                    yield finding

    def _check_container(self, container: Any) -> Finding | None:
        container_name = self._get_property(container, "name")
        container_properties = self.blob_service_client.get_container_client(
            container_name
        ).get_container_properties()
        public_access = self._get_property(container_properties, "public_access")
        if public_access not in {"blob", "container"}:
            return None
        resource = f"{self.storage_account_url}/{container_name}"
        return self._finding(
            f"container-{public_access}",
            Severity.HIGH,
            resource,
            f"El contenedor permite acceso público anónimo ({public_access}).",
            "Deshabilita el acceso público del contenedor.",
        )

    def run(self) -> Iterator[Finding]:
        """Backward-compatible alias for :meth:`audit`."""
        return self.audit()

    @staticmethod
    def _get_property(resource: Any, name: str) -> Any:
        """Read a property from either an Azure model or a dictionary."""
        if isinstance(resource, dict):
            return resource.get(name)
        return getattr(resource, name, None)

    @staticmethod
    def _is_valid_storage_url(storage_account_url: str) -> bool:
        """Validate an HTTPS URL with a hostname and no embedded credentials."""
        if not isinstance(storage_account_url, str):
            return False
        try:
            parsed = urlsplit(storage_account_url)
            return (
                parsed.scheme == "https"
                and parsed.hostname is not None
                and parsed.username is None
                and parsed.password is None
                and parsed.query == ""
                and parsed.fragment == ""
            )
        except ValueError:
            return False

    def _finding(
        self,
        finding_id: str,
        severity: Severity,
        resource: str,
        description: str,
        remediation: str,
    ) -> Finding:
        return Finding(
            id=f"azure-{finding_id}",
            provider=CloudProvider.AZURE,
            service="Azure Blob",
            resource=resource,
            severity=severity,
            description=description,
            timestamp=datetime.now(timezone.utc),
            remediation=remediation,
        )
