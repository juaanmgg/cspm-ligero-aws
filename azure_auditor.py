from typing import Any

from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient


class AzureSecurityAuditor:
    """Audita configuraciones de acceso público en Azure Blob Storage."""

    def __init__(
        self,
        storage_account_url: str,
        credential: Any | None = None,
    ) -> None:
        """Inicializa el auditor con una cuenta de almacenamiento de Azure."""
        self.storage_account_url = storage_account_url
        self.credential = (
            credential if credential is not None else DefaultAzureCredential()
        )
        self.blob_service_client = BlobServiceClient(
            account_url=storage_account_url,
            credential=self.credential,
        )
        self.findings: list[dict[str, str]] = []

    def check_public_storage_accounts(self) -> None:
        """Detecta acceso anónimo habilitado en la cuenta o sus contenedores."""
        service_properties = self.blob_service_client.get_service_properties()
        allow_blob_public_access = self._get_property(
            service_properties, "allow_blob_public_access"
        )

        if allow_blob_public_access is True:
            self.findings.append(
                {
                    "Servicio": "Azure Blob",
                    "Recurso": self.storage_account_url,
                    "Riesgo": "Crítico",
                    "Descripción": (
                        "La cuenta de almacenamiento permite acceso público "
                        "anónimo a blobs."
                    ),
                }
            )

        for container in self.blob_service_client.list_containers():
            container_name = self._get_property(container, "name")
            container_client = self.blob_service_client.get_container_client(
                container_name
            )
            container_properties = container_client.get_container_properties()
            public_access = self._get_property(container_properties, "public_access")

            if public_access in {"blob", "container"}:
                self.findings.append(
                    {
                        "Servicio": "Azure Blob",
                        "Recurso": f"{self.storage_account_url}/{container_name}",
                        "Riesgo": "Alto",
                        "Descripción": (
                            "El contenedor permite acceso público anónimo "
                            f"({public_access})."
                        ),
                    }
                )

    def run(self) -> list[dict[str, str]]:
        """Ejecuta la auditoría y devuelve todos los hallazgos encontrados."""
        self.check_public_storage_accounts()
        return self.findings

    @staticmethod
    def _get_property(resource: Any, name: str) -> Any:
        """Obtiene una propiedad tanto de modelos Azure como de diccionarios."""
        if isinstance(resource, dict):
            return resource.get(name)
        return getattr(resource, name, None)
