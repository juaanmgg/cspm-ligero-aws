from unittest.mock import patch

from azure_auditor import AzureSecurityAuditor


@patch("azure_auditor.DefaultAzureCredential")
@patch("azure_auditor.BlobServiceClient")
def test_check_public_storage_accounts_detects_public_container(
    mock_blob_service_client,
    mock_default_credential,
):
    """Detecta un contenedor Blob con acceso anónimo sin llamar a Azure."""
    mock_default_credential.return_value = "mock-credential"
    blob_service_client = mock_blob_service_client.return_value
    blob_service_client.get_service_properties.return_value = {
        "allow_blob_public_access": False
    }
    blob_service_client.list_containers.return_value = [{"name": "public-container"}]
    container_client = blob_service_client.get_container_client.return_value
    container_client.get_container_properties.return_value = {
        "public_access": "blob"
    }

    auditor = AzureSecurityAuditor("https://storage.blob.core.windows.net")
    findings = auditor.run()

    assert findings == [
        {
            "Servicio": "Azure Blob",
            "Recurso": (
                "https://storage.blob.core.windows.net/public-container"
            ),
            "Riesgo": "Alto",
            "Descripción": (
                "El contenedor permite acceso público anónimo (blob)."
            ),
        }
    ]
    mock_blob_service_client.assert_called_once_with(
        account_url="https://storage.blob.core.windows.net",
        credential="mock-credential",
    )
    blob_service_client.get_container_client.assert_called_once_with(
        "public-container"
    )


@patch("azure_auditor.DefaultAzureCredential")
@patch("azure_auditor.BlobServiceClient")
def test_check_public_storage_accounts_detects_public_account(
    mock_blob_service_client,
    mock_default_credential,
):
    """Detecta una cuenta con acceso público anónimo habilitado."""
    mock_default_credential.return_value = "mock-credential"
    blob_service_client = mock_blob_service_client.return_value
    blob_service_client.get_service_properties.return_value = {
        "allow_blob_public_access": True
    }
    blob_service_client.list_containers.return_value = []

    auditor = AzureSecurityAuditor("https://storage.blob.core.windows.net")
    findings = auditor.run()

    assert findings[0]["Riesgo"] == "Crítico"
    assert findings[0]["Servicio"] == "Azure Blob"
