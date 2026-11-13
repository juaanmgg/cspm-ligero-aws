from unittest.mock import MagicMock, patch

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
    findings = list(auditor.audit())

    assert [finding.to_dict() for finding in findings] == [
        {
            "Servicio": "Azure Blob",
            "Recurso": "https://storage.blob.core.windows.net/public-container",
            "Riesgo": "Alto",
            "Descripción": "El contenedor permite acceso público anónimo (blob).",
        }
    ]
    mock_blob_service_client.assert_called_once_with(
        account_url="https://storage.blob.core.windows.net",
        credential="mock-credential",
        connection_timeout=5,
        read_timeout=10,
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
    findings = list(auditor.audit())

    assert findings[0].severity.value == "CRITICAL"
    assert findings[0].service == "Azure Blob"


@patch("azure_auditor.DefaultAzureCredential")
@patch("azure_auditor.BlobServiceClient")
def test_audits_without_vulnerabilities_return_empty_findings(
    mock_blob_service_client,
    mock_default_credential,
):
    """Devuelve una lista vacía cuando Azure no presenta acceso público."""
    mock_default_credential.return_value = "mock-credential"
    blob_service_client = mock_blob_service_client.return_value
    blob_service_client.get_service_properties.return_value = {
        "allow_blob_public_access": False
    }
    blob_service_client.list_containers.return_value = []

    auditor = AzureSecurityAuditor("https://storage.blob.core.windows.net")

    assert list(auditor.audit()) == []


@patch("azure_auditor.ThreadPoolExecutor")
def test_container_inspection_uses_bounded_thread_pool(mock_executor):
    """Usa diez workers para inspeccionar contenedores Blob."""
    client = MagicMock()
    client.get_service_properties.return_value = {
        "allow_blob_public_access": False
    }
    client.list_containers.return_value = [{"name": "container-1"}]
    client.get_container_client.return_value.get_container_properties.return_value = {
        "public_access": None
    }
    executor = mock_executor.return_value.__enter__.return_value
    executor.map.side_effect = lambda function, containers: map(function, containers)

    auditor = AzureSecurityAuditor(
        "https://storage.blob.core.windows.net",
        blob_service_client=client,
    )

    assert list(auditor.audit()) == []
    mock_executor.assert_called_once_with(max_workers=10)
