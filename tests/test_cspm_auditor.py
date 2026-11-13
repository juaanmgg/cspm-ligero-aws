from unittest.mock import patch

from botocore.exceptions import ClientError, NoCredentialsError
import pytest

from cspm_auditor import AWS_CLIENT_CONFIG, CloudSecurityAuditor
from core.exceptions import AuthenticationError


@patch("boto3.client")
def test_check_iam_mfa_detects_missing_mfa(mock_boto_client):
    """Detecta y registra un usuario IAM que no tiene dispositivos MFA."""
    iam_client = mock_boto_client.return_value
    iam_client.list_users.return_value = {"Users": [{"UserName": "usuario-sin-mfa"}]}
    iam_client.list_mfa_devices.return_value = {"MFADevices": []}

    auditor = CloudSecurityAuditor()
    findings = list(auditor.check_iam_mfa())

    assert [finding.to_dict() for finding in findings] == [
        {
            "Recurso": "Usuario IAM: usuario-sin-mfa",
            "Servicio": "IAM",
            "Riesgo": "Alto",
            "Descripción": (
                "El usuario no tiene Autenticación Multifactor (MFA) habilitada."
            ),
        }
    ]
    mock_boto_client.assert_any_call(
        "iam", region_name="us-east-1", config=AWS_CLIENT_CONFIG
    )


@patch("boto3.client")
def test_check_open_ssh_detects_public_port_22(mock_boto_client):
    """Detecta un Security Group que expone el puerto SSH a Internet."""
    ec2_client = mock_boto_client.return_value
    ec2_client.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupName": "grupo-publico",
                "GroupId": "sg-0123456789abcdef0",
                "IpPermissions": [
                    {
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ]
    }

    auditor = CloudSecurityAuditor()
    findings = list(auditor.check_open_ssh())

    assert [finding.to_dict() for finding in findings] == [
        {
            "Recurso": "Security Group: grupo-publico (sg-0123456789abcdef0)",
            "Servicio": "EC2",
            "Riesgo": "Crítico",
            "Descripción": "El puerto 22 (SSH) está expuesto a todo Internet.",
        }
    ]
    mock_boto_client.assert_any_call(
        "ec2", region_name="us-east-1", config=AWS_CLIENT_CONFIG
    )


@patch("boto3.client")
def test_check_open_ssh_detects_port_range(mock_boto_client):
    """Detecta SSH cuando el puerto está dentro de un rango permitido."""
    ec2_client = mock_boto_client.return_value
    ec2_client.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupName": "grupo-rango",
                "GroupId": "sg-range",
                "IpPermissions": [
                    {
                        "FromPort": 20,
                        "ToPort": 25,
                        "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ]
    }

    findings = list(CloudSecurityAuditor().check_open_ssh())

    assert len(findings) == 1


@patch("boto3.client")
def test_check_open_ssh_detects_public_ipv6(mock_boto_client):
    """Detecta SSH expuesto mediante el rango IPv6 global."""
    ec2_client = mock_boto_client.return_value
    ec2_client.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupName": "grupo-ipv6",
                "GroupId": "sg-ipv6",
                "IpPermissions": [
                    {
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpProtocol": "tcp",
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                    }
                ],
            }
        ]
    }

    findings = list(CloudSecurityAuditor().check_open_ssh())

    assert len(findings) == 1


@patch("boto3.client")
def test_check_public_s3_buckets_detects_unrestricted_bucket(mock_boto_client):
    """Detecta un bucket S3 sin configuración de bloqueo de acceso público."""
    s3_client = mock_boto_client.return_value
    s3_client.list_buckets.return_value = {"Buckets": [{"Name": "bucket-publico"}]}
    s3_client.get_public_access_block.side_effect = ClientError(
        {
            "Error": {
                "Code": "NoSuchPublicAccessBlockConfiguration",
                "Message": "The public access block configuration was not found",
            }
        },
        "GetPublicAccessBlock",
    )

    auditor = CloudSecurityAuditor()
    findings = list(auditor.check_public_s3_buckets())

    assert [finding.to_dict() for finding in findings] == [
        {
            "Recurso": "Bucket S3: bucket-publico",
            "Servicio": "S3",
            "Riesgo": "Crítico",
            "Descripción": (
                "El bucket NO tiene configurado ningún bloque de acceso público."
            ),
        }
    ]
    mock_boto_client.assert_any_call(
        "s3", region_name="us-east-1", config=AWS_CLIENT_CONFIG
    )


@patch("boto3.client")
def test_audits_without_vulnerabilities_return_empty_findings(mock_boto_client):
    """Devuelve una lista vacía cuando AWS no presenta configuraciones inseguras."""
    aws_client = mock_boto_client.return_value
    aws_client.list_users.return_value = {"Users": []}
    aws_client.describe_security_groups.return_value = {"SecurityGroups": []}
    aws_client.list_buckets.return_value = {"Buckets": []}

    auditor = CloudSecurityAuditor()
    assert list(auditor.audit()) == []


@patch.dict("os.environ", {"AWS_DEFAULT_REGION": "eu-west-1"})
@patch("boto3.client")
def test_cloud_security_auditor_uses_configured_aws_region(mock_boto_client):
    """Usa la región AWS definida en AWS_DEFAULT_REGION para cada cliente."""
    CloudSecurityAuditor()

    assert mock_boto_client.call_args_list == [
        (("iam",), {"region_name": "eu-west-1", "config": AWS_CLIENT_CONFIG}),
        (("ec2",), {"region_name": "eu-west-1", "config": AWS_CLIENT_CONFIG}),
        (("s3",), {"region_name": "eu-west-1", "config": AWS_CLIENT_CONFIG}),
    ]


@patch("boto3.client")
def test_check_iam_mfa_handles_missing_aws_credentials(mock_boto_client):
    """Muestra el error de credenciales y no interrumpe la auditoría IAM."""
    mock_boto_client.return_value.list_users.side_effect = NoCredentialsError()

    auditor = CloudSecurityAuditor()
    with pytest.raises(AuthenticationError):
        list(auditor.check_iam_mfa())


@patch("boto3.client")
def test_check_open_ssh_handles_missing_aws_credentials(mock_boto_client):
    """Muestra el error de credenciales y no interrumpe la auditoría EC2."""
    mock_boto_client.return_value.describe_security_groups.side_effect = (
        NoCredentialsError()
    )

    auditor = CloudSecurityAuditor()
    with pytest.raises(AuthenticationError):
        list(auditor.check_open_ssh())


@patch("boto3.client")
def test_check_public_s3_buckets_handles_missing_aws_credentials(mock_boto_client):
    """Muestra el error de credenciales y no interrumpe la auditoría S3."""
    mock_boto_client.return_value.list_buckets.side_effect = NoCredentialsError()

    auditor = CloudSecurityAuditor()
    with pytest.raises(AuthenticationError):
        list(auditor.check_public_s3_buckets())


@patch("cspm_auditor.ThreadPoolExecutor")
@patch("boto3.client")
def test_iam_mfa_uses_bounded_thread_pool(mock_boto_client, mock_executor):
    """Usa diez workers para consultar MFA sin acumular dicts legacy."""
    iam_client = mock_boto_client.return_value
    iam_client.list_users.return_value = {
        "Users": [{"UserName": "user-1"}, {"UserName": "user-2"}]
    }
    iam_client.list_mfa_devices.return_value = {"MFADevices": []}
    executor = mock_executor.return_value.__enter__.return_value
    executor.map.side_effect = lambda function, users: map(function, users)

    findings = list(CloudSecurityAuditor().check_iam_mfa())

    mock_executor.assert_called_once_with(max_workers=10)
    assert len(findings) == 2


@patch("cspm_auditor.ThreadPoolExecutor")
@patch("boto3.client")
def test_s3_public_access_uses_bounded_thread_pool(mock_boto_client, mock_executor):
    """Usa diez workers para consultar el bloqueo de acceso de buckets."""
    s3_client = mock_boto_client.return_value
    s3_client.list_buckets.return_value = {
        "Buckets": [{"Name": "bucket-1"}, {"Name": "bucket-2"}]
    }
    s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    executor = mock_executor.return_value.__enter__.return_value
    executor.map.side_effect = lambda function, buckets: map(function, buckets)

    assert list(CloudSecurityAuditor().check_public_s3_buckets()) == []

    mock_executor.assert_called_once_with(max_workers=10)
