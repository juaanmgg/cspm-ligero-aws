from unittest.mock import patch

from botocore.exceptions import ClientError

from cspm_auditor import CloudSecurityAuditor


@patch("boto3.client")
def test_check_iam_mfa_detects_missing_mfa(mock_boto_client):
    """Detecta y registra un usuario IAM que no tiene dispositivos MFA."""
    iam_client = mock_boto_client.return_value
    iam_client.list_users.return_value = {
        "Users": [{"UserName": "usuario-sin-mfa"}]
    }
    iam_client.list_mfa_devices.return_value = {"MFADevices": []}

    auditor = CloudSecurityAuditor()
    auditor.check_iam_mfa()

    assert auditor.findings == [
        {
            "Recurso": "Usuario IAM: usuario-sin-mfa",
            "Servicio": "IAM",
            "Riesgo": "Alto",
            "Descripción": (
                "El usuario no tiene Autenticación Multifactor (MFA) habilitada."
            ),
        }
    ]
    mock_boto_client.assert_any_call("iam")


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
    auditor.check_open_ssh()

    assert auditor.findings == [
        {
            "Recurso": "Security Group: grupo-publico (sg-0123456789abcdef0)",
            "Servicio": "EC2",
            "Riesgo": "Crítico",
            "Descripción": (
                "El puerto 22 (SSH) está expuesto a todo Internet (0.0.0.0/0)."
            ),
        }
    ]
    mock_boto_client.assert_any_call("ec2")


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
    auditor.check_public_s3_buckets()

    assert auditor.findings == [
        {
            "Recurso": "Bucket S3: bucket-publico",
            "Servicio": "S3",
            "Riesgo": "Crítico",
            "Descripción": (
                "El bucket NO tiene configurado ningún bloque de acceso público."
            ),
        }
    ]
    mock_boto_client.assert_any_call("s3")