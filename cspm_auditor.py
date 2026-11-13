"""AWS security posture auditor."""

from collections.abc import Iterator
from datetime import datetime, timezone
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from core.base import BaseAuditor
from core.exceptions import AuthenticationError, ResourceAccessError
from core.models import CloudProvider, Finding, Severity

LOGGER = logging.getLogger(__name__)


class AWSSecurityAuditor(BaseAuditor):
    """Audit IAM, EC2 security groups and S3 public access settings."""

    def __init__(
        self,
        session: Any | None = None,
        iam_client: Any | None = None,
        ec2_client: Any | None = None,
        s3_client: Any | None = None,
    ) -> None:
        region_name = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        aws_session = session if session is not None else boto3
        self.iam_client = iam_client or aws_session.client("iam", region_name=region_name)
        self.ec2_client = ec2_client or aws_session.client("ec2", region_name=region_name)
        self.s3_client = s3_client or aws_session.client("s3", region_name=region_name)

    def audit(self) -> Iterator[Finding]:
        """Yield findings from all AWS checks."""
        yield from self.check_iam_mfa()
        yield from self.check_open_ssh()
        yield from self.check_public_s3_buckets()

    def check_iam_mfa(self) -> Iterator[Finding]:
        """Yield IAM users without an MFA device."""
        LOGGER.info("Auditando usuarios IAM (MFA)...")
        try:
            for user in self.iam_client.list_users()["Users"]:
                username = user["UserName"]
                if not self.iam_client.list_mfa_devices(
                    UserName=username
                )["MFADevices"]:
                    yield self._finding(
                        "iam-mfa",
                        username,
                        Severity.HIGH,
                        "IAM",
                        f"Usuario IAM: {username}",
                        "El usuario no tiene Autenticación Multifactor (MFA) habilitada.",
                    )
        except NoCredentialsError as error:
            raise AuthenticationError("No se encontraron credenciales de AWS.") from error
        except ClientError as error:
            raise ResourceAccessError(f"Error leyendo IAM: {error}") from error

    def check_open_ssh(self) -> Iterator[Finding]:
        """Yield security groups exposing SSH to the internet."""
        LOGGER.info("Auditando Grupos de Seguridad (Puerto 22)...")
        try:
            for security_group in self.ec2_client.describe_security_groups()[
                "SecurityGroups"
            ]:
                for rule in security_group["IpPermissions"]:
                    ssh_or_all = (
                        rule.get("FromPort") == 22 and rule.get("ToPort") == 22
                    ) or rule.get("IpProtocol") == "-1"
                    if ssh_or_all:
                        for ip_range in rule.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                group_id = security_group["GroupId"]
                                yield self._finding(
                                    "open-ssh",
                                    group_id,
                                    Severity.CRITICAL,
                                    "EC2",
                                    f"Security Group: {security_group['GroupName']} ({group_id})",
                                    "El puerto 22 (SSH) está expuesto a todo Internet (0.0.0.0/0).",
                                )
        except NoCredentialsError as error:
            raise AuthenticationError("No se encontraron credenciales de AWS.") from error
        except ClientError as error:
            raise ResourceAccessError(f"Error leyendo EC2: {error}") from error

    def check_public_s3_buckets(self) -> Iterator[Finding]:
        """Yield buckets without complete public access blocking."""
        LOGGER.info("Auditando Buckets S3 (Acceso Público)...")
        try:
            for bucket in self.s3_client.list_buckets()["Buckets"]:
                bucket_name = bucket["Name"]
                try:
                    config = self.s3_client.get_public_access_block(
                        Bucket=bucket_name
                    )["PublicAccessBlockConfiguration"]
                    if not all(config.values()):
                        yield self._finding(
                            "public-s3",
                            bucket_name,
                            Severity.HIGH,
                            "S3",
                            f"Bucket S3: {bucket_name}",
                            "El bucket no tiene bloqueado el acceso público en todas sus políticas.",
                        )
                except NoCredentialsError as error:
                    raise AuthenticationError(
                        "No se encontraron credenciales de AWS."
                    ) from error
                except ClientError as error:
                    if error.response["Error"]["Code"] == (
                        "NoSuchPublicAccessBlockConfiguration"
                    ):
                        yield self._finding(
                            "public-s3",
                            bucket_name,
                            Severity.CRITICAL,
                            "S3",
                            f"Bucket S3: {bucket_name}",
                            "El bucket NO tiene configurado ningún bloque de acceso público.",
                        )
                    else:
                        raise ResourceAccessError(
                            f"Error leyendo el bucket S3 {bucket_name}: {error}"
                        ) from error
        except NoCredentialsError as error:
            raise AuthenticationError("No se encontraron credenciales de AWS.") from error
        except ClientError as error:
            raise ResourceAccessError(f"Error leyendo S3: {error}") from error

    @staticmethod
    def _finding(
        check_id: str,
        resource_id: str,
        severity: Severity,
        service: str,
        resource: str,
        description: str,
    ) -> Finding:
        return Finding(
            id=f"aws-{check_id}-{resource_id}",
            provider=CloudProvider.AWS,
            service=service,
            resource=resource,
            severity=severity,
            description=description,
            timestamp=datetime.now(timezone.utc),
        )


CloudSecurityAuditor = AWSSecurityAuditor
