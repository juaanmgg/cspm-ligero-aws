"""AWS security posture auditor."""

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import logging
import os
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError

from core.base import BaseAuditor
from core.exceptions import AuthenticationError, ResourceAccessError
from core.models import CloudProvider, Finding, Severity

LOGGER = logging.getLogger(__name__)
AWS_CLIENT_CONFIG = Config(
    connect_timeout=5,
    read_timeout=10,
    retries={"max_attempts": 3, "mode": "adaptive"},
)


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
        self._session = session if session is not None else boto3
        self.iam_client = iam_client or self._client("iam", region_name)
        self.ec2_client = ec2_client or self._client("ec2", region_name)
        self.s3_client = s3_client or self._client("s3", region_name)

    def _client(self, service_name: str, region_name: str) -> Any:
        return self._session.client(
            service_name,
            region_name=region_name,
            config=AWS_CLIENT_CONFIG,
        )

    def audit(self) -> Iterator[Finding]:
        """Yield findings from all AWS checks."""
        yield from self.check_iam_mfa()
        yield from self.check_open_ssh()
        yield from self.check_public_s3_buckets()

    def check_credentials(self) -> None:
        """Validate AWS credentials without auditing cloud resources."""
        try:
            self._client(
                "sts",
                os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
            ).get_caller_identity()
        except NoCredentialsError as error:
            raise AuthenticationError(
                "No se encontraron credenciales de AWS."
            ) from error
        except ClientError as error:
            raise AuthenticationError(
                f"No se pudieron validar las credenciales de AWS: {error}"
            ) from error

    def check_iam_mfa(self) -> Iterator[Finding]:
        """Yield IAM users without an MFA device using concurrent checks."""
        LOGGER.info("Auditando usuarios IAM (MFA)...")
        try:
            users = self.iam_client.list_users()["Users"]
            with ThreadPoolExecutor(max_workers=10) as executor:
                findings = executor.map(self._check_user_mfa, users)
                for finding in findings:
                    if finding is not None:
                        yield finding
        except NoCredentialsError as error:
            raise AuthenticationError(
                "No se encontraron credenciales de AWS."
            ) from error
        except ClientError as error:
            raise ResourceAccessError(f"Error leyendo IAM: {error}") from error

    def _check_user_mfa(self, user: dict[str, Any]) -> Finding | None:
        username = user["UserName"]
        if self.iam_client.list_mfa_devices(UserName=username)["MFADevices"]:
            return None
        return self._finding(
            "iam-mfa",
            username,
            Severity.HIGH,
            "IAM",
            f"Usuario IAM: {username}",
            "El usuario no tiene Autenticación Multifactor (MFA) habilitada.",
            "Habilita MFA para el usuario IAM.",
        )

    def check_open_ssh(self) -> Iterator[Finding]:
        """Yield security groups exposing SSH to the internet."""
        LOGGER.info("Auditando Grupos de Seguridad (Puerto 22)...")
        try:
            for security_group in self.ec2_client.describe_security_groups()[
                "SecurityGroups"
            ]:
                for rule in security_group["IpPermissions"]:
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    port_22_open = rule.get("IpProtocol") == "-1" or (
                        isinstance(from_port, int)
                        and isinstance(to_port, int)
                        and from_port <= 22 <= to_port
                    )
                    if not port_22_open:
                        continue
                    exposed_to_ipv4 = any(
                        ip_range.get("CidrIp") == "0.0.0.0/0"
                        for ip_range in rule.get("IpRanges", [])
                    )
                    exposed_to_ipv6 = any(
                        ip_range.get("CidrIpv6") == "::/0"
                        for ip_range in rule.get("Ipv6Ranges", [])
                    )
                    if exposed_to_ipv4 or exposed_to_ipv6:
                        group_id = security_group["GroupId"]
                        yield self._finding(
                            "open-ssh",
                            group_id,
                            Severity.CRITICAL,
                            "EC2",
                            f"Security Group: {security_group['GroupName']} ({group_id})",
                            "El puerto 22 (SSH) está expuesto a todo Internet.",
                            "Restringe el puerto 22 a redes de administración conocidas.",
                        )
        except NoCredentialsError as error:
            raise AuthenticationError(
                "No se encontraron credenciales de AWS."
            ) from error
        except ClientError as error:
            raise ResourceAccessError(f"Error leyendo EC2: {error}") from error

    def check_public_s3_buckets(self) -> Iterator[Finding]:
        """Yield bucket findings using concurrent public-access checks."""
        LOGGER.info("Auditando Buckets S3 (Acceso Público)...")
        try:
            buckets = self.s3_client.list_buckets()["Buckets"]
            with ThreadPoolExecutor(max_workers=10) as executor:
                findings = executor.map(self._check_bucket_public_access, buckets)
                for finding in findings:
                    if finding is not None:
                        yield finding
        except NoCredentialsError as error:
            raise AuthenticationError(
                "No se encontraron credenciales de AWS."
            ) from error
        except ClientError as error:
            raise ResourceAccessError(f"Error leyendo S3: {error}") from error

    def _check_bucket_public_access(self, bucket: dict[str, Any]) -> Finding | None:
        bucket_name = bucket["Name"]
        try:
            config = self.s3_client.get_public_access_block(Bucket=bucket_name)[
                "PublicAccessBlockConfiguration"
            ]
            if all(config.values()):
                return None
            return self._finding(
                "public-s3",
                bucket_name,
                Severity.HIGH,
                "S3",
                f"Bucket S3: {bucket_name}",
                "El bucket no tiene bloqueado el acceso público en todas sus políticas.",
                "Activa todas las opciones de bloqueo de acceso público del bucket.",
            )
        except NoCredentialsError as error:
            raise AuthenticationError(
                "No se encontraron credenciales de AWS."
            ) from error
        except ClientError as error:
            if (
                error.response["Error"]["Code"]
                == "NoSuchPublicAccessBlockConfiguration"
            ):
                return self._finding(
                    "public-s3",
                    bucket_name,
                    Severity.CRITICAL,
                    "S3",
                    f"Bucket S3: {bucket_name}",
                    "El bucket NO tiene configurado ningún bloque de acceso público.",
                    "Configura Public Access Block en el bucket S3.",
                )
            raise ResourceAccessError(
                f"Error leyendo el bucket S3 {bucket_name}: {error}"
            ) from error

    @staticmethod
    def _finding(
        check_id: str,
        resource_id: str,
        severity: Severity,
        service: str,
        resource: str,
        description: str,
        remediation: str,
    ) -> Finding:
        return Finding(
            id=f"aws-{check_id}-{resource_id}",
            provider=CloudProvider.AWS,
            service=service,
            resource=resource,
            severity=severity,
            description=description,
            timestamp=datetime.now(timezone.utc),
            remediation=remediation,
        )


CloudSecurityAuditor = AWSSecurityAuditor
