import boto3
import csv
from datetime import datetime
from botocore.exceptions import ClientError
from fpdf import FPDF

class CloudSecurityAuditor:
    def __init__(self):
        # Inicializa los clientes de AWS
        self.iam_client = boto3.client('iam')
        self.ec2_client = boto3.client('ec2')
        self.s3_client = boto3.client('s3')
        self.findings = []

    def check_iam_mfa(self):
        """Verifica si los usuarios de IAM tienen MFA habilitado."""
        print("[*] Auditando usuarios IAM (MFA)...")
        try:
            users = self.iam_client.list_users()['Users']
            for user in users:
                username = user['UserName']
                mfa_devices = self.iam_client.list_mfa_devices(UserName=username)['MFADevices']
                
                if not mfa_devices:
                    self.findings.append({
                        'Recurso': f'Usuario IAM: {username}',
                        'Servicio': 'IAM',
                        'Riesgo': 'Alto',
                        'Descripción': 'El usuario no tiene Autenticación Multifactor (MFA) habilitada.'
                    })
        except ClientError as e:
            print(f"[!] Error leyendo IAM: {e}")

    def check_open_ssh(self):
        """Busca Security Groups con el puerto 22 abierto al mundo (0.0.0.0/0)."""
        print("[*] Auditando Grupos de Seguridad (Puerto 22)...")
        try:
            sgs = self.ec2_client.describe_security_groups()['SecurityGroups']
            for sg in sgs:
                sg_name = sg['GroupName']
                sg_id = sg['GroupId']
                
                for rule in sg['IpPermissions']:
                    # Verifica si el puerto 22 está en el rango permitido
                    if rule.get('FromPort') == 22 and rule.get('ToPort') == 22 or rule.get('IpProtocol') == '-1':
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                self.findings.append({
                                    'Recurso': f'Security Group: {sg_name} ({sg_id})',
                                    'Servicio': 'EC2',
                                    'Riesgo': 'Crítico',
                                    'Descripción': 'El puerto 22 (SSH) está expuesto a todo Internet (0.0.0.0/0).'
                                })
        except ClientError as e:
            print(f"[!] Error leyendo EC2: {e}")

    def check_public_s3_buckets(self):
        """Verifica si hay buckets de S3 sin el bloqueo de acceso público."""
        print("[*] Auditando Buckets S3 (Acceso Público)...")
        try:
            buckets = self.s3_client.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    pab = self.s3_client.get_public_access_block(Bucket=bucket_name)
                    config = pab['PublicAccessBlockConfiguration']
                    # Si alguna de las configuraciones de bloqueo es False, hay riesgo
                    if not all(config.values()):
                        self.findings.append({
                            'Recurso': f'Bucket S3: {bucket_name}',
                            'Servicio': 'S3',
                            'Riesgo': 'Alto',
                            'Descripción': 'El bucket no tiene bloqueado el acceso público en todas sus políticas.'
                        })
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        self.findings.append({
                            'Recurso': f'Bucket S3: {bucket_name}',
                            'Servicio': 'S3',
                            'Riesgo': 'Crítico',
                            'Descripción': 'El bucket NO tiene configurado ningún bloque de acceso público.'
                        })
        except ClientError as e:
            print(f"[!] Error leyendo S3: {e}")

    def generate_csv_report(self):
        """Genera un reporte CSV con los hallazgos de seguridad."""
        if not self.findings:
            print("[+] ¡Felicidades! No se encontraron configuraciones inseguras.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reporte_seguridad_{timestamp}.csv"
        
        campos = ['Servicio', 'Recurso', 'Riesgo', 'Descripción']
        
        with open(filename, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=campos)
            writer.writeheader()
            for finding in self.findings:
                writer.writerow(finding)
                
        print(f"[+] Auditoría completada. Se encontraron {len(self.findings)} vulnerabilidades.")
        print(f"[+] Reporte generado exitosamente: {filename}")

    def generate_pdf_report(self):
        """Genera un reporte PDF elegante con los hallazgos de seguridad."""
        if not self.findings:
            return # No hay vulnerabilidades

        pdf = FPDF()
        pdf.add_page()
        
        # Título
        pdf.set_font("helvetica", "B", 16)
        pdf.cell(0, 10, "Auditoría de Seguridad AWS (CSPM Ligero)", ln=True, align="C")
        pdf.ln(5)
        
        # Fecha
        pdf.set_font("helvetica", "I", 10)
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pdf.cell(0, 10, f"Fecha de generación: {timestamp_str}", ln=True, align="R")
        pdf.ln(5)

        # Iterar sobre los hallazgos
        for idx, finding in enumerate(self.findings, 1):
            # Asignar color según el riesgo (Rojo para Crítico, Naranja para Alto)
            if finding['Riesgo'] == 'Crítico':
                pdf.set_text_color(220, 53, 69) # Rojo
            else:
                pdf.set_text_color(253, 126, 20) # Naranja oscuro
                
            pdf.set_font("helvetica", "B", 12)
            pdf.cell(0, 8, f"{idx}. [{finding['Riesgo']}] {finding['Servicio']} - {finding['Recurso']}", ln=True)
            
            pdf.set_text_color(0, 0, 0) # Negro para la descripción
            pdf.set_font("helvetica", "", 11)
            pdf.multi_cell(0, 6, txt=f"Detalle: {finding['Descripción']}")
            pdf.ln(4)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reporte_seguridad_{timestamp}.pdf"
        pdf.output(filename)
        print(f"[+] Reporte PDF generado exitosamente: {filename}")

    def run(self):
        self.check_iam_mfa()
        self.check_open_ssh()
        self.check_public_s3_buckets()
        self.generate_pdf_report()
        self.generate_csv_report()

if __name__ == "__main__":
    auditor = CloudSecurityAuditor()
    auditor.run()