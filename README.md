# 🛡️ AWS Lightweight CSPM (Cloud Security Posture Management)

Un auditor de seguridad en la nube automatizado diseñado para identificar rápidamente las malas configuraciones más comunes en infraestructuras de AWS. Ideal para pipelines de DevSecOps y revisiones rápidas de infraestructura.

## 🎯 Características Principales
* **Auditoría IAM:** Identifica usuarios sin Autenticación Multifactor (MFA) habilitada.
* **Auditoría de Red (EC2):** Detecta Grupos de Seguridad (Security Groups) con el puerto 22 (SSH) abierto a `0.0.0.0/0`.
* **Auditoría de Almacenamiento (S3):** Localiza buckets que carecen de configuraciones restrictivas de Bloqueo de Acceso Público.
* **Reportes Automatizados:** Genera un archivo detallado con el servicio, recurso, nivel de riesgo y descripción de la vulnerabilidad.

## 🚀 Requisitos Previos
* Python 3.8+
* Credenciales de AWS configuradas localmente (`aws configure`) con permisos de lectura (ej. `SecurityAudit` o `ReadOnlyAccess`).

## 🛠️ Instalación y Uso

1. Clona el repositorio:
```bash
git clone [https://github.com/TU_USUARIO/cspm-ligero-aws.git](https://github.com/TU_USUARIO/cspm-ligero-aws.git)
cd cspm-ligero-aws
```

2. Instala las dependencias:
```bash
pip install -r requirements.txt
```

3. Ejecuta el auditor:
```bash
python cspm_auditor.py
```