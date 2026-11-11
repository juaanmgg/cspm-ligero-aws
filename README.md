<div align="center">

# Multi-Cloud Lightweight CSPM (Cloud Security Posture Management)

</div>

---

Una herramienta CLI de auditoría de seguridad automatizada diseñada para identificar malas configuraciones en entornos **AWS** y **Azure**. Ideal para integraciones en pipelines de DevSecOps y revisiones continuas de infraestructura.

## 🎯 Características Principales

- **AWS Audit:**
  - Identificación de usuarios IAM sin Autenticación Multifactor (MFA).
  - Detección de Security Groups con el puerto 22 (SSH) abierto a `0.0.0.0/0`.
  - Verificación de bloqueos de acceso público en Buckets S3.
- **Azure Audit:**
  - Detección de cuentas de almacenamiento y contenedores Blob con acceso anónimo habilitado.
- **CLI Avanzada:** Filtrado por proveedor, nivel de severidad y múltiples formatos de exportación (CSV / PDF).
- **CI/CD Integrado:** Pruebas unitarias automáticas con `pytest` y ejecución programada semanal con GitHub Actions.

## 🚀 Requisitos Previos

- Python 3.10+
- Credenciales de AWS (`aws configure`) y/o credenciales de Azure (`az login` o variables de entorno).

## 🛠️ Uso de la CLI

```bash
# Instalación de dependencias
pip install -r requirements.txt

# Ejecución por defecto (AWS, todos los formatos y severidades)
python main.py

# Escanear Azure filtrando solo hallazgos de severidad Crítica y exportando a PDF
AZURE_STORAGE_ACCOUNT_URL="https://mi-cuenta.blob.core.windows.net" python main.py --provider azure --min-severity Crítico --format pdf

# Escanear AWS y Azure consolidando reportes en una carpeta específica
python main.py --provider all --output-dir ./reportes
```

## 📋 Opciones de la CLI

| Opción | Valores Permitidos | Valor por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--provider` | `aws`, `azure`, `all` | `aws` | Proveedor cloud a auditar |
| `--format` | `csv`, `pdf`, `both` | `both` | Formato de generación del reporte |
| `--min-severity` | `Crítico`, `Alto`, `Todos` | `Todos` | Filtro de severidad mínima a reportar |
| `--output-dir` | Ruta de directorio | `.` | Carpeta donde se guardarán los reportes |

## 🧪 Ejecución de Pruebas Unitarias

```bash
pytest -v
```

## 🐳 Ejecución con Docker

Construye la imagen desde la raíz del proyecto:

```bash
docker build -t cspm-ligero-aws .
```

Ejecuta la auditoría pasando argumentos de la CLI al contenedor:

```bash
docker run --rm cspm-ligero-aws --provider aws --format both --output-dir /app/reportes
```
