FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN addgroup --system --gid 10001 appgroup \
    && adduser --system --uid 10001 --ingroup appgroup appuser

COPY --chown=appuser:appgroup . .
RUN chmod -R u=rwX,go-rwx /app

USER appuser

ENTRYPOINT ["python", "main.py"]
CMD ["--provider", "aws", "--format", "all"]
