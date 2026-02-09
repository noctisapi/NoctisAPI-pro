FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    # Default policy: degrade to CORE if licensing is missing/invalid.
    # Set HP_ENFORCE_LICENSE=1 to fail startup on invalid/DENY (hard enforcement).
    HP_ENFORCE_LICENSE=0 \
    HP_APP_ID=shadowapi-pro \
    INSTANCE_ID_PATH=/var/lib/myapp/instance_id \
    LICENSING_PINNED_PUBLIC_KEY_PATH=/app/app/licensing_server_public_key.pem

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data /var/lib/myapp

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

RUN useradd -r -u 10001 -g root appuser \
    && chown -R appuser:root /data /var/lib/myapp /app

EXPOSE 8000
USER appuser
CMD ["uvicorn", "app.honeypot_public:app", "--host", "0.0.0.0", "--port", "8000"]
