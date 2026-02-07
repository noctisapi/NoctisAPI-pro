FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

RUN useradd -r -u 10001 -g root appuser \
    && chown -R appuser:root /data /app

EXPOSE 8000
USER appuser
CMD ["uvicorn", "app.honeypot_public:app", "--host", "0.0.0.0", "--port", "8000"]
