# ── Stage 1: build deps ──────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ── Stage 2: production image ─────────────────────────────────────────────────
FROM python:3.12-slim AS final

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/opt/venv/bin:$PATH" \
    HP_ENFORCE_LICENSE=0 \
    HP_APP_ID=noctisapi-pro \
    INSTANCE_ID_PATH=/var/lib/myapp/instance_id

WORKDIR /app

# Runtime system deps only (no build tools)
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data /var/lib/myapp

# Copy compiled venv from builder
COPY --from=builder /opt/venv /opt/venv

# Copy only runtime files — no tests, docs, compose, ops, dist, etc.
COPY app/          ./app/
COPY honey_licensing/ ./honey_licensing/
COPY migrations/   ./migrations/
COPY scripts/      ./scripts/
COPY static/       ./static/
COPY templates/    ./templates/
COPY alembic.ini   ./alembic.ini
COPY main.py       ./main.py
COPY main_panel.py ./main_panel.py

# Compile Python sources to bytecode for faster startup.
RUN python -m compileall -q -j 0 app/ honey_licensing/ scripts/

RUN useradd -r -u 10001 -g root appuser \
    && chown -R appuser:root /data /var/lib/myapp /app

EXPOSE 8000
USER appuser
CMD ["python", "main.py"]
