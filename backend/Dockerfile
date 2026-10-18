FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# libzbar0 is needed by pyzbar for QR decoding; curl is used by the healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# .dockerignore keeps .env files, local databases, venvs and datasets OUT of this copy
COPY backend/ ./backend/

# Don't run as root
RUN useradd --create-home --uid 10001 appuser && chown -R appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/api/v1/health || exit 1

# One worker on purpose: the rate limiter keeps its counts in memory
CMD ["uvicorn", "app.main:app", "--app-dir", "backend", "--host", "0.0.0.0", "--port", "8000"]