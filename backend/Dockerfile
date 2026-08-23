FROM python:3.11-slim

# Install system dependencies including libzbar0 for pyzbar QR code processing
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY backend/ ./backend/

# Expose FastAPI backend port
EXPOSE 8001

# Run uvicorn server
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8001"]
