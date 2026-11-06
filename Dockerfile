# Unravel Service Dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy and install python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy service code, templates, and self-contained assets
COPY . /app/services/

# Create persistent storage dir for SQLite
RUN mkdir -p /app/data

ENV UNRAVEL_HOST=0.0.0.0
ENV UNRAVEL_PORT=8001
ENV UNRAVEL_DB_PATH=/app/data/unravel.db
ENV PYTHONPATH=/app/services

EXPOSE 8001

CMD ["python", "/app/services/unravel_service.py"]

