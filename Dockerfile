FROM python:3.11-slim

LABEL maintainer="VulnHunter"
LABEL description="Automated Web Vulnerability Scanner"

# Set working directory
WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ ./app/
COPY frontend/ ./frontend/

# Create output directory for reports
RUN mkdir -p /app/reports

# Non-root user
RUN useradd -m -u 1000 scanner
USER scanner

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]