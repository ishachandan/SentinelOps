# ChromaDB's native hnswlib dependency does not yet support Python 3.14.
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt requirements-chromadb.txt ./

# Docker Compose enables real APIs and semantic search.
RUN pip install --no-cache-dir -r requirements-chromadb.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p data/firewall_sandbox data/chromadb data/test_real_chromadb

# Expose Flask port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=web_ui.py
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/', timeout=5)" || exit 1

# Run Flask with Gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "120", "web_ui:app"]
