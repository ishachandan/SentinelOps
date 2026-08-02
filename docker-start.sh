#!/bin/bash
# Quick start script for Docker on Linux/Mac

set -e

echo "======================================"
echo "SentinelOps Docker Quick Start"
echo "======================================"
echo

# Check if .env exists
if [ ! -f .env ]; then
    echo "[ERROR] .env file not found!"
    echo
    echo "Please create .env file from .env.example:"
    echo "  cp .env.example .env"
    echo
    echo "Then edit .env with your API keys."
    exit 1
fi

echo "[1/3] Validating setup..."
python3 validate_docker.py || {
    echo
    echo "[ERROR] Validation failed. Please fix the issues above."
    exit 1
}

echo
echo "[2/3] Building Docker image..."
docker-compose build || {
    echo
    echo "[ERROR] Docker build failed!"
    exit 1
}

echo
echo "[3/3] Starting services..."
docker-compose up -d || {
    echo
    echo "[ERROR] Failed to start services!"
    exit 1
}

echo
echo "======================================"
echo "✓ Success! SentinelOps is running."
echo "======================================"
echo
echo "Open your browser to: http://localhost:5000"
echo
echo "Useful commands:"
echo "  docker-compose logs -f     (View logs)"
echo "  docker-compose down        (Stop services)"
echo "  docker-compose ps          (Check status)"
echo
