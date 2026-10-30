.PHONY: help validate build up down restart logs ps test test-docker clean

# Default target
help:
	@echo "SentinelOps Management"
	@echo "======================="
	@echo ""
	@echo "Available commands:"
	@echo "  make test        - Run comprehensive test suite"
	@echo "  make validate    - Validate Docker setup"
	@echo "  make build       - Build Docker image"
	@echo "  make up          - Start services"
	@echo "  make down        - Stop services"
	@echo "  make restart     - Restart services"
	@echo "  make logs        - View logs (follow mode)"
	@echo "  make ps          - Show service status"
	@echo "  make test-docker - Test Docker deployment"
	@echo "  make clean       - Clean up containers and images"
	@echo ""

# Validate setup before building
validate:
	@python validate_docker.py

# Build Docker image
build:
	@docker-compose build

# Start services
up:
	@docker-compose up -d
	@echo ""
	@echo "✓ Services started. Access at http://localhost:5000"
	@echo ""

# Stop services
down:
	@docker-compose down

# Restart services
restart:
	@docker-compose restart

# View logs
logs:
	@docker-compose logs -f

# Show service status
ps:
	@docker-compose ps

# Run complete test suite
test:
	@pytest -v
	@python tests/e2e_stdio_check.py
	@python tests/test_transcript_fix.py

# Test deployment
test-docker:
	@echo "Waiting 10 seconds for services to stabilize..."
	@sleep 10
	@python test_docker_deployment.py

# Full cleanup
clean:
	@docker-compose down -v
	@docker system prune -f
	@echo "✓ Cleaned up containers, volumes, and dangling images"
