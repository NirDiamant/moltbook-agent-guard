.PHONY: install dev test lint format clean build publish help

# Default target
help:
	@echo "Moltbook Toolkit - Available Commands"
	@echo ""
	@echo "  make install    - Install the toolkit"
	@echo "  make dev        - Install with dev dependencies"
	@echo "  make test       - Run tests"
	@echo "  make lint       - Run linter"
	@echo "  make format     - Format code"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make build      - Build package"
	@echo "  make publish    - Publish to PyPI (requires credentials)"
	@echo ""

# Install
install:
	pip install -e .

# Install with dev dependencies
dev:
	pip install -e ".[dev]"

# Run tests
test:
	pytest tests/ -v --cov=tools --cov-report=term-missing

# Run linter
lint:
	ruff check .
	black --check .

# Format code
format:
	black .
	ruff check --fix .

# Clean build artifacts
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Build package
build: clean
	python -m build

# Publish to PyPI
publish: build
	python -m twine upload dist/*

# Run the CLI (for testing)
cli:
	python -m tools.moltbook_cli.cli --help

# Start Docker environment
start:
	./start.sh

# Stop Docker environment
stop:
	./stop.sh

# View logs
logs:
	./logs.sh

# Scan for security issues in the codebase
security-scan:
	@echo "Scanning for hardcoded secrets..."
	@grep -r "api_key\s*=" --include="*.py" . || echo "No hardcoded API keys found"
	@grep -r "password\s*=" --include="*.py" . || echo "No hardcoded passwords found"
	@echo "Security scan complete"
