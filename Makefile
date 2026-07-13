.PHONY: help install install-dev test test-integration clean format lint type-check docs ifds-validate-rules ifds-benchmark

help:  ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## Install the package in development mode
	pip install -e .

install-dev:  ## Install with development dependencies
	pip install -e ".[dev]"
	pip install -e third-party/a3_python

install-third-party:  ## Install third-party packages
	pip install -e third-party/a3_python

test-a3:  ## Run a3_python tests
	pytest third-party/a3_python/tests/

test:  ## Run tests
	pytest

test-integration:  ## Run integration tests
	pytest -m integration tests/integration

test-cov:  ## Run tests with coverage
	pytest --cov=pyflow --cov-report=html --cov-report=term

ifds-validate-rules:  ## Validate all IFDS registry rule packs
	python -m pyflow.analysis.ifds.clients.registry.validate

ifds-benchmark:  ## Run the synthetic IFDS solver benchmark
	python benchmarks/ifds_solver_benchmark.py

clean:  ## Clean up build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

format:  ## Format code with black
	black src/ tests/

lint:  ## Lint code with flake8
	flake8 src/ tests/

type-check:  ## Type check with mypy
	mypy src/

docs:  ## Build documentation
	cd docs && make html

docs-serve:  ## Serve documentation locally
	cd docs && python -m http.server 8000 --directory _build/html

all-checks: format lint type-check test  ## Run all checks
