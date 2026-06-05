# ==============================================================================
# Kubernetes Security Operations Center — Makefile
# ==============================================================================

.PHONY: all install lint test scan build deploy clean help

SHELL := /bin/bash
VENV := venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
IMAGE_NAME := security-scanner
IMAGE_TAG := $(shell date +%Y%m%d%H%M%S)

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

all: install lint test build deploy ## Run the full pipeline

install: ## Set up Python venv and install dependencies
	@echo ">>> Setting up Python virtual environment..."
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r app/requirements.txt
	@echo ">>> Dependencies installed successfully."

lint: ## Run flake8 linter
	@echo ">>> Running flake8 linter..."
	$(VENV)/bin/flake8 app/ --max-line-length=120 --exclude=__pycache__,venv
	@echo ">>> Linting passed."

test: ## Run unit tests with coverage
	@echo ">>> Running unit tests..."
	cd app && ../$(VENV)/bin/python -m pytest tests/ -v --tb=short --cov=. --cov-report=term-missing
	@echo ">>> Tests passed."

scan: build ## Run Trivy scan on built image
	@echo ">>> Running Trivy security scan on $(IMAGE_NAME):$(IMAGE_TAG)..."
	trivy image --severity HIGH,CRITICAL $(IMAGE_NAME):$(IMAGE_TAG) || true
	@echo ">>> Security scan complete."

build: ## Build Docker image
	@echo ">>> Building Docker image $(IMAGE_NAME):$(IMAGE_TAG)..."
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) -t $(IMAGE_NAME):latest .
	@echo ">>> Docker image built successfully."

deploy: ## Deploy to Minikube via deployment script
	@echo ">>> Starting full deployment..."
	chmod +x deploy-security-soc.sh
	./deploy-security-soc.sh
	@echo ">>> Deployment complete."

clean: ## Clean up generated files
	@echo ">>> Cleaning up..."
	rm -rf $(VENV) __pycache__ .pytest_cache .coverage coverage.xml htmlcov
	rm -rf app/__pycache__ app/tests/__pycache__ app/.pytest_cache
	@echo ">>> Cleanup complete."
