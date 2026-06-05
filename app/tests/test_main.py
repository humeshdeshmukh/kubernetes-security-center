"""
Unit tests for the Security Scanner API.
"""

import json
import pytest
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import app  # noqa: E402
import scanner  # noqa: E402


@pytest.fixture
def client():
    """Create a Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def clear_scan_cache():
    """Clear the scan cache before each test."""
    scanner.clear_cache()
    yield
    scanner.clear_cache()


# ==============================================================================
# Health Endpoint Tests
# ==============================================================================

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_returns_json(self, client):
        response = client.get("/health")
        data = json.loads(response.data)
        assert data["status"] == "UP"
        assert data["service"] == "security-scanner"

    def test_health_contains_checks(self, client):
        response = client.get("/health")
        data = json.loads(response.data)
        assert "checks" in data
        assert "scanner" in data["checks"]
        assert "system" in data["checks"]


# ==============================================================================
# Metrics Endpoint Tests
# ==============================================================================

class TestMetricsEndpoint:
    def test_metrics_returns_200(self, client):
        response = client.get("/metrics")
        assert response.status_code == 200

    def test_metrics_returns_prometheus_format(self, client):
        response = client.get("/metrics")
        assert "text/plain" in response.content_type or "openmetrics" in response.content_type

    def test_metrics_contains_custom_metrics(self, client):
        response = client.get("/metrics")
        body = response.data.decode("utf-8")
        assert "security_scans_total" in body
        assert "security_scan_duration_seconds" in body


# ==============================================================================
# Index Endpoint Tests
# ==============================================================================

class TestIndexEndpoint:
    def test_index_returns_200(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_index_returns_service_info(self, client):
        response = client.get("/")
        data = json.loads(response.data)
        assert data["service"] == "security-scanner"
        assert data["version"] == "1.0.0"
        assert "endpoints" in data


# ==============================================================================
# Scan Image Endpoint Tests
# ==============================================================================

class TestScanImageEndpoint:
    def test_scan_missing_body_returns_400(self, client):
        response = client.post(
            "/api/v1/scan/image",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert response.status_code == 400

    def test_scan_missing_image_returns_400(self, client):
        response = client.post(
            "/api/v1/scan/image",
            data=json.dumps({"timeout": 60}),
            content_type="application/json",
        )
        assert response.status_code == 400

    def test_scan_invalid_timeout_returns_400(self, client):
        response = client.post(
            "/api/v1/scan/image",
            data=json.dumps({"image": "nginx:latest", "timeout": 5}),
            content_type="application/json",
        )
        assert response.status_code == 400

    def test_scan_empty_image_returns_400(self, client):
        response = client.post(
            "/api/v1/scan/image",
            data=json.dumps({"image": "   "}),
            content_type="application/json",
        )
        assert response.status_code == 400

    @patch("scanner.subprocess.run")
    def test_scan_success(self, mock_run, client):
        """Test successful scan with mocked Trivy output."""
        trivy_output = {
            "Results": [
                {
                    "Target": "nginx:1.25",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1",
                            "FixedVersion": "1.1.2",
                            "Severity": "HIGH",
                            "Title": "Test vulnerability",
                        },
                        {
                            "VulnerabilityID": "CVE-2024-0002",
                            "PkgName": "curl",
                            "InstalledVersion": "7.0",
                            "FixedVersion": "7.1",
                            "Severity": "CRITICAL",
                            "Title": "Critical test vuln",
                        },
                    ],
                }
            ]
        }

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(trivy_output),
            stderr="",
        )

        response = client.post(
            "/api/v1/scan/image",
            data=json.dumps({"image": "nginx:1.25"}),
            content_type="application/json",
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "completed"
        assert data["summary"]["CRITICAL"] == 1
        assert data["summary"]["HIGH"] == 1
        assert data["summary"]["total"] == 2

    @patch("scanner.subprocess.run")
    def test_scan_trivy_not_found(self, mock_run, client):
        """Test graceful handling when Trivy is not installed."""
        mock_run.side_effect = FileNotFoundError("trivy not found")

        response = client.post(
            "/api/v1/scan/image",
            data=json.dumps({"image": "nginx:latest"}),
            content_type="application/json",
        )

        assert response.status_code == 500
        data = json.loads(response.data)
        assert data["status"] == "error"
        assert "not found" in data["error"].lower()


# ==============================================================================
# Scan Results Endpoint Tests
# ==============================================================================

class TestScanResultsEndpoint:
    def test_results_empty_cache(self, client):
        response = client.get("/api/v1/scan/results")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["count"] == 0
        assert data["results"] == []

    def test_results_with_limit(self, client):
        response = client.get("/api/v1/scan/results?limit=5")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["limit"] == 5


# ==============================================================================
# Scan Summary Endpoint Tests
# ==============================================================================

class TestScanSummaryEndpoint:
    def test_summary_empty(self, client):
        response = client.get("/api/v1/scan/summary")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "scan_statistics" in data
        assert "vulnerability_totals" in data
        assert data["scan_statistics"]["total_scans"] == 0


# ==============================================================================
# Scanner Module Tests
# ==============================================================================

class TestScannerModule:
    def test_clear_cache(self):
        scanner._scan_cache.append({"test": True})
        scanner.clear_cache()
        assert len(scanner._scan_cache) == 0

    def test_get_cached_results_empty(self):
        results = scanner.get_cached_results()
        assert results == []

    def test_get_summary_empty(self):
        summary = scanner.get_summary()
        assert summary["scan_statistics"]["total_scans"] == 0
        assert summary["last_scan"] is None

    def test_cache_eviction(self):
        """Test that cache evicts old entries when full."""
        for i in range(scanner.MAX_CACHE_SIZE + 10):
            scanner._cache_result({"id": i, "timestamp": "test", "status": "completed"})
        assert len(scanner._scan_cache) == scanner.MAX_CACHE_SIZE

    @patch("scanner.subprocess.run")
    def test_trivy_timeout(self, mock_run):
        """Test handling of Trivy command timeout."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="trivy", timeout=10)

        result = scanner.run_trivy_image_scan("nginx:latest", timeout=10)
        assert result["status"] == "timeout"
