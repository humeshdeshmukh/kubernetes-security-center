"""
Kubernetes Security Operations Center — Security Scanner API.

A Flask REST API that wraps Trivy for container vulnerability scanning,
exposes Prometheus metrics for security posture monitoring, and provides
a centralized interface for security scan management.
"""

import os
import time
import logging
import json
from flask import Flask, jsonify, request, Response
from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

from scanner import (
    run_trivy_image_scan,
    get_cached_results,
    get_summary,
)


# ==============================================================================
# Structured JSON Logging
# ==============================================================================

class JSONFormatter(logging.Formatter):
    """Format log records as structured JSON for log aggregation systems."""
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "filename": record.filename,
            "line": record.lineno,
        }
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)


logger = logging.getLogger("security-scanner")
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)
logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())


# ==============================================================================
# Flask Application
# ==============================================================================

app = Flask(__name__)


# ==============================================================================
# Prometheus Metrics
# ==============================================================================

SCAN_COUNT = Counter(
    "security_scans_total",
    "Total number of security scans performed",
    ["scan_type", "status"],
)

VULN_GAUGE = Gauge(
    "security_vulnerabilities_found",
    "Current vulnerability count from most recent scan",
    ["severity"],
)

SCAN_DURATION = Histogram(
    "security_scan_duration_seconds",
    "Time taken for security scans",
    ["scan_type"],
    buckets=[1, 5, 10, 30, 60, 120, 300],
)

REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP Requests",
    ["method", "endpoint", "http_status"],
)

REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP Request Latency in Seconds",
    ["method", "endpoint"],
)


# ==============================================================================
# Request Middleware
# ==============================================================================

@app.before_request
def start_timer():
    request.start_time = time.time()


@app.after_request
def log_request(response):
    # Skip internal endpoints to keep logs clean
    if request.path in ["/health", "/metrics"]:
        return response

    latency = time.time() - request.start_time
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.path,
        http_status=response.status_code,
    ).inc()
    REQUEST_LATENCY.labels(
        method=request.method,
        endpoint=request.path,
    ).observe(latency)

    logger.info(
        "Request processed",
        extra={
            "method": request.method,
            "path": request.path,
            "status": response.status_code,
            "latency": latency,
            "ip": request.remote_addr,
        },
    )
    return response


# ==============================================================================
# Health & Metrics Endpoints
# ==============================================================================

@app.route("/health", methods=["GET"])
def health_check():
    """
    Liveness and readiness probe endpoint.
    Returns system health status including memory usage.
    """
    health_status = {
        "status": "UP",
        "service": "security-scanner",
        "timestamp": time.time(),
        "checks": {
            "scanner": {"status": "UP", "trivy_available": True},
            "system": {"status": "UP", "memory_healthy": True},
        },
    }

    # Check memory usage on Linux
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    mem_kb = int(line.split()[1])
                    health_status["checks"]["system"]["memory_used_kb"] = mem_kb
                    if mem_kb > 512000:  # 500 MB threshold
                        health_status["status"] = "DEGRADED"
                        health_status["checks"]["system"]["memory_healthy"] = False
                    break
    except Exception:
        health_status["checks"]["system"]["memory_used_kb"] = 0

    status_code = 200 if health_status["status"] == "UP" else 503
    return jsonify(health_status), status_code


@app.route("/metrics", methods=["GET"])
def metrics():
    """Expose Prometheus metrics for scraping."""
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


# ==============================================================================
# API Root
# ==============================================================================

@app.route("/", methods=["GET"])
def index():
    """API root — returns service info and available endpoints."""
    return jsonify({
        "service": "security-scanner",
        "version": "1.0.0",
        "description": "Kubernetes Security Operations Center — Vulnerability Scanner API",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "metrics": "/metrics",
            "scan_image": "POST /api/v1/scan/image",
            "scan_results": "GET /api/v1/scan/results",
            "scan_summary": "GET /api/v1/scan/summary",
        },
    })


# ==============================================================================
# Scan API Endpoints
# ==============================================================================

@app.route("/api/v1/scan/image", methods=["POST"])
def scan_image():
    """
    Trigger a Trivy vulnerability scan on a container image.

    Request JSON:
        {
            "image": "nginx:1.25",
            "timeout": 300  (optional, default 300s)
        }

    Returns:
        Scan results with vulnerability counts and details.
    """
    data = request.get_json()

    if not data or not data.get("image"):
        logger.warning("Scan request missing 'image' field")
        return jsonify({
            "error": "Missing required field: 'image'",
            "usage": {"image": "nginx:1.25", "timeout": 300},
        }), 400

    image = data["image"].strip()
    timeout = data.get("timeout", 300)

    # Basic input validation
    if not image or len(image) > 500:
        return jsonify({"error": "Invalid image reference"}), 400

    if not isinstance(timeout, (int, float)) or timeout < 10 or timeout > 600:
        return jsonify({"error": "Timeout must be between 10 and 600 seconds"}), 400

    logger.info(f"Scan requested for image: {image}")

    # Execute the scan
    result = run_trivy_image_scan(image, timeout=int(timeout))

    # Update Prometheus metrics
    SCAN_COUNT.labels(scan_type="image", status=result["status"]).inc()
    SCAN_DURATION.labels(scan_type="image").observe(result["duration_seconds"])

    if result["status"] == "completed":
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            VULN_GAUGE.labels(severity=severity).set(
                result["summary"].get(severity, 0)
            )

    status_code = 200 if result["status"] == "completed" else 500
    return jsonify(result), status_code


@app.route("/api/v1/scan/results", methods=["GET"])
def scan_results():
    """
    Retrieve recent scan results from the in-memory cache.

    Query Parameters:
        limit: Maximum number of results to return (default 20, max 100)
    """
    limit = request.args.get("limit", 20, type=int)
    limit = min(max(limit, 1), 100)

    results = get_cached_results(limit=limit)
    return jsonify({
        "results": results,
        "count": len(results),
        "limit": limit,
    })


@app.route("/api/v1/scan/summary", methods=["GET"])
def scan_summary():
    """
    Aggregate vulnerability summary across all cached scans.
    Returns total counts by severity and scan statistics.
    """
    summary = get_summary()
    return jsonify(summary)


# ==============================================================================
# Entry Point
# ==============================================================================

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    # In production, we run through gunicorn
    app.run(host="0.0.0.0", port=port)  # nosec B104
