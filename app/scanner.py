"""
Trivy Security Scanner Integration Module.

Wraps the Trivy CLI to provide programmatic vulnerability scanning
for container images, with structured JSON output parsing and
in-memory result caching.
"""

import json
import logging
import subprocess
import time
from typing import Any

logger = logging.getLogger("security-scanner")

# In-memory cache for scan results
_scan_cache: list[dict[str, Any]] = []
MAX_CACHE_SIZE = 100


def run_trivy_image_scan(image: str, timeout: int = 300) -> dict[str, Any]:
    """
    Execute a Trivy image scan and return parsed results.

    Args:
        image: Container image reference (e.g., 'nginx:1.25')
        timeout: Maximum seconds to wait for scan completion

    Returns:
        Dictionary containing scan results with vulnerability counts
    """
    start_time = time.time()
    result = {
        "image": image,
        "scan_type": "image",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "pending",
        "duration_seconds": 0,
        "summary": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
            "total": 0,
        },
        "vulnerabilities": [],
    }

    try:
        cmd = [
            "trivy",
            "image",
            "--format", "json",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--no-progress",
            "--timeout", f"{timeout}s",
            image,
        ]

        logger.info(f"Starting Trivy scan for image: {image}")
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        duration = time.time() - start_time
        result["duration_seconds"] = round(duration, 2)

        if process.returncode != 0 and not process.stdout:
            result["status"] = "error"
            result["error"] = process.stderr.strip() or "Trivy scan failed with no output"
            logger.error(f"Trivy scan failed for {image}: {result['error']}")
            _cache_result(result)
            return result

        # Parse Trivy JSON output
        trivy_output = json.loads(process.stdout)
        result = _parse_trivy_output(trivy_output, result)
        result["status"] = "completed"
        logger.info(
            f"Scan completed for {image}: "
            f"{result['summary']['total']} vulnerabilities found "
            f"(CRITICAL={result['summary']['CRITICAL']}, "
            f"HIGH={result['summary']['HIGH']}) "
            f"in {duration:.1f}s"
        )

    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["error"] = f"Scan timed out after {timeout}s"
        result["duration_seconds"] = timeout
        logger.error(f"Trivy scan timed out for {image}")

    except json.JSONDecodeError as e:
        result["status"] = "error"
        result["error"] = f"Failed to parse Trivy output: {str(e)}"
        result["duration_seconds"] = round(time.time() - start_time, 2)
        logger.error(f"JSON parse error for {image}: {e}")

    except FileNotFoundError:
        result["status"] = "error"
        result["error"] = "Trivy CLI not found. Install: https://aquasecurity.github.io/trivy"
        result["duration_seconds"] = round(time.time() - start_time, 2)
        logger.error("Trivy binary not found in PATH")

    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Unexpected error: {str(e)}"
        result["duration_seconds"] = round(time.time() - start_time, 2)
        logger.error(f"Unexpected scan error for {image}: {e}")

    _cache_result(result)
    return result


def _parse_trivy_output(trivy_output: dict, result: dict) -> dict:
    """
    Parse Trivy JSON output and populate the result dictionary
    with vulnerability counts and details.
    """
    results_list = trivy_output.get("Results", [])

    for target_result in results_list:
        vulnerabilities = target_result.get("Vulnerabilities", [])
        if vulnerabilities is None:
            continue

        for vuln in vulnerabilities:
            severity = vuln.get("Severity", "UNKNOWN").upper()
            if severity in result["summary"]:
                result["summary"][severity] += 1
            else:
                result["summary"]["UNKNOWN"] += 1

            result["summary"]["total"] += 1

            # Keep top 50 vulnerabilities for detail view
            if len(result["vulnerabilities"]) < 50:
                result["vulnerabilities"].append({
                    "id": vuln.get("VulnerabilityID", "N/A"),
                    "package": vuln.get("PkgName", "N/A"),
                    "installed_version": vuln.get("InstalledVersion", "N/A"),
                    "fixed_version": vuln.get("FixedVersion", "N/A"),
                    "severity": severity,
                    "title": vuln.get("Title", "No description"),
                })

    return result


def _cache_result(result: dict) -> None:
    """Cache a scan result, evicting old entries if at capacity."""
    global _scan_cache
    _scan_cache.append(result)
    if len(_scan_cache) > MAX_CACHE_SIZE:
        _scan_cache = _scan_cache[-MAX_CACHE_SIZE:]


def get_cached_results(limit: int = 20) -> list[dict]:
    """Return the most recent cached scan results."""
    return list(reversed(_scan_cache[-limit:]))


def get_summary() -> dict[str, Any]:
    """
    Aggregate vulnerability counts across all cached scans.

    Returns:
        Dictionary with total counts, per-severity breakdown,
        and scan statistics.
    """
    total_scans = len(_scan_cache)
    successful = sum(1 for r in _scan_cache if r["status"] == "completed")
    failed = sum(1 for r in _scan_cache if r["status"] == "error")

    aggregated = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "total": 0}
    for r in _scan_cache:
        if r["status"] == "completed":
            for sev in aggregated:
                aggregated[sev] += r["summary"].get(sev, 0)

    return {
        "scan_statistics": {
            "total_scans": total_scans,
            "successful": successful,
            "failed": failed,
            "timeout": total_scans - successful - failed,
        },
        "vulnerability_totals": aggregated,
        "last_scan": _scan_cache[-1]["timestamp"] if _scan_cache else None,
    }


def clear_cache() -> None:
    """Clear all cached scan results."""
    global _scan_cache
    _scan_cache = []
