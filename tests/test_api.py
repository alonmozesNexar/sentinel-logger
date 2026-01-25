#!/usr/bin/env python3
"""
Comprehensive API Tests for Sentinel Logger
Tests all 62 API endpoints in app/routes/api.py

Run with: python tests/test_api.py

NOTE: This is a standalone integration test script that runs against a live server.
It is NOT designed to be run via pytest. To prevent pytest from collecting these
functions as tests, we use a naming convention that avoids the 'test_' prefix
for functions that require parameters.
"""

import pytest
import requests
import json
import time
import sys
from datetime import datetime
from typing import Dict, List, Any, Tuple

# Skip this entire module when running via pytest
pytestmark = pytest.mark.skip(reason="Standalone integration test - run with: python tests/test_api.py")

# Configuration
BASE_URL = "http://127.0.0.1:5051/api"
TIMEOUT = 30

# Test results storage
results = {
    "passed": [],
    "failed": [],
    "errors": [],
    "warnings": [],
    "total_time": 0
}


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def log_pass(test_name: str, message: str = ""):
    """Log a passing test"""
    results["passed"].append({"test": test_name, "message": message})
    print(f"  {Colors.GREEN}[PASS]{Colors.RESET} {test_name} {message}")


def log_fail(test_name: str, message: str, response=None):
    """Log a failing test"""
    details = {"test": test_name, "message": message}
    if response:
        details["status_code"] = response.status_code
        try:
            details["response"] = response.json()
        except:
            details["response"] = response.text[:500]
    results["failed"].append(details)
    print(f"  {Colors.RED}[FAIL]{Colors.RESET} {test_name}: {message}")


def log_error(test_name: str, error: str):
    """Log a test error"""
    results["errors"].append({"test": test_name, "error": str(error)})
    print(f"  {Colors.RED}[ERROR]{Colors.RESET} {test_name}: {error}")


def log_warning(test_name: str, message: str):
    """Log a warning"""
    results["warnings"].append({"test": test_name, "message": message})
    print(f"  {Colors.YELLOW}[WARN]{Colors.RESET} {test_name}: {message}")


def make_request(method: str, endpoint: str, **kwargs) -> Tuple[requests.Response, float]:
    """Make an HTTP request and return response with timing"""
    url = f"{BASE_URL}{endpoint}"
    kwargs.setdefault("timeout", TIMEOUT)

    start = time.time()
    response = getattr(requests, method.lower())(url, **kwargs)
    elapsed = time.time() - start

    return response, elapsed


def test_section(name: str):
    """Print section header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}{Colors.RESET}")


# ============================================
# LOG FILES ENDPOINTS
# ============================================

def test_get_log_files():
    """GET /log-files - Get all log files"""
    try:
        resp, elapsed = make_request("GET", "/log-files")
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                log_pass("GET /log-files", f"({len(data)} files, {elapsed:.2f}s)")
                return data
            else:
                log_fail("GET /log-files", "Response is not a list", resp)
        else:
            log_fail("GET /log-files", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error("GET /log-files", str(e))
    return []


def test_get_log_file(file_id: int):
    """GET /log-files/<id> - Get specific log file"""
    try:
        resp, elapsed = make_request("GET", f"/log-files/{file_id}")
        if resp.status_code == 200:
            data = resp.json()
            if "id" in data:
                log_pass(f"GET /log-files/{file_id}", f"({elapsed:.2f}s)")
                return data
            else:
                log_fail(f"GET /log-files/{file_id}", "Missing 'id' in response", resp)
        else:
            log_fail(f"GET /log-files/{file_id}", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /log-files/{file_id}", str(e))
    return None


def test_get_log_file_404():
    """GET /log-files/<invalid_id> - Test 404 handling"""
    try:
        resp, elapsed = make_request("GET", "/log-files/99999")
        if resp.status_code == 404:
            log_pass("GET /log-files/99999 (404 test)", f"({elapsed:.2f}s)")
        else:
            log_fail("GET /log-files/99999 (404 test)", f"Expected 404, got {resp.status_code}", resp)
    except Exception as e:
        log_error("GET /log-files/99999 (404 test)", str(e))


def test_get_log_entries(file_id: int):
    """GET /log-files/<id>/entries - Get log entries with pagination"""
    try:
        # Basic request
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/entries")
        if resp.status_code == 200:
            data = resp.json()
            required_fields = ["entries", "total", "pages", "current_page", "per_page", "has_next", "has_prev"]
            missing = [f for f in required_fields if f not in data]
            if not missing:
                log_pass(f"GET /log-files/{file_id}/entries", f"({len(data['entries'])} entries, {elapsed:.2f}s)")
            else:
                log_fail(f"GET /log-files/{file_id}/entries", f"Missing fields: {missing}", resp)
        else:
            log_fail(f"GET /log-files/{file_id}/entries", f"Status code: {resp.status_code}", resp)

        # Test pagination
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/entries?page=1&per_page=10")
        if resp.status_code == 200:
            data = resp.json()
            if len(data["entries"]) <= 10:
                log_pass(f"GET /log-files/{file_id}/entries (pagination)", f"(page=1, per_page=10, {elapsed:.2f}s)")
            else:
                log_fail(f"GET /log-files/{file_id}/entries (pagination)", f"Returned {len(data['entries'])} entries, expected <= 10")

        # Test per_page limit (max 500)
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/entries?per_page=1000")
        if resp.status_code == 200:
            data = resp.json()
            if data["per_page"] <= 500:
                log_pass(f"GET /log-files/{file_id}/entries (per_page limit)", f"(limited to {data['per_page']}, {elapsed:.2f}s)")
            else:
                log_fail(f"GET /log-files/{file_id}/entries (per_page limit)", f"per_page={data['per_page']}, expected <= 500")

        # Test severity filter
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/entries?severity=ERROR")
        if resp.status_code == 200:
            data = resp.json()
            log_pass(f"GET /log-files/{file_id}/entries (severity filter)", f"({len(data['entries'])} errors, {elapsed:.2f}s)")

        # Test search filter
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/entries?search=error")
        if resp.status_code == 200:
            data = resp.json()
            log_pass(f"GET /log-files/{file_id}/entries (search filter)", f"({len(data['entries'])} matches, {elapsed:.2f}s)")

        # Test line range filter
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/entries?start_line=1&end_line=50")
        if resp.status_code == 200:
            data = resp.json()
            log_pass(f"GET /log-files/{file_id}/entries (line range)", f"({len(data['entries'])} entries, {elapsed:.2f}s)")

    except Exception as e:
        log_error(f"GET /log-files/{file_id}/entries", str(e))


def test_get_log_issues(file_id: int):
    """GET /log-files/<id>/issues - Get issues for log file"""
    try:
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/issues")
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                log_pass(f"GET /log-files/{file_id}/issues", f"({len(data)} issues, {elapsed:.2f}s)")
                return data
            else:
                log_fail(f"GET /log-files/{file_id}/issues", "Response is not a list", resp)
        else:
            log_fail(f"GET /log-files/{file_id}/issues", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /log-files/{file_id}/issues", str(e))
    return []


def test_get_chart_data(file_id: int):
    """GET /log-files/<id>/charts - Get chart data"""
    try:
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/charts")
        if resp.status_code == 200:
            data = resp.json()
            log_pass(f"GET /log-files/{file_id}/charts", f"({elapsed:.2f}s)")
        else:
            log_fail(f"GET /log-files/{file_id}/charts", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /log-files/{file_id}/charts", str(e))


def test_get_log_stats(file_id: int):
    """GET /log-files/<id>/stats - Get statistics"""
    try:
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/stats")
        if resp.status_code == 200:
            data = resp.json()
            log_pass(f"GET /log-files/{file_id}/stats", f"({elapsed:.2f}s)")
        else:
            log_fail(f"GET /log-files/{file_id}/stats", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /log-files/{file_id}/stats", str(e))


def test_get_log_minimap(file_id: int):
    """GET /log-files/<id>/minimap - Get minimap data"""
    try:
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/minimap")
        if resp.status_code == 200:
            data = resp.json()
            required_fields = ["total_lines", "error_count", "warning_count", "entries"]
            missing = [f for f in required_fields if f not in data]
            if not missing:
                log_pass(f"GET /log-files/{file_id}/minimap", f"({len(data['entries'])} entries, {elapsed:.2f}s)")
            else:
                log_fail(f"GET /log-files/{file_id}/minimap", f"Missing fields: {missing}", resp)
        else:
            log_fail(f"GET /log-files/{file_id}/minimap", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /log-files/{file_id}/minimap", str(e))


def test_get_health_score(file_id: int):
    """GET /log-files/<id>/health - Get health score"""
    try:
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/health")
        if resp.status_code == 200:
            log_pass(f"GET /log-files/{file_id}/health", f"({elapsed:.2f}s)")
        else:
            log_fail(f"GET /log-files/{file_id}/health", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /log-files/{file_id}/health", str(e))


def test_export_log_file(file_id: int):
    """GET /log-files/<id>/export - Test all export formats"""
    formats = ["json", "csv", "summary"]
    for fmt in formats:
        try:
            resp, elapsed = make_request("GET", f"/log-files/{file_id}/export?format={fmt}")
            if resp.status_code == 200:
                log_pass(f"GET /log-files/{file_id}/export?format={fmt}", f"({elapsed:.2f}s)")
            else:
                log_fail(f"GET /log-files/{file_id}/export?format={fmt}", f"Status code: {resp.status_code}", resp)
        except Exception as e:
            log_error(f"GET /log-files/{file_id}/export?format={fmt}", str(e))

    # Test invalid format
    try:
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/export?format=invalid")
        if resp.status_code == 400:
            log_pass(f"GET /log-files/{file_id}/export?format=invalid (400 test)", f"({elapsed:.2f}s)")
        else:
            log_fail(f"GET /log-files/{file_id}/export?format=invalid (400 test)", f"Expected 400, got {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /log-files/{file_id}/export?format=invalid", str(e))


def test_get_patterns(file_id: int):
    """GET /log-files/<id>/patterns - Get detected patterns"""
    try:
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/patterns")
        if resp.status_code == 200:
            log_pass(f"GET /log-files/{file_id}/patterns", f"({elapsed:.2f}s)")
        else:
            log_fail(f"GET /log-files/{file_id}/patterns", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /log-files/{file_id}/patterns", str(e))


def test_get_error_sequences(file_id: int):
    """GET /log-files/<id>/sequences - Get error sequences"""
    try:
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/sequences")
        if resp.status_code == 200:
            data = resp.json()
            if "sequences" in data and "count" in data:
                log_pass(f"GET /log-files/{file_id}/sequences", f"({data['count']} sequences, {elapsed:.2f}s)")
            else:
                log_fail(f"GET /log-files/{file_id}/sequences", "Missing fields in response", resp)
        else:
            log_fail(f"GET /log-files/{file_id}/sequences", f"Status code: {resp.status_code}", resp)

        # Test with window parameter
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/sequences?window=10")
        if resp.status_code == 200:
            log_pass(f"GET /log-files/{file_id}/sequences?window=10", f"({elapsed:.2f}s)")
    except Exception as e:
        log_error(f"GET /log-files/{file_id}/sequences", str(e))


def test_get_service_health(file_id: int):
    """GET /log-files/<id>/service-health - Get service health metrics"""
    try:
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/service-health")
        if resp.status_code == 200:
            data = resp.json()
            if "services" in data and "count" in data:
                log_pass(f"GET /log-files/{file_id}/service-health", f"({data['count']} services, {elapsed:.2f}s)")
            else:
                log_fail(f"GET /log-files/{file_id}/service-health", "Missing fields in response", resp)
        else:
            log_fail(f"GET /log-files/{file_id}/service-health", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /log-files/{file_id}/service-health", str(e))


def test_get_raw_log(file_id: int):
    """GET /log-files/<id>/raw - Get raw log content"""
    try:
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/raw")
        if resp.status_code == 200:
            data = resp.json()
            if "content" in data and "filename" in data:
                log_pass(f"GET /log-files/{file_id}/raw", f"({elapsed:.2f}s)")
            else:
                log_fail(f"GET /log-files/{file_id}/raw", "Missing fields in response", resp)
        elif resp.status_code == 404:
            log_warning(f"GET /log-files/{file_id}/raw", "File not found on disk")
        else:
            log_fail(f"GET /log-files/{file_id}/raw", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /log-files/{file_id}/raw", str(e))


def test_get_timeline(file_id: int):
    """GET /log-files/<id>/timeline - Get issue timeline"""
    try:
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/timeline")
        if resp.status_code == 200:
            data = resp.json()
            if "events" in data:
                log_pass(f"GET /log-files/{file_id}/timeline", f"({data.get('total_events', 0)} events, {elapsed:.2f}s)")
            else:
                log_fail(f"GET /log-files/{file_id}/timeline", "Missing 'events' in response", resp)
        elif resp.status_code == 404:
            log_warning(f"GET /log-files/{file_id}/timeline", "No timestamped entries found")
        else:
            log_fail(f"GET /log-files/{file_id}/timeline", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /log-files/{file_id}/timeline", str(e))


def test_export_csv(file_id: int):
    """GET /log-files/<id>/export/csv - Export as CSV"""
    try:
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/export/csv")
        if resp.status_code == 200:
            if "text/csv" in resp.headers.get("Content-Type", ""):
                log_pass(f"GET /log-files/{file_id}/export/csv", f"({elapsed:.2f}s)")
            else:
                log_fail(f"GET /log-files/{file_id}/export/csv", f"Wrong Content-Type: {resp.headers.get('Content-Type')}")
        else:
            log_fail(f"GET /log-files/{file_id}/export/csv", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /log-files/{file_id}/export/csv", str(e))


def test_export_json(file_id: int):
    """GET /log-files/<id>/export/json - Export as JSON"""
    try:
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/export/json")
        if resp.status_code == 200:
            log_pass(f"GET /log-files/{file_id}/export/json", f"({elapsed:.2f}s)")
        else:
            log_fail(f"GET /log-files/{file_id}/export/json", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /log-files/{file_id}/export/json", str(e))


def test_export_pdf(file_id: int):
    """GET /log-files/<id>/export/pdf - Export as PDF"""
    try:
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/export/pdf")
        if resp.status_code == 200:
            if "application/pdf" in resp.headers.get("Content-Type", ""):
                log_pass(f"GET /log-files/{file_id}/export/pdf", f"({elapsed:.2f}s)")
            else:
                log_fail(f"GET /log-files/{file_id}/export/pdf", f"Wrong Content-Type: {resp.headers.get('Content-Type')}")
        elif resp.status_code == 503:
            log_warning(f"GET /log-files/{file_id}/export/pdf", "reportlab not installed")
        else:
            log_fail(f"GET /log-files/{file_id}/export/pdf", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /log-files/{file_id}/export/pdf", str(e))


# ============================================
# ISSUES ENDPOINTS
# ============================================

def test_get_all_issues():
    """GET /issues - Get all issues"""
    try:
        resp, elapsed = make_request("GET", "/issues")
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                log_pass("GET /issues", f"({len(data)} issues, {elapsed:.2f}s)")
                return data
            else:
                log_fail("GET /issues", "Response is not a list", resp)
        else:
            log_fail("GET /issues", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error("GET /issues", str(e))
    return []


def test_get_issues_filters():
    """GET /issues - Test filtering options"""
    filters = [
        ("severity=CRITICAL", "severity filter"),
        ("status=open", "status filter"),
        ("category=crash", "category filter"),
    ]
    for filter_str, desc in filters:
        try:
            resp, elapsed = make_request("GET", f"/issues?{filter_str}")
            if resp.status_code == 200:
                data = resp.json()
                log_pass(f"GET /issues?{filter_str}", f"({len(data)} results, {elapsed:.2f}s)")
            else:
                log_fail(f"GET /issues?{filter_str}", f"Status code: {resp.status_code}", resp)
        except Exception as e:
            log_error(f"GET /issues?{filter_str}", str(e))


def test_get_issue(issue_id: int):
    """GET /issues/<id> - Get specific issue"""
    try:
        resp, elapsed = make_request("GET", f"/issues/{issue_id}")
        if resp.status_code == 200:
            data = resp.json()
            if "id" in data:
                log_pass(f"GET /issues/{issue_id}", f"({elapsed:.2f}s)")
                return data
            else:
                log_fail(f"GET /issues/{issue_id}", "Missing 'id' in response", resp)
        else:
            log_fail(f"GET /issues/{issue_id}", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /issues/{issue_id}", str(e))
    return None


def test_update_issue(issue_id: int):
    """PATCH /issues/<id> - Update issue status"""
    try:
        # Test valid status update
        resp, elapsed = make_request("PATCH", f"/issues/{issue_id}", json={"status": "resolved"})
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "resolved":
                log_pass(f"PATCH /issues/{issue_id}", f"(status updated, {elapsed:.2f}s)")
            else:
                log_fail(f"PATCH /issues/{issue_id}", "Status not updated", resp)
        else:
            log_fail(f"PATCH /issues/{issue_id}", f"Status code: {resp.status_code}", resp)

        # Reset status
        resp, elapsed = make_request("PATCH", f"/issues/{issue_id}", json={"status": "open"})
    except Exception as e:
        log_error(f"PATCH /issues/{issue_id}", str(e))


def test_get_issue_context(issue_id: int):
    """GET /issues/<id>/context - Get issue context"""
    try:
        resp, elapsed = make_request("GET", f"/issues/{issue_id}/context")
        if resp.status_code == 200:
            data = resp.json()
            if "issue" in data and "context_entries" in data:
                log_pass(f"GET /issues/{issue_id}/context", f"({len(data['context_entries'])} entries, {elapsed:.2f}s)")
            else:
                log_fail(f"GET /issues/{issue_id}/context", "Missing fields in response", resp)
        else:
            log_fail(f"GET /issues/{issue_id}/context", f"Status code: {resp.status_code}", resp)

        # Test context parameters
        resp, elapsed = make_request("GET", f"/issues/{issue_id}/context?before=10&after=10")
        if resp.status_code == 200:
            log_pass(f"GET /issues/{issue_id}/context?before=10&after=10", f"({elapsed:.2f}s)")
    except Exception as e:
        log_error(f"GET /issues/{issue_id}/context", str(e))


def test_export_issue(issue_id: int):
    """GET /issues/<id>/export/<format> - Export issue"""
    formats = ["json", "jira", "github", "markdown"]
    for fmt in formats:
        try:
            resp, elapsed = make_request("GET", f"/issues/{issue_id}/export/{fmt}")
            if resp.status_code == 200:
                log_pass(f"GET /issues/{issue_id}/export/{fmt}", f"({elapsed:.2f}s)")
            else:
                log_fail(f"GET /issues/{issue_id}/export/{fmt}", f"Status code: {resp.status_code}", resp)
        except Exception as e:
            log_error(f"GET /issues/{issue_id}/export/{fmt}", str(e))


# ============================================
# BUG REPORTS ENDPOINTS
# ============================================

def test_get_bug_reports():
    """GET /bug-reports - Get all bug reports"""
    try:
        resp, elapsed = make_request("GET", "/bug-reports")
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                log_pass("GET /bug-reports", f"({len(data)} reports, {elapsed:.2f}s)")
                return data
            else:
                log_fail("GET /bug-reports", "Response is not a list", resp)
        else:
            log_fail("GET /bug-reports", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error("GET /bug-reports", str(e))
    return []


def test_create_bug_report(issue_id: int = None):
    """POST /bug-reports - Create a new bug report"""
    try:
        # Create with manual data
        report_data = {
            "title": "Test Bug Report",
            "description": "This is a test bug report created by API tests",
            "severity": "MEDIUM",
            "steps_to_reproduce": "1. Test step",
            "expected_behavior": "Expected result",
            "actual_behavior": "Actual result"
        }
        if issue_id:
            report_data["issue_id"] = issue_id

        resp, elapsed = make_request("POST", "/bug-reports", json=report_data)
        if resp.status_code == 201:
            data = resp.json()
            if "id" in data:
                log_pass("POST /bug-reports", f"(created id={data['id']}, {elapsed:.2f}s)")
                return data
            else:
                log_fail("POST /bug-reports", "Missing 'id' in response", resp)
        else:
            log_fail("POST /bug-reports", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error("POST /bug-reports", str(e))
    return None


def test_get_bug_report(report_id: int):
    """GET /bug-reports/<id> - Get specific bug report"""
    try:
        resp, elapsed = make_request("GET", f"/bug-reports/{report_id}")
        if resp.status_code == 200:
            log_pass(f"GET /bug-reports/{report_id}", f"({elapsed:.2f}s)")
        else:
            log_fail(f"GET /bug-reports/{report_id}", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"GET /bug-reports/{report_id}", str(e))


def test_export_bug_report(report_id: int):
    """GET /bug-reports/<id>/export/<format> - Export bug report"""
    formats = ["jira", "github", "markdown"]
    for fmt in formats:
        try:
            resp, elapsed = make_request("GET", f"/bug-reports/{report_id}/export/{fmt}")
            if resp.status_code == 200:
                data = resp.json()
                if "title" in data and "content" in data:
                    log_pass(f"GET /bug-reports/{report_id}/export/{fmt}", f"({elapsed:.2f}s)")
                else:
                    log_fail(f"GET /bug-reports/{report_id}/export/{fmt}", "Missing fields in response", resp)
            else:
                log_fail(f"GET /bug-reports/{report_id}/export/{fmt}", f"Status code: {resp.status_code}", resp)
        except Exception as e:
            log_error(f"GET /bug-reports/{report_id}/export/{fmt}", str(e))


# ============================================
# SEARCH ENDPOINTS
# ============================================

def test_search_logs():
    """GET /search - Search across logs"""
    try:
        # Test with query
        resp, elapsed = make_request("GET", "/search?q=error")
        if resp.status_code == 200:
            data = resp.json()
            if "entries" in data and "count" in data:
                log_pass("GET /search?q=error", f"({data['count']} results, {elapsed:.2f}s)")
            else:
                log_fail("GET /search?q=error", "Missing fields in response", resp)
        else:
            log_fail("GET /search?q=error", f"Status code: {resp.status_code}", resp)

        # Test smart search
        resp, elapsed = make_request("GET", "/search?q=boot&smart=true")
        if resp.status_code == 200:
            data = resp.json()
            if "search_terms" in data and len(data["search_terms"]) > 1:
                log_pass("GET /search?q=boot&smart=true", f"({len(data['search_terms'])} expanded terms, {elapsed:.2f}s)")
            else:
                log_warning("GET /search?q=boot&smart=true", "Smart search may not be expanding terms")

        # Test without smart search
        resp, elapsed = make_request("GET", "/search?q=boot&smart=false")
        if resp.status_code == 200:
            data = resp.json()
            log_pass("GET /search?q=boot&smart=false", f"({elapsed:.2f}s)")

        # Test with file_id filter
        resp, elapsed = make_request("GET", "/search?q=error&file_id=1")
        if resp.status_code == 200:
            log_pass("GET /search?q=error&file_id=1", f"({elapsed:.2f}s)")

        # Test limit parameter
        resp, elapsed = make_request("GET", "/search?q=error&limit=10")
        if resp.status_code == 200:
            data = resp.json()
            if len(data["entries"]) <= 10:
                log_pass("GET /search?q=error&limit=10", f"({elapsed:.2f}s)")
            else:
                log_fail("GET /search?q=error&limit=10", f"Returned {len(data['entries'])} entries, expected <= 10")

        # Test empty query (should return 400)
        resp, elapsed = make_request("GET", "/search?q=")
        if resp.status_code == 400:
            log_pass("GET /search?q= (empty query 400 test)", f"({elapsed:.2f}s)")
        else:
            log_fail("GET /search?q= (empty query 400 test)", f"Expected 400, got {resp.status_code}")

    except Exception as e:
        log_error("GET /search", str(e))


# ============================================
# SERVICES ENDPOINT
# ============================================

def test_get_services():
    """GET /services - Get unique services"""
    try:
        resp, elapsed = make_request("GET", "/services")
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                log_pass("GET /services", f"({len(data)} services, {elapsed:.2f}s)")
            else:
                log_fail("GET /services", "Response is not a list", resp)
        else:
            log_fail("GET /services", f"Status code: {resp.status_code}", resp)

        # Test with file_id filter
        resp, elapsed = make_request("GET", "/services?file_id=1")
        if resp.status_code == 200:
            log_pass("GET /services?file_id=1", f"({elapsed:.2f}s)")
    except Exception as e:
        log_error("GET /services", str(e))


# ============================================
# SUMMARY ENDPOINT
# ============================================

def test_get_summary():
    """GET /summary - Get overall summary"""
    try:
        resp, elapsed = make_request("GET", "/summary")
        if resp.status_code == 200:
            data = resp.json()
            required_fields = ["total_files", "total_entries", "total_issues", "issues_by_severity"]
            missing = [f for f in required_fields if f not in data]
            if not missing:
                log_pass("GET /summary", f"({data['total_files']} files, {data['total_issues']} issues, {elapsed:.2f}s)")
            else:
                log_fail("GET /summary", f"Missing fields: {missing}", resp)
        else:
            log_fail("GET /summary", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error("GET /summary", str(e))


# ============================================
# SEVERITY & CATEGORY INFO ENDPOINTS
# ============================================

def test_get_severity_info():
    """GET /severity-info - Get severity level info"""
    try:
        resp, elapsed = make_request("GET", "/severity-info")
        if resp.status_code == 200:
            data = resp.json()
            log_pass("GET /severity-info", f"({elapsed:.2f}s)")
        else:
            log_fail("GET /severity-info", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error("GET /severity-info", str(e))


def test_get_category_info():
    """GET /category-info - Get category info"""
    try:
        resp, elapsed = make_request("GET", "/category-info")
        if resp.status_code == 200:
            data = resp.json()
            log_pass("GET /category-info", f"({elapsed:.2f}s)")
        else:
            log_fail("GET /category-info", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error("GET /category-info", str(e))


# ============================================
# COMPARE ENDPOINTS
# ============================================

def test_compare_log_files(file_ids: List[int]):
    """POST /log-files/compare - Compare multiple log files"""
    if len(file_ids) < 2:
        log_warning("POST /log-files/compare", "Need at least 2 files to compare")
        return

    try:
        resp, elapsed = make_request("POST", "/log-files/compare", json={"file_ids": file_ids[:2]})
        if resp.status_code == 200:
            data = resp.json()
            if "comparisons" in data:
                log_pass("POST /log-files/compare", f"({len(data['comparisons'])} files compared, {elapsed:.2f}s)")
            else:
                log_fail("POST /log-files/compare", "Missing 'comparisons' in response", resp)
        else:
            log_fail("POST /log-files/compare", f"Status code: {resp.status_code}", resp)

        # Test with insufficient files
        resp, elapsed = make_request("POST", "/log-files/compare", json={"file_ids": [1]})
        if resp.status_code == 400:
            log_pass("POST /log-files/compare (400 test - insufficient files)", f"({elapsed:.2f}s)")
        else:
            log_fail("POST /log-files/compare (400 test)", f"Expected 400, got {resp.status_code}")

    except Exception as e:
        log_error("POST /log-files/compare", str(e))


def test_compare_logs():
    """POST /compare - Compare two log files"""
    try:
        resp, elapsed = make_request("POST", "/compare", json={"file1_id": 1, "file2_id": 2})
        if resp.status_code == 200:
            data = resp.json()
            if "file1" in data and "file2" in data and "comparison" in data:
                log_pass("POST /compare", f"({elapsed:.2f}s)")
            else:
                log_fail("POST /compare", "Missing fields in response", resp)
        elif resp.status_code == 404:
            log_warning("POST /compare", "One of the files not found")
        else:
            log_fail("POST /compare", f"Status code: {resp.status_code}", resp)

        # Test without required fields
        resp, elapsed = make_request("POST", "/compare", json={"file1_id": 1})
        if resp.status_code == 400:
            log_pass("POST /compare (400 test - missing file2_id)", f"({elapsed:.2f}s)")
        else:
            log_fail("POST /compare (400 test)", f"Expected 400, got {resp.status_code}")

    except Exception as e:
        log_error("POST /compare", str(e))


# ============================================
# SYSTEM MONITORING
# ============================================

def test_system_stats():
    """GET /system/stats - Get system statistics"""
    try:
        resp, elapsed = make_request("GET", "/system/stats")
        if resp.status_code == 200:
            data = resp.json()
            if data.get("available"):
                log_pass("GET /system/stats", f"(CPU: {data['cpu']['percent']}%, MEM: {data['memory']['percent']}%, {elapsed:.2f}s)")
            else:
                log_warning("GET /system/stats", "psutil not available")
        elif resp.status_code == 503:
            log_warning("GET /system/stats", "psutil not installed")
        else:
            log_fail("GET /system/stats", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error("GET /system/stats", str(e))


# ============================================
# SAVED QUERIES ENDPOINTS
# ============================================

def test_saved_queries():
    """Test all saved queries endpoints"""
    created_query_id = None

    try:
        # GET all saved queries
        resp, elapsed = make_request("GET", "/saved-queries")
        if resp.status_code == 200:
            log_pass("GET /saved-queries", f"({len(resp.json())} queries, {elapsed:.2f}s)")
        else:
            log_fail("GET /saved-queries", f"Status code: {resp.status_code}", resp)

        # POST new saved query
        query_data = {
            "name": "Test Query",
            "query": "Find test errors",
            "description": "API test query",
            "category": "test"
        }
        resp, elapsed = make_request("POST", "/saved-queries", json=query_data)
        if resp.status_code == 201:
            data = resp.json()
            created_query_id = data.get("id")
            log_pass("POST /saved-queries", f"(created id={created_query_id}, {elapsed:.2f}s)")
        else:
            log_fail("POST /saved-queries", f"Status code: {resp.status_code}", resp)

        # Test validation
        resp, elapsed = make_request("POST", "/saved-queries", json={})
        if resp.status_code == 400:
            log_pass("POST /saved-queries (400 test - missing fields)", f"({elapsed:.2f}s)")
        else:
            log_fail("POST /saved-queries (400 test)", f"Expected 400, got {resp.status_code}")

        if created_query_id:
            # GET specific query
            resp, elapsed = make_request("GET", f"/saved-queries/{created_query_id}")
            if resp.status_code == 200:
                log_pass(f"GET /saved-queries/{created_query_id}", f"({elapsed:.2f}s)")
            else:
                log_fail(f"GET /saved-queries/{created_query_id}", f"Status code: {resp.status_code}", resp)

            # PUT update query
            resp, elapsed = make_request("PUT", f"/saved-queries/{created_query_id}", json={"name": "Updated Test Query"})
            if resp.status_code == 200:
                log_pass(f"PUT /saved-queries/{created_query_id}", f"({elapsed:.2f}s)")
            else:
                log_fail(f"PUT /saved-queries/{created_query_id}", f"Status code: {resp.status_code}", resp)

            # POST use query (increment counter)
            resp, elapsed = make_request("POST", f"/saved-queries/{created_query_id}/use")
            if resp.status_code == 200:
                log_pass(f"POST /saved-queries/{created_query_id}/use", f"({elapsed:.2f}s)")
            else:
                log_fail(f"POST /saved-queries/{created_query_id}/use", f"Status code: {resp.status_code}", resp)

            # DELETE query
            resp, elapsed = make_request("DELETE", f"/saved-queries/{created_query_id}")
            if resp.status_code == 200:
                log_pass(f"DELETE /saved-queries/{created_query_id}", f"({elapsed:.2f}s)")
            else:
                log_fail(f"DELETE /saved-queries/{created_query_id}", f"Status code: {resp.status_code}", resp)

        # Seed default queries
        resp, elapsed = make_request("POST", "/saved-queries/seed-defaults")
        if resp.status_code == 200:
            log_pass("POST /saved-queries/seed-defaults", f"({elapsed:.2f}s)")
        else:
            log_fail("POST /saved-queries/seed-defaults", f"Status code: {resp.status_code}", resp)

        # Test category filter
        resp, elapsed = make_request("GET", "/saved-queries?category=general")
        if resp.status_code == 200:
            log_pass("GET /saved-queries?category=general", f"({elapsed:.2f}s)")

    except Exception as e:
        log_error("Saved queries tests", str(e))


# ============================================
# ANNOTATIONS ENDPOINTS
# ============================================

def test_annotations(file_id: int):
    """Test annotation endpoints"""
    created_annotation_id = None

    try:
        # GET annotations
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/annotations")
        if resp.status_code == 200:
            log_pass(f"GET /log-files/{file_id}/annotations", f"({len(resp.json())} annotations, {elapsed:.2f}s)")
        else:
            log_fail(f"GET /log-files/{file_id}/annotations", f"Status code: {resp.status_code}", resp)

        # POST new annotation
        annotation_data = {
            "line_number": 1,
            "note": "Test annotation from API",
            "annotation_type": "note"
        }
        resp, elapsed = make_request("POST", f"/log-files/{file_id}/annotations", json=annotation_data)
        if resp.status_code == 201:
            data = resp.json()
            created_annotation_id = data.get("id")
            log_pass(f"POST /log-files/{file_id}/annotations", f"(created id={created_annotation_id}, {elapsed:.2f}s)")
        else:
            log_fail(f"POST /log-files/{file_id}/annotations", f"Status code: {resp.status_code}", resp)

        # Test validation
        resp, elapsed = make_request("POST", f"/log-files/{file_id}/annotations", json={})
        if resp.status_code == 400:
            log_pass(f"POST /log-files/{file_id}/annotations (400 test)", f"({elapsed:.2f}s)")
        else:
            log_fail(f"POST /log-files/{file_id}/annotations (400 test)", f"Expected 400, got {resp.status_code}")

        if created_annotation_id:
            # PUT update annotation
            resp, elapsed = make_request("PUT", f"/annotations/{created_annotation_id}", json={"note": "Updated note"})
            if resp.status_code == 200:
                log_pass(f"PUT /annotations/{created_annotation_id}", f"({elapsed:.2f}s)")
            else:
                log_fail(f"PUT /annotations/{created_annotation_id}", f"Status code: {resp.status_code}", resp)

            # DELETE annotation
            resp, elapsed = make_request("DELETE", f"/annotations/{created_annotation_id}")
            if resp.status_code == 200:
                log_pass(f"DELETE /annotations/{created_annotation_id}", f"({elapsed:.2f}s)")
            else:
                log_fail(f"DELETE /annotations/{created_annotation_id}", f"Status code: {resp.status_code}", resp)

    except Exception as e:
        log_error("Annotations tests", str(e))


# ============================================
# SHARED ANALYSIS ENDPOINTS
# ============================================

def test_shared_analysis(file_id: int):
    """Test shared analysis endpoints"""
    share_id = None

    try:
        # POST create shared link
        share_data = {
            "log_file_id": file_id,
            "title": "Test Shared Analysis",
            "expires_hours": 24
        }
        resp, elapsed = make_request("POST", "/shared", json=share_data)
        if resp.status_code == 201:
            data = resp.json()
            share_id = data.get("share_id")
            log_pass("POST /shared", f"(share_id={share_id}, {elapsed:.2f}s)")
        else:
            log_fail("POST /shared", f"Status code: {resp.status_code}", resp)

        # Test validation
        resp, elapsed = make_request("POST", "/shared", json={})
        if resp.status_code == 400:
            log_pass("POST /shared (400 test - missing log_file_id)", f"({elapsed:.2f}s)")
        else:
            log_fail("POST /shared (400 test)", f"Expected 400, got {resp.status_code}")

        if share_id:
            # GET shared analysis
            resp, elapsed = make_request("GET", f"/shared/{share_id}")
            if resp.status_code == 200:
                data = resp.json()
                log_pass(f"GET /shared/{share_id}", f"(views: {data.get('view_count', 0)}, {elapsed:.2f}s)")
            else:
                log_fail(f"GET /shared/{share_id}", f"Status code: {resp.status_code}", resp)

            # DELETE shared link
            resp, elapsed = make_request("DELETE", f"/shared/{share_id}")
            if resp.status_code == 200:
                log_pass(f"DELETE /shared/{share_id}", f"({elapsed:.2f}s)")
            else:
                log_fail(f"DELETE /shared/{share_id}", f"Status code: {resp.status_code}", resp)

        # Test 404 for invalid share_id
        resp, elapsed = make_request("GET", "/shared/invalid-share-id")
        if resp.status_code == 404:
            log_pass("GET /shared/invalid (404 test)", f"({elapsed:.2f}s)")
        else:
            log_fail("GET /shared/invalid (404 test)", f"Expected 404, got {resp.status_code}")

        # GET file shared links
        resp, elapsed = make_request("GET", f"/log-files/{file_id}/shared-links")
        if resp.status_code == 200:
            log_pass(f"GET /log-files/{file_id}/shared-links", f"({len(resp.json())} links, {elapsed:.2f}s)")
        else:
            log_fail(f"GET /log-files/{file_id}/shared-links", f"Status code: {resp.status_code}", resp)

    except Exception as e:
        log_error("Shared analysis tests", str(e))


# ============================================
# JIRA INTEGRATION ENDPOINTS
# ============================================

def test_jira_integration():
    """Test Jira integration endpoints"""
    try:
        # GET Jira config
        resp, elapsed = make_request("GET", "/jira/config")
        if resp.status_code == 200:
            data = resp.json()
            configured = data.get("configured", False)
            log_pass("GET /jira/config", f"(configured: {configured}, {elapsed:.2f}s)")
        else:
            log_fail("GET /jira/config", f"Status code: {resp.status_code}", resp)

        # POST Jira config validation test
        resp, elapsed = make_request("POST", "/jira/config", json={})
        if resp.status_code == 400:
            log_pass("POST /jira/config (400 test - missing fields)", f"({elapsed:.2f}s)")
        else:
            log_fail("POST /jira/config (400 test)", f"Expected 400, got {resp.status_code}")

        # POST test connection (will fail without config)
        resp, elapsed = make_request("POST", "/jira/test")
        if resp.status_code in [200, 400, 500]:
            log_pass("POST /jira/test", f"(status: {resp.status_code}, {elapsed:.2f}s)")

        # GET projects (will fail without config)
        resp, elapsed = make_request("GET", "/jira/projects")
        if resp.status_code in [200, 400]:
            log_pass("GET /jira/projects", f"(status: {resp.status_code}, {elapsed:.2f}s)")

        # POST create issue validation
        resp, elapsed = make_request("POST", "/jira/create-issue", json={})
        if resp.status_code == 400:
            log_pass("POST /jira/create-issue (400 test)", f"({elapsed:.2f}s)")

    except Exception as e:
        log_error("Jira integration tests", str(e))


# ============================================
# AI ENDPOINTS
# ============================================

def test_ai_endpoints(file_id: int):
    """Test AI-related endpoints"""
    try:
        # GET AI agent status
        resp, elapsed = make_request("GET", "/ai-agent/status")
        if resp.status_code == 200:
            data = resp.json()
            available = data.get("available", False)
            log_pass("GET /ai-agent/status", f"(available: {available}, {elapsed:.2f}s)")
        else:
            log_fail("GET /ai-agent/status", f"Status code: {resp.status_code}", resp)

        # POST AI search
        resp, elapsed = make_request("POST", f"/log-files/{file_id}/ai-search", json={"query": "find errors"})
        if resp.status_code == 200:
            log_pass(f"POST /log-files/{file_id}/ai-search", f"({elapsed:.2f}s)")
        elif resp.status_code == 400:
            log_pass(f"POST /log-files/{file_id}/ai-search (validation)", f"({elapsed:.2f}s)")
        else:
            log_fail(f"POST /log-files/{file_id}/ai-search", f"Status code: {resp.status_code}", resp)

        # Test empty query validation
        resp, elapsed = make_request("POST", f"/log-files/{file_id}/ai-search", json={"query": ""})
        if resp.status_code == 400:
            log_pass(f"POST /log-files/{file_id}/ai-search (400 test - empty query)", f"({elapsed:.2f}s)")
        else:
            log_fail(f"POST /log-files/{file_id}/ai-search (400 test)", f"Expected 400, got {resp.status_code}")

        # POST deep analysis (may be slow or require API key)
        resp, elapsed = make_request("POST", f"/log-files/{file_id}/deep-analysis",
                                     json={"query": "analyze", "session_id": "test"}, timeout=60)
        if resp.status_code in [200, 503]:
            log_pass(f"POST /log-files/{file_id}/deep-analysis", f"(status: {resp.status_code}, {elapsed:.2f}s)")
        else:
            log_fail(f"POST /log-files/{file_id}/deep-analysis", f"Status code: {resp.status_code}", resp)

        # POST AI followup
        resp, elapsed = make_request("POST", f"/log-files/{file_id}/ai-followup",
                                     json={"query": "explain more", "session_id": "test"})
        if resp.status_code in [200, 503]:
            log_pass(f"POST /log-files/{file_id}/ai-followup", f"(status: {resp.status_code}, {elapsed:.2f}s)")

        # POST clear conversation validation
        resp, elapsed = make_request("POST", "/ai-agent/clear-conversation", json={})
        if resp.status_code == 400:
            log_pass("POST /ai-agent/clear-conversation (400 test)", f"({elapsed:.2f}s)")
        else:
            log_fail("POST /ai-agent/clear-conversation (400 test)", f"Expected 400, got {resp.status_code}")

        # POST clear conversation with session_id
        resp, elapsed = make_request("POST", "/ai-agent/clear-conversation", json={"session_id": "test"})
        if resp.status_code == 200:
            log_pass("POST /ai-agent/clear-conversation", f"({elapsed:.2f}s)")

    except Exception as e:
        log_error("AI endpoints tests", str(e))


def test_multi_file_analysis(file_ids: List[int]):
    """POST /multi-analysis - Analyze multiple files"""
    if len(file_ids) < 2:
        log_warning("POST /multi-analysis", "Need at least 2 files")
        return

    try:
        resp, elapsed = make_request("POST", "/multi-analysis",
                                     json={"file_ids": file_ids[:2], "query": "compare"}, timeout=60)
        if resp.status_code in [200, 503]:
            log_pass("POST /multi-analysis", f"(status: {resp.status_code}, {elapsed:.2f}s)")
        else:
            log_fail("POST /multi-analysis", f"Status code: {resp.status_code}", resp)

        # Test validation
        resp, elapsed = make_request("POST", "/multi-analysis", json={"file_ids": [1]})
        if resp.status_code == 400:
            log_pass("POST /multi-analysis (400 test - insufficient files)", f"({elapsed:.2f}s)")

    except Exception as e:
        log_error("POST /multi-analysis", str(e))


# ============================================
# REPARSE ENDPOINT
# ============================================

def test_reparse_log_file(file_id: int):
    """POST /log-files/<id>/reparse - Re-parse log file"""
    try:
        resp, elapsed = make_request("POST", f"/log-files/{file_id}/reparse")
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success"):
                log_pass(f"POST /log-files/{file_id}/reparse", f"({data.get('total_lines', 0)} lines, {elapsed:.2f}s)")
            else:
                log_fail(f"POST /log-files/{file_id}/reparse", "success=False in response", resp)
        elif resp.status_code == 404:
            log_warning(f"POST /log-files/{file_id}/reparse", "File not found on disk")
        else:
            log_fail(f"POST /log-files/{file_id}/reparse", f"Status code: {resp.status_code}", resp)
    except Exception as e:
        log_error(f"POST /log-files/{file_id}/reparse", str(e))


# ============================================
# COMPRESSED FILE UPLOAD
# ============================================

def test_compressed_upload():
    """POST /upload/compressed - Test compressed file validation"""
    try:
        # Test without file
        resp, elapsed = make_request("POST", "/upload/compressed")
        if resp.status_code == 400:
            log_pass("POST /upload/compressed (400 test - no file)", f"({elapsed:.2f}s)")
        else:
            log_fail("POST /upload/compressed (400 test)", f"Expected 400, got {resp.status_code}")
    except Exception as e:
        log_error("POST /upload/compressed", str(e))


# ============================================
# MAIN TEST RUNNER
# ============================================

def run_all_tests():
    """Run all API tests"""
    start_time = time.time()

    print(f"\n{Colors.BOLD}{'='*60}")
    print("  SENTINEL LOGGER API TEST SUITE")
    print(f"  Target: {BASE_URL}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}{Colors.RESET}")

    # Get initial data for tests
    test_section("LOG FILES ENDPOINTS")
    log_files = test_get_log_files()

    if log_files:
        file_id = log_files[0]["id"]
        file_ids = [f["id"] for f in log_files[:3]]

        test_get_log_file(file_id)
        test_get_log_file_404()
        test_get_log_entries(file_id)
        test_get_log_issues(file_id)
        test_get_chart_data(file_id)
        test_get_log_stats(file_id)
        test_get_log_minimap(file_id)
        test_get_health_score(file_id)
        test_export_log_file(file_id)
        test_get_patterns(file_id)
        test_get_error_sequences(file_id)
        test_get_service_health(file_id)
        test_get_raw_log(file_id)
        test_get_timeline(file_id)
        test_export_csv(file_id)
        test_export_json(file_id)
        test_export_pdf(file_id)
    else:
        log_warning("Log file tests", "No log files found, skipping file-specific tests")

    test_section("ISSUES ENDPOINTS")
    issues = test_get_all_issues()
    test_get_issues_filters()

    issue_id = None
    if issues:
        issue_id = issues[0]["id"]
        test_get_issue(issue_id)
        test_update_issue(issue_id)
        test_get_issue_context(issue_id)
        test_export_issue(issue_id)
    else:
        log_warning("Issue tests", "No issues found, skipping issue-specific tests")

    test_section("BUG REPORTS ENDPOINTS")
    bug_reports = test_get_bug_reports()
    new_report = test_create_bug_report(issue_id)
    if new_report:
        test_get_bug_report(new_report["id"])
        test_export_bug_report(new_report["id"])

    test_section("SEARCH & SERVICES ENDPOINTS")
    test_search_logs()
    test_get_services()

    test_section("SUMMARY & INFO ENDPOINTS")
    test_get_summary()
    test_get_severity_info()
    test_get_category_info()

    test_section("COMPARISON ENDPOINTS")
    if log_files and len(log_files) >= 2:
        test_compare_log_files(file_ids)
        test_compare_logs()
    else:
        log_warning("Comparison tests", "Need at least 2 files to test comparison")

    test_section("SYSTEM MONITORING")
    test_system_stats()

    test_section("SAVED QUERIES ENDPOINTS")
    test_saved_queries()

    test_section("ANNOTATIONS ENDPOINTS")
    if log_files:
        test_annotations(log_files[0]["id"])

    test_section("SHARED ANALYSIS ENDPOINTS")
    if log_files:
        test_shared_analysis(log_files[0]["id"])

    test_section("JIRA INTEGRATION ENDPOINTS")
    test_jira_integration()

    test_section("AI ENDPOINTS")
    if log_files:
        test_ai_endpoints(log_files[0]["id"])
        if len(log_files) >= 2:
            test_multi_file_analysis(file_ids)

    test_section("REPARSE & UPLOAD ENDPOINTS")
    # Skip reparse to avoid modifying data
    # if log_files:
    #     test_reparse_log_file(log_files[0]["id"])
    test_compressed_upload()

    # Calculate total time
    results["total_time"] = time.time() - start_time

    # Print summary
    print_summary()


def print_summary():
    """Print test results summary"""
    total_tests = len(results["passed"]) + len(results["failed"]) + len(results["errors"])

    print(f"\n{Colors.BOLD}{'='*60}")
    print("  TEST RESULTS SUMMARY")
    print(f"{'='*60}{Colors.RESET}")

    print(f"\n  {Colors.GREEN}Passed:{Colors.RESET}   {len(results['passed'])}")
    print(f"  {Colors.RED}Failed:{Colors.RESET}   {len(results['failed'])}")
    print(f"  {Colors.RED}Errors:{Colors.RESET}   {len(results['errors'])}")
    print(f"  {Colors.YELLOW}Warnings:{Colors.RESET} {len(results['warnings'])}")
    print(f"  Total:    {total_tests}")
    print(f"  Time:     {results['total_time']:.2f}s")

    pass_rate = (len(results["passed"]) / total_tests * 100) if total_tests > 0 else 0
    print(f"\n  Pass Rate: {pass_rate:.1f}%")

    if results["failed"]:
        print(f"\n{Colors.RED}{Colors.BOLD}FAILED TESTS:{Colors.RESET}")
        for fail in results["failed"]:
            print(f"  - {fail['test']}: {fail['message']}")

    if results["errors"]:
        print(f"\n{Colors.RED}{Colors.BOLD}TEST ERRORS:{Colors.RESET}")
        for error in results["errors"]:
            print(f"  - {error['test']}: {error['error']}")

    if results["warnings"]:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}WARNINGS:{Colors.RESET}")
        for warn in results["warnings"]:
            print(f"  - {warn['test']}: {warn['message']}")

    print(f"\n{'='*60}\n")

    # Return exit code
    if results["failed"] or results["errors"]:
        return 1
    return 0


if __name__ == "__main__":
    try:
        exit_code = run_all_tests()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nTest run interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFatal error: {e}")
        sys.exit(1)
