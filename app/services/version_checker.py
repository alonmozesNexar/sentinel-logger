"""
Background version checker for Sentinel Logger.
Checks for updates on startup without blocking.
"""
import threading
import logging

logger = logging.getLogger(__name__)

REPO_URL = "https://github.com/niceforbear/sentinel-logger"
INSTALL_CMD = f"pip install --upgrade git+{REPO_URL}.git"


def check_for_updates(current_version: str):
    """Check for updates in a background thread. Prints a message if a newer version exists."""
    thread = threading.Thread(target=_check, args=(current_version,), daemon=True)
    thread.start()


def _check(current_version: str):
    try:
        import requests
        # Check latest release tag via GitHub API
        api_url = REPO_URL.replace("github.com", "api.github.com/repos") + "/releases/latest"
        resp = requests.get(api_url, timeout=5)
        if resp.status_code != 200:
            return

        latest = resp.json().get("tag_name", "").lstrip("v")
        if not latest:
            return

        if _version_newer(latest, current_version):
            print(f"\n    ** Update available: v{current_version} -> v{latest}")
            print(f"    ** Run: {INSTALL_CMD}\n")
    except Exception:
        # Silently fail — user may be offline
        pass


def _version_newer(latest: str, current: str) -> bool:
    """Compare semver strings. Returns True if latest > current."""
    try:
        lat = tuple(int(x) for x in latest.split("."))
        cur = tuple(int(x) for x in current.split("."))
        return lat > cur
    except (ValueError, AttributeError):
        return False
