import re
import json
import time
from pathlib import Path
from typing import Optional, Dict, Any
from app.config import CACHE_DIR

DEFAULT_CACHE_TTL_SEC = 86400  # 24 Hours


def _sanitize_domain(domain: str) -> str:
    """Strictly sanitizes domain name to prevent directory traversal attacks."""
    clean = domain.strip().lower()
    # Strip protocol prefix if present
    clean = re.sub(r"^https?://", "", clean).split("/")[0]
    # Allow only alphanumeric, dot, and hyphen; replace everything else with underscore
    sanitized = re.sub(r"[^a-z0-9.-]", "_", clean).strip("._-")
    return sanitized or "invalid_target"


def get_cached_scan(domain: str, max_age_sec: int = DEFAULT_CACHE_TTL_SEC) -> Optional[Dict[str, Any]]:
    """
    Retrieves cached scan results for a domain if available and not expired.
    Returns None if cache is missing or stale.
    """
    clean_domain = _sanitize_domain(domain)

    # Check for demo fixture first if target is demo-sandbox.corp
    if clean_domain in ("demo-sandbox.corp", "demo"):
        fixture_path = CACHE_DIR / "demo_mock.json"
        if fixture_path.exists():
            try:
                with open(fixture_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[CACHE] Error reading demo fixture: {e}")

    cache_file = (CACHE_DIR / f"{clean_domain}.json").resolve()
    # Path traversal protection: Ensure resolved path is strictly within CACHE_DIR
    if not str(cache_file).startswith(str(CACHE_DIR.resolve())):
        return None

    if not cache_file.exists():
        return None

    try:
        # Check TTL
        mtime = cache_file.stat().st_mtime
        if time.time() - mtime > max_age_sec:
            return None  # Stale cache

        with open(cache_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data
    except Exception as e:
        print(f"[CACHE] Error reading cache for {domain}: {e}")
        return None


def set_cached_scan(domain: str, data: Dict[str, Any]) -> None:
    """Writes scan result to cache disk securely."""
    clean_domain = _sanitize_domain(domain)
    cache_file = (CACHE_DIR / f"{clean_domain}.json").resolve()
    # Path traversal protection: Ensure resolved path is strictly within CACHE_DIR
    if not str(cache_file).startswith(str(CACHE_DIR.resolve())):
        return

    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[CACHE] Error writing cache for {domain}: {e}")
