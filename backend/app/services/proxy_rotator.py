import os
import time
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Any
from pathlib import Path

logger = logging.getLogger("proxy_rotator")


class ProxyRotator:
    """
    Enterprise-grade, compliant proxy pool manager.
    Security Principles:
    - Zero public scraping: NEVER harvests unauthenticated public GitHub mirrors or open honeypots.
    - Strictly opt-in: Only routes through user-provided proxies in `backend/proxies.txt` or `PROXY_LIST` env var.
    - Direct connection by default: Fast, compliant, zero initialization lag.
    - Thread-safe round-robin dispatch with automatic circuit-breaker quarantine on HTTP 429/403/timeouts.
    """

    def __init__(self, quarantine_duration: int = 300, health_check_timeout: float = 2.0):
        self.quarantine_duration = quarantine_duration
        self.health_check_timeout = health_check_timeout
        self.proxies: List[str] = []
        self.quarantined: Dict[str, float] = {}  # proxy -> expiration timestamp
        self.stats: Dict[str, Dict[str, Any]] = {}
        self.current_idx = 0
        self._lock = threading.Lock()
        self.is_refreshing = False
        self.last_refresh_timestamp: Optional[float] = None

        # Initialize user-defined proxies
        self.refresh_pool()

    def _clean_proxy_url(self, raw: str) -> Optional[str]:
        line = raw.strip()
        if not line or line.startswith("#"):
            return None
        if not line.startswith(("http://", "https://", "socks4://", "socks5://")):
            line = f"http://{line}"
        return line

    def _load_user_proxies(self) -> List[str]:
        """Loads proxies from PROXY_LIST env var and backend/proxies.txt file."""
        proxies = []

        # 1. Environment Variable PROXY_LIST
        from app.config import PROXY_LIST, ENABLE_PROXY_ROTATION
        if not ENABLE_PROXY_ROTATION:
            return []

        if PROXY_LIST:
            for item in PROXY_LIST.split(","):
                cleaned = self._clean_proxy_url(item)
                if cleaned and cleaned not in proxies:
                    proxies.append(cleaned)

        # 2. backend/proxies.txt file
        proxy_file = Path(__file__).resolve().parent.parent.parent / "proxies.txt"
        if proxy_file.exists():
            try:
                with open(proxy_file, "r", encoding="utf-8") as f:
                    for line in f:
                        cleaned = self._clean_proxy_url(line)
                        if cleaned and cleaned not in proxies:
                            proxies.append(cleaned)
            except Exception as e:
                logger.warning(f"Failed to read proxies.txt: {e}")

        return proxies

    def _verify_proxy(self, proxy_url: str) -> bool:
        """Lightweight pre-flight probe using requests with strict timeout."""
        import requests
        try:
            proxies = {"http": proxy_url, "https": proxy_url}
            # Use Google 204 or httpbin for quick handshake check
            resp = requests.get(
                "https://www.google.com/generate_204",
                proxies=proxies,
                timeout=self.health_check_timeout
            )
            return resp.status_code == 204 or resp.status_code == 200
        except Exception:
            return False

    def _verify_proxy_batch(self, proxy_list: List[str]) -> List[str]:
        """Concurrently verifies proxy candidates using ThreadPoolExecutor."""
        if not proxy_list:
            return []

        healthy = []
        with ThreadPoolExecutor(max_workers=min(10, len(proxy_list))) as executor:
            future_to_proxy = {executor.submit(self._verify_proxy, p): p for p in proxy_list}
            for future in as_completed(future_to_proxy, timeout=self.health_check_timeout + 1.0):
                p = future_to_proxy[future]
                try:
                    if future.result():
                        healthy.append(p)
                except Exception:
                    pass

        return healthy

    def refresh_pool(self):
        """Refreshes user-provided proxy list without blocking server startup."""
        with self._lock:
            if self.is_refreshing:
                return
            self.is_refreshing = True

        try:
            user_candidates = self._load_user_proxies()
            if user_candidates:
                verified = self._verify_proxy_batch(user_candidates)
                with self._lock:
                    self.proxies = verified if verified else user_candidates
            else:
                with self._lock:
                    self.proxies = []
        finally:
            with self._lock:
                self.is_refreshing = False
                self.last_refresh_timestamp = time.time()

    def get_proxy(self) -> Optional[str]:
        """
        Retrieves the next active proxy using round-robin.
        Returns None if no user proxies configured, enabling clean direct connection.
        """
        now = time.time()
        with self._lock:
            # Release expired quarantines
            expired = [p for p, exp in self.quarantined.items() if exp <= now]
            for p in expired:
                del self.quarantined[p]

            available = [p for p in self.proxies if p not in self.quarantined]
            if not available:
                return None  # Direct connection fallback

            self.current_idx = (self.current_idx + 1) % len(available)
            return available[self.current_idx]

    def report_success(self, proxy_url: Optional[str]):
        if not proxy_url:
            return
        with self._lock:
            if proxy_url not in self.stats:
                self.stats[proxy_url] = {"successes": 0, "failures": 0}
            self.stats[proxy_url]["successes"] += 1

    def report_failure(self, proxy_url: Optional[str], status_code: Optional[int] = None):
        """Places failing proxy on quarantine cooldown."""
        if not proxy_url:
            return
        with self._lock:
            if proxy_url not in self.stats:
                self.stats[proxy_url] = {"successes": 0, "failures": 0}
            self.stats[proxy_url]["failures"] += 1
            self.quarantined[proxy_url] = time.time() + self.quarantine_duration
            logger.info(f"Quarantined proxy {proxy_url} for {self.quarantine_duration}s (status={status_code})")

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            active_quarantines = {p: int(exp - now) for p, exp in self.quarantined.items() if exp > now}
            active_count = len([p for p in self.proxies if p not in active_quarantines])
            from app.config import ENABLE_PROXY_ROTATION

            return {
                "enabled": ENABLE_PROXY_ROTATION and len(self.proxies) > 0,
                "mode": "user_configured_pool" if self.proxies else "direct_connection",
                "total_proxies": len(self.proxies),
                "active_proxies": active_count,
                "quarantined_proxies": len(active_quarantines),
                "quarantined_details": active_quarantines,
                "quarantine_duration_sec": self.quarantine_duration,
                "is_refreshing": self.is_refreshing,
                "last_refresh_timestamp": self.last_refresh_timestamp,
                "stats": self.stats
            }


# Global singleton proxy rotator instance
proxy_rotator = ProxyRotator()
