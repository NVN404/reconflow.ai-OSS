"""
ReconFlow AI: Open-Source Search Client
========================================
High-throughput multi-engine search client using free, open-source search libraries:
  - googlesearch-python: Google organic search results
  - duckduckgo_search: DuckDuckGo text, news, and video search

All methods return the standard (List[Dict], Optional[str]) interface expected
by phase1_domain.py and phase2_external.py.
"""

import time
import traceback
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from app.services.proxy_rotator import proxy_rotator


class OpenSearchClient:
    """
    Unified open-source search client with resilient proxy rotation.
    Handles multi-engine search execution across DuckDuckGo, Google, and OSINT sources.
    """

    def __init__(self):
        self.proxy_rotator = proxy_rotator

    def search(
        self,
        query: str,
        engine: str = "google",
        num_results: int = 10,
        timeout: int = 15,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Dispatches a search query to the appropriate open-source engine.
        Returns: (results_list, error_message)
        Each result dict has: { "link": str, "title": str, "snippet": str }
        """
        engine_lower = engine.lower().strip()

        try:
            if engine_lower in ("google", "google_light"):
                return self._search_google(query, num_results=num_results, timeout=timeout)
            elif engine_lower in ("duckduckgo", "ddg", "bing"):
                return self._search_duckduckgo(query, num_results=num_results)
            elif engine_lower in ("duckduckgo_news", "google_news", "news"):
                return self._search_duckduckgo_news(query, num_results=num_results)
            elif engine_lower in ("duckduckgo_videos", "youtube", "videos"):
                return self._search_duckduckgo_videos(query, num_results=num_results)
            elif engine_lower == "google_play":
                return self._search_google_play(query, num_results=num_results, timeout=timeout)
            else:
                return self._search_duckduckgo(query, num_results=num_results)
        except Exception as e:
            return [], f"Search error ({engine_lower}): {str(e)}"

    # ─── Certificate Transparency (crt.sh) ────────────────────────────────

    def search_crt_sh(self, domain: str, timeout: int = 6) -> List[str]:
        """
        Passive, ToS-compliant subdomain reconnaissance using public Certificate Transparency logs (crt.sh).
        Queries public SSL/TLS certificate transparency records with zero rate limits or scraping blocks.
        """
        import requests
        clean_domain = domain.strip().lower()
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{clean_domain}&output=json"
            resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name_val = entry.get("name_value", "")
                    for name in name_val.split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(clean_domain) and name != clean_domain and "." in name:
                            subdomains.add(name)
        except Exception:
            pass
        return sorted(list(subdomains))[:20]

    # ─── Google Search via googlesearch-python ────────────────────────────

    def _search_google(
        self, query: str, num_results: int = 10, timeout: int = 10
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        try:
            from googlesearch import search as google_search
        except ImportError:
            return [], "googlesearch-python is not installed. Run: pip install googlesearch-python"

        proxy = self.proxy_rotator.get_proxy()

        def _run_query(active_proxy: Optional[str]):
            res = []
            # 1.0s sleep interval prevents immediate Google IP blocks
            for url in google_search(query, num_results=num_results, sleep_interval=1.0, advanced=False, proxy=active_proxy, timeout=timeout):
                if isinstance(url, str):
                    host = urlparse(url).netloc
                    res.append({
                        "link": url,
                        "title": host,
                        "snippet": f"Discovered via Google search: {query}",
                    })
                else:
                    res.append({
                        "link": getattr(url, "url", str(url)),
                        "title": getattr(url, "title", ""),
                        "snippet": getattr(url, "description", ""),
                    })
            return res

        try:
            results = _run_query(proxy)
            if proxy:
                self.proxy_rotator.report_success(proxy)
            return results, None
        except Exception as e:
            if proxy:
                self.proxy_rotator.report_failure(proxy)
            # Resilient fallback to DuckDuckGo when Google is blocked or rate-limited
            ddg_results, ddg_err = self._search_duckduckgo(query, num_results=num_results)
            if ddg_results:
                return ddg_results, None
            return [], f"Search error (Google rate-limited: {str(e)}; DDG fallback: {ddg_err})"

    # ─── DuckDuckGo Text Search ───────────────────────────────────────────

    def _search_duckduckgo(
        self, query: str, num_results: int = 10
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        try:
            from duckduckgo_search import DDGS
        except ImportError:
            return [], "duckduckgo_search is not installed. Run: pip install duckduckgo_search"

        proxy = self.proxy_rotator.get_proxy()

        def _run_query(active_proxy: Optional[str]):
            res = []
            with DDGS(proxy=active_proxy) as ddgs:
                for r in ddgs.text(query, max_results=num_results):
                    res.append({
                        "link": r.get("href", ""),
                        "title": r.get("title", ""),
                        "snippet": r.get("body", ""),
                    })
            return res

        try:
            results = _run_query(proxy)
            if proxy:
                self.proxy_rotator.report_success(proxy)
            return results, None
        except Exception as e:
            if proxy:
                self.proxy_rotator.report_failure(proxy)
                # Retry once with another proxy or direct
                try:
                    fallback_proxy = self.proxy_rotator.get_proxy()
                    results = _run_query(fallback_proxy)
                    if fallback_proxy:
                        self.proxy_rotator.report_success(fallback_proxy)
                    return results, None
                except Exception:
                    pass
            return [], f"DuckDuckGo search error: {str(e)}"

    # ─── DuckDuckGo News Search (replaces google_news engine) ─────────────

    def _search_duckduckgo_news(
        self, query: str, num_results: int = 10
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        try:
            from duckduckgo_search import DDGS
        except ImportError:
            return [], "duckduckgo_search is not installed. Run: pip install duckduckgo_search"

        proxy = self.proxy_rotator.get_proxy()

        def _run_query(active_proxy: Optional[str]):
            res = []
            with DDGS(proxy=active_proxy) as ddgs:
                for r in ddgs.news(query, max_results=num_results):
                    res.append({
                        "link": r.get("url", ""),
                        "title": r.get("title", ""),
                        "snippet": r.get("body", ""),
                        "source": r.get("source", ""),
                        "date": r.get("date", ""),
                    })
            return res

        try:
            results = _run_query(proxy)
            if proxy:
                self.proxy_rotator.report_success(proxy)
            return results, None
        except Exception as e:
            if proxy:
                self.proxy_rotator.report_failure(proxy)
                # Retry once with another proxy or direct
                try:
                    fallback_proxy = self.proxy_rotator.get_proxy()
                    results = _run_query(fallback_proxy)
                    if fallback_proxy:
                        self.proxy_rotator.report_success(fallback_proxy)
                    return results, None
                except Exception:
                    pass
            return [], f"DuckDuckGo News error: {str(e)}"

    # ─── DuckDuckGo Video Search (replaces YouTube engine) ────────────────

    def _search_duckduckgo_videos(
        self, query: str, num_results: int = 10
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        try:
            from duckduckgo_search import DDGS
        except ImportError:
            return [], "duckduckgo_search is not installed. Run: pip install duckduckgo_search"

        proxy = self.proxy_rotator.get_proxy()

        def _run_query(active_proxy: Optional[str]):
            res = []
            with DDGS(proxy=active_proxy) as ddgs:
                for r in ddgs.videos(query, max_results=num_results):
                    content_url = r.get("content", "")
                    embed_url = r.get("embed_url", "")
                    link = content_url or embed_url or ""
                    res.append({
                        "link": link,
                        "title": r.get("title", ""),
                        "snippet": r.get("description", ""),
                        "description": r.get("description", ""),
                        "channel": {"name": r.get("publisher", r.get("uploader", "Unknown Channel"))},
                        "views": r.get("statistics", {}).get("viewCount", "N/A") if isinstance(r.get("statistics"), dict) else "N/A",
                        "published_date": r.get("published", ""),
                    })
            return res

        try:
            results = _run_query(proxy)
            if proxy:
                self.proxy_rotator.report_success(proxy)
            return results, None
        except Exception as e:
            if proxy:
                self.proxy_rotator.report_failure(proxy)
                # Retry once with another proxy or direct
                try:
                    fallback_proxy = self.proxy_rotator.get_proxy()
                    results = _run_query(fallback_proxy)
                    if fallback_proxy:
                        self.proxy_rotator.report_success(fallback_proxy)
                    return results, None
                except Exception:
                    pass
            return [], f"DuckDuckGo Videos error: {str(e)}"

    # ─── Google Play via Google Search ────────────────────────────────────

    def _search_google_play(
        self, query: str, num_results: int = 5, timeout: int = 15
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Searches Google Play Store by performing a Google search scoped to play.google.com."""
        play_query = f"site:play.google.com {query}"
        results, err = self._search_google(play_query, num_results=num_results, timeout=timeout)
        if err:
            return results, err

        # Enrich results with Play Store metadata from the URL
        enriched: List[Dict[str, Any]] = []
        for r in results:
            link = r.get("link", "")
            if "play.google.com" not in link:
                continue
            # Extract package ID from URL if present
            product_id = ""
            if "id=" in link:
                product_id = link.split("id=")[-1].split("&")[0]

            enriched.append({
                "link": link,
                "title": r.get("title", "").replace(" - Apps on Google Play", "").replace(" - Google Play", "").strip(),
                "snippet": r.get("snippet", ""),
                "product_id": product_id,
                "developer": "",
                "rating": "N/A",
            })

        return enriched, None

    def is_available(self) -> bool:
        """Check if at least one search library is installed."""
        try:
            from googlesearch import search as _
            return True
        except ImportError:
            pass
        try:
            from duckduckgo_search import DDGS as _
            return True
        except ImportError:
            pass
        return False

    def get_proxy_status(self) -> Dict[str, Any]:
        """Returns the current proxy rotation health and pool metrics."""
        return self.proxy_rotator.get_status()
