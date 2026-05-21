"""
Wayback Machine Scanner — Find archived versions of known leaked repos.
Uses the CDX API to discover historical snapshots where deleted keys may persist.
"""

import aiohttp
import asyncio
import urllib.parse
from .base import BaseScanner, extract_keys


class WaybackScanner(BaseScanner):
    CDX_API = "https://web.archive.org/cdx/search/cdx"

    def __init__(self, target_domains: list = None, max_snapshots: int = 200, **kwargs):
        super().__init__(**kwargs)
        self.target_domains = target_domains or [
            "github.com",
            "gitlab.com",
            "gitee.com",
            "raw.githubusercontent.com",
            "pastebin.com",
        ]
        self.max_snapshots = max_snapshots

    @property
    def source_name(self) -> str:
        return "wayback"

    async def search(self, query: str | None = None) -> list[dict]:
        """query can be a domain or a file path to search for in archived URLs"""
        self.results = []
        query = query or "github.com"
        sem = asyncio.Semaphore(self.concurrency)

        async with aiohttp.ClientSession() as session:
            for domain in ([query] if query else self.target_domains):
                if self._should_stop():
                    break

                snapshots = await self._query_cdx(session, domain)
                if not snapshots:
                    continue

                tasks = [self._fetch_snapshot(session, sem, s) for s in snapshots]
                await asyncio.gather(*tasks)

        return self.results

    async def _query_cdx(self, session, domain: str) -> list:
        """Query CDX API for archived URLs matching domain, filtering for target file types."""
        filter_expr = "statuscode:200"
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "limit": 5000,
            "filter": "statuscode:200",
            "fl": "timestamp,original,statuscode",
            "collapse": "digest",
        }
        qs = urllib.parse.urlencode(params)
        url = f"{self.CDX_API}?{qs}"

        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    lines = text.strip().split("\n")
                    if len(lines) > 1:
                        snapshots = []
                        for line in lines[1:]:  # Skip header
                            parts = line.split(" ", 2)
                            if len(parts) >= 2:
                                ts, original = parts[0], parts[1]
                                original_lower = original.lower()
                                if any(ext in original_lower for ext in
                                       [".env", ".json", ".yml", ".yaml", ".py", ".js",
                                        ".txt", ".md", ".properties", "config", "credential",
                                        "secret", "dockerfile", ".npmrc", ".env."]):
                                    snapshots.append((ts, original))
                                    if len(snapshots) >= self.max_snapshots:
                                        break
                        return snapshots
        except Exception:
            pass
        return []

    async def _fetch_snapshot(self, session, sem, snapshot: tuple):
        ts, original_url = snapshot
        wayback_url = f"https://web.archive.org/web/{ts}id_/{original_url}"

        async with sem:
            try:
                async with session.get(wayback_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        content_type = resp.headers.get("Content-Type", "")
                        if "text" in content_type or "json" in content_type or "javascript" in content_type:
                            text = await resp.text()
                            for k in extract_keys(text, self.extra_bad):
                                self._add_result(
                                    k, wayback_url,
                                    original_url.split("/")[2] if "/" in original_url else "",
                                    original_url, self.source_name
                                )
            except Exception:
                pass

    def search_known_repo(self, repo_url: str, file_path: str = "") -> list:
        """Synchronous helper for targeted search of a known repo."""
        import requests

        results = []
        search_url = f"{repo_url}/{file_path}" if file_path else repo_url

        params = {
            "url": f"*.{search_url}*",
            "output": "json",
            "limit": 100,
            "filter": "statuscode:200",
            "fl": "timestamp,original",
        }
        try:
            resp = requests.get(self.CDX_API, params=params, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if len(data) > 1:
                    for row in data[1:]:
                        if len(row) >= 2:
                            ts, original = row[0], row[1]
                            wayback_url = f"https://web.archive.org/web/{ts}id_/{original}"
                            try:
                                r2 = requests.get(wayback_url, timeout=15,
                                                  headers={"User-Agent": "Mozilla/5.0"})
                                if r2.status_code == 200:
                                    for k in extract_keys(r2.text):
                                        results.append({
                                            "key": k,
                                            "source": "wayback",
                                            "url": wayback_url,
                                            "original_url": original,
                                        })
                            except Exception:
                                pass
        except Exception:
            pass
        return results
