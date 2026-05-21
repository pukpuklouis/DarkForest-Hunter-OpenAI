"""
Common Crawl Scanner — Query the Common Crawl Index to find URLs containing
leaked DeepSeek keys in archived web pages (used as LLM training data).
"""

import aiohttp
import asyncio
import json
import gzip
import io
import time
from .base import BaseScanner, extract_keys


class CommonCrawlScanner(BaseScanner):
    INDEX_API = "https://index.commoncrawl.org"

    def __init__(self, index_name: str = "", max_urls: int = 500, **kwargs):
        super().__init__(**kwargs)
        self.index_name = index_name or self._latest_index()
        self.max_urls = max_urls

    @staticmethod
    def _latest_index() -> str:
        """Return the latest CC index name by querying the Collinfo API.
        Falls back to a sensible default if the API is unreachable."""
        import requests
        try:
            resp = requests.get("https://index.commoncrawl.org/collinfo.json", timeout=10)
            if resp.status_code == 200:
                indexes = resp.json()
                if indexes:
                    return indexes[0]["id"]
        except Exception:
            pass
        # Fallback: estimate latest index (CC publishes ~6 indexes/year)
        from datetime import datetime
        now = datetime.now()
        # CC indexes are roughly every 2 months: 2026-17, 2026-21, 2026-25, 2026-29, 2026-33, 2026-38...
        week = now.isocalendar()[1]
        return f"CC-MAIN-{now.year}-{max(1, week - 4)}"

    @property
    def source_name(self) -> str:
        return "commoncrawl"

    async def search(self, query: str | None = None) -> list[dict]:
        """query: domain or URL pattern to filter, e.g. 'github.com' or '*.github.com'"""
        self.results = []
        query = query or "github.com"

        sem = asyncio.Semaphore(self.concurrency)

        async with aiohttp.ClientSession() as session:
            urls = await self._query_index(session, query)
            if not urls:
                return self.results

            tasks = [self._fetch_and_scan(session, sem, u) for u in urls[:self.max_urls]]
            await asyncio.gather(*tasks)

        return self.results

    async def _query_index(self, session, pattern: str) -> list:
        """Query the CC index for URLs matching the pattern that may contain keys."""
        api_url = f"{self.INDEX_API}/{self.index_name}-index"
        params = {
            "url": f"*.{pattern}/*",
            "output": "json",
            "filter": "status:200",
            "limit": self.max_urls,
        }
        urls = []
        try:
            async with session.get(api_url, params=params,
                                   timeout=aiohttp.ClientTimeout(total=60)) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    offset = 0
                    for line in text.strip().split("\n"):
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            url = entry.get("url", "")
                            if url and not url.endswith((".png", ".jpg", ".gif", ".ico",
                                                         ".css", ".woff", ".woff2", ".svg")):
                                urls.append({
                                    "url": url,
                                    "offset": int(entry.get("offset", 0)),
                                    "length": int(entry.get("length", 0)),
                                    "filename": entry.get("filename", ""),
                                    "timestamp": entry.get("timestamp", ""),
                                })
                        except json.JSONDecodeError:
                            pass
                        if len(urls) >= self.max_urls:
                            break
        except Exception:
            pass
        return urls

    async def _fetch_and_scan(self, session, sem, entry: dict):
        """Download WARC segment and scan for keys."""
        url = entry.get("url", "")
        offset = entry.get("offset", 0)
        length = entry.get("length", 0)
        filename = entry.get("filename", "")
        timestamp = entry.get("timestamp", "")

        if not filename or not length:
            return

        # Download WARC segment
        warc_url = f"https://data.commoncrawl.org/{filename}"
        range_header = f"bytes={offset}-{offset + min(length, 524288) - 1}"

        async with sem:
            try:
                async with session.get(warc_url,
                                       headers={"Range": range_header},
                                       timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status in (200, 206):
                        data = await resp.read()
                        text = self._extract_text_from_warc(data)
                        for k in extract_keys(text, self.extra_bad):
                            display_url = f"https://web.archive.org/web/{timestamp}/{url}" if timestamp else url
                            self._add_result(k, display_url, url, "web_page", self.source_name)
            except Exception:
                pass

    @staticmethod
    def _extract_text_from_warc(data: bytes) -> str:
        """Rudimentary WARC text extraction. Handles gzipped content."""
        try:
            decompressed = gzip.decompress(data)
        except Exception:
            decompressed = data

        try:
            return decompressed.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def search_sync(self, pattern: str, limit: int = 200) -> list:
        """Synchronous search helper for smaller queries."""
        import requests

        results = []
        params = {
            "url": f"*.{pattern}/*",
            "output": "json",
            "filter": "status:200",
            "limit": limit,
        }
        try:
            resp = requests.get(
                f"{self.INDEX_API}/{self.index_name}-index",
                params=params, timeout=60
            )
            if resp.status_code == 200:
                for line in resp.text.strip().split("\n"):
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        u = entry.get("url", "")
                        filename = entry.get("filename", "")
                        offset = int(entry.get("offset", 0))
                        length = int(entry.get("length", 0))
                        if u and filename and length:
                            range_hdr = f"bytes={offset}-{offset + min(length, 262144) - 1}"
                            warc_url = f"https://data.commoncrawl.org/{filename}"
                            r2 = requests.get(warc_url, headers={"Range": range_hdr}, timeout=30)
                            if r2.status_code in (200, 206):
                                text = CommonCrawlScanner._extract_text_from_warc(r2.content)
                                for k in extract_keys(text):
                                    results.append({
                                        "key": k,
                                        "source": "commoncrawl",
                                        "url": u,
                                    })
                    except (json.JSONDecodeError, ValueError):
                        pass
                    if len(results) >= limit:
                        break
        except Exception:
            pass
        return results
