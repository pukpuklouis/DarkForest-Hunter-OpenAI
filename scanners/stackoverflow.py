"""
Stack Overflow Scanner — Search for code snippets containing DeepSeek API keys.
Users often post code with keys in questions/answers and later edit them out.
We use the StackExchange API to search posts.
"""

import aiohttp
import asyncio
import urllib.parse
from .base import BaseScanner, extract_keys


class StackOverflowScanner(BaseScanner):
    API = "https://api.stackexchange.com/2.3"

    def __init__(self, max_posts: int = 200, **kwargs):
        super().__init__(**kwargs)
        self.max_posts = max_posts

    @property
    def source_name(self) -> str:
        return "stackoverflow"

    async def search(self, query: str | None = None) -> list[dict]:
        self.results = []
        sem = asyncio.Semaphore(self.concurrency)

        searches = [
            ("deepseek api_key", "DeepSeek API key questions"),
            ("deepseek sk-", "DeepSeek key pattern"),
            ("DEEPSEEK_API_KEY", "DeepSeek env var"),
            ("deepseek client initialization", "DeepSeek client setup"),
            ("deepseek openai python", "DeepSeek OpenAI client"),
        ]

        async with aiohttp.ClientSession() as session:
            for q, desc in searches:
                if self._should_stop():
                    break
                posts = await self._search_posts(session, q)
                self.log(f"SO [{desc}]: {len(posts)} posts")

                tasks = [self._scan_post(session, sem, p) for p in posts[:self.max_posts // len(searches)]]
                await asyncio.gather(*tasks)

                await asyncio.sleep(1.0)

        return self.results

    async def _search_posts(self, session, q: str, pages: int = 5) -> list:
        all_items = []
        for page in range(1, pages + 1):
            if self._should_stop():
                break
            params = {
                "order": "desc",
                "sort": "creation",
                "site": "stackoverflow",
                "intitle": q,
                "pagesize": 100,
                "page": page,
                "filter": "withbody",
            }
            qs = urllib.parse.urlencode(params)
            url = f"{self.API}/search/advanced?{qs}"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        items = data.get("items", [])
                        all_items.extend(items)
                        if not data.get("has_more", False):
                            break
                    elif resp.status == 429:
                        await asyncio.sleep(30)
                        continue
                    else:
                        break
            except Exception:
                break
            await asyncio.sleep(0.5)
        return all_items

    async def _scan_post(self, session, sem, post: dict):
        """Scan a post's body and fetch answers."""
        post_id = post.get("question_id", 0)
        link = post.get("link", "")
        title = post.get("title", "")
        body = post.get("body", "")

        # Scan title + body
        text = f"{title}\n{self._strip_html(body)}"
        for k in extract_keys(text, self.extra_bad):
            self._add_result(k, link, f"so:{post_id}", "question", self.source_name)

        # Fetch answers
        if post_id:
            async with sem:
                try:
                    params = {
                        "order": "desc",
                        "sort": "votes",
                        "site": "stackoverflow",
                        "filter": "withbody",
                    }
                    qs = urllib.parse.urlencode(params)
                    url = f"{self.API}/questions/{post_id}/answers?{qs}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for ans in data.get("items", []):
                                ans_body = ans.get("body", "")
                                ans_text = self._strip_html(ans_body)
                                for k in extract_keys(ans_text, self.extra_bad):
                                    self._add_result(k, link, f"so:{post_id}", "answer", self.source_name)
                except Exception:
                    pass

    @staticmethod
    def _strip_html(html: str) -> str:
        """Basic HTML tag removal."""
        import re
        text = re.sub(r'<[^>]+>', ' ', html)
        text = re.sub(r'&lt;', '<', text)
        text = re.sub(r'&gt;', '>', text)
        text = re.sub(r'&amp;', '&', text)
        text = re.sub(r'&quot;', '"', text)
        return re.sub(r'\s+', ' ', text).strip()
