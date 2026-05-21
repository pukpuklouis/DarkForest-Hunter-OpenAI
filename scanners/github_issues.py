"""
GitHub Issues / PRs Scanner — Search for leaked keys in issues, PRs, and comments.
Targets high-star repositories and AI-related projects.
"""

import aiohttp
import asyncio
from .base import BaseScanner, extract_keys


class IssuesScanner(BaseScanner):
    BASE = "https://api.github.com"
    PER_PAGE = 100

    def __init__(self, token: str = "", target_repos: list = None, **kwargs):
        super().__init__(**kwargs)
        self.token = token
        self._headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "DeepSeekKeyHunter/5.0",
        }
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

        self.target_repos = target_repos or [
            "deepseek-ai/DeepSeek-V3",
            "deepseek-ai/DeepSeek-R1",
            "deepseek-ai/DeepSeek-Coder",
            "deepseek-ai/DeepSeek-Coder-V2",
            "deepseek-ai/DeepSeek-LLM",
            "deepseek-ai/awesome-deepseek-integration",
            "deepseek-ai/DeepSeek-MoE",
            "deepseek-ai/DeepSeek-V2",
        ]

        self.target_searches = [
            (f'repo:{repo} "sk-"', f"Issues/PRs in {repo}")
            for repo in self.target_repos
        ] + [
            ('"DEEPSEEK_API_KEY" "sk-" is:issue', "Issues with DEEPSEEK_API_KEY"),
            ('"deepseek" "sk-" is:issue', "Issues with deepseek key"),
            ('"deepseek" "sk-" is:pr', "PRs with deepseek key"),
            ('"deepseek" "sk-" is:issue is:open', "Open issues with deepseek key"),
        ]

    @property
    def source_name(self) -> str:
        return "github_issues"

    async def search(self, query: str | None = None) -> list[dict]:
        self.results = []
        searches = self.target_searches
        if query:
            searches = [(query, "custom")]

        sem = asyncio.Semaphore(self.concurrency)

        async with aiohttp.ClientSession(headers=self._headers) as session:
            for q, desc in searches:
                if self._should_stop():
                    break

                items = await self._search_issues(session, q)
                if not items:
                    continue

                tasks = [self._scan_issue(session, sem, item) for item in items]
                await asyncio.gather(*tasks)

                await asyncio.sleep(2.0)

        return self.results

    async def _search_issues(self, session, q: str, pages: int = 3) -> list:
        all_items = []
        for page in range(1, pages + 1):
            if self._should_stop():
                break
            try:
                import urllib.parse
                encoded = urllib.parse.quote(q, safe="")
                url = f"{self.BASE}/search/issues?q={encoded}&per_page={self.PER_PAGE}&page={page}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        items = data.get("items", [])
                        all_items.extend(items)
                        if len(items) < self.PER_PAGE:
                            break
                    elif resp.status == 403:
                        await asyncio.sleep(60)
                        break
            except Exception:
                break
            await asyncio.sleep(0.8)
        return all_items

    async def _scan_issue(self, session, sem, item: dict):
        html_url = item.get("html_url", "")
        repo = item.get("repository_url", "").replace("https://api.github.com/repos/", "")
        title = item.get("title", "") or ""
        body = item.get("body", "") or ""
        comments_url = item.get("comments_url", "")

        # Scan title + body
        for k in extract_keys(title + "\n" + body, self.extra_bad):
            self._add_result(k, html_url, repo, "issue_body", self.source_name)

        # Scan comments
        if comments_url:
            async with sem:
                try:
                    async with session.get(f"{comments_url}?per_page=100",
                                           timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            comments = await resp.json()
                            for c in comments:
                                cbody = c.get("body", "") or ""
                                for k in extract_keys(cbody, self.extra_bad):
                                    self._add_result(k, html_url, repo, "issue_comment", self.source_name)
                except Exception:
                    pass
