"""
Gitee (码云) Scanner — Search China's largest code hosting platform.
Targets .env files, config, and source code in public repositories.
"""

import aiohttp
import asyncio
import urllib.parse
from .base import BaseScanner, extract_keys


class GiteeScanner(BaseScanner):
    API = "https://gitee.com/api/v5"

    def __init__(self, token: str = "", max_repos: int = 150, **kwargs):
        super().__init__(**kwargs)
        self.token = token
        self.max_repos = max_repos
        self._headers = {"User-Agent": "DeepSeekKeyHunter/5.0"}
        if token:
            self._params = {"access_token": token}
        else:
            self._params = {}

    @property
    def source_name(self) -> str:
        return "gitee"

    async def search(self, query: str | None = None) -> list[dict]:
        self.results = []
        sem = asyncio.Semaphore(self.concurrency)

        async with aiohttp.ClientSession(headers=self._headers) as session:
            repos = await self._search_repos(session, query)
            if not repos:
                return self.results

            tasks = [self._scan_repo(session, sem, r) for r in repos[:self.max_repos]]
            await asyncio.gather(*tasks)

        return self.results

    async def _search_repos(self, session, query: str, pages: int = 5) -> list:
        all_repos = []
        query = query or "deepseek"

        for page in range(1, pages + 1):
            if self._should_stop():
                break
            params = dict(self._params)
            params.update({"q": query, "page": page, "per_page": 100})
            qs = urllib.parse.urlencode(params)
            url = f"{self.API}/search/repositories?{qs}"

            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        repos = await resp.json()
                        all_repos.extend(repos)
                        if len(repos) < 100:
                            break
                    elif resp.status == 429:
                        await asyncio.sleep(60)
                        continue
                    else:
                        break
            except Exception:
                break
            await asyncio.sleep(1.0)
        return all_repos

    async def _scan_repo(self, session, sem, repo: dict):
        full_name = repo.get("full_name", "")
        html_url = repo.get("html_url", "")

        params = dict(self._params)
        tree_url = f"{self.API}/repos/{full_name}/git/trees/HEAD?recursive=1"

        try:
            async with session.get(tree_url, timeout=aiohttp.ClientTimeout(total=10),
                                   params=params) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()
                tree = data.get("tree", [])
        except Exception:
            return

        target = []
        for node in tree:
            path = node.get("path", "")
            p_lower = path.lower()
            if any(p_lower.endswith(ext) for ext in [
                ".env", ".py", ".js", ".ts", ".java", ".php", ".kt", ".swift",
                ".go", ".rs", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini",
                ".sh", ".bash", ".txt", ".md", ".html", ".xml", ".properties",
                ".gradle", ".dart", ".rb"
            ]):
                target.append(path)

        for fpath in target[:80]:
            async with sem:
                try:
                    params = dict(self._params)
                    params["ref"] = "master"
                    qs = urllib.parse.urlencode(params)
                    raw_url = f"{self.API}/repos/{full_name}/raw/{fpath}?{qs}"
                    async with session.get(raw_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            for k in extract_keys(text, self.extra_bad):
                                self._add_result(k, html_url, full_name, fpath, self.source_name)
                except Exception:
                    pass
