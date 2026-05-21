"""
GitHub Commits Scanner — Search commit history and diffs for keys that were
committed and later "removed". The key still exists in git history even if
deleted from current files. This catches keys that regular code search misses.
"""

import aiohttp
import asyncio
import re
from .base import BaseScanner, extract_keys


class CommitsScanner(BaseScanner):
    BASE = "https://api.github.com"
    KEY_PATTERN = re.compile(r"sk-[a-zA-Z0-9]{32,64}")

    def __init__(self, token: str = "", max_repos: int = 100, **kwargs):
        super().__init__(**kwargs)
        self.token = token
        self.max_repos = max_repos
        self._headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "DeepSeekKeyHunter/5.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    @property
    def source_name(self) -> str:
        return "github_commits"

    async def search(self, query: str | None = None) -> list[dict]:
        self.results = []
        sem = asyncio.Semaphore(self.concurrency)

        # Step 1: Find repos that mention deepseek
        repos = await self._search_repos()
        if not repos:
            return self.results

        async with aiohttp.ClientSession(headers=self._headers) as session:
            for repo in repos[:self.max_repos]:
                if self._should_stop():
                    break
                await self._scan_repo_commits(session, sem, repo)

        return self.results

    async def _search_repos(self) -> list:
        """Find repos mentioning deepseek that may have commit history leaks."""
        repos = []
        queries = [
            "deepseek in:readme",
            "deepseek-ai",
            "deepseek language:python",
            "deepseek-api",
        ]
        for q in queries:
            url = f"{self.BASE}/search/repositories?q={q.replace(' ', '+')}&sort=updated&per_page=30"
            try:
                async with aiohttp.ClientSession(headers=self._headers) as s:
                    async with s.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for item in data.get("items", []):
                                repos.append(item.get("full_name", ""))
                        elif resp.status == 403:
                            await asyncio.sleep(60)
            except Exception:
                pass
            await asyncio.sleep(1)
        return list(dict.fromkeys(repos))  # dedup preserving order

    async def _scan_repo_commits(self, session, sem, repo: str):
        """Scan recent commits for diffs containing sk- keys."""
        url = f"{self.BASE}/repos/{repo}/commits?per_page=30"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return
                commits = await resp.json()
                if not isinstance(commits, list):
                    return
        except Exception:
            return

        tasks = []
        for commit in commits:
            sha = commit.get("sha", "")
            if not sha:
                continue
            tasks.append(self._scan_commit_diff(session, sem, repo, sha))

        if tasks:
            await asyncio.gather(*tasks)

    async def _scan_commit_diff(self, session, sem, repo: str, sha: str):
        """Fetch a single commit diff and extract keys from added/removed lines."""
        url = f"{self.BASE}/repos/{repo}/commits/{sha}"
        async with sem:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        return
                    data = await resp.json()

                    # Scan commit message
                    msg = data.get("commit", {}).get("message", "")
                    for k in extract_keys(msg, self.extra_bad):
                        self._add_result(k, f"https://github.com/{repo}/commit/{sha}",
                                         repo, f"commit:{sha[:7]}", self.source_name)

                    # Scan patch diffs
                    files = data.get("files", [])
                    for f in files:
                        patch = f.get("patch", "")
                        if not patch:
                            continue
                        # Only look at added lines (lines starting with +)
                        added_lines = "\n".join(
                            line[1:] for line in patch.split("\n")
                            if line.startswith("+") and not line.startswith("+++")
                        )
                        for k in extract_keys(added_lines, self.extra_bad):
                            self._add_result(k, f.get("blob_url", f"https://github.com/{repo}/commit/{sha}"),
                                             repo, f.get("filename", ""), self.source_name)
            except Exception:
                pass
