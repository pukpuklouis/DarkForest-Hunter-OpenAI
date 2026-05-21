"""
GitLab Scanner — Search GitLab.com public projects for leaked DeepSeek keys.
Supports both gitlab.com and self-hosted instances.
"""

import aiohttp
import asyncio
import urllib.parse
from .base import BaseScanner, extract_keys, TARGET_FILE_EXTS, TARGET_FILENAMES


class GitLabScanner(BaseScanner):
    def __init__(self, token: str = "", base_url: str = "https://gitlab.com",
                 max_projects: int = 200, max_files_per_project: int = 100, **kwargs):
        super().__init__(**kwargs)
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.max_projects = max_projects
        self.max_files_per_project = max_files_per_project
        self._headers = {"User-Agent": "DeepSeekKeyHunter/5.0"}
        if token:
            self._headers["PRIVATE-TOKEN"] = token

    @property
    def source_name(self) -> str:
        return "gitlab"

    async def search(self, query: str | None = None) -> list[dict]:
        self.results = []
        query = query or "deepseek"

        sem = asyncio.Semaphore(self.concurrency)

        async with aiohttp.ClientSession(headers=self._headers) as session:
            projects = await self._search_projects(session, query)
            if not projects:
                return self.results

            for proj in projects[:self.max_projects]:
                if self._should_stop():
                    break
                await self._scan_project(session, sem, proj)

        return self.results

    async def _search_projects(self, session, q: str, pages: int = 10) -> list:
        all_projects = []
        api = f"{self.base_url}/api/v4"

        for page in range(1, pages + 1):
            if self._should_stop():
                break
            try:
                params = urllib.parse.urlencode({
                    "search": q,
                    "visibility": "public",
                    "per_page": 100,
                    "page": page,
                })
                url = f"{api}/projects?{params}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        projects = await resp.json()
                        all_projects.extend(projects)
                        if len(projects) < 100:
                            break
                    elif resp.status == 429:
                        await asyncio.sleep(30)
                    else:
                        break
            except Exception:
                break
            await asyncio.sleep(0.3)
        return all_projects

    async def _scan_project(self, session, sem, proj: dict):
        proj_id = proj.get("id", 0)
        proj_name = proj.get("path_with_namespace", "")
        web_url = proj.get("web_url", "")
        api = f"{self.base_url}/api/v4/projects/{proj_id}"

        # Get repository tree
        try:
            tree_url = f"{api}/repository/tree?per_page=100&recursive=true"
            async with session.get(tree_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return
                tree = await resp.json()
        except Exception:
            return

        target_files = []
        for node in tree:
            path = node.get("path", "")
            name = node.get("name", "")
            fname_lower = name.lower()
            if any(name.endswith(ext) for ext in TARGET_FILE_EXTS):
                target_files.append(path)
            elif fname_lower in TARGET_FILENAMES:
                target_files.append(path)

        for fpath in target_files[:self.max_files_per_project]:
            async with sem:
                try:
                    encoded = urllib.parse.quote(fpath, safe="")
                    raw_url = f"{api}/repository/files/{encoded}/raw?ref=HEAD"
                    async with session.get(raw_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            for k in extract_keys(text, self.extra_bad):
                                self._add_result(k, f"{web_url}/-/blob/HEAD/{fpath}",
                                                 proj_name, fpath, self.source_name)
                except Exception:
                    pass
