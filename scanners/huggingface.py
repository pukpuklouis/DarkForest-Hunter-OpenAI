"""
HuggingFace Scanner — Search models, datasets, and spaces for leaked DeepSeek keys.
HuggingFace is a major hub for AI projects; many embed API keys in example
notebooks, inference configs, and space secrets.
"""

import aiohttp
import asyncio
import urllib.parse
from .base import BaseScanner, extract_keys


class HuggingFaceScanner(BaseScanner):
    API = "https://huggingface.co/api"
    HF_HUB = "https://huggingface.co"

    def __init__(self, token: str = "", max_items: int = 200, **kwargs):
        super().__init__(**kwargs)
        self.token = token
        self.max_items = max_items
        self._headers = {"User-Agent": "DeepSeekKeyHunter/5.0"}
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    @property
    def source_name(self) -> str:
        return "huggingface"

    async def search(self, query: str | None = None) -> list[dict]:
        self.results = []
        query = query or "deepseek"
        sem = asyncio.Semaphore(self.concurrency)

        async with aiohttp.ClientSession(headers=self._headers) as session:
            # Search models
            models = await self._search_models(session, query)
            self.log(f"HF Models: {len(models)} found")
            for m in models[:self.max_items // 3]:
                if self._should_stop():
                    break
                await self._scan_model(session, sem, m)

            # Search datasets
            datasets = await self._search_datasets(session, query)
            self.log(f"HF Datasets: {len(datasets)} found")
            for d in datasets[:self.max_items // 3]:
                if self._should_stop():
                    break
                await self._scan_dataset(session, sem, d)

            # Search spaces
            spaces = await self._search_spaces(session, query)
            self.log(f"HF Spaces: {len(spaces)} found")
            for s in spaces[:self.max_items // 3]:
                if self._should_stop():
                    break
                await self._scan_space(session, sem, s)

        return self.results

    async def _search_models(self, session, q: str) -> list:
        return await self._hf_search(session, q, "model")

    async def _search_datasets(self, session, q: str) -> list:
        return await self._hf_search(session, q, "dataset")

    async def _search_spaces(self, session, q: str) -> list:
        return await self._hf_search(session, q, "space")

    async def _hf_search(self, session, q: str, item_type: str, pages: int = 5) -> list:
        all_items = []
        for page in range(1, pages + 1):
            if self._should_stop():
                break
            params = {"search": q, "limit": 50, "full": "False"}
            # HF uses cursor-based pagination; we use offset
            if page > 1:
                params["cursor"] = f"{all_items[-1].get('id', '')}"
            qs = urllib.parse.urlencode(params)
            url = f"{self.API}/{item_type}s?{qs}"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        items = []
                        # Response is a dict with list or list directly
                        if isinstance(data, dict):
                            items = data.get("items", data.get(item_type + "s", []))
                        elif isinstance(data, list):
                            items = data
                        all_items.extend(items)
                        if len(items) < 50:
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

    async def _scan_model(self, session, sem, model: dict):
        repo_id = model.get("id", "")
        if not repo_id:
            return
        await self._scan_repo_files(session, sem, repo_id, "model")

    async def _scan_dataset(self, session, sem, dataset: dict):
        repo_id = dataset.get("id", "")
        if not repo_id:
            return
        await self._scan_repo_files(session, sem, repo_id, "dataset")

    async def _scan_space(self, session, sem, space: dict):
        repo_id = space.get("id", "")
        if not repo_id:
            return
        await self._scan_repo_files(session, sem, repo_id, "space")
        # Also scan space README (often has .env instructions)
        readme_url = f"{self.HF_HUB}/{repo_id}/raw/main/README.md"
        async with sem:
            try:
                async with session.get(readme_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for k in extract_keys(text, self.extra_bad):
                            self._add_result(k, f"{self.HF_HUB}/{repo_id}",
                                             repo_id, "README.md", self.source_name)
            except Exception:
                pass

    async def _scan_repo_files(self, session, sem, repo_id: str, item_type: str):
        """List files in repo and scan target files."""
        api_url = f"{self.API}/{item_type}s/{repo_id}/tree/main/"
        try:
            async with session.get(api_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    # Try 'master' branch
                    api_url = api_url.replace("/main/", "/master/")
                    async with session.get(api_url, timeout=aiohttp.ClientTimeout(total=10)) as resp2:
                        if resp2.status != 200:
                            return
                        files = await resp2.json()
                else:
                    files = await resp.json()
        except Exception:
            return

        if not isinstance(files, list):
            return

        target_exts = (".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env",
                       ".sh", ".ipynb", ".md", ".txt", ".cfg", ".ini", ".toml",
                       ".properties", ".gradle", ".dart", ".swift", ".go", ".rs",
                       ".kt", ".java", ".php", ".rb", ".cs", ".cpp", ".c", ".h")
        target_names = {"dockerfile", "docker-compose.yml", "docker-compose.yaml",
                        ".env", ".env.local", ".env.production", ".envrc",
                        "config.json", "settings.json", "application.yml",
                        "credentials", "secrets", ".npmrc", ".pypirc"}

        for f in files:
            if self._should_stop():
                break
            path = f.get("path", "")
            fname = path.split("/")[-1].lower()
            is_target = (fname in target_names or
                         any(fname.endswith(ext) for ext in target_exts))
            if not is_target:
                continue

            raw_url = f"{self.HF_HUB}/{repo_id}/resolve/main/{path}"
            async with sem:
                for br in ["main", "master", "HEAD"]:
                    try:
                        url = raw_url.replace("/main/", f"/{br}/")
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                            if r.status == 200:
                                text = await r.text()
                                for k in extract_keys(text, self.extra_bad):
                                    self._add_result(k, f"{self.HF_HUB}/{repo_id}/blob/main/{path}",
                                                     repo_id, path, self.source_name)
                                break
                    except Exception:
                        continue
