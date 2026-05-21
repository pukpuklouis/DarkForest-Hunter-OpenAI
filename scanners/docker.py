"""
Docker Hub Scanner — Search Docker Hub for images with "deepseek" references.
Scans Dockerfile layers and image content for accidentally embedded API keys.
"""

import aiohttp
import asyncio
import urllib.parse
import json
from .base import BaseScanner, extract_keys


class DockerHubScanner(BaseScanner):
    HUB_API = "https://hub.docker.com/v2"
    REGISTRY = "https://registry-1.docker.io"

    def __init__(self, token: str = "", max_images: int = 100, **kwargs):
        super().__init__(**kwargs)
        self.token = token
        self.max_images = max_images
        self._headers = {"User-Agent": "DeepSeekKeyHunter/5.0"}
        self._registry_headers = {
            "User-Agent": "DeepSeekKeyHunter/5.0",
        }
        if token:
            self._headers["Authorization"] = f"JWT {token}"

    @property
    def source_name(self) -> str:
        return "docker_hub"

    async def search(self, query: str | None = None) -> list[dict]:
        self.results = []
        query = query or "deepseek"

        sem = asyncio.Semaphore(self.concurrency)

        async with aiohttp.ClientSession(headers=self._headers) as session:
            images = await self._search_images(session, query)
            if not images:
                return self.results

            for img_summary in images[:self.max_images]:
                if self._should_stop():
                    break

                repo_name = img_summary.get("name", "")
                namespace = img_summary.get("namespace", "")
                full_name = f"{namespace}/{repo_name}"

                await self._scan_tags(session, sem, full_name)

        return self.results

    async def _search_images(self, session, q: str, pages: int = 5) -> list:
        all_images = []
        for page in range(1, pages + 1):
            if self._should_stop():
                break
            try:
                params = urllib.parse.urlencode({
                    "query": q,
                    "page": page,
                    "page_size": 25,
                })
                url = f"{self.HUB_API}/search/repositories/?{params}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        results = data.get("results", [])
                        all_images.extend(results)
                        if len(results) < 25:
                            break
                    elif resp.status == 429:
                        await asyncio.sleep(60)
                        continue
                    else:
                        break
            except Exception:
                break
            await asyncio.sleep(0.5)
        return all_images

    async def _scan_tags(self, session, sem, repo_name: str):
        """List tags and scan the most recent ones."""
        try:
            # List tags (first 5 pages)
            tags = []
            for page in range(1, 3):
                url = f"{self.HUB_API}/repositories/{repo_name}/tags/?page={page}&page_size=25"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        page_tags = data.get("results", [])
                        tags.extend(page_tags)
                        if len(page_tags) < 25:
                            break
            for tag_info in tags[:10]:
                tag_name = tag_info.get("name", "latest")
                images = tag_info.get("images", [])
                for img in images[:3]:
                    await self._scan_image_layers(session, sem, repo_name, tag_name, img)
        except Exception:
            pass

    async def _scan_image_layers(self, session, sem, repo_name: str, tag: str, img_info: dict):
        """Inspect image layers for config (Dockerfile instructions, env vars)."""
        digest = img_info.get("digest", "")
        if not digest:
            return

        # We can inspect the manifest to get config blob with env/history
        registry_repo = f"library/{repo_name}" if "/" not in repo_name else repo_name
        url = f"{self.REGISTRY}/v2/{registry_repo}/manifests/{tag}"
        headers = dict(self._registry_headers)
        headers["Accept"] = "application/vnd.docker.distribution.manifest.v2+json"

        async with sem:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), headers=headers) as resp:
                    if resp.status == 200:
                        manifest = await resp.json()
                        config = manifest.get("config", {})
                        config_digest = config.get("digest", "")
                        if config_digest:
                            config_url = f"{self.REGISTRY}/v2/{registry_repo}/blobs/{config_digest}"
                            async with session.get(config_url, timeout=aiohttp.ClientTimeout(total=15),
                                                    headers=self._registry_headers) as c_resp:
                                if c_resp.status == 200:
                                    config_data = await c_resp.json()
                                    # Scan history for env vars and commands
                                    history = config_data.get("history", [])
                                    for entry in history:
                                        created_by = entry.get("created_by", "") or ""
                                        for k in extract_keys(created_by, self.extra_bad):
                                            self._add_result(k,
                                                             f"https://hub.docker.com/r/{repo_name}",
                                                             repo_name, f"layer:{tag}", self.source_name)

                                    # Scan config for exposed env vars
                                    config_env = config_data.get("config", {})
                                    env_list = config_env.get("Env", []) or []
                                    for env_var in env_list:
                                        for k in extract_keys(env_var, self.extra_bad):
                                            self._add_result(k,
                                                             f"https://hub.docker.com/r/{repo_name}",
                                                             repo_name, f"env:{tag}", self.source_name)
            except Exception:
                pass
