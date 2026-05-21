"""
npm Registry Scanner — Search npm for packages related to DeepSeek.
Downloads package tarballs and scans source code for keys in .npmrc, config, etc.
"""

import aiohttp
import asyncio
import tarfile
import io
import urllib.parse
from .base import BaseScanner, extract_keys


class NpmScanner(BaseScanner):
    REGISTRY = "https://registry.npmjs.org"

    def __init__(self, max_packages: int = 100, **kwargs):
        super().__init__(**kwargs)
        self.max_packages = max_packages

    @property
    def source_name(self) -> str:
        return "npm"

    async def search(self, query: str | None = None) -> list[dict]:
        self.results = []
        query = query or "deepseek"

        sem = asyncio.Semaphore(self.concurrency)

        async with aiohttp.ClientSession() as session:
            packages = await self._search_packages(session, query)
            if not packages:
                return self.results

            tasks = [self._scan_package(session, sem, p) for p in packages[:self.max_packages]]
            await asyncio.gather(*tasks)

        return self.results

    async def _search_packages(self, session, q: str, size: int = 250) -> list:
        params = urllib.parse.urlencode({
            "text": q,
            "size": size,
        })
        url = f"{self.REGISTRY}/-/v1/search?{params}"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("objects", [])
        except Exception:
            pass
        return []

    async def _scan_package(self, session, sem, pkg_obj: dict):
        pkg = pkg_obj.get("package", {})
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        npm_url = pkg.get("links", {}).get("npm", "")
        if not name or not version:
            return

        async with sem:
            try:
                # Get package metadata for tarball URL
                pkg_url = f"{self.REGISTRY}/{name}"
                async with session.get(pkg_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        return
                    data = await resp.json()

                tarball_url = data.get("versions", {}).get(version, {}).get("dist", {}).get("tarball", "")
                if not tarball_url:
                    return

                async with session.get(tarball_url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        return
                    tarball_data = await resp.read()

                for k in self._scan_tarball(tarball_data):
                    self._add_result(k, npm_url, name, f"v{version}", self.source_name)

            except Exception:
                pass

    def _scan_tarball(self, data: bytes) -> list[str]:
        keys = []
        target_names = {
            ".npmrc", ".env", ".env.example", ".env.sample",
            "config.js", "config.json", "config.ts",
            "credentials.json", "secrets.json",
            "settings.py", "settings.js", "settings.json",
            ".pypirc", ".dockercfg",
            "docker-compose.yml", "docker-compose.yaml",
            "Dockerfile", ".envrc",
        }
        target_suffixes = (
            ".env", ".json", ".yml", ".yaml", ".py", ".js", ".ts",
            ".txt", ".md", ".sh", ".ini", ".cfg", ".conf",
            ".properties", ".env.local",
        )

        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                for member in tar.getmembers():
                    name = member.name.split("/")[-1]
                    name_lower = name.lower()

                    if not (name_lower in target_names or
                            name_lower.endswith(target_suffixes)):
                        continue

                    if member.isfile() and member.size < 1_000_000:
                        try:
                            f = tar.extractfile(member)
                            if f:
                                content = f.read().decode("utf-8", errors="replace")
                                for k in extract_keys(content):
                                    keys.append(k)
                        except Exception:
                            pass
        except (tarfile.ReadError, EOFError):
            pass

        return keys
