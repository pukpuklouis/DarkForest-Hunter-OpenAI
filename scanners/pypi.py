"""
PyPI Scanner — Download and scan Python packages for DeepSeek API keys.
Many Python packages embed config files, .env examples, and demo scripts
with real API keys. We download source distributions and scan them.
"""

import aiohttp
import asyncio
import tarfile
import zipfile
import io
from .base import BaseScanner, extract_keys


class PyPIScanner(BaseScanner):
    INDEX = "https://pypi.org/simple"
    JSON_API = "https://pypi.org/pypi"

    def __init__(self, max_packages: int = 200, **kwargs):
        super().__init__(**kwargs)
        self.max_packages = max_packages

    @property
    def source_name(self) -> str:
        return "pypi"

    async def search(self, query: str | None = None) -> list[dict]:
        self.results = []
        query = query or "deepseek"
        sem = asyncio.Semaphore(self.concurrency)

        async with aiohttp.ClientSession() as session:
            packages = await self._search_packages(session, query)
            if not packages:
                return self.results

            self.log(f"PyPI: {len(packages)} packages found")
            tasks = [self._scan_package(session, sem, p) for p in packages[:self.max_packages]]
            await asyncio.gather(*tasks)

        return self.results

    async def _search_packages(self, session, q: str) -> list:
        """Search PyPI via search API."""
        url = f"https://pypi.org/search/?q={q}"
        # PyPI search page parsing - find package links
        packages = []
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15),
                                   headers={"User-Agent": "DeepSeekKeyHunter/5.0"}) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    # Parse search results for package names
                    import re
                    matches = re.findall(r'/project/([^/"\']+)/', text)
                    packages = list(dict.fromkeys(matches))  # dedup
        except Exception:
            pass

        # Also try JSON API search via alternative endpoint
        try:
            search_url = f"https://pypi.org/search/?q={q}&page=1"
            async with session.get(search_url, timeout=aiohttp.ClientTimeout(total=15),
                                   headers={"User-Agent": "DeepSeekKeyHunter/5.0"}) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    import re
                    # Find all package names in search results
                    names = re.findall(r'<span class="package-snippet__name">([^<]+)</span>', text)
                    for name in names:
                        clean = name.strip()
                        if clean and clean not in packages:
                            packages.append(clean)
        except Exception:
            pass

        return packages

    async def _scan_package(self, session, sem, pkg_name: str):
        """Download and scan a single package's source distribution."""
        async with sem:
            try:
                # Get package metadata
                url = f"{self.JSON_API}/{pkg_name}/json"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        return
                    data = await resp.json()

                info = data.get("info", {})
                urls = data.get("urls", [])

                # Find source distribution (sdist)
                sdist = None
                for u in urls:
                    if u.get("packagetype") == "sdist":
                        sdist = u
                        break

                if not sdist:
                    return

                download_url = sdist.get("url", "")
                if not download_url:
                    return

                # Download sdist
                async with session.get(download_url, timeout=aiohttp.ClientTimeout(total=60)) as dl:
                    if dl.status != 200:
                        return
                    content = await dl.read()

                # Scan archive
                keys = self._scan_archive(content, pkg_name)
                for k in keys:
                    self._add_result(k, f"https://pypi.org/project/{pkg_name}/",
                                     pkg_name, "source", self.source_name)

                # Also scan project description
                description = info.get("description", "") or ""
                for k in extract_keys(description, self.extra_bad):
                    self._add_result(k, f"https://pypi.org/project/{pkg_name}/",
                                     pkg_name, "description", self.source_name)

            except Exception:
                pass

    def _scan_archive(self, data: bytes, pkg_name: str) -> list[str]:
        """Scan a tar.gz or zip archive for API keys."""
        keys = []
        target_exts = (
            ".py", ".json", ".yml", ".yaml", ".env", ".cfg", ".ini",
            ".toml", ".txt", ".md", ".sh", ".rst", ".properties"
        )
        target_names = {
            ".env", ".env.example", ".env.local", "config.json",
            "settings.py", "settings.json", "credentials.json",
            "secrets.json", "setup.py", "setup.cfg", "pyproject.toml",
        }

        # Try tar.gz first
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                for member in tar.getmembers():
                    if not member.isfile() or member.size > 2_000_000:
                        continue
                    name = member.name.split("/")[-1]
                    if name in target_names or name.endswith(target_exts):
                        try:
                            f = tar.extractfile(member)
                            if f:
                                text = f.read().decode("utf-8", errors="replace")
                                for k in extract_keys(text):
                                    keys.append(k)
                        except Exception:
                            pass
            return keys
        except (tarfile.ReadError, EOFError):
            pass

        # Try zip
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for name in zf.namelist():
                    fname = name.split("/")[-1]
                    if fname in target_names or fname.endswith(target_exts):
                        try:
                            with zf.open(name) as f:
                                text = f.read().decode("utf-8", errors="replace")
                                for k in extract_keys(text):
                                    keys.append(k)
                        except Exception:
                            pass
            return keys
        except (zipfile.BadZipFile, zipfile.LargeZipFile):
            pass

        return keys
