"""
GitHub Events API Real-Time Monitor — Polls /events to catch new pushes.
Extracts keys from files changed in public PushEvents in real time.
"""

import aiohttp
import asyncio
import time
from collections import deque
from .base import BaseScanner, extract_keys


class EventsMonitor(BaseScanner):
    BASE = "https://api.github.com"
    POLL_INTERVAL = 60

    def __init__(self, token: str = "", poll_interval: int = 60,
                 max_events_per_poll: int = 30, **kwargs):
        super().__init__(**kwargs)
        self.token = token
        self.poll_interval = poll_interval or self.POLL_INTERVAL
        self.max_events_per_poll = max_events_per_poll
        self._headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "DeepSeekKeyHunter/5.0",
        }
        if token:
            self._headers["Authorization"] = f"Bearer {token}"
        self._event_queue = deque(maxlen=500)
        self._seen_commits = set()
        self.on_key_found = None

    @property
    def source_name(self) -> str:
        return "github_events"

    async def search(self, query: str | None = None) -> list[dict]:
        self.results = []
        sem = asyncio.Semaphore(self.concurrency)

        async with aiohttp.ClientSession(headers=self._headers) as session:
            while not self._should_stop():
                events = await self._fetch_events(session)
                if events:
                    push_events = [e for e in events if e.get("type") == "PushEvent" and e.get("public")]
                    for ev in push_events[:self.max_events_per_poll]:
                        if self._should_stop():
                            break
                        await self._handle_push(session, sem, ev)

                await asyncio.sleep(self.poll_interval)

        return self.results

    async def _fetch_events(self, session) -> list:
        url = f"{self.BASE}/events?per_page=30"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 403:
                    await asyncio.sleep(300)
        except Exception:
            pass
        return []

    async def _handle_push(self, session, sem, event: dict):
        repo = event.get("repo", {}).get("name", "")
        commits = event.get("payload", {}).get("commits", [])

        for commit in commits:
            sha = commit.get("sha", "")
            if sha in self._seen_commits:
                continue
            self._seen_commits.add(sha)

            added = commit.get("added", [])
            modified = commit.get("modified", [])
            changed = added + modified

            for fpath in changed:
                async with sem:
                    try:
                        url = f"https://raw.githubusercontent.com/{repo}/{sha}/{fpath}"
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                for k in extract_keys(text, self.extra_bad):
                                    self._add_result(k, url, repo, fpath, self.source_name)
                                    if self.on_key_found:
                                        self.on_key_found(k, repo, fpath, url)
                            elif resp.status == 404:
                                pass
                    except Exception:
                        pass
