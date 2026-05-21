"""
Base class for all scanners.
"""

import re
import time
import hashlib
from abc import ABC, abstractmethod
from collections import OrderedDict

# Key pattern: sk- followed by 32-64 alphanumeric chars
KEY_PATTERN = re.compile(r"sk-[a-zA-Z0-9]{32,64}")

BAD_PATTERNS = [
    "your", "xxx", "example", "placeholder", "replace", "here",
    "demo", "sample", "fake", "dummy", "changeme", "insert",
    "sk-xxxx", "sk-0000", "sk-1111", "sk-aaaa", "sk-bbbb",
    "sk-proj-",
]

# Paths that strongly indicate test/demo keys (low chance of balance)
LOW_VALUE_PATH_KEYWORDS = [
    "/test/", "/tests/", "/test/java/", "/test/kotlin/",
    "test.java", "test.kt", "test.py", "test.js", "test.ts",
    "demo.java", "demo.py", "example.java", "example.py",
    "sample.java", "sample.py",
    "TestMain", "TestDeep", "DeepSeekTest", "ApiTest",
    "/target/site/", "/target/",  # Build artifacts
    "TongYiChatModelTests", "DeepSeekChatModelTests",  # Common test duplicates
]

TARGET_FILE_EXTS = {
    ".py", ".js", ".ts", ".java", ".kt", ".php", ".rb", ".go",
    ".rs", ".cs", ".swift", ".dart", ".cpp", ".c", ".h",
    ".sh", ".bash", ".zsh", ".fish",
    ".env", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini",
    ".conf", ".config", ".properties", ".gradle",
    ".txt", ".md", ".html", ".xml", ".plist", ".lua",
    ".ipynb", ".dockerfile", ".envrc", ".env.local",
    ".env.production", ".env.development", ".env.example",
    ".env.sample", ".env.backup", ".credentials",
}

TARGET_FILENAMES = {
    "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".env", ".npmrc", ".pypirc", "credentials", "secrets",
    "config.json", "settings.json", "application.properties",
    "application.yml", "application.yaml",
    "gradle.properties", "local.properties",
}


def is_bad_key(key: str, extra_bad: list = None) -> bool:
    lower = key.lower()
    patterns = BAD_PATTERNS + (extra_bad or [])
    if any(b.lower() in lower for b in patterns):
        return True
    body = key[3:]
    if body.isdigit() or len(set(body)) < 4:
        return True
    return False


def extract_keys(text: str, extra_bad: list = None) -> list[str]:
    keys = KEY_PATTERN.findall(text)
    return [k for k in keys if not is_bad_key(k, extra_bad)]


def dedup_results(results: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for r in results:
        h = hashlib.md5(f"{r.get('source','')}:{r.get('key','')}:{r.get('url','')}".encode()).hexdigest()
        if h not in seen:
            seen.add(h)
            out.append(r)
    return out


class BaseScanner(ABC):
    def __init__(self, concurrency: int = 10, timeout: int = 15,
                 min_key_length: int = 32, max_key_length: int = 64,
                 extra_bad_patterns: list = None, session=None):
        self.concurrency = concurrency
        self.timeout = timeout
        self.min_key_length = min_key_length
        self.max_key_length = max_key_length
        self.extra_bad = extra_bad_patterns or []
        self._session = session
        self.key_pattern = re.compile(
            rf"sk-[a-zA-Z0-9]{{{min_key_length},{max_key_length}}}"
        )
        self._stop_requested = False
        self._seen_urls = set()
        self.results: list[dict] = []

    @abstractmethod
    async def search(self, query: str | None = None) -> list[dict]:
        ...

    @property
    @abstractmethod
    def source_name(self) -> str:
        ...

    def extract_local(self, text: str) -> list[str]:
        keys = self.key_pattern.findall(text)
        return [k for k in keys if not is_bad_key(k, self.extra_bad)]

    def stop(self):
        self._stop_requested = True

    def _add_result(self, key: str, url: str, repo: str = "",
                    file_path: str = "", source: str = ""):
        self.results.append({
            "key": key,
            "key_preview": key[:10] + "..." + key[-4:],
            "source": source or self.source_name,
            "repo": repo,
            "file": file_path,
            "url": url,
        })

    def _should_stop(self) -> bool:
        return self._stop_requested

    def _rate_limit_wait(self, delay: float = 1.0):
        time.sleep(delay)
