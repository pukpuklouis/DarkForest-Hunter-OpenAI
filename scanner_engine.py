"""
API Key Hunter - 多提供商扫描引擎核心模块
支持 DeepSeek / OpenAI / OpenRouter + CLI / GUI
"""

import asyncio
import aiohttp
import subprocess
import json
import re
import time
import os
import sys
import random
import urllib.parse
import fnmatch
import requests
from datetime import datetime
from typing import Callable, Optional

# Scanner imports for multi-source mode
from scanners.base import extract_keys as scanner_extract_keys, is_bad_key as _scanner_is_bad_key
from scanners.github_gist import GistScanner
from scanners.github_issues import IssuesScanner
from scanners.github_events import EventsMonitor
from scanners.github_commits import CommitsScanner
from scanners.gitlab import GitLabScanner
from scanners.wayback import WaybackScanner
from scanners.docker import DockerHubScanner
from scanners.commoncrawl import CommonCrawlScanner
from scanners.gitee import GiteeScanner
from scanners.npm_registry import NpmScanner
from scanners.huggingface import HuggingFaceScanner
from scanners.pypi import PyPIScanner
from scanners.stackoverflow import StackOverflowScanner

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# 默认汇率（1 USD = ? CNY）
DEFAULT_USD_CNY_RATE = 7.25

KEY_PATTERN = re.compile(r"sk-[a-zA-Z0-9]{32,64}")

# ═══════════════════════════════════════════════════════════════════
#  Multi-Provider Verification — Try each provider until one matches
# ═══════════════════════════════════════════════════════════════════

PROVIDER_CONFIGS = [
    {
        "name": "deepseek",
        "display": "DeepSeek",
        "base": "https://api.deepseek.com",
        "balance_url": "/user/balance",
    },
    {
        "name": "openai",
        "display": "OpenAI",
        "base": "https://api.openai.com",
        "balance_url": "/v1/models",
        "credit_url": "/dashboard/billing/credit_grants",
    },
    {
        "name": "openrouter",
        "display": "OpenRouter",
        "base": "https://openrouter.ai/api/v1",
        "balance_url": "/auth/key",
    },
]


def _parse_deepseek_balance(data: dict) -> dict:
    """Parse DeepSeek /user/balance response."""
    balance_infos = data.get("balance_infos", [])
    total = 0.0
    details = []
    primary_currency = "USD"
    for info in balance_infos:
        currency = info.get("currency", "unknown")
        t = float(info.get("total_balance", 0))
        g = float(info.get("granted_balance", 0))
        tp = float(info.get("tipped_balance", 0))
        total += t
        details.append({"currency": currency, "total_balance": t,
                        "granted_balance": g, "tipped_balance": tp})
        if currency == "CNY":
            primary_currency = "CNY"
    return {"valid": True, "total_balance": total, "balance_details": details,
            "primary_currency": primary_currency}


def _parse_openai_models(data: dict) -> dict:
    """Parse OpenAI /v1/models — valid key confirmed, no balance."""
    if data.get("object") == "list" and "data" in data:
        return {"valid": True, "total_balance": 0.0, "balance_details": [],
                "primary_currency": "USD", "balance_unavailable": True}
    return {"valid": False, "reason": "unexpected_response"}


def _parse_openai_credits(data: dict) -> dict:
    """Parse OpenAI /dashboard/billing/credit_grants response."""
    grants = data.get("grants", {}).get("data", [])
    total = sum(float(g.get("credit_amount", 0)) for g in grants)
    used = sum(float(g.get("used_amount", 0)) for g in grants)
    balance = total - used
    return {"valid": True, "total_balance": balance, "balance_details": [],
            "primary_currency": "USD", "openai_grants": {"total": total, "used": used}}


def _parse_openrouter_balance(data: dict) -> dict:
    """Parse OpenRouter /auth/key response."""
    credits = float(data.get("data", {}).get("credits", 0))
    return {"valid": True, "total_balance": credits, "balance_details": [],
            "primary_currency": "USD"}


# ═══════════════════════════════════════════════════════════════════
#  终极查询库 (按热度排序 — 高产出 → 低产出)
#  基于: 实测数据 + GitGuardian 2025 + TruffleHog + GH Dorking 研究
# ═══════════════════════════════════════════════════════════════════

BUILTIN_QUERIES = [
    # ═══════════════════════════════════════════════════════
    #  🔥 第一梯队 — 实测最高产出 (Java/Kotlin/PHP/Python)
    # ═══════════════════════════════════════════════════════

    # Java (Spring Boot / Android — 实测 90+ keys)
    "deepseek sk- filename:java",
    "deepseek sk- filename:properties",
    "deepseek sk- filename:gradle",

    # Kotlin (Android — 实测 22 keys)
    "deepseek sk- filename:kt",

    # PHP (Web后端 — 实测 26 keys)
    "deepseek sk- filename:php",
    "api.deepseek.com sk- filename:php",

    # Python (AI/ML 代码硬编码)
    "deepseek sk- language:Python NOT env NOT export",
    "deepseek sk- filename:py NOT env",
    "deepseek OpenAI(api_key sk- filename:py",
    "deepseek client sk- filename:py",
    "deepseek def sk- filename:py",
    "deepseek requests sk- filename:py",
    "api.deepseek.com sk- filename:py",

    # ═══════════════════════════════════════════════════════
    #  🔥 第二梯队 — 配置文件泄露 (.env / config)
    # ═══════════════════════════════════════════════════════

    "deepseek sk- filename:env",
    "deepseek sk- filename:env.local",
    "deepseek sk- filename:env.production",
    "deepseek sk- filename:env.development",
    "deepseek sk- filename:env.example",
    "deepseek sk- filename:env.sample",
    "deepseek sk- filename:env.backup",
    "deepseek sk- filename:credentials",
    "deepseek sk- filename:secrets",

    # 配置文件
    "deepseek sk- filename:yml",
    "deepseek sk- filename:yaml",
    "deepseek sk- filename:json",
    "deepseek sk- filename:toml",
    "deepseek sk- filename:cfg",
    "deepseek sk- filename:ini",
    "deepseek sk- filename:conf",
    "deepseek sk- filename:config",

    # ═══════════════════════════════════════════════════════
    #  🔥 第三梯队 — 移动端 (Dart/Swift) + Shell 脚本
    # ═══════════════════════════════════════════════════════

    "deepseek sk- filename:dart",
    "api.deepseek.com sk- filename:dart",

    "deepseek sk- filename:swift",

    "deepseek sk- filename:sh",
    "deepseek sk- filename:zsh",
    "deepseek sk- filename:bash",
    "deepseek sk- filename:fish",

    # ═══════════════════════════════════════════════════════
    #  🔥 第四梯队 — JS/TS + C++ + Go + C#
    # ═══════════════════════════════════════════════════════

    "deepseek sk- filename:js",
    "deepseek sk- filename:ts",
    "deepseek API_KEY sk- filename:js",

    "deepseek sk- filename:cpp",

    "deepseek sk- filename:go",

    "deepseek sk- filename:cs",

    # ═══════════════════════════════════════════════════════
    #  🔥 第五梯队 — Jupyter / Docker / Lua / 变量名
    # ═══════════════════════════════════════════════════════

    "deepseek sk- filename:ipynb",
    "DEEPSEEK_API_KEY sk- filename:ipynb",

    "deepseek sk- filename:dockerfile",
    "deepseek sk- filename:docker-compose",
    "deepseek.com sk- filename:yml path:.github",

    "deepseek sk- filename:lua path:nvim",

    # 变量名变体
    "DEEPSEEK_API_KEY sk-",
    "DEEPSEEK_KEY sk-",
    "deepseek_api_key sk-",
    "deepseek_key sk-",
    "DEEPSEEK_TOKEN sk-",
    "DEEPSEEK_API_TOKEN sk-",

    # ═══════════════════════════════════════════════════════
    #  第六梯队 — API 客户端模式 + 文本文件
    # ═══════════════════════════════════════════════════════

    "api.deepseek.com OpenAI sk-",
    "deepseek Authorization Bearer sk-",
    "deepseek base_url sk-",
    "deepseek OpenAIClient sk-",

    "deepseek sk- filename:txt",
    "deepseek sk- filename:md",

    # ═══════════════════════════════════════════════════════
    #  第七梯队 — 跨文件类型 + 时间限定
    # ═══════════════════════════════════════════════════════

    "deepseek process.env sk- filename:js",
    "deepseek sk- filename:py pushed:>2025-01-01",
    "deepseek sk- filename:envrc",
    "deepseek sk- filename:html",

    # ═══════════════════════════════════════════════════════
    #  第八梯队 — 小众语言但偶尔有产出
    # ═══════════════════════════════════════════════════════

    "deepseek sk- filename:rb",
    "deepseek sk- filename:rs",
    "deepseek sk- filename:lua",
    "deepseek sk- filename:plist",

    # ═══════════════════════════════════════════════════════
    #  第九梯队 — 时间限定 + 2026 新模式 (v5 实测高产)
    # ═══════════════════════════════════════════════════════

    "deepseek sk- pushed:>2026-05-01",
    "deepseek sk- pushed:>2026-04-01",
    "deepseek sk- filename:java pushed:>2026-04-01",
    "deepseek sk- filename:py pushed:>2026-04-01",
    "deepseek sk- filename:env pushed:>2026-04-01",
    "deepseek sk- filename:js pushed:>2026-04-01",
    "deepseek sk- filename:yml pushed:>2026-04-01",
    "deepseek sk- filename:json pushed:>2026-04-01",
    "deepseek API_KEY sk- language:Java NOT test NOT example",
    "deepseek Authorization sk- language:Python NOT test",
    "deepseek DEEPSEEK_API_KEY sk- language:TypeScript",
    "deepseek base_url sk- filename:json",
    "deepseek sk- path:config",
    "deepseek sk- path:src/main/resources",
    "deepseek sk- filename:application.yml",
    "deepseek sk- filename:application.properties",
    "deepseek sk- path:.github/workflows",
    "api.deepseek.com sk- path:src",
    "deepseek deepseek_api_key sk- filename:env",
    "deepseek Client sk- filename:kt NOT test",
    "deepseek import sk- filename:dart",
    "deepseek sk- filename:ipynb pushed:>2026-01-01",
    "deepseek OpenAIClient sk- filename:go NOT test",
    "deepseek sk- filename:toml path:config",
    "deepseek Authorization Bearer sk- filename:js NOT test",
    "deepseek process.env.DEEPSEEK sk- filename:ts",

    # ═══════════════════════════════════════════════════════
    #  第十梯队 — 替代平台 + 框架集成 (OpenRouter/LangChain/等)
    # ═══════════════════════════════════════════════════════

    # OpenRouter proxy (people proxy DeepSeek through OpenRouter)
    "OPENROUTER_API_KEY sk-",
    "openrouter deepseek sk-",
    "openrouter api_key sk- filename:py",

    # LangChain integration
    "langchain deepseek api_key",
    "langchain deepseek sk- filename:py",

    # vLLM / open-webui / dify deployment configs
    "vllm deepseek sk- filename:yml",
    "open-webui deepseek sk-",
    "dify deepseek api_key",

    # LLM framework configs
    "llamaindex deepseek sk-",
    "litellm deepseek api_key",

    # CI/CD workflows with hardcoded secrets
    "deepseek sk- path:.github/workflows",
    "DEEPSEEK_API_KEY path:.github/workflows",

    # Keys in README / documentation
    "deepseek sk- filename:README",

    # Terraform / K8s / Helm
    "deepseek sk- filename:tf",
    "deepseek sk- filename:hcl",
    "deepseek sk- path:k8s",
    "deepseek sk- filename:values.yaml",

    # IDE configs
    "deepseek sk- path:.vscode",

    # Package manager configs
    "deepseek sk- filename:.npmrc",
    "deepseek sk- filename:.pypirc",

    # Jupyter / Colab specific
    "deepseek sk- filename:colab",
    "deepseek sk- filename:notebook",

    # Mobile app configs
    "deepseek sk- path:android",
    "deepseek sk- path:ios",

    # Alternative key prefixes (DeepSeek sometimes uses ds-)
    "deepseek ds-",

    # ═══════════════════════════════════════════════════════
    #  第十一梯队 — 更多框架/平台/部署场景
    # ═══════════════════════════════════════════════════════

    # FastGPT / ChatGPT-Next-Web / LobeChat / OneAPI
    "fastgpt deepseek api_key",
    "chatgpt-next-web deepseek sk-",
    "lobechat deepseek sk-",
    "oneapi deepseek sk-",

    # AI agent frameworks
    "autogen deepseek api_key",
    "crewai deepseek api_key",
    "agno deepseek api_key",

    # RAG frameworks
    "ragflow deepseek api_key",
    "quivr deepseek api_key",
    "anythingllm deepseek api_key",

    # API gateway / proxy
    "kong deepseek api_key",
    "apifox deepseek api_key",
    "postman deepseek api_key",

    # Cloud deployment
    "vercel deepseek api_key",
    "netlify deepseek api_key",
    "heroku deepseek api_key",
    "railway deepseek api_key",

    # Serverless functions
    "deepseek sk- path:cloudfunctions",
    "deepseek sk- path:supabase/functions",
    "deepseek sk- path:netlify/functions",

    # More mobile frameworks
    "deepseek sk- filename:xml path:android",
    "deepseek sk- filename:gradle path:android",
    "deepseek sk- filename:plist path:ios",
    "deepseek sk- filename:xcconfig",

    # Game engines
    "deepseek sk- filename:cs path:unity",
    "deepseek sk- filename:gd",

    # More config files
    "deepseek sk- filename:.babelrc",
    "deepseek sk- filename:webpack.config.js",
    "deepseek sk- filename:vite.config.ts",
    "deepseek sk- filename:next.config.js",
    "deepseek sk- filename:nuxt.config.ts",
    "deepseek sk- filename:svelte.config.js",

    # Database / ORM configs
    "deepseek sk- filename:prisma/schema.prisma",
    "deepseek sk- filename:schema.prisma",
    "deepseek sk- filename:supabase/config.toml",

    # Testing configs
    "deepseek sk- filename:cypress.config",
    "deepseek sk- filename:playwright.config",
    "deepseek sk- filename:jest.config",
    "deepseek sk- filename:vitest.config",

    # More shell variants
    "deepseek sk- filename:ps1",
    "deepseek sk- filename:bat",
    "deepseek sk- filename:cmd",

    # WASM / embedded
    "deepseek sk- filename:wasm",
    "deepseek sk- filename:proto",

    # ═══════════════════════════════════════════════════════
    #  第十二梯队 — 深度时间过滤 (2026年最新)
    # ═══════════════════════════════════════════════════════

    "deepseek sk- pushed:>2026-05-15",
    "deepseek sk- pushed:2026-05-15..2026-05-20",
    "deepseek sk- filename:java pushed:>2026-05-01",
    "deepseek sk- filename:py pushed:>2026-05-01",
    "deepseek sk- filename:js pushed:>2026-05-01",
    "deepseek sk- filename:ts pushed:>2026-05-01",
    "deepseek sk- filename:env pushed:>2026-05-01",
    "deepseek sk- filename:yml pushed:>2026-05-01",
    "deepseek sk- filename:json pushed:>2026-05-01",
    "deepseek sk- filename:kt pushed:>2026-05-01",
    "deepseek sk- filename:php pushed:>2026-05-01",
    "deepseek sk- filename:go pushed:>2026-05-01",
    "deepseek sk- filename:rs pushed:>2026-05-01",
    "deepseek sk- filename:cpp pushed:>2026-05-01",
    "deepseek sk- filename:swift pushed:>2026-05-01",
    "deepseek sk- filename:dart pushed:>2026-05-01",

    # ═══════════════════════════════════════════════════════
    #  第十三梯队 — 变量名变体 + 拼接模式
    # ═══════════════════════════════════════════════════════

    "deepseek_api_key = sk-",
    "deepseek_key = sk-",
    "deepseek_token = sk-",
    "deepseek_secret = sk-",
    "ds_api_key = sk-",
    "ds_key = sk-",

    # process.env variants
    "process.env.DEEPSEEK",
    "process.env[\"DEEPSEEK",
    "os.environ[\"DEEPSEEK",
    "os.getenv(\"DEEPSEEK",

    # Config class patterns
    "class Config deepseek sk-",
    "dataclass deepseek sk-",
    "pydantic deepseek sk-",

    # ═══════════════════════════════════════════════════════
    #  第十四梯队 — API 调用模式
    # ═══════════════════════════════════════════════════════

    "deepseek.chat.completions sk-",
    "deepseek.completions sk-",
    "api.deepseek.com/v1 sk-",
    "api.deepseek.com/chat sk-",

    # Client initialization patterns
    "DeepSeekClient sk-",
    "deepseek.Client sk-",
    "create_deepseek_client sk-",

    # More auth patterns
    "x-deepseek-api-key",
    "deepseek-api-key sk-",

    # ═══════════════════════════════════════════════════════
    #  第十五梯队 — 小众但偶尔有产出
    # ═══════════════════════════════════════════════════════

    "deepseek sk- filename:sql",
    "deepseek sk- filename:graphql",
    "deepseek sk- filename:prisma",
    "deepseek sk- filename:eslintrc",
    "deepseek sk- filename:prettierrc",
    "deepseek sk- filename:babelrc",
    "deepseek sk- filename:postcss.config",
    "deepseek sk- filename:tailwind.config",
    "deepseek sk- filename:astro.config",
    "deepseek sk- filename:gatsby-config",
    "deepseek sk- filename:gridsome.config",
    "deepseek sk- filename:vue.config",
    "deepseek sk- filename:nuxt.config",
    "deepseek sk- filename:quasar.conf",
    "deepseek sk- filename:capacitor.config",
    "deepseek sk- filename:ionic.config",
    "deepseek sk- filename:cordova.config",
    "deepseek sk- filename:electron-main",
    "deepseek sk- filename:tauri.conf",
    "deepseek sk- filename:expo.config",
    "deepseek sk- filename:metro.config",
    "deepseek sk- filename:fastlane",
    "deepseek sk- filename:bitrise.yml",
    "deepseek sk- filename:appveyor.yml",
    "deepseek sk- filename:travis.yml",
    "deepseek sk- filename:circleci",
    "deepseek sk- path:.circleci",
    "deepseek sk- path:.travis",
    "deepseek sk- path:deploy",
    "deepseek sk- path:scripts",
    "deepseek sk- path:tools",
    "deepseek sk- path:infra",
    "deepseek sk- path:infrastructure",
    "deepseek sk- path:terraform",
    "deepseek sk- path:ansible",
    "deepseek sk- path:pulumi",
    "deepseek sk- path:cdk",

    # ═══════════════════════════════════════════════════════
    #  第十六梯队 — 通用 sk- 查询 (无 deepseek 关键词, 覆盖 OpenAI/OpenRouter)
    # ═══════════════════════════════════════════════════════

    # 纯 sk- 密钥搜索 (不限提供商)
    "sk- filename:env NOT deepseek",
    "sk- filename:env.local NOT deepseek",
    "sk- filename:env.production NOT deepseek",
    "sk- filename:env.development NOT deepseek",
    "sk- filename:env.example NOT deepseek",
    "sk- filename:env.sample NOT deepseek",
    "sk- filename:env.backup NOT deepseek",
    "sk- filename:credentials NOT deepseek",
    "sk- filename:secrets NOT deepseek",

    # API Key 变量名模式 (OpenAI/OpenRouter)
    "OPENAI_API_KEY sk-",
    "OPENROUTER_API_KEY sk-",
    "OPENAI_KEY sk-",
    "OPENAI_TOKEN sk-",
    "OPENROUTER_KEY sk-",
    "openai_api_key sk- filename:py",
    "openrouter_api_key sk- filename:py",
    "openai_api_key sk- filename:js",
    "openrouter_api_key sk- filename:js",
    "openai_api_key sk- filename:env",
    "openrouter_api_key sk- filename:env",

    # 通用 API 客户端模式
    "api.openai.com sk- filename:py NOT deepseek",
    "api.openai.com sk- filename:js NOT deepseek",
    "openrouter.ai sk- filename:py",
    "openrouter.ai sk- filename:js",
    "OpenAI(api_key sk- filename:py NOT deepseek",
    "OpenAI(api_key sk- filename:js NOT deepseek",
    "Authorization Bearer sk- filename:py NOT deepseek",
    "Authorization Bearer sk- filename:js NOT deepseek",
    "Authorization Bearer sk- filename:env NOT deepseek",

    # 通用配置文件
    "sk- filename:yml NOT deepseek",
    "sk- filename:yaml NOT deepseek",
    "sk- filename:json NOT deepseek",
    "sk- filename:toml NOT deepseek",
    "sk- filename:ini NOT deepseek",
    "sk- filename:conf NOT deepseek",
    "sk- filename:config NOT deepseek",

    # 通用 Code 文件 (无 deepseek 关键词)
    "sk- filename:py NOT deepseek NOT env",
    "sk- filename:js NOT deepseek NOT env",
    "sk- filename:ts NOT deepseek",
    "sk- filename:java NOT deepseek",
    "sk- filename:kt NOT deepseek",
    "sk- filename:go NOT deepseek",
    "sk- filename:php NOT deepseek",
    "sk- filename:rs NOT deepseek",
    "sk- filename:rb NOT deepseek",
    "sk- filename:cpp NOT deepseek",
    "sk- filename:cs NOT deepseek",
    "sk- filename:swift NOT deepseek",
    "sk- filename:dart NOT deepseek",

    # LangChain / 框架集成 (无 deepseek)
    "langchain openai_api_key",
    "langchain openrouter_api_key",
    "litellm api_key sk-",

    # CI/CD 密钥泄露
    "OPENAI_API_KEY path:.github/workflows",
    "OPENROUTER_API_KEY path:.github/workflows",
    "API_KEY sk- path:.github/workflows NOT deepseek",

    # Docker / Kubernetes
    "sk- filename:dockerfile NOT deepseek",
    "sk- filename:docker-compose NOT deepseek",
    "sk- path:k8s NOT deepseek",

    # 时间限定 (2026 最新)
    "sk- pushed:>2026-05-01 NOT deepseek",
    "sk- pushed:>2026-04-01 NOT deepseek",
    "sk- filename:env pushed:>2026-04-01 NOT deepseek",
    "sk- filename:py pushed:>2026-04-01 NOT deepseek",
    "sk- filename:js pushed:>2026-04-01 NOT deepseek",
    "sk- filename:yml pushed:>2026-04-01 NOT deepseek",
    "sk- filename:json pushed:>2026-04-01 NOT deepseek",
    "sk- filename:java pushed:>2026-04-01 NOT deepseek",

    # process.env 模式
    "process.env.OPENAI_API_KEY sk-",
    "process.env.OPENROUTER_API_KEY sk-",
    "process.env sk- filename:js NOT deepseek",
    "os.environ sk- filename:py NOT deepseek",
    "os.getenv sk- filename:py NOT deepseek",

    # AI 框架 config (无需 deepseek)
    "sk- path:config NOT deepseek",
    "sk- path:src/main/resources NOT deepseek",
    "sk- filename:application.yml NOT deepseek",
    "sk- filename:application.properties NOT deepseek",

    # OpenRouter 特定模式
    "openrouter sk- filename:py",
    "openrouter sk- filename:js",
    "openrouter sk- filename:ts",
    "openrouter API_KEY sk-",
    "openrouter api_key sk- filename:env",

    # OpenAI 特定模式
    "openai sk- filename:py NOT deepseek",
    "openai sk- filename:js NOT deepseek",
    "openai sk- filename:env NOT deepseek",
    "openai.Client sk- filename:py",
    "openai.OpenAI sk- filename:py",

    # 通用 LLM 平台 (LobeChat / Dify / vLLM)
    "lobechat OPENAI_API_KEY",
    "dify OPENAI_API_KEY",
    "fastgpt OPENAI_API_KEY",
    "oneapi sk- token",
    "chatgpt-next-web OPENAI_API_KEY",
    "open-webui OPENAI_API_KEY",
    "vllm api_key sk-",

    # 通用 key 文件
    "sk- filename:txt NOT deepseek",
    "sk- filename:md NOT deepseek",
    "sk- filename:html NOT deepseek",
    "sk- filename:ipynb NOT deepseek",
    "sk- filename:sh NOT deepseek",
    "sk- filename:bash NOT deepseek",
]


def is_bad_key(key: str, extra_bad: list = None) -> bool:
    return _scanner_is_bad_key(key, extra_bad)


def convert_to_usd(balance: float, currency: str, rate: float = DEFAULT_USD_CNY_RATE) -> float:
    if currency.upper() == "CNY":
        return balance / rate if rate > 0 else 0
    return balance


def convert_to_cny(balance: float, currency: str, rate: float = DEFAULT_USD_CNY_RATE) -> float:
    if currency.upper() == "USD":
        return balance * rate
    return balance


class ScannerEngine:
    def __init__(self,
                 concurrency: int = 20,
                 timeout: int = 15,
                 search_delay: float = 2.5,
                 max_pages: int = 3,
                 min_key_length: int = 32,
                 max_key_length: int = 64,
                 output_dir: str = ".",
                 providers: list = None,
                 deepseek_api_base: str = None,  # deprecated, use providers
                 usd_cny_rate: float = DEFAULT_USD_CNY_RATE,
                 exclude_repos: list = None,
                 extra_bad_patterns: list = None,
                 log_callback: Callable[[str, str], None] = None,
                 progress_callback: Callable[[int, int, str], None] = None,
                 max_duration: int = 0,
                 max_valid_keys: int = 0,
                 auto_save_interval: int = 0,
                 scan_pages: int = 5,
                 ):
        self.concurrency = concurrency
        self.timeout = timeout
        self.search_delay = search_delay
        self.max_pages = max_pages
        self.min_key_length = min_key_length
        self.max_key_length = max_key_length
        self.output_dir = output_dir
        # Provider list (backward compat: deepseek_api_base → providers)
        if providers is None:
            if deepseek_api_base:
                self.providers = ["deepseek"]
            else:
                self.providers = ["deepseek", "openai", "openrouter"]
        else:
            self.providers = providers
        self.usd_cny_rate = usd_cny_rate
        self.exclude_repos = exclude_repos or []
        self.extra_bad_patterns = extra_bad_patterns or []
        self.log_callback = log_callback or (lambda msg, level="info": print(msg))
        self.progress_callback = progress_callback or (lambda cur, total, phase: None)

        # 退出机制
        self.max_duration = max_duration
        self.max_valid_keys = max_valid_keys
        self.auto_save_interval = auto_save_interval or 20
        self.scan_pages = max(1, min(10, scan_pages or 10))  # 默认10页, 限1-10

        self.key_pattern = re.compile(
            rf"sk-[a-zA-Z0-9]{{{min_key_length},{max_key_length}}}"
        )
        self._stop_requested = False
        self._start_time = time.time()
        self._valid_count = 0
        self._saved_count = 0
        self.results = []
        self.all_keys = {}

    _gh_authenticated = None  # class-level cache

    @staticmethod
    def check_gh_auth() -> bool:
        """检测 gh CLI 是否已认证"""
        return bool(ScannerEngine.get_gh_token())

    @staticmethod
    def get_gh_token() -> str:
        """Get GitHub token from gh CLI, env var, or git config."""
        # Try GH_TOKEN / GITHUB_TOKEN env var first
        for env_var in ["GH_TOKEN", "GITHUB_TOKEN"]:
            token = os.environ.get(env_var, "")
            if token:
                return token
        # Try gh CLI
        try:
            r = subprocess.run(
                ["gh", "auth", "token"], capture_output=True, timeout=5,
                encoding="utf-8", errors="replace"
            )
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except Exception:
            pass
        return ""

    @staticmethod
    def suggested_search_delay() -> float:
        """根据认证状态建议安全请求间隔"""
        return 2.5 if ScannerEngine.check_gh_auth() else 6.5

    def log(self, msg: str, level: str = "info"):
        self.log_callback(msg, level)

    def stop(self):
        self._stop_requested = True

    # ================================================================
    #  主流水线: 搜索 → 验证 → 保存 → 检查退出 → 下一轮
    #  每轮 = 一条查询, 边扫边验边存, 时间/数量达标立即退出
    # ================================================================

    def run(self, queries: list) -> list:
        """主流水线: 逐条查询, 搜索→验证→保存→检查限制→循环
        支持 Ctrl+C 优雅退出: 保存进度, 验证已扫 Key, 保存结果
        """
        if not queries:
            return []

        all_valid = []      # 最终有效结果
        total_scanned = 0
        current_round = 0
        unverified_keys = {}  # 当前轮未验证的 Key (Ctrl+C 时补验)
        os.makedirs(self.output_dir, exist_ok=True)
        self._start_time = time.time()

        # 按热度顺序扫描 (热→冷, 前期快速产出)
        ordered = queries.copy()

        self.log(f"流水线启动: {len(queries)} 条查询 (热度排序), 并发 {self.concurrency}, "
                 f"时长限制 {self.max_duration}s, 目标 {self.max_valid_keys} 个有效Key")

        try:
            for qi, query in enumerate(ordered):
                current_round = qi + 1

                # ── 检查退出条件 ──
                if self._should_stop():
                    self.log(f"流水线退出: {self._stop_reason()}", "warning")
                    break

                self.log(f"\n{'='*40}")
                self.log(f"轮次 [{qi+1}/{len(queries)}]: {query}")
                self.progress_callback(qi + 1, len(queries), "search")

                # ── 第一步: 搜索 ──
                round_keys = self._scan_one_query(query)
                unverified_keys = round_keys  # 暂存，用于 Ctrl+C 恢复
                if not round_keys:
                    self.log(f"  本轮发现: 0 个 Key，跳过验证")
                    unverified_keys = {}
                    time.sleep(self.search_delay)
                    continue

                self.log(f"  本轮发现: {len(round_keys)} 个疑似 Key")

                # ── 第二步: 立即验证 ──
                self.log(f"  开始验证 {len(round_keys)} 个 Key...")
                round_results = self._verify_dict(round_keys)
                unverified_keys = {}  # 已验证，清空暂存

                valid = [r for r in round_results if r.get("valid")]
                invalid = [r for r in round_results if not r.get("valid")]
                self.log(f"  验证结果: {len(valid)} 有效, {len(invalid)} 无效 (丢弃)")

                # 有效 Key 加入累计 (去重)
                existing_keys = {r["key"] for r in all_valid}
                for r in valid:
                    if r["key"] not in existing_keys:
                        all_valid.append(r)
                        existing_keys.add(r["key"])
                # 统计所有有效 Key (原始逻辑: 多多益善)
                self._valid_count = len(all_valid)
                total_scanned += len(round_keys)

                # ── 第三步: 增量保存 (仅有效 Key) ──
                self._save_incremental(all_valid, qi, len(queries))

                # ── 第四步: 检查退出条件 ──
                if self._should_stop():
                    self.log(f"  轮次结束后 {self._stop_reason()}", "warning")
                    break

                time.sleep(self.search_delay)

        except KeyboardInterrupt:
            self.log(f"\n!!! 收到 Ctrl+C 信号 !!!", "error")
            self.log(f"已扫描 {current_round-1}/{len(queries)} 轮, {len(all_valid)} 个有效Key")

            # 验证未完成的轮次的 Key
            if unverified_keys:
                self.log(f"正在验证当前轮 {len(unverified_keys)} 个未验证 Key...")
                try:
                    emergency_results = self._verify_dict(unverified_keys)
                    valid_emergency = [r for r in emergency_results if r.get("valid")]
                    existing = {r["key"] for r in all_valid}
                    added = 0
                    for r in valid_emergency:
                        if r["key"] not in existing:
                            all_valid.append(r)
                            existing.add(r["key"])
                            added += 1
                    self.log(f"紧急验证完成: {len(valid_emergency)} 有效, 新增 {added} 个")
                except Exception as e:
                    self.log(f"紧急验证失败: {e}", "error")

            # 保存进度
            self._save_final(all_valid)
            self.log(f"已安全保存 {len(all_valid)} 个有效Key, 优雅退出", "warning")

        # 最终保存
        self._save_final(all_valid)
        elapsed = time.time() - self._start_time

        positive_only = [r for r in all_valid if r.get("balance_usd", 0) > 0]
        self.log(f"\n{'='*40}")
        self.log(f"流水线完成: {elapsed:.0f}s | 扫描 {total_scanned} 个Key | "
                 f"有效 {len(all_valid)} 个 | 正余额 {len(positive_only)} 个")
        if positive_only:
            total_usd = sum(r.get("balance_usd", 0) for r in positive_only)
            total_cny = sum(r.get("balance_cny", 0) for r in positive_only)
            self.log(f"正余额总价值: ${total_usd:.2f} / ¥{total_cny:.2f} (欠费不计入)")

        return all_valid

    def run_multi_source(self, sources: list, queries: list = None,
                         github_token: str = "", gitlab_token: str = "",
                         gitee_token: str = "") -> list:
        """多源扫描: 同时扫描 GitHub + Gist + Issues + GitLab + Gitee + Docker + ...
        sources: ['github', 'gist', 'issues', 'gitlab', 'wayback', 'docker',
                   'commoncrawl', 'gitee', 'npm']
        每个 source 用独立 scanner 实例，并发运行。
        """
        if not sources:
            self.log("未指定扫描来源", "warning")
            return []

        os.makedirs(self.output_dir, exist_ok=True)
        self._start_time = time.time()

        scanner_map = {
            "github": ("GitHub Code Search", queries or BUILTIN_QUERIES),
            "gist": ("GitHub Gists", None),
            "issues": ("GitHub Issues/PRs", None),
            "commits": ("GitHub Commit History", None),
            "gitlab": ("GitLab", None),
            "wayback": ("Wayback Machine", None),
            "docker": ("Docker Hub", None),
            "commoncrawl": ("Common Crawl", None),
            "gitee": ("Gitee 码云", None),
            "npm": ("npm Registry", None),
            "huggingface": ("HuggingFace", None),
            "pypi": ("PyPI Registry", None),
            "stackoverflow": ("Stack Overflow", None),
        }

        self.log(f"多源扫描启动: {len(sources)} 个来源 -> {[scanner_map[s][0] for s in sources]}")
        self.log(f"验证并发: {self.concurrency}, 时长限制: {self.max_duration}s, 目标: {self.max_valid_keys} 个")

        all_discovered = {}

        for src in sources:
            if self._should_stop():
                break

            label, default_query = scanner_map.get(src, (src, None))
            self.log(f"\n{'='*50}")
            self.log(f"  [{label}] 开始扫描...")
            self.log(f"{'='*50}")

            try:
                round_keys = self._run_one_scanner(src, default_query, github_token,
                                                   gitlab_token, gitee_token)
            except Exception as e:
                self.log(f"  [{label}] 扫描异常: {e}", "error")
                continue

            if not round_keys:
                self.log(f"  [{label}] 未发现 Key")
                continue

            self.log(f"  [{label}] 发现 {len(round_keys)} 个疑似 Key")

            # Verify
            self.log(f"  验证 {len(round_keys)} 个 Key...")
            round_results = self._verify_dict(round_keys)

            valid = [r for r in round_results if r.get("valid")]
            invalid = [r for r in round_results if not r.get("valid")]
            self.log(f"  [{label}] 有效: {len(valid)}, 无效: {len(invalid)}")

            for r in valid:
                k = r["key"]
                if k not in all_discovered:
                    all_discovered[k] = r

            self._save_incremental(
                list(all_discovered.values()),
                sources.index(src), len(sources)
            )

            if self._should_stop():
                self.log(f"  达到退出条件: {self._stop_reason()}", "warning")
                break

            time.sleep(1.0)

        all_results = list(all_discovered.values())
        self._save_final(all_results)
        elapsed = time.time() - self._start_time

        positive_only = [r for r in all_results if r.get("balance_usd", 0) > 0]
        self.log(f"\n{'='*40}")
        self.log(f"多源扫描完成: {elapsed:.0f}s | 有效 {len(all_results)} 个 | 正余额 {len(positive_only)} 个")
        if positive_only:
            total_usd = sum(r.get("balance_usd", 0) for r in positive_only)
            total_cny = sum(r.get("balance_cny", 0) for r in positive_only)
            self.log(f"正余额总价值: ${total_usd:.2f} / ¥{total_cny:.2f} (欠费不计入)")

        return all_results

    # Scanner factory: (class, search_term, extra_init_kwargs)
    _SCANNER_REGISTRY = None

    def _get_scanner_registry(self, github_token: str = "", gitlab_token: str = "",
                              gitee_token: str = ""):
        if self._SCANNER_REGISTRY is None:
            ScannerEngine._SCANNER_REGISTRY = {
                "gist": (GistScanner, None, {"token": github_token}),
                "issues": (IssuesScanner, '"sk-"', {"token": github_token}),
                "commits": (CommitsScanner, None, {"token": github_token}),
                "gitlab": (GitLabScanner, '"sk-"', {"token": gitlab_token, "max_projects": 100}),
                "wayback": (WaybackScanner, "github.com", {"max_snapshots": 100}),
                "docker": (DockerHubScanner, '"sk-"', {"max_images": 50}),
                "commoncrawl": (CommonCrawlScanner, "github.com", {"max_urls": 200}),
                "gitee": (GiteeScanner, '"sk-"', {"token": gitee_token, "max_repos": 100}),
                "npm": (NpmScanner, '"sk-"', {"max_packages": 50}),
                "huggingface": (HuggingFaceScanner, '"sk-"', {"max_items": 150}),
                "pypi": (PyPIScanner, '"sk-"', {"max_packages": 150}),
                "stackoverflow": (StackOverflowScanner, '"sk-"', {"max_posts": 200}),
            }
        return ScannerEngine._SCANNER_REGISTRY

    def _run_one_scanner(self, source: str, queries: list = None,
                         github_token: str = "", gitlab_token: str = "",
                         gitee_token: str = "") -> dict:
        """Run a single scanner by name and return discovered keys dict."""
        discovered = {}

        async def _do():
            nonlocal discovered
            if source == "github":
                if not queries:
                    queries = BUILTIN_QUERIES
                for query in queries[:50]:
                    if self._should_stop():
                        break
                    batch = self._scan_one_query(query)
                    for k, v in batch.items():
                        if k not in discovered:
                            discovered[k] = v
                    time.sleep(self.search_delay)
                return

            registry = self._get_scanner_registry(github_token, gitlab_token, gitee_token)
            scanner_cls, search_term, extra_kwargs = registry.get(source, (None, None, {}))
            if scanner_cls is None:
                return

            scanner = scanner_cls(concurrency=self.concurrency, timeout=self.timeout, **extra_kwargs)
            results = await scanner.search(search_term)
            for r in results:
                k = r["key"]
                if k not in discovered:
                    discovered[k] = {
                        "key": k,
                        "key_preview": r.get("key_preview", k[:10] + "..." + k[-4:]),
                        "repos": [{"repo": r.get("repo", ""), "file": r.get("file", ""),
                                   "url": r.get("url", "")}],
                    }

        asyncio.run(_do())
        return discovered

    def _is_likely_test_key(self, file_path: str, repo: str) -> bool:
        """Pre-filter to skip test/demo files and build artifacts.
        Test files often contain real keys with balance, so we only skip
        unambiguous low-value patterns."""
        lower = (file_path + "/" + repo).lower()
        # Build artifacts
        for kw in ["/target/site/", "/target/classes/", "/build/resources/",
                    "/bin/main/", "/.html"]:
            if kw in lower:
                return True
        # Common test/demo paths that are almost always zero-balance
        for kw in ["/test/java/", "/test/kotlin/", "testdeepseek", "tongyichat",
                   "/demo/", "/examples/", "/sample/", "/samples/",
                   "/tests/", "/__tests__/", "/spec/", "/fixtures/"]:
            if kw in lower:
                return True
        return False

    def _scan_one_query(self, query: str) -> dict:
        """扫描单条查询: 取最多 N 页 (每页100条), 异步并发抓取原始文件"""
        max_pages_to_fetch = getattr(self, 'scan_pages', 5)
        items = []
        for page in range(1, max_pages_to_fetch + 1):
            if page > 1:
                time.sleep(4.0)  # 页间延迟 4s — 30/min 限制下安全
            batch = self._gh_search(query, per_page=100, page=page)
            if not batch:
                break
            items.extend(batch)
            if len(batch) < 100:  # 最后一页, 无需继续
                break
        if not items:
            return {}
        return asyncio.run(self._scan_one_query_async(items))

    async def _scan_one_query_async(self, items: list) -> dict:
        """异步并发抓取所有文件并提取 Key"""
        all_keys = {}
        seen = set()
        seen_lock = asyncio.Lock()
        sem = asyncio.Semaphore(15)  # 并发抓取 15 个文件

        async def fetch_and_extract(item):
            repo = item.get("repository", {}).get("full_name", "")
            path = item.get("path", "")
            html_url = item.get("html_url", "")
            if not repo or not path:
                return []
            if any(fnmatch.fnmatch(repo, p) for p in self.exclude_repos):
                return []
            # Skip test/demo files (vast majority are zero-balance)
            if self._is_likely_test_key(path, repo):
                return []

            # 线程安全的去重检查
            cache = f"{repo}/{path}"
            async with seen_lock:
                if cache in seen:
                    return []
                seen.add(cache)

            branch = "main"
            if "/blob/" in html_url:
                branch = html_url.split("/blob/")[1].split("/")[0]

            text = await self._fetch_raw_async(sem, repo, path, branch)
            if not text:
                return []

            keys = self.key_pattern.findall(text)
            keys = [k for k in keys if not is_bad_key(k, self.extra_bad_patterns)]
            result = []
            for k in keys:
                result.append((k, repo, path, html_url))
            return result

        async with aiohttp.ClientSession() as session:
            self._async_session = session
            tasks = [fetch_and_extract(item) for item in items]
            batch_results = await asyncio.gather(*tasks)
            self._async_session = None

        for results in batch_results:
            for k, repo, path, html_url in results:
                if k not in all_keys:
                    all_keys[k] = {"key": k, "key_preview": k[:10] + "..." + k[-4:], "repos": []}
                if repo not in [r["repo"] for r in all_keys[k]["repos"]]:
                    all_keys[k]["repos"].append({"repo": repo, "file": path, "url": html_url})
                    self.log(f"  [KEY] {k[:10]}...{k[-4:]} | {repo}/{path}")

        return all_keys

    async def _fetch_raw_async(self, sem: asyncio.Semaphore, repo: str, path: str, branch: str = "main") -> str:
        """异步抓取原始文件内容 (尝试多个分支名)"""
        async with sem:
            tried = set()
            for br in [branch, "main", "master", "develop", "dev", "HEAD"]:
                if br in tried:
                    continue
                tried.add(br)
                url = f"https://raw.githubusercontent.com/{repo}/{br}/{path}"
                try:
                    async with self._async_session.get(url,
                                                        timeout=aiohttp.ClientTimeout(total=8),
                                                        headers={"User-Agent": "Mozilla/5.0"}) as resp:
                        if resp.status == 200:
                            return await resp.text()
                except Exception:
                    pass
            return ""

    def _verify_dict(self, keys_dict: dict) -> list:
        """验证一个 key 字典, 返回结果列表"""
        if not keys_dict:
            return []
        return asyncio.run(self._verify_all_async(keys_dict))

    def _save_incremental(self, valid_results: list, round_idx: int, total_rounds: int):
        """增量保存: JSON + CSV 全部覆写（CSV 不再追加，避免重复）"""
        os.makedirs(self.output_dir, exist_ok=True)
        sorted_r = self.sort_results(valid_results)

        # CSV 覆写 (去重)
        csv_path = os.path.join(self.output_dir, "api_keys_result.csv")
        try:
            with open(csv_path, "w", encoding="utf-8", newline="") as f:
                f.write("Key预览,完整Key,提供商,有效,原始余额,币种,USD等值,CNY等值,仓库名,文件名,文件路径,仓库链接,验证时间\n")
                for r in sorted_r:
                    repos_str = "; ".join([x["repo"] for x in r.get("repos", [])[:3]])
                    file_names = "; ".join([x.get("file", "").split("/")[-1] for x in r.get("repos", [])[:3]])
                    file_paths = "; ".join([x.get("file", "") for x in r.get("repos", [])[:3]])
                    repo_urls = "; ".join([x.get("url", "") for x in r.get("repos", [])[:3]])
                    cur = r.get("primary_currency", "N/A")
                    provider = r.get("provider", "?")
                    f.write(f'{r["key_preview"]},{r["key"]},{provider},{r["valid"]},'
                            f'{r["balance"]:.4f},{cur},{r["balance_usd"]:.2f},{r["balance_cny"]:.2f},'
                            f'"{repos_str}","{file_names}","{file_paths}","{repo_urls}",{r["verified_at"]}\n')
        except PermissionError:
            pass

        # JSON 覆写
        json_path = os.path.join(self.output_dir, "api_keys_result.json")
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(sorted_r, f, ensure_ascii=False, indent=2)
        except PermissionError:
            pass

        self.log(f"  增量保存: {len(valid_results)} 条有效Key | 轮次 {round_idx+1}/{total_rounds}")

    def _save_final(self, valid_results: list):
        """最终保存"""
        sorted_r = self.sort_results(valid_results)
        os.makedirs(self.output_dir, exist_ok=True)

        # JSON
        json_path = os.path.join(self.output_dir, "api_keys_result.json")
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(sorted_r, f, ensure_ascii=False, indent=2)
            self.log(f"最终保存 JSON: {json_path} ({len(sorted_r)} 条)")
        except Exception as e:
            self.log(f"JSON 保存失败: {e}", "error")

        # Markdown
        md_path = os.path.join(self.output_dir, "api_keys_result.md")
        try:
            with open(md_path, "w", encoding="utf-8") as f:
                f.write("# API Key Hunter - Scan Results\n\n")
                f.write(f"**Scan Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Exchange Rate:** 1 USD = {self.usd_cny_rate} CNY\n\n")
                f.write("## Summary\n\n")
                f.write(f"| Metric | Value |\n|---|---|\n")
                f.write(f"| Valid Keys | {len(sorted_r)} |\n")
                if sorted_r:
                    total_usd = sum(r["balance_usd"] for r in sorted_r)
                    total_cny = sum(r["balance_cny"] for r in sorted_r)
                    f.write(f"| Total USD | ${total_usd:.2f} |\n")
                    f.write(f"| Total CNY | ¥{total_cny:.2f} |\n")
                    f.write(f"| Max Balance | ${max(r['balance_usd'] for r in sorted_r):.2f} |\n")
                f.write(f"\n## Keys by Provider & USD Value\n\n")
                f.write(f"| # | Key | Provider | Balance | USD | CNY | Source |\n")
                f.write(f"|---|---|---|---|---|---|---|\n")
                for i, r in enumerate(sorted_r):
                    src = r["repos"][0]["repo"] if r.get("repos") else "N/A"
                    cur = r.get("primary_currency", "USD")
                    prov = r.get("provider", "?").upper()
                    f.write(f"| {i+1} | `{r['key_preview']}` | {prov} | {cur} {r['balance']:.4f} | "
                            f"${r['balance_usd']:.2f} | ¥{r['balance_cny']:.2f} | {src} |\n")
            self.log(f"最终保存 Markdown: {md_path}")
        except Exception as e:
            self.log(f"Markdown 保存失败: {e}", "error")

    def _should_stop(self) -> bool:
        if self._stop_requested:
            return True
        if self.max_duration > 0:
            elapsed = time.time() - self._start_time
            if elapsed >= self.max_duration:
                return True
        if self.max_valid_keys > 0 and self._valid_count >= self.max_valid_keys:
            return True
        return False

    def _stop_reason(self) -> str:
        if self._stop_requested:
            return "手动停止"
        if self.max_duration > 0 and time.time() - self._start_time >= self.max_duration:
            return f"达到时间限制 ({self.max_duration}s)"
        if self.max_valid_keys > 0 and self._valid_count >= self.max_valid_keys:
            return f"达到有效 Key 数量目标 ({self.max_valid_keys})"
        return ""

    def _auto_save(self, results: list, force: bool = False):
        n = len(results)
        if not force and n - self._saved_count < self.auto_save_interval:
            return
        self._saved_count = n
        os.makedirs(self.output_dir, exist_ok=True)
        # Save sorted results as JSON
        sorted_r = self.sort_results(results)
        path = os.path.join(self.output_dir, "api_keys_autosave.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(sorted_r, f, ensure_ascii=False, indent=2)
            self.log(f"实时保存: {n} 条结果 → {path}", "info")
        except Exception as e:
            pass  # silent fail for autosave

    # ---- GitHub Search ----

    def _gh_search(self, query: str, per_page: int = 100, page: int = 1) -> list:
        """GitHub Code Search via direct HTTP API (no gh CLI dependency).
        Uses token from env var or gh CLI for authenticated access (30 req/min).
        Tracks X-RateLimit-Remaining to avoid hitting the rate limit."""
        encoded = urllib.parse.quote(query, safe=":+")
        url = f"https://api.github.com/search/code?q={encoded}&per_page={per_page}&page={page}"
        token = self.get_gh_token()
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "DeepSeekKeyHunter/5.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        max_retries = 3
        for attempt in range(max_retries):
            try:
                r = requests.get(url, headers=headers, timeout=20)
                remaining = r.headers.get("X-RateLimit-Remaining")
                if remaining:
                    remaining = int(remaining)
                    if remaining < 5:
                        reset_ts = int(r.headers.get("X-RateLimit-Reset", 0))
                        wait = max(5, reset_ts - int(time.time()) + 1) if reset_ts else 30
                        self.log(f"GitHub 限流预警: 剩余 {remaining} 次, 等待 {wait}s", "warning")
                        time.sleep(wait)

                if r.status_code == 200:
                    data = r.json()
                    return data.get("items", [])
                elif r.status_code == 429 or r.status_code == 403:
                    # Use Retry-After header if available, else exponential backoff
                    retry_after = r.headers.get("Retry-After")
                    wait = int(retry_after) if retry_after else (10 + (2 ** attempt) * 15)
                    self.log(f"GitHub API 限流 (HTTP {r.status_code}), 等待 {wait}s (attempt {attempt+1})...", "warning")
                    time.sleep(wait)
                    continue
                elif r.status_code == 422:
                    return []
                else:
                    self.log(f"GitHub API HTTP {r.status_code} (attempt {attempt+1})", "warning")
                    if attempt < max_retries - 1:
                        time.sleep(5 + attempt * 5)
                        continue
                    return []
            except (requests.RequestException, requests.Timeout) as e:
                self.log(f"GitHub API 网络错误: {e} (attempt {attempt+1})", "warning")
                if attempt < max_retries - 1:
                    time.sleep(3 + attempt * 3)
                else:
                    return []
        return []

    def _fetch_raw(self, repo: str, path: str, branch: str = "main") -> str:
        for br in [branch, "main", "master"]:
            url = f"https://raw.githubusercontent.com/{repo}/{br}/{path}"
            try:
                resp = requests.get(url, timeout=self.timeout,
                                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    return resp.text
            except Exception:
                pass
        return ""

    def scan_github(self, queries: list) -> dict:
        all_keys = {}
        seen = set()
        stopped_early = False

        for i, query in enumerate(queries):
            if self._should_stop():
                stopped_early = True
                break

            self.log(f"[{i+1}/{len(queries)}] {query}")
            self.progress_callback(i + 1, len(queries), "search")

            items = self._gh_search(query)
            self.log(f"  结果: {len(items)} 个文件")

            for j, item in enumerate(items):
                # 检查遍历中是否超时（每 5 个文件或时间到就跳出）
                if j % 5 == 0 and self._should_stop():
                    stopped_early = True
                    break

                repo = item.get("repository", {}).get("full_name", "")
                path = item.get("path", "")
                html_url = item.get("html_url", "")
                if not repo or not path:
                    continue
                if any(fnmatch.fnmatch(repo, p) for p in self.exclude_repos):
                    continue

                cache = f"{repo}/{path}"
                if cache in seen:
                    continue
                seen.add(cache)

                branch = "main"
                if "/blob/" in html_url:
                    branch = html_url.split("/blob/")[1].split("/")[0]

                text = self._fetch_raw(repo, path, branch)
                if not text:
                    continue

                keys = self.key_pattern.findall(text)
                keys = [k for k in keys if not is_bad_key(k, self.extra_bad_patterns)]

                for k in keys:
                    if k not in all_keys:
                        all_keys[k] = {"key": k, "key_preview": k[:10] + "..." + k[-4:], "repos": []}
                    if repo not in [r["repo"] for r in all_keys[k]["repos"]]:
                        all_keys[k]["repos"].append({"repo": repo, "file": path, "url": html_url})
                        self.log(f"  [KEY] {k[:10]}...{k[-4:]} | {repo}/{path}")

            # 当前查询处理完后检查是否应停止（不等下一个查询才开始检查）
            if stopped_early or self._should_stop():
                stopped_early = True
                break

            time.sleep(self.search_delay)

        if stopped_early:
            elapsed = time.time() - self._start_time
            self.log(f"扫描提前终止: {self._stop_reason()} ({elapsed:.0f}s), 已收集 {len(all_keys)} 个 Key", "warning")
        return all_keys

    # ---- Async Verification (Multi-Provider) ----

    def _get_active_providers(self) -> list:
        """Return list of provider configs matching self.providers."""
        active = []
        for pc in PROVIDER_CONFIGS:
            if pc["name"] in self.providers:
                active.append(pc)
        return active or [PROVIDER_CONFIGS[0]]  # fallback: default to first provider

    async def _try_provider_endpoint(self, session: aiohttp.ClientSession,
                                     api_key: str, provider: dict) -> dict:
        """Try a single provider's balance endpoint. Returns verification result."""
        name = provider["name"]
        url = f"{provider['base']}{provider['balance_url']}"
        headers = {"Authorization": f"Bearer {api_key}"}

        try:
            async with session.get(url, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result = self._parse_provider_response(name, data)
                    # For OpenAI: try credit_grants to get actual balance
                    if name == "openai" and provider.get("credit_url"):
                        balance = await self._try_openai_credits(session, api_key, provider)
                        if balance is not None:
                            result.update(balance)
                    return result
                elif resp.status == 401:
                    return {"valid": False, "reason": f"{name}:invalid_key"}
                elif resp.status == 429:
                    await asyncio.sleep(1.5)
                    return {"valid": False, "reason": f"{name}:rate_limited"}
                else:
                    return {"valid": False, "reason": f"{name}:HTTP_{resp.status}"}
        except asyncio.TimeoutError:
            return {"valid": False, "reason": f"{name}:timeout"}
        except Exception as e:
            return {"valid": False, "reason": f"{name}:{str(e)[:60]}"}

    async def _try_openai_credits(self, session: aiohttp.ClientSession,
                                   api_key: str, provider: dict):
        """Try OpenAI credit_grants endpoint to get actual balance.
        Returns balance dict or None if endpoint is unavailable."""
        url = f"{provider['base']}{provider['credit_url']}"
        headers = {"Authorization": f"Bearer {api_key}"}
        try:
            async with session.get(url, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    parsed = _parse_openai_credits(data)
                    return {"total_balance": parsed["total_balance"],
                            "primary_currency": parsed["primary_currency"],
                            "openai_grants": parsed.get("openai_grants"),
                            "balance_unavailable": False,
                            "provider_note": ""}
        except Exception:
            pass
        return None

    def _parse_provider_response(self, provider_name: str, data: dict) -> dict:
        """Parse balance response based on provider name."""
        if provider_name == "deepseek":
            result = _parse_deepseek_balance(data)
        elif provider_name == "openai":
            result = _parse_openai_models(data)
            result["provider_note"] = "Valid key (balance requires billing scope)"
        elif provider_name == "openrouter":
            result = _parse_openrouter_balance(data)
        else:
            result = {"valid": False, "reason": "unknown_provider"}
        result["provider"] = provider_name
        return result

    async def _verify_one(self, session: aiohttp.ClientSession, api_key: str,
                          semaphore: asyncio.Semaphore) -> dict:
        """Verify one API key against all configured providers.
        Returns result for the first matching provider (valid) or
        the last attempted provider (invalid).
        """
        async with semaphore:
            active = self._get_active_providers()
            last_result = None
            for provider in active:
                result = await self._try_provider_endpoint(session, api_key, provider)
                if result.get("valid"):
                    return result
                last_result = result
            # All providers failed — return last result
            if last_result:
                return last_result
            return {"valid": False, "reason": "no_provider_match"}

    async def _verify_all_async(self, all_keys: dict) -> list:
        semaphore = asyncio.Semaphore(self.concurrency)
        keys_list = list(all_keys.items())
        total = len(keys_list)
        done = [0]
        results = []
        valid_count = [0]
        batch_stop = [False]  # flag to signal batch completion

        async with aiohttp.ClientSession() as session:
            async def wrapped(key, info):
                nonlocal done
                v = await self._verify_one(session, key, semaphore)
                done[0] += 1

                if v.get("valid"):
                    valid_count[0] += 1
                    self._valid_count = valid_count[0]
                    primary_cur = v.get("primary_currency", "USD")
                    usd_eq = convert_to_usd(v["total_balance"], primary_cur, self.usd_cny_rate)
                    cny_eq = convert_to_cny(v["total_balance"], primary_cur, self.usd_cny_rate)
                    provider_name = v.get("provider", "").upper() if v.get("provider") else ""
                    self.log(f"  [{done[0]}/{total}] {key[:10]}...{key[-4:]} -> "
                             f"[{provider_name}] {primary_cur} {v['total_balance']:.4f} (≈${usd_eq:.2f} / ¥{cny_eq:.2f})")
                else:
                    self.log(f"  [{done[0]}/{total}] {key[:10]}...{key[-4:]} -> {v.get('reason', '?')}")

                self.progress_callback(done[0], total, "verify")

                entry = {
                    "key": key,
                    "key_preview": info["key_preview"],
                    "valid": v.get("valid", False),
                    "balance": v.get("total_balance", 0),
                    "balance_details": v.get("balance_details", []),
                    "primary_currency": v.get("primary_currency", "USD"),
                    "balance_usd": convert_to_usd(v.get("total_balance", 0),
                                                   v.get("primary_currency", "USD"), self.usd_cny_rate),
                    "balance_cny": convert_to_cny(v.get("total_balance", 0),
                                                   v.get("primary_currency", "USD"), self.usd_cny_rate),
                    "reason": v.get("reason", ""),
                    "provider": v.get("provider", "unknown"),
                    "provider_note": v.get("provider_note", ""),
                    "balance_unavailable": v.get("balance_unavailable", False),
                    "repos": info["repos"],
                    "verified_at": datetime.now().isoformat(),
                }
                results.append(entry)

                # Batch stop: count ALL valid keys (original high-throughput logic)
                if self.max_valid_keys > 0 and valid_count[0] >= self.max_valid_keys and not batch_stop[0]:
                    batch_stop[0] = True

                return entry

            # 分批处理：首批不检查超时（确保至少验证一批）
            batch_size = self.concurrency
            first_batch = True
            for start in range(0, len(keys_list), batch_size):
                if not first_batch and (self._should_stop() or batch_stop[0]):
                    unprocessed = len(keys_list) - start
                    self.log(f"验证已停止: {self._stop_reason()}，跳过剩余 {unprocessed} 个 Key")
                    break
                first_batch = False
                batch = keys_list[start:start + batch_size]
                tasks = [wrapped(k, v) for k, v in batch]
                await asyncio.gather(*tasks)

        return results

    def verify_keys(self, all_keys: dict) -> list:
        self.log(f"开始验证 {len(all_keys)} 个 Key (并发 {self.concurrency})...")
        self.progress_callback(0, len(all_keys), "verify")
        t0 = time.time()
        results = asyncio.run(self._verify_all_async(all_keys))
        self.log(f"验证完成: {time.time()-t0:.1f}s")
        return results

    # ---- 结果处理 ----

    def sort_results(self, results: list) -> list:
        results.sort(key=lambda x: x.get("balance_usd", 0), reverse=True)
        return results

    def _safe_write(self, path: str, write_func, retries: int = 5) -> bool:
        """安全写文件，处理文件被锁的情况"""
        for attempt in range(retries):
            try:
                write_func(path)
                return True
            except PermissionError:
                if attempt < retries - 1:
                    # 带时间戳的备用文件名
                    base, ext = os.path.splitext(path)
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    path = f"{base}_{ts}{ext}"
                else:
                    self.log(f"保存失败(文件被锁定): {path}", "warning")
                    return False
            except Exception as e:
                self.log(f"保存失败: {e}", "error")
                return False
        return False

    def save_results(self, results: list, fmt: str = "all") -> list:
        os.makedirs(self.output_dir, exist_ok=True)
        results = self.sort_results(results)

        if fmt in ("all", "json"):
            path = os.path.join(self.output_dir, "api_keys_result.json")

            def _write(p):
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(results, f, ensure_ascii=False, indent=2)

            if self._safe_write(path, _write):
                self.log(f"JSON: {path}")

        if fmt in ("all", "csv"):
            path = os.path.join(self.output_dir, "api_keys_result.csv")

            def _write(p):
                with open(p, "w", encoding="utf-8") as f:
                    f.write("Key预览,完整Key,提供商,有效,原始余额,币种,USD等值,CNY等值,仓库名,文件名,文件路径,仓库链接,验证时间\n")
                    for r in results:
                        repos_str = "; ".join([x["repo"] for x in r["repos"][:3]])
                        cur = r.get("primary_currency", "N/A")
                        provider = r.get("provider", "?")
                        f.write(f'{r["key_preview"]},{r["key"]},{provider},{r["valid"]},'
                                f'{r["balance"]:.4f},{cur},{r["balance_usd"]:.2f},{r["balance_cny"]:.2f},'
                                f'"{repos_str}",{r["verified_at"]}\n')

            if self._safe_write(path, _write):
                self.log(f"CSV: {path}")

        if fmt in ("all", "markdown"):
            path = os.path.join(self.output_dir, "api_keys_result.md")

            def _write(p):
                with open(p, "w", encoding="utf-8") as f:
                    f.write("# API Key Hunter - Scan Results\n\n")
                    f.write(f"**Scan Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"**Exchange Rate:** 1 USD = {self.usd_cny_rate} CNY\n\n")
                    valid = [r for r in results if r["valid"]]
                    f.write("## Summary\n\n")
                    f.write(f"| Metric | Value |\n|---|---|\n")
                    f.write(f"| Total Keys | {len(results)} |\n")
                    f.write(f"| Valid Keys | {len(valid)} |\n")
                    if valid:
                        total_usd = sum(r["balance_usd"] for r in valid)
                        total_cny = sum(r["balance_cny"] for r in valid)
                        f.write(f"| Total Balance | ${total_usd:.2f} / ¥{total_cny:.2f} |\n")
                    f.write(f"\n## Keys by Provider & USD Value\n\n")
                    f.write(f"| # | Key | Provider | Balance (Original) | USD Equivalent | CNY Equivalent | Source |\n")
                    f.write(f"|---|---|---|---|---|---|---|\n")
                    for i, r in enumerate(valid):
                        src = r["repos"][0]["repo"] if r.get("repos") else "N/A"
                        cur = r.get("primary_currency", "USD")
                        prov = r.get("provider", "?").upper()
                        f.write(f"| {i+1} | `{r['key_preview']}` | {prov} | "
                                f"{cur} {r['balance']:.4f} | ${r['balance_usd']:.2f} | "
                                f"¥{r['balance_cny']:.2f} | {src} |\n")

            if self._safe_write(path, _write):
                self.log(f"Markdown: {path}")

        return results

    # ---- 进度管理 ----

    def save_progress(self, all_keys: dict, path: str = None):
        path = path or os.path.join(self.output_dir, ".akh_progress.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(all_keys, f, ensure_ascii=False, indent=2)

    def load_progress(self, path: str = None) -> dict:
        path = path or os.path.join(self.output_dir, ".akh_progress.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    @staticmethod
    def load_keys_from_file(path: str) -> dict:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, list):
            keys = {}
            for item in raw:
                key = item.get("key", "")
                if key:
                    keys[key] = {
                        "key": key,
                        "key_preview": item.get("key_preview", key[:10] + "..." + key[-4:]),
                        "repos": item.get("repos", []),
                    }
            return keys
        return raw

    @staticmethod
    def load_queries_file(path: str) -> list:
        queries = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    queries.append(line)
        return queries
