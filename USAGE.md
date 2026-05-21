# DeepSeek Key Hunter — Usage Guide

## Setup

### 1. Install Dependencies

```bash
pip install aiohttp requests
```

Python 3.10+ required. No other dependencies.

### 2. Authenticate (Optional but Recommended)

Authenticated GitHub API access gives you 3x more search requests (30/min vs 10/min):

```bash
# Method A: GitHub CLI
gh auth login

# Method B: Environment variable
export GITHUB_TOKEN="ghp_your_token_here"

# Method C: GitLab (optional)
export GITLAB_TOKEN="glpat-your-token"

# Method D: Gitee (optional)
export GITEE_TOKEN="your-gitee-token"
```

### 3. Verify Setup

```bash
python -c "from scanner_engine import ScannerEngine; print('OK')"
```

## Running Scans

### Quick Start

```bash
# Test run (15 minutes)
python quick_batch.py

# Standard scan (2 hours)
python max_scan.py

# Deep scan (custom hours)
python deep_scan.py --hours 3
```

### Comprehensive Coverage

```bash
# Full 5-phase scan (10-14 hours, no time limit)
python ultimate_scan.py

# Expanded multi-source (3-5 hours)
python expanded_scan.py
```

### Using the CLI

```bash
# Single query search
python deepseek_key_scanner.py --query "deepseek sk- filename:py"

# Multi-source scan
python deepseek_key_scanner.py --multi-source github gist issues

# With custom tokens
python deepseek_key_scanner.py --github-token "ghp_xxx" --gitlab-token "glpat-xxx"
```

## Understanding Results

Results are saved in `results/`:
- `deepseek_keys_result.json` — All verified keys with balances
- `deepseek_keys_result.csv` — CSV format
- `deepseek_keys_result.md` — Markdown report

### Balance Fields

| Field | Meaning |
|-------|---------|
| `balance` | Raw balance from API (original currency) |
| `primary_currency` | USD or CNY |
| `balance_usd` | Converted to USD equivalent |
| `balance_cny` | Converted to CNY equivalent |
| `balance_details` | Breakdown: granted vs tipped balance |
| `valid` | `true` = valid API key |

### Result Types

- **Positive balance**: Active key with money — highest priority
- **Zero balance**: Valid key but depleted
- **Negative balance**: Overage/exhausted (欠费)
- **Invalid**: Not a real API key (filtered out)

## Query Patterns

The built-in query library (`queries_v4.txt`) uses GitHub Code Search syntax:

| Pattern | Example |
|---------|---------|
| File extension | `deepseek sk- filename:py` |
| Language | `deepseek sk- language:Python` |
| Path | `deepseek sk- path:config` |
| Time filter | `deepseek sk- pushed:>2026-05-01` |
| Variable name | `DEEPSEEK_API_KEY sk-` |
| API pattern | `api.deepseek.com sk-` |

## Adding Custom Queries

Edit `queries_v4.txt` or pass queries directly:

```python
from scanner_engine import ScannerEngine

custom_queries = [
    "my-org deepseek sk- filename:env",
    "deepseek sk- path:deploy",
]
engine = ScannerEngine(max_duration=1800, scan_pages=3)
results = engine.run(custom_queries)
```

## Selecting Scan Sources

For multi-source mode, specify which scanners to use:

```python
engine = ScannerEngine(concurrency=15)

# Available sources:
# github, gist, issues, commits, gitlab, gitee,
# huggingface, pypi, npm, stackoverflow,
# docker, wayback, commoncrawl

results = engine.run_multi_source([
    "huggingface",
    "pypi",
    "gist",
    "issues",
])
```

## Tips for Better Results

1. **Use time filters**: `pushed:>2026-05-01` finds recent leaks before they're noticed
2. **Target config files**: `.env`, `application.yml`, `credentials` have highest hit rate
3. **Scan commit history**: Deleted keys in git history are often overlooked
4. **Check alternative platforms**: HuggingFace, PyPI, npm — less scanned than GitHub
5. **Run cyclically**: Use `marathon_scan.py` or cron to catch new leaks continuously

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Rate limit" errors | Add GitHub auth token, reduce `concurrency` |
| No results | Check internet connection, verify queries |
| "Module not found" | `pip install aiohttp requests` |
| Encoding errors (Windows) | Set terminal to UTF-8 or use WSL |
| Scan too slow | Authenticate GitHub, reduce `search_delay`, increase `concurrency` |

## Security Notes

- Results contain actual API keys — treat `results/` as sensitive
- Use `.gitignore` to exclude result files from version control
- Never commit `deepseek_keys_result.json` to a public repository
- Rotate any discovered keys if you are the owner
