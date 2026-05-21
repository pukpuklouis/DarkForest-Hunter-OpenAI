<p align="right"><a href="README.md">English</a></p>

<br>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Scanners-14-green?style=flat-square" alt="Scanners">
  <img src="https://img.shields.io/badge/Queries-238-red?style=flat-square" alt="Queries">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="License">
</p>

<h1 align="center">🌲 DarkForest Hunter</h1>

<p align="center">
  <em>"宇宙就是一座黑暗森林，每个文明都是带枪的猎人。"</em><br>
  <sub>— <strong>刘慈欣</strong>，《三体II：黑暗森林》</sub>
</p>

---

> 一个用 238 条搜索模式扫描 14 个平台的工具，找出公开暴露的 DeepSeek API Key，然后验证有效性并查询余额。做这个工具是因为我们发现公开仓库里泄露的高余额 key 多到让人震惊，而且已经暴露了几个月甚至更久，完全无人知晓。

---

## 🌲 黑暗森林

在 GitHub 这片代码森林中，数以千万计的开发者日复一日地提交代码。每一行 `API_KEY=sk-...` 都是一次**"广播"**——一个暴露了自己坐标的文明。

**我们，是这片森林里的猎人。**

不是为了猎杀，而是为了在别人开枪之前，**告诉他们：你暴露了。**

这和《三体》中的黑暗森林法则惊人地相似——每个泄露的 key 都是一次广播，暴露了自己的位置。只不过，在安全领域，猎人可能是：自动化脚本、加密货币矿工、数据窃贼，或其他恶意行为者。

**我们把这个工具开源，是希望让善意的猎人先到达现场。**

## 🔭 项目背景

DeepSeek 已经成为全球开发者最常用的 AI API 之一。每天，成千上万的开发者将 API Key 硬编码在配置文件、测试脚本、Jupyter Notebook、Docker Compose 甚至 GitHub Actions 中，然后不小心推送到公开仓库。

我们最初做这个工具，是为了研究一个命题：**在公开代码中，到底有多少 DeepSeek key 被意外泄露？** 几次扫描之后，我们发现数字远比想象中惊人——不仅有 key，而且**很多还有高额余额**。这意味着这些 key 在被我们发现之前，已经暴露了几个月甚至更久，完全无人知晓。

## 🎯 它能做什么

全自动扫描 **14 个平台**，使用 **238 条搜索模式**，发现公开暴露的 DeepSeek API Key，然后**验证有效性**并**查询余额**。

### 覆盖的扫描源

| 类别 | 来源 |
|------|------|
| 代码托管 | GitHub Code Search、Gist、Issues、Commits、GitLab、Gitee |
| AI 平台 | HuggingFace（Models / Datasets / Spaces） |
| 包管理器 | PyPI、npm |
| 开发者社区 | Stack Overflow |
| 归档/镜像 | Docker Hub、Wayback Machine、Common Crawl |
| 实时监控 | GitHub Events（PushEvent 流） |

### 主要用途

- **安全研究** — 量化分析 API key 泄露的规模和模式
- **企业安全审计** — 扫描你的组织仓库，确保没有 key 意外泄露
- **漏洞赏金** — 发现泄露 key 后进行负责任披露
- **安全意识教育** — 用真实数据展示硬编码凭据的风险

## 🚀 快速开始

```bash
pip install aiohttp requests

# 可选：认证 GitHub CLI 以提升速率限制
gh auth login

# 全量扫描（10-14小时）
python ultimate_scan.py

# 快速测试（15分钟）
python quick_batch.py
```

### 扫描脚本

| 脚本 | 说明 | 时长 |
|------|------|------|
| `ultimate_scan.py` | 全 5 阶段综合扫描 | 10-14h |
| `expanded_scan.py` | 扩展多源扫描 | 3-5h |
| `max_scan.py` | 最大吞吐量扫描 | 2h |
| `deep_scan.py --hours N` | 深度优化扫描 | 可自定义 |
| `quick_batch.py` | 快速批量测试 | 15min |
| `marathon_scan.py` | 长时循环扫描 | 6h+ |

### 程序化调用

```python
from scanner_engine import ScannerEngine, BUILTIN_QUERIES

engine = ScannerEngine(
    concurrency=20,
    scan_pages=5,
    max_duration=3600,
    output_dir="./results",
)
results = engine.run(BUILTIN_QUERIES)
```

## 📁 项目结构

```
DarkForest-Hunter/
├── scanner_engine.py        # 核心引擎（搜索 + 验证 + 保存）
├── scanners/
│   ├── base.py              # 基础扫描器类
│   ├── github_gist.py       # GitHub Gist 扫描器
│   ├── github_issues.py     # GitHub Issues/PR 扫描器
│   ├── github_commits.py    # 提交历史 + diff 扫描器
│   ├── github_events.py     # 实时 PushEvent 监控
│   ├── gitlab.py            # GitLab 扫描器
│   ├── gitee.py             # Gitee（码云）扫描器
│   ├── huggingface.py       # HuggingFace 扫描器
│   ├── pypi.py              # PyPI 扫描器
│   ├── npm_registry.py      # npm 注册表扫描器
│   ├── stackoverflow.py     # Stack Overflow 扫描器
│   ├── docker.py            # Docker Hub 扫描器
│   ├── commoncrawl.py       # Common Crawl 扫描器
│   └── wayback.py           # Wayback Machine 扫描器
├── ultimate_scan.py         # 终极扫描脚本
├── queries_v4.txt           # 查询库（238条）
├── results/                 # 扫描结果目录
├── README.md                # 英文说明（English）
├── README_CN.md             # 中文说明（本文件）
├── USAGE.md                 # 详细使用指南
└── LICENSE                  # MIT 许可证
```

## ⚠️ 免责声明

本工具仅用于**授权的安全研究、渗透测试和凭据审计**。使用本工具发现的 API Key 不应被用于未经授权的访问。作者不对任何滥用行为承担责任。如果你在扫描中发现了属于你的 key，请立即在 DeepSeek 平台轮换。

## 📄 开源许可

MIT License — 详见 [LICENSE](LICENSE)

---

<p align="center">
  🌲🌲🌲🌲🌲🌲🌲🌲🌲🌲🌲🌲🌲🌲🌲<br>
  <em>"宇宙就是一座黑暗森林，每个文明都是带枪的猎人。"</em><br>
  <sub>—— 刘慈欣，《三体II：黑暗森林》</sub><br>
  <br>
  <sub>愿善意的猎人率先抵达。</sub>
</p>
