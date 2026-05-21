#!/usr/bin/env python3
"""
DeepSeek Key Hunter - CLI 命令行版本 (基于 ScannerEngine)
公开仓库中暴露的 DeepSeek API Key 扫描与验证工具

用法示例:
  python deepseek_key_scanner.py                    # 默认全流程
  python deepseek_key_scanner.py --dry-run          # 只搜索不验证
  python deepseek_key_scanner.py --resume           # 断点续跑
  python deepseek_key_scanner.py -c 50              # 并发 50
  python deepseek_key_scanner.py --verify-only results/deepseek_keys_result.json
  python deepseek_key_scanner.py --verify-only results/.dkh_progress.json
"""

import argparse
import os
import sys
import time
import json
from datetime import datetime

from scanner_engine import (
    ScannerEngine, BUILTIN_QUERIES, DEFAULT_USD_CNY_RATE
)

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def build_parser():
    p = argparse.ArgumentParser(
        prog="deepseek-key-hunter",
        description="DeepSeek Key Hunter - 公开仓库暴露 API Key 扫描工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s                                         默认全流程
  %(prog)s --dry-run                               仅搜索，不验证
  %(prog)s --resume                                断点续跑
  %(prog)s -c 50                                   提高并发
  %(prog)s --verify-only results/result.json       仅验证已有结果
  %(prog)s --verify-only results/.dkh_progress.json
  %(prog)s --queries-file queries_v4.txt           使用自定义查询文件
  %(prog)s --min-balance 0.01                      过滤余额 >= $0.01 的 Key
  %(prog)s --cmd-gen                               打开命令生成器网页
        """,
    )

    g = p.add_argument_group("通用")
    g.add_argument("-c", "--concurrency", type=int, default=20, help="并发数 (默认: 20)")
    g.add_argument("--timeout", type=int, default=15, help="HTTP 超时秒数 (默认: 15)")
    g.add_argument("--output-dir", type=str, default="./results", help="输出目录")
    g.add_argument("-q", "--quiet", action="store_true", help="安静模式")

    g_search = p.add_argument_group("搜索")
    g_search.add_argument("--search-delay", type=float, default=2.5, help="请求间隔秒数 (默认: 2.5)")
    g_search.add_argument("--scan-pages", type=int, default=10, help="每个查询翻页数 1-10 (默认: 10, 每页100条)")
    g_search.add_argument("--queries-file", type=str, default=None, help="自定义查询文件")
    g_search.add_argument("--skip-builtin", action="store_true", help="跳过内置查询")

    g_multi = p.add_argument_group("多源扫描 (新)")
    g_multi.add_argument("--sources", type=str, default="github",
                         help="扫描来源, 逗号分隔. 可选: github, gist, issues, gitlab, wayback, docker, commoncrawl, gitee, npm, all (默认: github)")
    g_multi.add_argument("--monitor", action="store_true", help="实时监控模式 (GitHub Events API)")
    g_multi.add_argument("--github-token", type=str, default="", help="GitHub Personal Access Token")
    g_multi.add_argument("--gitlab-token", type=str, default="", help="GitLab Personal Access Token")
    g_multi.add_argument("--gitee-token", type=str, default="", help="Gitee Access Token")

    g_filter = p.add_argument_group("过滤")
    g_filter.add_argument("--min-key-length", type=int, default=32, help="最短 Key 长度")
    g_filter.add_argument("--max-key-length", type=int, default=64, help="最长 Key 长度")
    g_filter.add_argument("--min-balance", type=float, default=None, help="只输出 USD 余额 >= 该值的 Key")
    g_filter.add_argument("--exclude-repo", type=str, action="append", default=[], help="排除仓库")
    g_filter.add_argument("--usd-cny-rate", type=float, default=DEFAULT_USD_CNY_RATE,
                          help=f"USD/CNY 汇率 (默认: {DEFAULT_USD_CNY_RATE})")

    g_verify = p.add_argument_group("验证")
    g_verify.add_argument("--dry-run", action="store_true", help="仅搜索不验证")
    g_verify.add_argument("--verify-only", type=str, default=None, help="仅验证 JSON/Progress 文件")

    g_stop = p.add_argument_group("退出机制 (自动停止)")
    g_stop.add_argument("--max-duration", type=int, default=0,
                       help="最大运行时长(秒), 超时自动保存退出 (默认: 0=不限)")
    g_stop.add_argument("--max-valid-keys", type=int, default=0,
                       help="收集到此数量的有效Key后自动保存退出 (默认: 0=不限)")
    g_stop.add_argument("--auto-save-interval", type=int, default=20,
                       help="每验证N个Key自动保存结果 (默认: 20)")

    g_output = p.add_argument_group("输出")
    g_output.add_argument("--format", choices=["all", "json", "csv", "markdown"], default="all", help="输出格式")

    g_resume = p.add_argument_group("进度")
    g_resume.add_argument("--resume", action="store_true", help="从进度文件恢复")

    g_gui = p.add_argument_group("界面")
    g_gui.add_argument("--cmd-gen", action="store_true", help="打开命令生成器网页 (cmd_generator.html)")

    return p


def log_func(msg, level="info"):
    if level == "warning":
        print(f"[!] {msg}")
    elif level == "error":
        print(f"[ERROR] {msg}")
    elif msg.startswith("[KEY]"):
        sign = "+" if level == "valid" else ("-" if level == "invalid" else " ")
        print(f"  {sign} {msg}")
    else:
        print(msg)


def main():
    parser = build_parser()
    args = parser.parse_args()

    # 命令生成器
    if args.cmd_gen:
        import webbrowser
        gen_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cmd_generator.html")
        if os.path.exists(gen_path):
            webbrowser.open(f"file://{gen_path}")
            print(f"已打开命令生成器: {gen_path}")
        else:
            print("[ERROR] 未找到 cmd_generator.html")
        return

    # 获取查询
    queries = []
    if not args.skip_builtin:
        queries.extend(BUILTIN_QUERIES)
    if args.queries_file and os.path.exists(args.queries_file):
        queries.extend(ScannerEngine.load_queries_file(args.queries_file))
    if not queries:
        queries = BUILTIN_QUERIES

    # 自动调整搜索延迟
    if not args.search_delay or args.search_delay == 2.5:
        suggested = ScannerEngine.suggested_search_delay()
        authed = ScannerEngine.check_gh_auth()
        args.search_delay = suggested

    rate_limit = "30次/分钟 (已认证)" if ScannerEngine.check_gh_auth() else "10次/分钟 (未认证)"

    print(f"DeepSeek Key Hunter - CLI")
    print(f"Queries: {len(queries)} | Concurrency: {args.concurrency} | Rate: {args.usd_cny_rate}")
    print(f"API限额: {rate_limit} | 搜索间隔: {args.search_delay}s")
    print(f"Output: {args.output_dir}")
    print()

    # 创建引擎
    engine = ScannerEngine(
        concurrency=args.concurrency,
        timeout=args.timeout,
        search_delay=args.search_delay,
        min_key_length=args.min_key_length,
        max_key_length=args.max_key_length,
        output_dir=args.output_dir,
        usd_cny_rate=args.usd_cny_rate,
        exclude_repos=args.exclude_repo,
        max_duration=args.max_duration,
        max_valid_keys=args.max_valid_keys,
        auto_save_interval=args.auto_save_interval,
        scan_pages=args.scan_pages,
        log_callback=log_func if not args.quiet else (lambda m, l: None),
    )

    # 仅验证模式
    if args.verify_only:
        all_keys = ScannerEngine.load_keys_from_file(args.verify_only)
        print(f"Loaded {len(all_keys)} keys from {args.verify_only}")
        results = engine.verify_keys(all_keys)
        results = engine.sort_results(results)
        engine.save_results(results, fmt=args.format)
        _print_summary(results, engine.usd_cny_rate)
        return

    # 多源扫描模式
    sources_str = args.sources.lower().strip()
    if sources_str != "github" or args.monitor:
        t0 = time.time()
        if sources_str == "all":
            sources = [s for s in ["github", "gist", "issues", "gitlab", "wayback",
                                   "docker", "commoncrawl", "gitee", "npm"]]
        elif sources_str == "events":
            print("--- Events Monitor (实时监控 GitHub PushEvent) ---")
            from scanners.github_events import EventsMonitor
            import asyncio

            def on_key(k, repo, fpath, url):
                print(f"  [KEY] {k[:10]}...{k[-4:]} | {repo}/{fpath}")

            async def monitor():
                m = EventsMonitor(
                    token=args.github_token,
                    poll_interval=60,
                    concurrency=args.concurrency,
                    timeout=args.timeout,
                )
                m.on_key_found = on_key
                results = await m.search()
                if results:
                    engine._save_final([{
                        "key": r["key"],
                        "key_preview": r.get("key_preview", r["key"][:10] + "..." + r["key"][-4:]),
                        "valid": False,
                        "balance": 0,
                        "balance_usd": 0,
                        "balance_cny": 0,
                        "primary_currency": "N/A",
                        "repos": [{"repo": r.get("repo", ""), "file": r.get("file", ""),
                                   "url": r.get("url", "")}],
                        "verified_at": "",
                    } for r in results])

            asyncio.run(monitor())
            return

        elif args.monitor:
            print("--- 实时监控模式 (GitHub Events API) ---")
            from scanners.github_events import EventsMonitor
            import asyncio

            def on_key(k, repo, fpath, url):
                print(f"  [KEY] {k[:10]}...{k[-4:]} | {repo}/{fpath}")
                # Also verify immediately
                all_keys = {k: {"key": k, "key_preview": k[:10] + "..." + k[-4:],
                                "repos": [{"repo": repo, "file": fpath, "url": url}]}}
                results = engine._verify_dict(all_keys)
                engine._save_incremental([r for r in results if r.get("valid")], 0, 1)

            async def monitor():
                m = EventsMonitor(
                    token=args.github_token,
                    poll_interval=60,
                    concurrency=args.concurrency,
                    timeout=args.timeout,
                    max_events_per_poll=30,
                )
                m.on_key_found = on_key
                await m.search()

            asyncio.run(monitor())
            return
        else:
            sources = [s.strip() for s in sources_str.split(",") if s.strip()]

        print(f"--- 多源扫描模式: {sources} ---")
        print(f"Sources: {len(sources)} | Concurrency: {args.concurrency} | Rate: {args.usd_cny_rate}")
        print(f"Output: {args.output_dir}")
        print()

        results = engine.run_multi_source(
            sources,
            queries=queries if not args.skip_builtin else [],
            github_token=args.github_token,
            gitlab_token=args.gitlab_token,
            gitee_token=args.gitee_token,
        )

        if args.min_balance is not None and args.min_balance > 0:
            before = len(results)
            results = [r for r in results if r["balance_usd"] >= args.min_balance]
            print(f"余额过滤: {before} -> {len(results)} (min ${args.min_balance})")

        engine._save_final(results)
        _print_summary(results, engine.usd_cny_rate)
        print(f"\n总耗时: {time.time()-t0:.1f}s")
        return

    # Dry run 模式
    if args.dry_run:
        print(f"--- Dry Run (仅搜索不验证) ---")
        all_keys = engine.scan_github(queries)
        print(f"\n发现 {len(all_keys)} 个疑似 Key (未验证)")
        if all_keys:
            engine.save_progress(all_keys)
        return

    # 主流水线: 逐条查询 → 搜索 → 验证 → 保存 → 检查退出
    t0 = time.time()
    print(f"--- Pipeline: 边扫边验边存 (Ctrl+C 安全退出) ---")
    try:
        results = engine.run(queries)
    except KeyboardInterrupt:
        print(f"\n[!] 已中断, 结果已自动保存到 {args.output_dir}")
        return

    # 最低余额过滤
    if args.min_balance is not None and args.min_balance > 0:
        before = len(results)
        results = [r for r in results if r["balance_usd"] >= args.min_balance]
        print(f"余额过滤: {before} -> {len(results)} (min ${args.min_balance})")

    # 写入最终 CSV
    engine._save_final(results)
    _print_summary(results, engine.usd_cny_rate)
    print(f"\n总耗时: {time.time()-t0:.1f}s")


def _print_summary(results, rate):
    valid = [r for r in results if r.get("valid")]
    invalid = [r for r in results if r.get("valid") is False]
    positive = [r for r in valid if r["balance_usd"] > 0]
    zero = [r for r in valid if r["balance_usd"] == 0]
    negative = [r for r in valid if r["balance_usd"] < 0]

    print(f"\n{'='*60}")
    print(f"  扫描总结")
    print(f"{'='*60}")
    print(f"  总共扫描 Key 数: {len(results)}")
    print(f"  有效 Key:       {len(valid)}")
    print(f"  无效 Key:       {len(invalid)}")
    print(f"  正余额 (>$0):   {len(positive)}")
    print(f"  零余额 (= $0):  {len(zero)}")
    print(f"  欠费 (< $0):    {len(negative)} (不计入总价值)")

    if positive:
        usd_pos = sum(r["balance_usd"] for r in positive)
        cny_pos = sum(r["balance_cny"] for r in positive)
        print(f"\n  正余额总价值: ${usd_pos:.2f} USD / ¥{cny_pos:.2f} CNY")
        print(f"  汇率: 1 USD = {rate} CNY")
        print(f"\n  正余额 Key 排行榜:")
        for i, r in enumerate(positive[:30]):
            cur = r.get("primary_currency", "USD")
            src = r["repos"][0]["repo"] if r.get("repos") else "N/A"
            print(f"  {i+1:2d}. {r['key_preview']} | {cur} {r['balance']:.4f} "
                  f"| ≈${r['balance_usd']:.2f} / ¥{r['balance_cny']:.2f} | {src}")
    else:
        print(f"\n  无正余额 Key (所有有效 Key 余额 ≤ $0)")

    if zero:
        print(f"\n  零余额 Key ({len(zero)} 个) — 可能曾被使用或即将充值")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
