#!/usr/bin/env python3
"""
VulnHunter CLI — Scanner autonome (sans FastAPI)

Usage:
    python -m app.cli --url http://target.com [options]

Examples:
    python -m app.cli --url http://localhost:8080
    python -m app.cli --url http://localhost:8080 --modules sqli xss --depth 3
    python -m app.cli --url http://localhost:8080 --output report.pdf
    python -m app.cli --url http://localhost:8080 --output report.md --verbose
"""

import asyncio
import argparse
import sys
import uuid
from datetime import datetime, timezone

from app.models.scan import ScanRequest, ScanResult, VulnType, Severity
from app.scanner.engine import run_scan, _scan_store
from app.reporter.report import generate_markdown, generate_pdf

# ANSI colors
R  = "\033[91m"
O  = "\033[33m"
Y  = "\033[93m"
G  = "\033[92m"
B  = "\033[94m"
C  = "\033[96m"
W  = "\033[97m"
DIM = "\033[2m"
RST = "\033[0m"
BOLD = "\033[1m"

MODULE_MAP = {
    "sqli":          VulnType.SQL_INJECTION,
    "xss":           VulnType.XSS,
    "csrf":          VulnType.CSRF,
    "ssrf":          VulnType.SSRF,
    "traversal":     VulnType.PATH_TRAVERSAL,
}

SEV_COLORS = {
    Severity.CRITICAL: R,
    Severity.HIGH:     O,
    Severity.MEDIUM:   Y,
    Severity.LOW:      B,
    Severity.INFO:     DIM,
}


def banner():
    print(f"""
{C}╔══════════════════════════════════════════════════════╗
║  {BOLD}⚔  VulnHunter{RST}{C}  —  Automated Web Vulnerability Scanner  ║
║  {DIM}OWASP Top 10  |  Python 3.11  |  Async Engine{RST}{C}          ║
╚══════════════════════════════════════════════════════╝{RST}
""")


def print_vuln(v, i: int):
    color = SEV_COLORS.get(v.severity, DIM)
    sev   = v.severity.value.upper().ljust(8)
    print(f"  {color}[{i:02d}] {sev}{RST}  {BOLD}{v.vuln_type.value}{RST}")
    print(f"       {DIM}URL      :{RST} {v.url}")
    if v.parameter:
        print(f"       {DIM}Param    :{RST} {v.parameter}")
    if v.payload:
        print(f"       {DIM}Payload  :{RST} {v.payload[:60]}")
    if v.evidence:
        print(f"       {DIM}Evidence :{RST} {v.evidence[:80]}")
    print(f"       {DIM}CVSS     :{RST} {color}{v.cvss_score}{RST}  {DIM}{v.cvss_vector}{RST}")
    print()


def print_summary(result: ScanResult):
    counts = result.severity_counts
    total  = len(result.vulnerabilities)
    dur    = result.duration_seconds

    print(f"\n{BOLD}{'─'*54}{RST}")
    print(f"{BOLD}  Scan Summary{RST}")
    print(f"{'─'*54}")
    print(f"  Target     : {C}{result.target_url}{RST}")
    print(f"  Status     : {G if result.status.value == 'completed' else R}{result.status.value.upper()}{RST}")
    print(f"  Duration   : {dur:.1f}s" if dur else "  Duration   : —")
    print(f"  Pages      : {result.pages_crawled}")
    print(f"  Requests   : {result.requests_sent}")
    print(f"  Vulns      : {BOLD}{total}{RST}")

    if total:
        print()
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            c = counts.get(sev.value, 0)
            if c:
                bar = "█" * c
                print(f"  {SEV_COLORS[sev]}{sev.value.capitalize().ljust(10)} {bar} {c}{RST}")
    print(f"{'─'*54}\n")


async def cli_scan(args):
    banner()

    # Resolve scan types
    if args.modules:
        scan_types = []
        for m in args.modules:
            if m not in MODULE_MAP:
                print(f"{R}Unknown module: {m}. Valid: {', '.join(MODULE_MAP)}{RST}")
                sys.exit(1)
            scan_types.append(MODULE_MAP[m])
    else:
        scan_types = list(VulnType)

    print(f"  {DIM}Target   :{RST} {C}{args.url}{RST}")
    print(f"  {DIM}Modules  :{RST} {', '.join(t.value for t in scan_types)}")
    print(f"  {DIM}Depth    :{RST} {args.depth}")
    print(f"  {DIM}Timeout  :{RST} {args.timeout}s")
    print()
    print(f"  {G}▶ Starting scan...{RST}")

    scan_id = str(uuid.uuid4())
    request = ScanRequest(
        target_url=args.url,
        scan_types=scan_types,
        depth=args.depth,
        timeout=args.timeout,
    )

    from app.models.scan import ScanStatus
    result = ScanResult(
        scan_id=scan_id,
        target_url=args.url,
        status=ScanStatus.PENDING,
    )
    _scan_store[scan_id] = result

    # Run with live spinner
    spinner_task = asyncio.create_task(_spinner(result))
    await run_scan(scan_id, request)
    spinner_task.cancel()

    print(f"\r  {G}✓ Scan complete{RST}          ")

    # Print findings if verbose
    if args.verbose and result.vulnerabilities:
        print(f"\n{BOLD}  Vulnerabilities Found{RST}")
        print(f"{'─'*54}")
        sorted_vulns = sorted(
            result.vulnerabilities,
            key=lambda v: [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO].index(v.severity)
        )
        for i, v in enumerate(sorted_vulns, 1):
            print_vuln(v, i)

    print_summary(result)

    # Generate report
    if args.output:
        ext = args.output.rsplit(".", 1)[-1].lower()
        if ext == "pdf":
            data = generate_pdf(result)
            with open(args.output, "wb") as f:
                f.write(data)
            print(f"  {G}📋 PDF report saved :{RST} {args.output}")
        else:
            md = generate_markdown(result)
            with open(args.output, "w") as f:
                f.write(md)
            print(f"  {G}📄 Markdown report  :{RST} {args.output}")
        print()

    # Exit code based on findings
    counts = result.severity_counts
    if counts.get("critical", 0) > 0:
        sys.exit(2)
    elif counts.get("high", 0) > 0:
        sys.exit(1)
    sys.exit(0)


async def _spinner(result: ScanResult):
    """Live progress spinner."""
    from app.models.scan import ScanStatus
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    i = 0
    while True:
        status = result.status
        pages  = result.pages_crawled
        vulns  = len(result.vulnerabilities)
        frame  = frames[i % len(frames)]
        print(
            f"\r  {C}{frame}{RST}  {DIM}pages: {pages}  vulns: {vulns}  status: {status.value}{RST}   ",
            end="", flush=True
        )
        if status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            break
        i += 1
        await asyncio.sleep(0.15)


def main():
    parser = argparse.ArgumentParser(
        prog="vulnhunter",
        description="VulnHunter — Automated Web Vulnerability Scanner",
    )
    parser.add_argument("--url", "-u", required=True, help="Target URL (e.g. https://target.com)")
    parser.add_argument(
        "--modules", "-m", nargs="+",
        choices=list(MODULE_MAP.keys()),
        help="Scan modules to run (default: all)",
    )
    parser.add_argument("--depth",   "-d", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--timeout", "-t", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--output",  "-o", help="Save report to file (.md or .pdf)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print vulnerability details")

    args = parser.parse_args()
    asyncio.run(cli_scan(args))


if __name__ == "__main__":
    main()