import asyncio
import httpx
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from collections import deque
import re
import logging

from app.models.scan import ScanRequest, ScanResult, ScanStatus, VulnType
from app.scanner.sqli import scan_sqli
from app.scanner.xss import scan_xss
from app.scanner.other_checks import scan_csrf, scan_ssrf, scan_path_traversal

logger = logging.getLogger(__name__)

# In-memory store for scan results
_scan_store: dict[str, ScanResult] = {}


def get_scan(scan_id: str) -> ScanResult | None:
    return _scan_store.get(scan_id)


def list_scans() -> list[ScanResult]:
    return list(_scan_store.values())


LINK_PATTERN = re.compile(r'href=["\']([^"\'#]+)["\']', re.IGNORECASE)
FORM_ACTION_PATTERN = re.compile(r'<form[^>]*action=["\']([^"\']+)["\']', re.IGNORECASE)
INPUT_PATTERN = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)


def _extract_links(base_url: str, html: str) -> list[str]:
    """Extract all internal links from HTML."""
    parsed_base = urlparse(base_url)
    links = []
    for match in LINK_PATTERN.finditer(html):
        href = match.group(1)
        if href.startswith("javascript:") or href.startswith("mailto:"):
            continue
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        if parsed.netloc == parsed_base.netloc:
            links.append(full_url)
    return links


def _extract_form_params(html: str) -> dict:
    """Extract form input names as params dict."""
    params = {}
    for match in INPUT_PATTERN.finditer(html):
        name = match.group(1)
        params[name] = "test"
    return params


async def _crawl(
    client: httpx.AsyncClient,
    start_url: str,
    depth: int,
    timeout: int,
) -> list[tuple[str, dict]]:
    """BFS crawler. Returns list of (url, params) tuples."""
    visited = set()
    queue = deque([(start_url, 0, {})])
    pages = []

    while queue:
        url, current_depth, params = queue.popleft()
        if url in visited or current_depth > depth:
            continue
        visited.add(url)

        try:
            resp = await client.get(url, timeout=timeout)
            html = resp.text
            pages.append((url, params))

            if current_depth < depth:
                links = _extract_links(url, html)
                form_params = _extract_form_params(html)

                for link in links[:20]:  # Limit per page
                    if link not in visited:
                        queue.append((link, current_depth + 1, form_params))

        except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError):
            continue

    return pages


async def run_scan(scan_id: str, request: ScanRequest) -> None:
    """Main scan coroutine — runs in background."""
    result = _scan_store[scan_id]
    result.status = ScanStatus.RUNNING
    result.started_at = datetime.now(timezone.utc)

    headers = {
        "User-Agent": request.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    async with httpx.AsyncClient(
        headers=headers,
        follow_redirects=True,
        verify=False,
        timeout=request.timeout,
    ) as client:
        try:
            # Phase 1: Crawl
            logger.info(f"[{scan_id}] Starting crawl on {request.target_url}")
            pages = await _crawl(client, request.target_url, request.depth, request.timeout)
            result.pages_crawled = len(pages)
            logger.info(f"[{scan_id}] Crawled {len(pages)} pages")

            # Phase 2: Scan each page
            all_vulns = []
            requests_count = 0

            scan_tasks = []
            for url, params in pages:
                for vuln_type in request.scan_types:
                    scan_tasks.append((vuln_type, url, params))

            # Run scans concurrently (batched)
            BATCH_SIZE = 10
            for i in range(0, len(scan_tasks), BATCH_SIZE):
                batch = scan_tasks[i:i + BATCH_SIZE]
                batch_results = await asyncio.gather(
                    *[_run_single_scan(client, vuln_type, url, params, request.timeout)
                      for vuln_type, url, params in batch],
                    return_exceptions=True,
                )
                for res in batch_results:
                    if isinstance(res, list):
                        all_vulns.extend(res)
                        requests_count += 1

            # Deduplicate vulnerabilities
            seen = set()
            unique_vulns = []
            for v in all_vulns:
                key = (v.vuln_type, v.url, v.parameter, v.payload)
                if key not in seen:
                    seen.add(key)
                    unique_vulns.append(v)

            result.vulnerabilities = unique_vulns
            result.requests_sent = requests_count
            result.status = ScanStatus.COMPLETED
            logger.info(f"[{scan_id}] Scan complete. Found {len(unique_vulns)} vulnerabilities.")

        except Exception as e:
            logger.error(f"[{scan_id}] Scan failed: {e}", exc_info=True)
            result.status = ScanStatus.FAILED
            result.error = str(e)

        finally:
            result.completed_at = datetime.now(timezone.utc)


async def _run_single_scan(
    client: httpx.AsyncClient,
    vuln_type: VulnType,
    url: str,
    params: dict,
    timeout: int,
) -> list:
    try:
        if vuln_type == VulnType.SQL_INJECTION:
            return await scan_sqli(client, url, params, timeout)
        elif vuln_type == VulnType.XSS:
            return await scan_xss(client, url, params, timeout)
        elif vuln_type == VulnType.CSRF:
            return await scan_csrf(client, url, timeout)
        elif vuln_type == VulnType.SSRF:
            return await scan_ssrf(client, url, params, timeout)
        elif vuln_type == VulnType.PATH_TRAVERSAL:
            return await scan_path_traversal(client, url, params, timeout)
        return []
    except Exception as e:
        logger.warning(f"Scanner error ({vuln_type} on {url}): {e}")
        return []