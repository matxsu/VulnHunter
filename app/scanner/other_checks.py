import httpx
import re
from urllib.parse import urlparse, parse_qs
from app.models.scan import Vulnerability, VulnType, Severity


# ─── CSRF ─────────────────────────────────────────────────────────────────────

CSRF_TOKEN_PATTERNS = [
    r"csrf[_\-]?token",
    r"_token",
    r"authenticity[_\-]?token",
    r"__requestverificationtoken",
    r"csrfmiddlewaretoken",
    r"xsrf[_\-]?token",
    r"x-csrf-token",
    r"nonce",
]

FORM_METHODS = re.compile(r'<form[^>]*method=["\']?(post|put|delete|patch)["\']?', re.IGNORECASE)
INPUT_HIDDEN = re.compile(r'<input[^>]*type=["\']?hidden["\']?[^>]*name=["\']?([^"\'>\s]+)["\']?', re.IGNORECASE)


def _has_csrf_token(html: str) -> bool:
    """Returns True if any CSRF token pattern is found in form inputs."""
    hidden_inputs = INPUT_HIDDEN.findall(html)
    for input_name in hidden_inputs:
        for pattern in CSRF_TOKEN_PATTERNS:
            if re.search(pattern, input_name, re.IGNORECASE):
                return True
    # Check meta tags
    for pattern in CSRF_TOKEN_PATTERNS:
        if re.search(rf'<meta[^>]*name=["\']?{pattern}["\']?', html, re.IGNORECASE):
            return True
    return False


def _has_samesite_cookie(response: httpx.Response) -> bool:
    """Check if session cookies have SameSite attribute."""
    for header_name, header_val in response.headers.items():
        if header_name.lower() == "set-cookie":
            if re.search(r"samesite=(strict|lax)", header_val, re.IGNORECASE):
                return True
    return False


async def scan_csrf(
    client: httpx.AsyncClient,
    url: str,
    timeout: int = 10,
) -> list[Vulnerability]:
    vulns = []
    try:
        resp = await client.get(url, timeout=timeout)
        html = resp.text

        has_forms = bool(FORM_METHODS.search(html))
        if not has_forms:
            return vulns

        has_token = _has_csrf_token(html)
        has_samesite = _has_samesite_cookie(resp)

        if not has_token and not has_samesite:
            vulns.append(Vulnerability(
                vuln_type=VulnType.CSRF,
                severity=Severity.MEDIUM,
                url=url,
                parameter=None,
                payload=None,
                evidence="POST form detected without CSRF token or SameSite cookie protection",
                description=(
                    "Cross-Site Request Forgery (CSRF) vulnerability. "
                    "The application contains state-changing forms (POST/PUT/DELETE) "
                    "without anti-CSRF token protection. An attacker could trick "
                    "authenticated users into performing unintended actions."
                ),
                remediation=(
                    "Implement synchronizer token pattern: generate unique CSRF tokens per session. "
                    "Add SameSite=Strict or SameSite=Lax attribute to session cookies. "
                    "Verify Origin/Referer headers for sensitive operations."
                ),
                cvss_score=6.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            ))
        elif not has_token and has_samesite:
            vulns.append(Vulnerability(
                vuln_type=VulnType.CSRF,
                severity=Severity.LOW,
                url=url,
                parameter=None,
                payload=None,
                evidence="POST form without CSRF token, but SameSite cookie present (partial protection)",
                description=(
                    "Partial CSRF protection. SameSite cookie is present but no explicit CSRF token. "
                    "SameSite alone may be insufficient in some browser configurations."
                ),
                remediation=(
                    "Add explicit CSRF tokens to all state-changing forms in addition to SameSite cookies. "
                    "Defense-in-depth: use both mechanisms."
                ),
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
            ))

    except (httpx.TimeoutException, httpx.ConnectError):
        pass

    return vulns


# ─── SSRF ─────────────────────────────────────────────────────────────────────

SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://169.254.169.254/computeMetadata/v1/",  # GCP metadata
    "http://metadata.google.internal/",
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "file:///etc/passwd",
    "dict://localhost:11211/",
    "gopher://localhost:25/",
]

SSRF_PARAMS = ["url", "uri", "path", "src", "source", "dest", "destination",
               "redirect", "next", "continue", "return", "returnto",
               "callback", "feed", "fetch", "webhook", "endpoint"]

SSRF_INTERNAL_PATTERNS = [
    r"root:.*:0:0",  # /etc/passwd
    r"ami-id",  # AWS metadata
    r"instance-id",
    r'"computeMetadata"',
    r"169\.254\.169\.254",
    r'"serviceAccounts"',
]


async def scan_ssrf(
    client: httpx.AsyncClient,
    url: str,
    params: dict,
    method: str = "GET",
    timeout: int = 10,
) -> list[Vulnerability]:
    vulns = []
    found_params = set()

    parsed = urlparse(url)
    query_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    all_params = {**query_params, **params}

    # Check existing params + common SSRF param names
    ssrf_candidate_params = {
        k: v for k, v in all_params.items()
        if any(ssrf_p in k.lower() for ssrf_p in SSRF_PARAMS)
    }
    if not ssrf_candidate_params and method == "GET":
        for ssrf_p in SSRF_PARAMS[:4]:
            ssrf_candidate_params[ssrf_p] = "http://example.com"

    for param_name, _ in ssrf_candidate_params.items():
        if param_name in found_params:
            continue

        for payload in SSRF_PAYLOADS:
            try:
                test_params = {**all_params, param_name: payload}
                if method.upper() == "POST":
                    resp = await client.post(url, data=test_params, timeout=timeout)
                else:
                    resp = await client.get(url, params=test_params, timeout=timeout)

                # Check for internal content in response
                for pattern in SSRF_INTERNAL_PATTERNS:
                    if re.search(pattern, resp.text):
                        vulns.append(Vulnerability(
                            vuln_type=VulnType.SSRF,
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Internal resource content detected matching pattern: '{pattern}' in {method} response",
                            description=(
                                f"Server-Side Request Forgery in parameter '{param_name}' ({method}). "
                                "The server fetches remote URLs based on user input and "
                                "returns internal resource content, enabling access to "
                                "metadata services, internal hosts, and cloud credentials."
                            ),
                            remediation=(
                                "Whitelist allowed URLs and domains. "
                                "Block requests to private IP ranges (RFC 1918). "
                                "Disable unnecessary URL schemes (file://, gopher://, dict://). "
                                "Use a dedicated egress proxy with strict allowlists."
                            ),
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        ))
                        found_params.add(param_name)
                        break

                # Check for unexpected 200 on internal addresses
                if (resp.status_code == 200
                        and ("127.0.0.1" in payload or "localhost" in payload)
                        and len(resp.text) > 100):
                    if param_name not in found_params:
                        vulns.append(Vulnerability(
                            vuln_type=VulnType.SSRF,
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"HTTP 200 response for internal address payload in {method}",
                            description=(
                                f"Potential SSRF in parameter '{param_name}' ({method}). "
                                "The server appears to follow redirects or fetch URLs pointing to localhost."
                            ),
                            remediation=(
                                "Validate and sanitize URL parameters. "
                                "Block SSRF with network-level controls and egress filtering."
                            ),
                            cvss_score=7.2,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                        ))
                        found_params.add(param_name)

            except (httpx.TimeoutException, httpx.ConnectError):
                continue

            if param_name in found_params:
                break

    return vulns


# ─── PATH TRAVERSAL ───────────────────────────────────────────────────────────

PATH_TRAVERSAL_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/etc/passwd",
    "..%2Fetc%2Fpasswd",
    "..%252Fetc%252Fpasswd",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    "%c0%ae%c0%ae/etc/passwd",
]

PATH_TRAVERSAL_PARAMS = ["file", "path", "page", "doc", "document",
                          "folder", "root", "name", "filename", "include",
                          "load", "read", "template", "view"]

TRAVERSAL_SUCCESS_PATTERNS = [
    r"root:.*:0:0:",  # Linux /etc/passwd
    r"daemon:.*:/usr/sbin",
    r"\[fonts\]",  # Windows win.ini
    r"\[extensions\]",
    r"for 16-bit app support",
]


async def scan_path_traversal(
    client: httpx.AsyncClient,
    url: str,
    params: dict,
    method: str = "GET",
    timeout: int = 10,
) -> list[Vulnerability]:
    vulns = []
    found_params = set()

    parsed = urlparse(url)
    query_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    all_params = {**query_params, **params}

    # Prioritize likely path params
    candidate_params = {
        k: v for k, v in all_params.items()
        if any(p in k.lower() for p in PATH_TRAVERSAL_PARAMS)
    }
    if not candidate_params and method == "GET":
        candidate_params = all_params or {"file": "index.html"}

    for param_name, original_value in candidate_params.items():
        if param_name in found_params:
            continue

        for payload in PATH_TRAVERSAL_PAYLOADS:
            try:
                test_params = {**all_params, param_name: payload}
                if method.upper() == "POST":
                    resp = await client.post(url, data=test_params, timeout=timeout)
                else:
                    resp = await client.get(url, params=test_params, timeout=timeout)

                for pattern in TRAVERSAL_SUCCESS_PATTERNS:
                    if re.search(pattern, resp.text):
                        vulns.append(Vulnerability(
                            vuln_type=VulnType.PATH_TRAVERSAL,
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Sensitive file content detected matching pattern: '{pattern}' in {method}",
                            description=(
                                f"Path Traversal vulnerability in parameter '{param_name}' ({method}). "
                                "The application allows reading arbitrary files from the "
                                "server filesystem using directory traversal sequences (../)."
                            ),
                            remediation=(
                                "Canonicalize file paths before use. "
                                "Use realpath() and verify the path starts with the expected base directory. "
                                "Never pass user input directly to file system functions. "
                                "Apply principle of least privilege for file system access."
                            ),
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        ))
                        found_params.add(param_name)
                        break

            except (httpx.TimeoutException, httpx.ConnectError):
                continue

            if param_name in found_params:
                break

    return vulns