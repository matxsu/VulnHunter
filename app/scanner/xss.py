import httpx
import re
from urllib.parse import urlparse, parse_qs
from app.models.scan import Vulnerability, VulnType, Severity

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=\"javascript:alert('XSS')\">",
    "\"><img src=x onerror=alert(1)>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "';alert('XSS')//",
    "</script><script>alert('XSS')</script>",
    "<details open ontoggle=alert('XSS')>",
    "<input autofocus onfocus=alert('XSS')>",
    # DOM-based
    "'-alert('XSS')-'",
    "\"-alert('XSS')-\"",
]

CVSS_XSS_REFLECTED = {
    "score": 6.1,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
}

CVSS_XSS_STORED = {
    "score": 8.2,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N"
}


def _check_reflected(payload: str, response_text: str) -> bool:
    """Check if the payload is directly reflected in the response."""
    return payload in response_text or payload.lower() in response_text.lower()


def _check_dom_sink(response_text: str) -> list[str]:
    """Detect dangerous DOM sinks in the response."""
    sinks = []
    patterns = [
        r"document\.write\s*\(",
        r"innerHTML\s*=",
        r"outerHTML\s*=",
        r"eval\s*\(",
        r"setTimeout\s*\(['\"]",
        r"setInterval\s*\(['\"]",
        r"location\.href\s*=",
        r"document\.URL",
        r"window\.location",
    ]
    for pattern in patterns:
        if re.search(pattern, response_text):
            sinks.append(pattern.replace(r"\s*", "").replace(r"\(", "("))
    return sinks


async def scan_xss(
    client: httpx.AsyncClient,
    url: str,
    params: dict,
    method: str = "GET",
    timeout: int = 10,
) -> list[Vulnerability]:
    vulns = []
    found_params = set()

    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    all_params = {**{k: v[0] for k, v in query_params.items()}, **params}

    if not all_params and method == "GET":
        all_params = {"q": "test", "search": "test", "name": "test", "comment": "test"}

    for param_name, original_value in all_params.items():
        if param_name in found_params:
            continue

        for payload in XSS_PAYLOADS:
            try:
                test_params = {**all_params, param_name: payload}
                
                if method.upper() == "POST":
                    resp = await client.post(url, data=test_params, timeout=timeout)
                else:
                    resp = await client.get(url, params=test_params, timeout=timeout)

                if _check_reflected(payload, resp.text):
                    # Check if it's inside a script context
                    dom_sinks = _check_dom_sink(resp.text)
                    is_dom = len(dom_sinks) > 0

                    vuln_desc = (
                        f"Reflected XSS in parameter '{param_name}' ({method}). "
                        "The user-supplied input is returned in the HTTP response without "
                        "proper HTML encoding, allowing script execution in victim's browser."
                    )
                    if is_dom:
                        vuln_desc += f" DOM sinks detected: {', '.join(dom_sinks[:3])}"

                    vulns.append(Vulnerability(
                        vuln_type=VulnType.XSS,
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Payload reflected verbatim in {method} response",
                        description=vuln_desc,
                        remediation=(
                            "Encode output using HTML entity encoding (e.g., &lt; &gt; &amp;). "
                            "Implement Content-Security-Policy headers. "
                            "Use a templating engine with auto-escaping. "
                            "Validate and sanitize all user inputs."
                        ),
                        cvss_score=CVSS_XSS_REFLECTED["score"],
                        cvss_vector=CVSS_XSS_REFLECTED["vector"],
                    ))
                    found_params.add(param_name)
                    break

            except (httpx.TimeoutException, httpx.ConnectError):
                continue

        if param_name in found_params:
            continue

        # Check for DOM sinks without payload reflection (DOM XSS potential)
        try:
            if method.upper() == "POST":
                resp = await client.post(url, data=all_params, timeout=timeout)
            else:
                resp = await client.get(url, params=all_params, timeout=timeout)
                
            dom_sinks = _check_dom_sink(resp.text)
            if dom_sinks:
                vulns.append(Vulnerability(
                    vuln_type=VulnType.XSS,
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter=param_name,
                    payload=None,
                    evidence=f"DOM sinks found on page with {method} form",
                    description=(
                        f"Potential DOM-based XSS. Dangerous JavaScript sinks detected "
                        f"in the page source: {', '.join(dom_sinks[:3])}. "
                        "If user-controlled data flows into these sinks, script execution may occur."
                    ),
                    remediation=(
                        "Avoid dangerous DOM sinks (innerHTML, document.write, eval). "
                        "Use textContent instead of innerHTML for user data. "
                        "Implement DOMPurify for HTML sanitization."
                    ),
                    cvss_score=5.4,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
                ))
                found_params.add(param_name)
        except (httpx.TimeoutException, httpx.ConnectError):
            pass

    return vulns