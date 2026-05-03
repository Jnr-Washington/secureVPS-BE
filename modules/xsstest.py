def test_xss(url):
    """
    Tests for reflected XSS vulnerabilities.

    Args:
        url (str): Target URL with parameters

    Returns:
        list: Possible XSS findings
    """
    import requests
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'><script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "';alert(1)//",
        "</script><script>alert(1)</script>",
        "<iframe src=javascript:alert(1)>",
    ]

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
        baseline_content = baseline.text
    except requests.exceptions.RequestException as e:
        return [{"issue": f"Baseline request failed: {e}", "type": "error"}]

    for param in params:
        for payload in PAYLOADS:
            injected = params.copy()
            injected[param] = payload

            test_url = urlunparse(parsed._replace(query=urlencode(injected, doseq=True)))

            try:
                response = session.get(test_url, timeout=5)
                content = response.text

                reflected = payload in content and payload not in baseline_content
                partial   = any(
                    frag in content and frag not in baseline_content
                    for frag in [payload[:10], payload[-10:]]
                )

                if reflected or partial:
                    key = (param, payload)
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "type":        "reflected_xss",
                            "parameter":   param,
                            "payload":     payload,
                            "reflected":   reflected,
                            "partial":     partial and not reflected,
                            "url":         test_url,
                        })

            except requests.exceptions.RequestException:
                continue

    return findings if findings else [{"type": "clean", "issue": "No XSS indicators found"}]