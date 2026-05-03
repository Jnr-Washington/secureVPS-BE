def check_headers(url):
    """
    Checks for missing important security headers.
    """
    import requests

    SECURITY_HEADERS = {
        "X-Frame-Options":              ("Missing X-Frame-Options",              "High"),
        "Content-Security-Policy":      ("Missing Content-Security-Policy",      "High"),
        "X-Content-Type-Options":       ("Missing X-Content-Type-Options",       "Medium"),
        "Strict-Transport-Security":    ("Missing Strict-Transport-Security",    "High"),
        "Referrer-Policy":              ("Missing Referrer-Policy",              "Low"),
        "Permissions-Policy":           ("Missing Permissions-Policy",           "Low"),
        "X-XSS-Protection":            ("Missing X-XSS-Protection",             "Medium"),
        "Cache-Control":               ("Missing Cache-Control",                "Low"),
    }

    issues = []

    try:
        response = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10,
            allow_redirects=True
        )
        headers = response.headers

        for header, (message, severity) in SECURITY_HEADERS.items():
            if header not in headers:
                issues.append({
                    "issue": message,
                    "severity": severity,
                    "header": header
                })
            else:
                value = headers[header].strip().lower()
                if header == "X-Frame-Options" and value not in ("deny", "sameorigin"):
                    issues.append({
                        "issue": f"Weak X-Frame-Options value: '{headers[header]}'",
                        "severity": "Medium",
                        "header": header
                    })
                elif header == "X-Content-Type-Options" and value != "nosniff":
                    issues.append({
                        "issue": f"Invalid X-Content-Type-Options value: '{headers[header]}'",
                        "severity": "Medium",
                        "header": header
                    })

        issues.sort(key=lambda x: {"High": 0, "Medium": 1, "Low": 2}[x["severity"]])
        return issues

    except requests.exceptions.RequestException as e:
        return [{"issue": f"Request failed: {str(e)}", "severity": "Critical", "header": None}]