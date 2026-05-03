def detect_cms(url):
    """
    Detects CMS, frameworks, server tech, and known CVE indicators.

    Args:
        url (str): Target URL

    Returns:
        dict: Detected technologies and associated risks
    """
    import requests
    from urllib.parse import urljoin

    SIGNATURES = {
        "WordPress": {
            "indicators": [
                {"type": "path",   "value": "/wp-login.php"},
                {"type": "path",   "value": "/wp-json/"},
                {"type": "path",   "value": "/xmlrpc.php"},
                {"type": "header", "key": "x-powered-by", "value": "wordpress"},
                {"type": "body",   "value": "wp-content"},
                {"type": "body",   "value": "wp-includes"},
            ],
            "risks": [
                "xmlrpc.php brute force / DDoS amplification",
                "wp-json user enumeration (/wp-json/wp/v2/users)",
                "Outdated plugins common attack vector",
            ]
        },
        "Joomla": {
            "indicators": [
                {"type": "path",   "value": "/administrator/"},
                {"type": "body",   "value": "joomla"},
                {"type": "body",   "value": "/media/jui/"},
            ],
            "risks": [
                "Admin panel exposed at /administrator/",
                "Known SQLi vulnerabilities in older versions",
            ]
        },
        "Drupal": {
            "indicators": [
                {"type": "path",   "value": "/user/login"},
                {"type": "body",   "value": "drupal"},
                {"type": "header", "key": "x-generator", "value": "drupal"},
            ],
            "risks": [
                "Drupalgeddon2 (CVE-2018-7600) if unpatched",
                "REST API may expose sensitive content",
            ]
        },
        "Laravel": {
            "indicators": [
                {"type": "header", "key": "set-cookie",    "value": "laravel_session"},
                {"type": "body",   "value": "laravel"},
                {"type": "path",   "value": "/.env"},
            ],
            "risks": [
                ".env file exposure leaks DB credentials",
                "Debug mode may expose full stack traces",
            ]
        },
        "Django": {
            "indicators": [
                {"type": "header", "key": "x-frame-options", "value": "sameorigin"},
                {"type": "body",   "value": "csrfmiddlewaretoken"},
                {"type": "body",   "value": "django"},
            ],
            "risks": [
                "Debug mode exposes full source code",
                "Admin panel at /admin if not moved",
            ]
        },
        "Apache": {
            "indicators": [
                {"type": "header", "key": "server", "value": "apache"},
            ],
            "risks": [
                "Server version disclosure aids targeted exploits",
                "Directory listing may be enabled",
            ]
        },
        "Nginx": {
            "indicators": [
                {"type": "header", "key": "server", "value": "nginx"},
            ],
            "risks": [
                "Server version disclosure",
                "Misconfigured proxy headers possible",
            ]
        },
        "PHP": {
            "indicators": [
                {"type": "header", "key": "x-powered-by", "value": "php"},
                {"type": "path",   "value": "/info.php"},
                {"type": "path",   "value": "/phpinfo.php"},
            ],
            "risks": [
                "phpinfo() exposure leaks full server config",
                "PHP version disclosure aids targeted exploits",
            ]
        },
        "Cloudflare": {
            "indicators": [
                {"type": "header", "key": "server",       "value": "cloudflare"},
                {"type": "header", "key": "cf-ray",       "value": ""},
                {"type": "body",   "value": "cdn-cgi"},
            ],
            "risks": [
                "Origin IP may be discoverable via DNS history",
                "Cloudflare bypass possible via direct IP access",
            ]
        },
    }

    results  = {
        "url":      url,
        "detected": [],
        "headers":  {},
        "risks":    [],
    }

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    try:
        response = session.get(url, timeout=10, allow_redirects=True)
        body     = response.text.lower()
        headers  = {k.lower(): v.lower() for k, v in response.headers.items()}
        results["headers"] = dict(response.headers)
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

    for tech, config in SIGNATURES.items():
        matched = False

        for indicator in config["indicators"]:
            if matched:
                break

            if indicator["type"] == "body":
                if indicator["value"] in body:
                    matched = True

            elif indicator["type"] == "header":
                key = indicator["key"]
                if key in headers:
                    if indicator["value"] == "" or indicator["value"] in headers[key]:
                        matched = True

            elif indicator["type"] == "path":
                probe_url = urljoin(url, indicator["value"])
                try:
                    r = session.get(probe_url, timeout=5, allow_redirects=False)
                    if r.status_code in (200, 301, 302, 403):
                        matched = True
                except requests.exceptions.RequestException:
                    pass

        if matched:
            results["detected"].append(tech)
            results["risks"].extend(config["risks"])

    return results


if __name__ == "__main__":
    target = input("Enter target URL: ").strip()
    results = detect_cms(target)

    if "error" in results:
        print(f"\n[ERROR] {results['error']}")
    else:
        print(f"\n[ CMS/TECH DETECTION — {results['url']} ]")
        print(f"  Detected: {', '.join(results['detected']) or 'Nothing identified'}\n")
        if results["risks"]:
            print("  Risks:")
            for risk in results["risks"]:
                print(f"    - {risk}")