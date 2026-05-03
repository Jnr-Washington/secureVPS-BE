def scan_subdomains(url):
    """
    Brute-forces common subdomains for a given domain.

    Args:
        url (str): Target URL or domain

    Returns:
        dict: Discovered subdomains with status and IP
    """
    import socket
    import requests
    from urllib.parse import urlparse
    from concurrent.futures import ThreadPoolExecutor, as_completed

    WORDLIST = [
        "www", "mail", "ftp", "admin", "portal", "vpn", "api",
        "dev", "staging", "test", "beta", "app", "mobile", "m",
        "blog", "shop", "store", "cdn", "static", "assets",
        "login", "auth", "sso", "id", "accounts", "dashboard",
        "staff", "student", "elearning", "library", "support",
        "helpdesk", "ict", "it", "remote", "intranet", "internal",
        "erp", "crm", "hr", "finance", "payroll", "db", "database",
        "backup", "old", "legacy", "new", "secure", "cpanel",
        "webmail", "smtp", "pop", "imap", "ns1", "ns2", "mx",
        "git", "gitlab", "github", "jenkins", "ci", "build",
        "monitor", "status", "health", "docs", "wiki", "kb",
        "erepository", "repository", "research", "data", "files",
        "onlineapplication", "apply", "admission", "admissions",
        "studentportal", "staffportal", "ictsupport", "opac",
    ]

    parsed = urlparse(url)
    domain = parsed.hostname or parsed.path.strip("/")

    if domain.startswith("www."):
        domain = domain[4:]

    found = []
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    def probe(sub):
        hostname = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

        for scheme in ("https", "http"):
            try:
                response = session.get(
                    f"{scheme}://{hostname}",
                    timeout=5,
                    allow_redirects=True
                )
                return {
                    "subdomain": hostname,
                    "ip":        ip,
                    "status":    response.status_code,
                    "scheme":    scheme,
                    "url":       f"{scheme}://{hostname}",
                }
            except requests.exceptions.RequestException:
                continue

        return {
            "subdomain": hostname,
            "ip":        ip,
            "status":    None,
            "scheme":    None,
            "url":       f"https://{hostname}",
            "note":      "DNS resolves but HTTP unreachable"
        }

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(probe, sub): sub for sub in WORDLIST}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    found.sort(key=lambda x: x["subdomain"])
    return {"domain": domain, "found": found, "count": len(found)}


if __name__ == "__main__":
    target = input("Enter target URL: ").strip()
    results = scan_subdomains(target)

    print(f"\n[ SUBDOMAIN SCAN — {results['domain']} ]")
    print(f"  Found: {results['count']}\n")

    for item in results["found"]:
        status = item.get("status") or "N/A"
        print(f"  [{status}] {item['url']} ({item['ip']})")