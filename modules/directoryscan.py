def directory_scan(base_url):
    """
    Scans for common hidden directories.

    Args:
        base_url (str): Target base URL

    Returns:
        list: Found directories
    """
    import requests
    from concurrent.futures import ThreadPoolExecutor, as_completed

    paths = [
        "/admin", "/login", "/dashboard", "/backup", "/uploads",
        "/config", "/api", "/hidden", "/private", "/dev",
        "/test", "/old", "/db", "/files", "/data"
    ]

    VALID_CODES  = {200, 201, 301, 302, 403}
    MIN_SIZE     = 500
    found        = []
    session      = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    try:
        baseline          = session.get(base_url.rstrip("/"), timeout=5, allow_redirects=True)
        baseline_size     = len(baseline.content)
        baseline_content  = baseline.text[:500].strip()
    except requests.exceptions.RequestException as e:
        return [{"error": f"Baseline request failed: {e}"}]

    def probe(path):
        url = base_url.rstrip("/") + path
        try:
            response = session.get(url, timeout=5, allow_redirects=False)

            if response.status_code not in VALID_CODES:
                return None

            size = len(response.content)

            if response.status_code == 200:
                if size < MIN_SIZE:
                    return None

                if abs(size - baseline_size) < 100:
                    return None

                snippet = response.text[:500].strip()
                if snippet == baseline_content:
                    return None

            return (url, response.status_code, size)

        except requests.exceptions.RequestException:
            return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(probe, path): path for path in paths}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append({
                    "url":    result[0],
                    "status": result[1],
                    "size":   result[2]
                })

    return found if found else [{"info": "No real directories found (all soft 404s or blocked)"}]