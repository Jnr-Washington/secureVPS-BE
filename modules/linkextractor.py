def extract_links(url):
    """
    Extracts all links from a given webpage.

    Args:
        url (str): Target website URL

    Returns:
        list: List of discovered links
    """
    import requests
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin, urlparse

    TAGS = {
        "a":      "href",
        "script": "src",
        "link":   "href",
        "img":    "src",
        "form":   "action",
        "iframe": "src",
    }

    base_domain = urlparse(url).netloc
    internal, external = [], []

    try:
        response = requests.get(
            url,
            timeout=5,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=True
        )
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        seen = set()

        for tag, attr in TAGS.items():
            for element in soup.find_all(tag):
                raw = element.get(attr)

                if not raw or raw.startswith(("mailto:", "tel:", "javascript:")):
                    continue

                full_url = urljoin(url, raw.strip())

                if full_url in seen:
                    continue
                seen.add(full_url)

                parsed = urlparse(full_url)

                if not parsed.scheme in ("http", "https"):
                    continue

                if parsed.netloc == base_domain:
                    internal.append(full_url)
                else:
                    external.append(full_url)

        return {"internal": internal, "external": external}

    except requests.exceptions.RequestException as e:
        return {"error": str(e), "internal": [], "external": []}