from urllib.parse import urlparse
def check_url_features(url):
    warnings = []
    score = 0

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    suspicious_keywords = [
        "login",
        "verify",
        "update",
        "secure",
        "bank"
    ]

    # HTTPS check
    if parsed.scheme != "https":
        warnings.append("No HTTPS encryption")
        score += 20

    # Hyphen check
    if "-" in domain:
        warnings.append("Hyphens detected in domain")
        score += 10

    # Long URL check
    if len(url) > 75:
        warnings.append("URL is unusually long")
        score += 10

    # Suspicious keyword detection
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            warnings.append(f"Suspicious keyword detected: {keyword}")
            score += 15
            break

    # Excessive subdomains
    if domain.count(".") > 3:
        warnings.append("Too many subdomains")
        score += 20

    return warnings, score