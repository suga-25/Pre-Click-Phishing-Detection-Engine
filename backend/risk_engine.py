import re
from urllib.parse import unquote, urlparse

# Base domains of major brands (whitelisted to prevent False Positives)
WHITELISTED_BRAND_DOMAINS = {
    "google.com",
    "github.com",
    "paypal.com",
    "amazon.com",
    "microsoft.com",
    "microsoftonline.com",
    "hubspot.com",
    "medium.com",
    "zoom.us",
    "apple.com",
    "netflix.com",
    "dropbox.com",
}

# Suspicious TLDs frequently used in automated phishing infrastructure
SUSPICIOUS_TLDS = {
    ".top",
    ".xyz",
    ".site",
    ".info",
    ".tech",
    ".online",
    ".club",
    ".work",
    ".vip",
}

# Known URL shortener domains
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}

# Target brand keywords for impersonation checks
BRAND_KEYWORDS = [
    "paypal",
    "google",
    "microsoft",
    "office365",
    "apple",
    "netflix",
    "dropbox",
    "wellsfargo",
    "chase",
    "bank",
]


def extract_base_domain(hostname):
    """Extracts subdomains and the base domain from a hostname string."""
    if not hostname:
        return "", ""
    parts = hostname.lower().split(".")
    if len(parts) <= 2:
        return "", hostname
    return ".".join(parts[:-2]), ".".join(parts[-2:])


def calculate_heuristics(url):
    """Calculates risk score (0-100), classification level, and reasons."""
    score = 0
    reasons = []

    # Decode percent-encoding and parse components
    decoded_url = unquote(url)
    parsed = urlparse(decoded_url)

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    hostname = netloc.split(":")[0]
    subdomain, base_domain = extract_base_domain(hostname)

    # 1. IP Address Host Check
    ip_match = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname)
    if ip_match:
        score += 80
        reasons.append("Raw IP address used instead of domain name")

    # 2. Base Domain Whitelist Bypass
    if base_domain in WHITELISTED_BRAND_DOMAINS and not ip_match:
        if scheme == "http":
            score += 15
            reasons.append("Insecure HTTP protocol used")
        return {
            "risk_score": min(score, 25),
            "classification": "LOW",
            "explainable_reasons": reasons if reasons else ["Verified legitimate domain"],
        }

    # 3. URL Shortener Service Check
    if base_domain in SHORTENER_DOMAINS:
        score += 45
        reasons.append("URL utilizes a known shortening service that masks the real destination")

    # 4. High-Risk TLD Check
    tld = f".{hostname.split('.')[-1]}" if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        score += 30
        reasons.append(f"Domain registered under high-risk TLD ({tld})")

    # 5. Brand Keyword Impersonation Check
    for brand in BRAND_KEYWORDS:
        if brand in hostname:
            score += 40
            reasons.append(f"Possible brand spoofing: '{brand}' keyword detected in domain")
            break

    # 6. Subdomain Depth & Hyphenation Obfuscation
    if subdomain.count(".") >= 3 or subdomain.count("-") >= 3:
        score += 30
        reasons.append("Excessive subdomain depth or hyphenation used for obfuscation")

    if "%20" in url or " " in decoded_url:
        score += 35
        reasons.append("URL contains space or percent-encoding obfuscation tactics")

    # 7. Sensitive Action Keywords in Path/Query
    suspicious_keywords = ["verify", "verification", "update", "billing"]
    if any(kw in path or kw in query for kw in suspicious_keywords):
        score += 20
        reasons.append("Sensitive action keywords found in URL path")

    # 8. Unencrypted HTTP Protocol Penalty
    if scheme == "http" and not ip_match:
        score += 20
        reasons.append("Unencrypted HTTP scheme used for sensitive/unknown site")

    # Cap score boundaries (0 - 100)
    score = min(max(score, 0), 100)

    # Classification mapping
    if score < 30:
        classification = "LOW"
    elif score < 70:
        classification = "MEDIUM"
    else:
        classification = "HIGH"

    return {
        "risk_score": score,
        "classification": classification,
        "explainable_reasons": reasons,
    }


def analyze_url(url_string):
    """Main function wrapper for API calls."""
    if not url_string:
        return {
            "risk_score": 0,
            "classification": "LOW",
            "explainable_reasons": ["Empty URL provided"],
        }
    return calculate_heuristics(url_string)