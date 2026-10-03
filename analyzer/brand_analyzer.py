from urllib.parse import urlparse

KNOWN_BRANDS = {
    'amazon', 'paypal', 'google', 'microsoft', 'apple', 'facebook', 
    'netflix', 'chase', 'ledger', 'coinsquare', 'phantom', 'robinhood', 
    'icloud', 'instagram', 'linkedin', 'wellsfargo', 'office365', 'trezor',
    'meta', 'orange', 'visa'
}

OFFICIAL_BRAND_DOMAINS = {
    'amazon': ['amazon.com', 'aws.amazon.com'],
    'paypal': ['paypal.com'],
    'google': ['google.com', 'accounts.google.com', 'docs.google.com'],
    'microsoft': ['microsoft.com', 'microsoftonline.com', 'live.com'],
    'apple': ['apple.com', 'appleid.apple.com'],
    'facebook': ['facebook.com'],
    'netflix': ['netflix.com'],
    'chase': ['chase.com'],
    'ledger': ['ledger.com'],
    'coinsquare': ['coinsquare.com'],
    'phantom': ['phantom.app'],
    'robinhood': ['robinhood.com'],
    'icloud': ['icloud.com'],
    'instagram': ['instagram.com'],
    'linkedin': ['linkedin.com'],
    'wellsfargo': ['wellsfargo.com'],
    'office365': ['office365.com', 'office.com'],
    'trezor': ['trezor.io'],
    'meta': ['meta.com'],
    'orange': ['orange.com', 'orange.fr'],
    'visa': ['visa.com']
}

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def analyze_brand_impersonation(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0].lower()
    full_url = url.lower()
    
    target_brand = None
    is_impersonation = False
    
    normalized_url = full_url.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('$', 's')
    
    # 1. Exact Brand Keyword Detection in Host/Path
    for brand in KNOWN_BRANDS:
        if brand in normalized_url:
            official_domains = OFFICIAL_BRAND_DOMAINS.get(brand, [])
            is_official = any(domain == off_d or domain.endswith('.' + off_d) for off_d in official_domains)
            
            if not is_official:
                target_brand = brand
                is_impersonation = True
                break

    # 2. Fuzzy Match / Typosquatting Check
    if not is_impersonation:
        domain_parts = domain.split('.')
        for part in domain_parts:
            if len(part) < 4:
                continue
            for brand in KNOWN_BRANDS:
                dist = levenshtein_distance(part, brand)
                if 1 <= dist <= 2 and part != brand:
                    target_brand = brand
                    is_impersonation = True
                    break
            if is_impersonation:
                break
            
    return {
        'target_brand': target_brand,
        'is_impersonation_detected': is_impersonation,
        'is_impersonation': is_impersonation,
        'suspected_typosquatting': is_impersonation
    }