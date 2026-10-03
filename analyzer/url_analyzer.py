import re
from urllib.parse import urlparse

SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly', 'rb.gy'}

SUSPICIOUS_KEYWORDS = {
    'login', 'verify', 'account', 'banking', 'secure', 'update', 'confirm', 
    'signin', 'credential', 'password', 'auth', 'recovery', 'support', 'sopport', 
    'servclients', 'suportcloud', 'recuperacion', 'painel', 'dpd-group'
}

HIGH_RISK_TLDS = {
    'sbs', 'autos', 'site', 'top', 'click', 'info', 'xyz', 'online', 'tech', 
    'cc', 'work', 'world', 'ch', 'eu.cc', 'infy.click'
}

def analyze_url_structure(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0].lower()
    path = parsed.path
    query = parsed.query
    full_path_query = (path + "?" + query).lower() if query else path.lower()
    
    # Explicit exception: raw.githubusercontent.com is NOT a link shortener
    is_raw_github = (domain == "raw.githubusercontent.com")
    
    # 1. IP Address Detection
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    is_ip = bool(ip_pattern.match(domain))
    
    # 2. Subdomain Count
    domain_parts = domain.split('.')
    subdomain_count = max(0, len(domain_parts) - 2) if not is_ip else 0
    
    # 3. Percent Encoding
    has_encoding = '%' in url
    
    # 4. Keyword Detection in Path/Query
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_path_query]
    
    # 5. Open Redirect / Embedded Domain Pattern
    has_embedded_domain = bool(re.search(r'/[a-z0-9-]+\.(com|org|net|io|us)/', path.lower()))

    # 6. High-Risk TLD Check
    tld = ".".join(domain_parts[-2:]) if len(domain_parts) > 2 and ".".join(domain_parts[-2:]) in HIGH_RISK_TLDS else domain_parts[-1] if domain_parts and not is_ip else ''
    is_high_risk_tld = tld in HIGH_RISK_TLDS or (len(domain_parts) > 0 and domain_parts[-1] in HIGH_RISK_TLDS)

    # 7. Special Character Count
    special_chars = set('@-=_~?%#')
    special_char_count = sum(1 for char in url if char in special_chars)
    
    # 8. Shortener Check (Bypassed for raw.githubusercontent.com)
    is_shortened = (domain in SHORTENERS) and not is_raw_github
    
    return {
        'url_length': len(url),
        'special_char_count': special_char_count,
        'is_ip_address': is_ip,
        'subdomain_count': subdomain_count,
        'has_encoding': has_encoding,
        'suspicious_keywords_found': found_keywords,
        'has_suspicious_keywords': len(found_keywords) > 0,
        'suspicious_path_detected': len(found_keywords) > 0 or has_embedded_domain,
        'has_embedded_domain': has_embedded_domain,
        'has_query_params': bool(query),
        'is_shortened': is_shortened,
        'is_high_risk_tld': is_high_risk_tld,
        'is_raw_github': is_raw_github
    }