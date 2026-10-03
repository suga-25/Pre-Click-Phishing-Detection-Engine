import re

URGENCY_KEYWORDS = {'urgent', 'immediately', 'suspended', 'lock', 'action required', '24 hours', 'verify now'}
ACCOUNT_KEYWORDS = {'verify', 'account', 'security', 'update', 'confirm', 'unauthorized'}

def analyze_message_context(message_body: str, target_url: str) -> dict:
    body_lower = message_body.lower()
    
    # 1. Urgency detection
    found_urgency = [kw for kw in URGENCY_KEYWORDS if kw in body_lower]
    
    # 2. Account verification context
    found_account_context = [kw for kw in ACCOUNT_KEYWORDS if kw in body_lower]
    
    # 3. Mismatched URL display (e.g. text says paypal.com but links to evil.com)
    url_mismatch_detected = False
    # Extract explicit text representations of domains in body
    explicit_domains = re.findall(r'https?://([a-zA-Z0-9.-]+)', body_lower)
    if explicit_domains:
        for domain in explicit_domains:
            if domain not in target_url.lower():
                url_mismatch_detected = True
                break

    return {
        'has_urgency_language': len(found_urgency) > 0,
        'urgency_keywords': found_urgency,
        'has_account_verification_context': len(found_account_context) > 0,
        'credential_context_detected': len(found_account_context) > 0 or len(found_urgency) > 0,
        'displayed_vs_actual_url_mismatch': url_mismatch_detected
    }