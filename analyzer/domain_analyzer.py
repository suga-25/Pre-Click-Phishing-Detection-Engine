from urllib.parse import urlparse
import dns.resolver
import whois
from datetime import datetime

FREE_HOSTING_PROVIDERS = {
    'pages.dev', 'netlify.app', 'webflow.io', 'vercel.app', 
    'blogspot.com', 'typedream.app', 'wasmer.app', 'github.io',
    'webadorsite.com', 'redirecthelp.com'
}

def extract_domain_components(domain: str) -> tuple[str, str, str]:
    domain = domain.lower().strip()
    
    for provider in FREE_HOSTING_PROVIDERS:
        if domain.endswith('.' + provider):
            subdomain = domain[:-len('.' + provider)]
            return subdomain, provider, provider.split('.')[-1]
            
    parts = domain.split('.')
    if len(parts) <= 2:
        return "", domain, parts[-1] if parts else ""
        
    tld = parts[-1]
    apex_domain = ".".join(parts[-2:])
    subdomain = ".".join(parts[:-2])
    return subdomain, apex_domain, tld

def analyze_domain(url: str) -> dict:
    domain = urlparse(url).netloc.split(':')[0].lower()
    subdomain, apex_domain, tld = extract_domain_components(domain)
    
    is_paas_platform = apex_domain in FREE_HOSTING_PROVIDERS
    
    has_dns_records = False
    try:
        dns.resolver.resolve(domain, 'A')
        has_dns_records = True
    except Exception:
        has_dns_records = False

    domain_age_days = None
    is_new_domain = False
    
    if not is_paas_platform:
        try:
            w = whois.whois(apex_domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            if creation_date:
                age_td = datetime.now() - creation_date
                domain_age_days = age_td.days
                if domain_age_days < 30:
                    is_new_domain = True
        except Exception:
            pass

    return {
        'domain': domain,
        'subdomain': subdomain,
        'apex_domain': apex_domain,
        'tld': tld,
        'is_paas_platform': is_paas_platform,
        'has_valid_dns': has_dns_records,
        'domain_age_days': domain_age_days,
        'is_new_domain': is_new_domain
    }