import requests
from urllib.parse import urlparse

def analyze_redirects(url: str) -> dict:
    redirect_chain = [url]
    has_redirects = False
    final_url = url
    
    try:
        response = requests.head(url, allow_redirects=True, timeout=3, headers={'User-Agent': 'Mozilla/5.0'})
        if response.history:
            has_redirects = True
            redirect_chain = [res.url for res in response.history] + [response.url]
            final_url = response.url
    except Exception:
        pass
        
    initial_domain = urlparse(url).netloc
    final_domain = urlparse(final_url).netloc
    
    return {
        'has_redirects': has_redirects,
        'redirect_count': max(0, len(redirect_chain) - 1),
        'redirect_chain': redirect_chain,
        'cross_domain_redirect': initial_domain != final_domain,
        'final_destination': final_url
    }