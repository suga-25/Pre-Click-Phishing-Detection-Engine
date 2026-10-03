from .url_analyzer import analyze_url_structure
from .domain_analyzer import analyze_domain
from .brand_analyzer import analyze_brand_impersonation
from .redirect_analyzer import analyze_redirects
from .page_analyzer import analyze_page_safely
from .context_analyzer import analyze_message_context

def run_full_analysis(url: str, message_text: str = "") -> dict:
    return {
        'target_url': url,
        'url_analysis': analyze_url_structure(url),
        'domain_analysis': analyze_domain(url),
        'brand_analysis': analyze_brand_impersonation(url),
        'redirect_analysis': analyze_redirects(url),
        'page_analysis': analyze_page_safely(url),
        'context_analysis': analyze_message_context(message_text, url)
    }