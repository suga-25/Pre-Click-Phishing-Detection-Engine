import requests
from bs4 import BeautifulSoup

def analyze_page_safely(url: str) -> dict:
    has_login_form = False
    has_credential_fields = False
    
    try:
        response = requests.get(url, timeout=2, headers={'User-Agent': 'Mozilla/5.0'}, stream=True)
        content_type = response.headers.get('Content-Type', '')
        
        if 'text/html' in content_type:
            html = response.raw.read(30000)
            soup = BeautifulSoup(html, 'html.parser')
            
            if soup.find_all('form'):
                has_login_form = True
                
            for inp in soup.find_all('input'):
                if inp.get('type', '').lower() == 'password' or inp.get('name', '').lower() in ['user', 'username', 'login', 'password']:
                    has_credential_fields = True
    except Exception:
        pass

    return {
        'has_login_form': has_login_form,
        'has_credential_fields': has_credential_fields
    }