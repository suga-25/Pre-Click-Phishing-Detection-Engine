import re

def extract_urls(text: str) -> list:
    # Captures http/https links including path, query strings, and fragments
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, text)
    
    # Clean trailing punctuation like periods or trailing parentheses
    cleaned_urls = []
    for url in urls:
        cleaned = url.rstrip('.,);:')
        cleaned_urls.append(cleaned)
        
    return cleaned_urls