"""Module for managing cookies of a URL."""

import logging
import requests
from http.cookies import SimpleCookie
import validators

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_cookies(url):
    """
    Get cookies from a URL and analyze them.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Cookies and their analysis
    """
    logger.debug(f"Getting cookies for URL: {url}")
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    if not validators.url(url):
        raise ValueError(f"Invalid URL: {url}")
    
    try:
        # Fetch URL and get cookies
        response = requests.get(url, allow_redirects=True)
        response.raise_for_status()
        
        cookie_dict = requests.utils.dict_from_cookiejar(response.cookies)
        
        if not cookie_dict:
            # Try to parse from headers if no cookies in jar
            if 'Set-Cookie' in response.headers:
                cookie = SimpleCookie()
                cookie.load(response.headers['Set-Cookie'])
                cookie_dict = {k: v.value for k, v in cookie.items()}
        
        # Analyze cookies
        cookies_analysis = analyze_cookies(cookie_dict)
        
        result = {
            'url': url,
            'cookie_count': len(cookie_dict),
            'cookies': cookie_dict,
            'analysis': cookies_analysis
        }
        
        logger.debug(f"Cookies result: {result}")
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL: {e}")
        raise

def analyze_cookies(cookies):
    """
    Analyze cookies for security, privacy, and compliance issues.
    
    Args:
        cookies (dict): Dictionary of cookies
        
    Returns:
        dict: Analysis of cookies
    """
    analysis = {
        'secure_cookies': 0,
        'httponly_cookies': 0,
        'third_party_cookies': 0,
        'session_cookies': 0,
        'persistent_cookies': 0,
        'issues': []
    }
    
    for name, value in cookies.items():
        # Check if it looks like a session cookie
        if name.lower() in ['sessionid', 'session', 'sid', 'phpsessid', 'jsessionid', 'aspsessionid']:
            analysis['session_cookies'] += 1
        else:
            analysis['persistent_cookies'] += 1
            
        # Simple check for Secure flag (this is approximate since we only have the value)
        if name.lower().endswith('secure'):
            analysis['secure_cookies'] += 1
            
        # Simple check for HttpOnly (this is approximate)
        if name.lower().endswith('httponly'):
            analysis['httponly_cookies'] += 1
            
        # Check for potentially sensitive data in cookie names
        sensitive_terms = ['pass', 'pwd', 'token', 'auth', 'secret', 'credential', 'session']
        for term in sensitive_terms:
            if term in name.lower():
                analysis['issues'].append({
                    'severity': 'high',
                    'cookie': name,
                    'issue': f"Potentially sensitive data in cookie '{name}'"
                })
                break
                
        # Check for very long cookie values (potential abuse)
        if len(str(value)) > 4000:
            analysis['issues'].append({
                'severity': 'medium',
                'cookie': name,
                'issue': f"Very long cookie value (>{len(str(value))} chars)"
            })
    
    return analysis