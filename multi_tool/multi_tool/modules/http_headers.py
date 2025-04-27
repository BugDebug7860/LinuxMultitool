"""Module for analyzing HTTP headers."""

import logging
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

def analyze_headers(url):
    """
    Analyze HTTP headers for a URL.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Analysis of HTTP headers
    """
    logger.debug(f"Analyzing HTTP headers for URL: {url}")
    
    # Ensure URL has scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    result = {
        "url": url,
        "headers": {},
        "security_headers": {},
        "status_code": None,
        "error": None
    }
    
    try:
        # Send a HEAD request first (to avoid downloading content)
        head_response = requests.head(
            url, 
            timeout=10, 
            allow_redirects=True, 
            verify=False,  # Don't verify SSL cert
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
        
        # Some servers don't respond well to HEAD requests, so use GET if needed
        if head_response.status_code >= 400:
            logger.debug(f"HEAD request failed with status {head_response.status_code}, trying GET")
            response = requests.get(
                url, 
                timeout=10, 
                allow_redirects=True, 
                verify=False,  # Don't verify SSL cert
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                },
                stream=True  # To avoid downloading the entire content
            )
            response.close()  # Close the connection immediately
        else:
            response = head_response
        
        # Store the request information
        result["status_code"] = response.status_code
        result["headers"] = dict(response.headers)
        result["redirects"] = [] if not response.history else [
            {
                "url": r.url,
                "status_code": r.status_code
            } for r in response.history
        ]
        
        # Analyze security headers
        security_headers = {
            "Strict-Transport-Security": response.headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": response.headers.get("Content-Security-Policy"),
            "X-Content-Type-Options": response.headers.get("X-Content-Type-Options"),
            "X-Frame-Options": response.headers.get("X-Frame-Options"),
            "X-XSS-Protection": response.headers.get("X-XSS-Protection"),
            "Referrer-Policy": response.headers.get("Referrer-Policy"),
            "Feature-Policy": response.headers.get("Feature-Policy", response.headers.get("Permissions-Policy")),
            "Access-Control-Allow-Origin": response.headers.get("Access-Control-Allow-Origin"),
            "Cross-Origin-Embedder-Policy": response.headers.get("Cross-Origin-Embedder-Policy"),
            "Cross-Origin-Opener-Policy": response.headers.get("Cross-Origin-Opener-Policy"),
            "Cross-Origin-Resource-Policy": response.headers.get("Cross-Origin-Resource-Policy")
        }
        
        # Remove None values from security headers
        result["security_headers"] = {k: v for k, v in security_headers.items() if v is not None}
        
        # Analyze for missing security headers
        missing_security_headers = [k for k, v in security_headers.items() if v is None]
        if missing_security_headers:
            result["missing_security_headers"] = missing_security_headers
        
        # Check for server information leakage
        if "Server" in response.headers:
            result["server"] = response.headers["Server"]
        
        if "X-Powered-By" in response.headers:
            result["powered_by"] = response.headers["X-Powered-By"]
        
        # Check for cookies
        if response.cookies:
            result["cookies"] = [
                {
                    "name": cookie.name,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "httpOnly": "HttpOnly" in cookie._rest,
                    "samesite": cookie._rest.get("SameSite"),
                    "expires": cookie.expires
                } for cookie in response.cookies
            ]
    
    except requests.RequestException as e:
        logger.error(f"Request error: {str(e)}")
        result["error"] = str(e)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        result["error"] = str(e)
    
    logger.debug(f"HTTP headers analysis result: {result}")
    return result
