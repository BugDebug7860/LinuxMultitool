"""Module for inspecting redirect chains."""

import logging
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

def inspect_redirect_chain(url, max_redirects=20):
    """
    Inspect the redirect chain for a URL.
    
    Args:
        url (str): The URL to inspect
        max_redirects (int, optional): Maximum number of redirects to follow. Defaults to 20.
        
    Returns:
        dict: Information about the redirect chain
    """
    logger.debug(f"Inspecting redirect chain for URL: {url}")
    
    # Ensure URL has scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    result = {
        "original_url": url,
        "final_url": None,
        "redirect_count": 0,
        "redirect_chain": [],
        "error": None
    }
    
    try:
        # Configure a session to automatically handle redirects
        session = requests.Session()
        
        # Make request with redirects allowed but track them manually
        response = session.get(
            url,
            timeout=10,
            allow_redirects=True,
            verify=False,  # Don't verify SSL cert for testing purposes
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
        
        # Get the redirect history
        if response.history:
            result["redirect_count"] = len(response.history)
            
            # Process each redirect
            for i, resp in enumerate(response.history):
                redirect_info = {
                    "step": i + 1,
                    "url": resp.url,
                    "status_code": resp.status_code,
                    "reason": resp.reason,
                    "location": resp.headers.get('Location')
                }
                
                # Add redirect type
                if resp.status_code == 301:
                    redirect_info["type"] = "Permanent Redirect (301)"
                elif resp.status_code == 302:
                    redirect_info["type"] = "Found (302) - Temporary Redirect"
                elif resp.status_code == 303:
                    redirect_info["type"] = "See Other (303)"
                elif resp.status_code == 307:
                    redirect_info["type"] = "Temporary Redirect (307)"
                elif resp.status_code == 308:
                    redirect_info["type"] = "Permanent Redirect (308)"
                else:
                    redirect_info["type"] = f"Other ({resp.status_code})"
                
                result["redirect_chain"].append(redirect_info)
            
            # Add final destination
            final_info = {
                "step": result["redirect_count"] + 1,
                "url": response.url,
                "status_code": response.status_code,
                "reason": response.reason,
                "type": "Final Destination"
            }
            result["redirect_chain"].append(final_info)
            result["final_url"] = response.url
        else:
            # No redirects occurred
            result["final_url"] = url
            result["redirect_chain"].append({
                "step": 1,
                "url": url,
                "status_code": response.status_code,
                "reason": response.reason,
                "type": "No Redirect (Direct)"
            })
        
        # Check for redirect loops
        urls = [item["url"] for item in result["redirect_chain"]]
        duplicate_urls = set([u for u in urls if urls.count(u) > 1])
        if duplicate_urls:
            result["redirect_loops"] = list(duplicate_urls)
    
    except requests.exceptions.TooManyRedirects:
        logger.error(f"Too many redirects for URL: {url}")
        result["error"] = "Too many redirects"
    except requests.RequestException as e:
        logger.error(f"Request error: {str(e)}")
        result["error"] = str(e)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        result["error"] = str(e)
    
    logger.debug(f"Redirect chain result: {result}")
    return result
