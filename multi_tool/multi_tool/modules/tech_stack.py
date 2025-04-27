"""Module for analyzing the technology stack of a website."""

import logging
import re
import requests
from bs4 import BeautifulSoup
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Define technology signatures to look for in HTML, headers, and scripts
TECH_SIGNATURES = {
    "WordPress": {
        "html": ["wp-content", "wp-includes"],
        "meta": {"generator": "WordPress"}
    },
    "Drupal": {
        "html": ["drupal.js", "drupal.min.js"],
        "meta": {"generator": "Drupal"}
    },
    "Joomla": {
        "html": ["/components/com_", "/media/jui/"],
        "meta": {"generator": "Joomla"}
    },
    "Magento": {
        "html": ["Mage.Cookies", "Magento_"]
    },
    "Bootstrap": {
        "html": ["bootstrap.css", "bootstrap.min.css", "bootstrap.js", "bootstrap.min.js", "bootstrap.bundle.js"]
    },
    "jQuery": {
        "html": ["jquery.js", "jquery.min.js", "jquery-"]
    },
    "React": {
        "html": ["react.js", "react.min.js", "react-dom", "__REACT_DEVTOOLS_GLOBAL_HOOK__", "reactjs"]
    },
    "Angular": {
        "html": ["angular.js", "angular.min.js", "ng-app", "ng-controller", "ng-repeat"]
    },
    "Vue.js": {
        "html": ["vue.js", "vue.min.js", "v-bind", "v-on", "v-model"]
    },
    "Font Awesome": {
        "html": ["font-awesome.css", "font-awesome.min.css", "fontawesome"]
    },
    "Google Analytics": {
        "html": ["google-analytics.com/analytics.js", "ga('create'", "gtag("]
    },
    "Google Tag Manager": {
        "html": ["googletagmanager.com/gtm.js", "GTM-"]
    },
    "Google Fonts": {
        "html": ["fonts.googleapis.com"]
    },
    "Cloudflare": {
        "headers": {"Server": "cloudflare", "CF-RAY": "", "CF-Cache-Status": ""}
    },
    "Nginx": {
        "headers": {"Server": "nginx"}
    },
    "Apache": {
        "headers": {"Server": "Apache"}
    },
    "IIS": {
        "headers": {"Server": "Microsoft-IIS"}
    },
    "PHP": {
        "headers": {"X-Powered-By": "PHP"}
    },
    "ASP.NET": {
        "headers": {"X-AspNet-Version": "", "X-Powered-By": "ASP.NET"}
    },
    "CloudFront": {
        "headers": {"Server": "CloudFront", "X-Amz-Cf-Id": ""}
    },
    "AWS": {
        "headers": {"X-Amz-": ""}
    },
    "AMP": {
        "html": ["⚡", "amp-", "<html amp>", "<html ⚡>"]
    }
}

def analyze_tech_stack(url):
    """
    Analyze the technology stack of a website.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Analysis of the technology stack
    """
    logger.debug(f"Analyzing tech stack for URL: {url}")
    
    # Ensure URL has scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    result = {
        "url": url,
        "technologies": [],
        "frameworks": [],
        "server": None,
        "cms": None,
        "javascript_libraries": [],
        "analytics": [],
        "cdn": None,
        "other": [],
        "error": None
    }
    
    try:
        # Get the website content
        response = requests.get(
            url,
            timeout=15,
            allow_redirects=True,
            verify=False,  # Don't verify SSL cert
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
        response.raise_for_status()
        
        # Parse HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract the page content as a string for pattern matching
        html_content = response.text.lower()
        
        # Check against technology signatures
        for tech, signatures in TECH_SIGNATURES.items():
            detected = False
            
            # Check HTML signatures
            if "html" in signatures:
                for pattern in signatures["html"]:
                    if pattern.lower() in html_content:
                        detected = True
                        break
            
            # Check meta generator tags
            if "meta" in signatures and not detected:
                for meta_name, meta_content in signatures["meta"].items():
                    meta_tags = soup.find_all("meta", attrs={"name": meta_name})
                    for tag in meta_tags:
                        if tag.get("content") and meta_content.lower() in tag.get("content").lower():
                            detected = True
                            break
            
            # Check headers
            if "headers" in signatures and not detected:
                for header_name, header_value in signatures["headers"].items():
                    if header_name in response.headers:
                        if not header_value or header_value.lower() in response.headers[header_name].lower():
                            detected = True
                            break
            
            if detected:
                # Categorize the technology
                if tech in ["WordPress", "Drupal", "Joomla", "Magento"]:
                    result["cms"] = tech
                elif tech in ["React", "Angular", "Vue.js", "Bootstrap"]:
                    result["frameworks"].append(tech)
                elif tech in ["jQuery", "Font Awesome"]:
                    result["javascript_libraries"].append(tech)
                elif tech in ["Google Analytics", "Google Tag Manager"]:
                    result["analytics"].append(tech)
                elif tech in ["Cloudflare", "CloudFront"]:
                    result["cdn"] = tech
                elif tech in ["Nginx", "Apache", "IIS"]:
                    result["server"] = tech
                else:
                    result["other"].append(tech)
                
                result["technologies"].append(tech)
        
        # Look for JavaScript frameworks from script tags
        script_tags = soup.find_all("script")
        js_frameworks = set()
        for script in script_tags:
            src = script.get("src", "")
            if src:
                if "react" in src.lower():
                    js_frameworks.add("React")
                elif "angular" in src.lower():
                    js_frameworks.add("Angular")
                elif "vue" in src.lower():
                    js_frameworks.add("Vue.js")
                elif "jquery" in src.lower():
                    js_frameworks.add("jQuery")
                elif "bootstrap" in src.lower():
                    js_frameworks.add("Bootstrap")
        
        # Add any frameworks detected from script tags that weren't already found
        for framework in js_frameworks:
            if framework not in result["frameworks"] and framework not in result["javascript_libraries"]:
                if framework in ["React", "Angular", "Vue.js", "Bootstrap"]:
                    result["frameworks"].append(framework)
                elif framework in ["jQuery"]:
                    result["javascript_libraries"].append(framework)
                result["technologies"].append(framework)
        
        # Check for server information in headers
        if "Server" in response.headers and not result["server"]:
            server_header = response.headers["Server"]
            if "nginx" in server_header.lower():
                result["server"] = "Nginx"
            elif "apache" in server_header.lower():
                result["server"] = "Apache"
            elif "microsoft-iis" in server_header.lower():
                result["server"] = "IIS"
            else:
                result["server"] = server_header
        
        # Check for programming language
        if "X-Powered-By" in response.headers:
            powered_by = response.headers["X-Powered-By"]
            if "php" in powered_by.lower():
                result["technologies"].append("PHP")
            elif "asp.net" in powered_by.lower():
                result["technologies"].append("ASP.NET")
            else:
                result["technologies"].append(powered_by)
    
    except requests.RequestException as e:
        logger.error(f"Request error: {str(e)}")
        result["error"] = str(e)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        result["error"] = str(e)
    
    logger.debug(f"Tech stack analysis result: {result}")
    return result
