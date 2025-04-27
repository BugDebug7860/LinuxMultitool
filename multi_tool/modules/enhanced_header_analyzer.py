#!/usr/bin/env python3
"""Module for enhanced HTTP security header analysis."""

import logging
import json
import requests
import validators
from urllib.parse import urlparse
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Security header definitions with details
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Controls resources the user agent is allowed to load",
        "importance": "high",
        "secure_value": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "importance": "high",
        "secure_value": "nosniff",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "importance": "high",
        "secure_value": "DENY",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
    },
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections",
        "importance": "high",
        "secure_value": "max-age=31536000; includeSubDomains; preload",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
    },
    "Referrer-Policy": {
        "description": "Controls what information is sent in the Referer header",
        "importance": "medium",
        "secure_value": "strict-origin-when-cross-origin",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
    },
    "Permissions-Policy": {
        "description": "Controls which browser features can be used (replaces Feature-Policy)",
        "importance": "medium",
        "secure_value": "geolocation=(), camera=(), microphone=()",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Feature_Policy"
    },
    "Feature-Policy": {
        "description": "Legacy header for controlling browser features, replaced by Permissions-Policy",
        "importance": "low",
        "secure_value": "geolocation 'none'; camera 'none'; microphone 'none'",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Feature_Policy"
    },
    "X-XSS-Protection": {
        "description": "Enables browser's built-in XSS filtering",
        "importance": "medium",
        "secure_value": "1; mode=block",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Controls which cross-origin resources can be loaded",
        "importance": "medium",
        "secure_value": "require-corp",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Controls cross-origin window interactions",
        "importance": "medium",
        "secure_value": "same-origin",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Controls cross-origin resource sharing",
        "importance": "medium",
        "secure_value": "same-site",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"
    },
    "Cache-Control": {
        "description": "Controls caching of sensitive content",
        "importance": "medium",
        "secure_value": "no-cache, no-store, must-revalidate",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"
    },
    "Clear-Site-Data": {
        "description": "Clears browsing data (cookies, storage, cache) associated with the site",
        "importance": "medium",
        "secure_value": "\"cache\", \"cookies\", \"storage\"",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data"
    },
    "Access-Control-Allow-Origin": {
        "description": "Controls which sites can access resources in cross-origin requests",
        "importance": "high",
        "secure_value": "https://trusted-site.com",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin"
    },
    "Content-Security-Policy-Report-Only": {
        "description": "Reports CSP violations without enforcing them",
        "importance": "low",
        "secure_value": "default-src 'self'; report-uri /csp-violation-report-endpoint/",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only"
    },
    "Expect-CT": {
        "description": "Certificate Transparency enforcement",
        "importance": "medium",
        "secure_value": "max-age=86400, enforce, report-uri=\"https://example.com/report\"",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT"
    },
    "Pragma": {
        "description": "Legacy cache control header",
        "importance": "low",
        "secure_value": "no-cache",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma"
    },
    "Public-Key-Pins": {
        "description": "Certificate pinning (deprecated)",
        "importance": "low",
        "secure_value": "Deprecated - no longer recommended",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins"
    },
    "Timing-Allow-Origin": {
        "description": "Controls which origins can see Resource Timing API data",
        "importance": "medium",
        "secure_value": "same-origin",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Timing-Allow-Origin"
    }
}

def analyze_enhanced_headers(url):
    """
    Perform enhanced analysis of security-related HTTP headers.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Enhanced header analysis results
    """
    logger.debug(f"Starting enhanced header analysis on {url}")
    
    # Validate URL
    if not validators.url(url):
        # Try to convert to URL if it's a domain
        if validators.domain(url):
            url = f"https://{url}"
        else:
            return {
                "error": "Invalid URL. Please provide a valid URL.",
                "url": url
            }
    
    # Initialize results
    results = {
        "url": url,
        "analysis_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "is_https": url.startswith("https://"),
        "headers": {},
        "security_score": 0,
        "missing_headers": [],
        "insecure_headers": [],
        "csp_analysis": None,
        "cors_analysis": None,
        "hsts_analysis": None,
        "detailed_analysis": {},
        "recommendations": []
    }
    
    try:
        # Request the URL
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        
        # Store all headers
        results["headers"] = dict(response.headers)
        results["status_code"] = response.status_code
        
        # Check if URL redirected to HTTPS
        if url.startswith("http://") and response.url.startswith("https://"):
            results["redirected_to_https"] = True
        else:
            results["redirected_to_https"] = False
        
        # Analyze security headers
        analyze_security_headers(response.headers, results)
        
        # Analyze Content Security Policy if present
        if "Content-Security-Policy" in response.headers:
            results["csp_analysis"] = analyze_csp(response.headers["Content-Security-Policy"])
        
        # Analyze CORS headers if present
        results["cors_analysis"] = analyze_cors(response.headers)
        
        # Analyze HSTS if present
        if "Strict-Transport-Security" in response.headers:
            results["hsts_analysis"] = analyze_hsts(response.headers["Strict-Transport-Security"])
        
        # Check for mixed content if HTTPS
        if results["is_https"]:
            results["mixed_content"] = check_mixed_content(response.text, response.url)
        
        # Calculate overall security score
        calculate_security_score(results)
        
        # Generate recommendations
        generate_recommendations(results)
        
    except Exception as e:
        logger.error(f"Error during enhanced header analysis: {str(e)}")
        results["error"] = f"Analysis error: {str(e)}"
    
    return results

def analyze_security_headers(headers, results):
    """
    Analyze security headers in the response.
    
    Args:
        headers (dict): The HTTP response headers
        results (dict): The results dictionary to update
    """
    # Check for presence and validity of each security header
    for header_name, header_info in SECURITY_HEADERS.items():
        # Setup default header analysis structure
        header_analysis = {
            "present": False,
            "value": None,
            "secure": False,
            "description": header_info["description"],
            "importance": header_info["importance"],
            "recommended_value": header_info["secure_value"],
            "issues": []
        }
        
        # Case-insensitive header check
        header_value = None
        for h in headers:
            if h.lower() == header_name.lower():
                header_value = headers[h]
                break
        
        if header_value:
            header_analysis["present"] = True
            header_analysis["value"] = header_value
            
            # Perform header-specific validation
            if header_name == "Content-Security-Policy":
                header_analysis["secure"] = validate_csp(header_value, header_analysis)
            elif header_name == "X-Content-Type-Options":
                header_analysis["secure"] = header_value.lower() == "nosniff"
                if not header_analysis["secure"]:
                    header_analysis["issues"].append("Value should be 'nosniff'")
            elif header_name == "X-Frame-Options":
                header_analysis["secure"] = header_value.upper() in ["DENY", "SAMEORIGIN"]
                if not header_analysis["secure"]:
                    header_analysis["issues"].append("Value should be 'DENY' or 'SAMEORIGIN'")
            elif header_name == "Strict-Transport-Security":
                header_analysis["secure"] = validate_hsts(header_value, header_analysis)
            elif header_name == "X-XSS-Protection":
                header_analysis["secure"] = "1" in header_value and "mode=block" in header_value.lower()
                if not header_analysis["secure"]:
                    header_analysis["issues"].append("Value should be '1; mode=block'")
            elif header_name == "Referrer-Policy":
                secure_values = [
                    "no-referrer", 
                    "no-referrer-when-downgrade", 
                    "strict-origin", 
                    "strict-origin-when-cross-origin"
                ]
                header_analysis["secure"] = any(val in header_value.lower() for val in secure_values)
                if not header_analysis["secure"]:
                    header_analysis["issues"].append(f"Value should be one of: {', '.join(secure_values)}")
            elif header_name == "Cache-Control":
                # For security-sensitive pages, cache control should be restrictive
                restrictive_values = ["no-store", "no-cache", "must-revalidate"]
                header_analysis["secure"] = all(val in header_value.lower() for val in restrictive_values)
                if not header_analysis["secure"]:
                    header_analysis["issues"].append(f"Consider using: {header_info['secure_value']}")
            elif header_name == "Access-Control-Allow-Origin":
                header_analysis["secure"] = header_value != "*"
                if not header_analysis["secure"]:
                    header_analysis["issues"].append("Using '*' allows any site to access resources")
            else:
                # Default validation - presence is better than absence for other headers
                header_analysis["secure"] = True
        else:
            # Header is missing
            if header_info["importance"] in ["high", "medium"]:
                results["missing_headers"].append(header_name)
        
        # Store analysis results
        results["detailed_analysis"][header_name] = header_analysis
        
        # Track insecure headers
        if header_analysis["present"] and not header_analysis["secure"]:
            results["insecure_headers"].append(header_name)

def validate_csp(csp_value, header_analysis):
    """
    Validate Content Security Policy value.
    
    Args:
        csp_value (str): The CSP header value
        header_analysis (dict): The header analysis to update
        
    Returns:
        bool: True if secure, False otherwise
    """
    is_secure = True
    directives = csp_value.split(';')
    
    # Check for unsafe directives
    unsafe_directives = []
    
    for directive in directives:
        directive = directive.strip().lower()
        
        # Check for unsafe-inline or unsafe-eval
        if "'unsafe-inline'" in directive:
            unsafe_directives.append("'unsafe-inline'")
            is_secure = False
        if "'unsafe-eval'" in directive:
            unsafe_directives.append("'unsafe-eval'")
            is_secure = False
        
        # Check for overly permissive sources
        if "* " in directive or " *" in directive or directive.endswith('*'):
            unsafe_directives.append("wildcard (*)")
            is_secure = False
        
        # Check for data: URIs in script-src or object-src
        if ("script-src" in directive or "object-src" in directive) and "data:" in directive:
            unsafe_directives.append("data: URI in script-src/object-src")
            is_secure = False
    
    # Check for critical missing directives
    important_directives = ["default-src", "script-src", "object-src"]
    missing_directives = []
    
    for directive in important_directives:
        if not any(directive in d.lower() for d in directives):
            missing_directives.append(directive)
            is_secure = False
    
    # Update header analysis with issues
    if unsafe_directives:
        header_analysis["issues"].append(f"Contains unsafe directives: {', '.join(unsafe_directives)}")
    
    if missing_directives:
        header_analysis["issues"].append(f"Missing important directives: {', '.join(missing_directives)}")
    
    return is_secure

def validate_hsts(hsts_value, header_analysis):
    """
    Validate HTTP Strict Transport Security value.
    
    Args:
        hsts_value (str): The HSTS header value
        header_analysis (dict): The header analysis to update
        
    Returns:
        bool: True if secure, False otherwise
    """
    is_secure = True
    directives = [d.strip().lower() for d in hsts_value.split(';')]
    
    # Check for max-age
    max_age = None
    for directive in directives:
        if directive.startswith('max-age='):
            try:
                max_age = int(directive.split('=')[1])
                break
            except (ValueError, IndexError):
                pass
    
    # Check if max-age is present and sufficient (at least 6 months)
    if max_age is None:
        header_analysis["issues"].append("Missing max-age directive")
        is_secure = False
    elif max_age < 15768000:  # 6 months in seconds
        header_analysis["issues"].append(f"max-age too short: {max_age} seconds (should be at least 15768000)")
        is_secure = False
    
    # Check for includeSubDomains
    if 'includesubdomains' not in directives:
        header_analysis["issues"].append("Missing includeSubDomains directive")
        is_secure = False
    
    # Check for preload (not strictly required but recommended)
    if 'preload' not in directives:
        header_analysis["issues"].append("Missing preload directive (recommended)")
    
    return is_secure

def analyze_csp(csp_value):
    """
    Analyze Content Security Policy in detail.
    
    Args:
        csp_value (str): The CSP header value
        
    Returns:
        dict: Detailed CSP analysis
    """
    csp_analysis = {
        "directives": {},
        "strength": "weak",
        "issues": []
    }
    
    # Split directives
    directives = [d.strip() for d in csp_value.split(';') if d.strip()]
    
    # Parse each directive
    for directive in directives:
        parts = directive.split(None, 1)
        
        if len(parts) == 2:
            directive_name = parts[0].lower()
            directive_value = parts[1]
            csp_analysis["directives"][directive_name] = directive_value
        elif len(parts) == 1:
            directive_name = parts[0].lower()
            csp_analysis["directives"][directive_name] = ""
    
    # Analyze security implications
    if not csp_analysis["directives"]:
        csp_analysis["issues"].append("Empty or malformed CSP")
        return csp_analysis
    
    # Check for baseline directives
    important_directives = ["default-src", "script-src", "object-src"]
    for directive in important_directives:
        if directive not in csp_analysis["directives"]:
            csp_analysis["issues"].append(f"Missing {directive} directive")
    
    # Check for unsafe patterns
    unsafe_patterns = {
        "unsafe-inline": "Allows inline scripts/styles, which bypasses CSP protections",
        "unsafe-eval": "Allows eval(), which can be dangerous if user input is evaluated",
        "data:": "Allows data: URIs which can be used to bypass CSP in some contexts",
        "*": "Overly permissive wildcard source"
    }
    
    for directive, value in csp_analysis["directives"].items():
        for pattern, issue in unsafe_patterns.items():
            if pattern in value:
                csp_analysis["issues"].append(f"{directive} contains {pattern}: {issue}")
    
    # Determine strength
    if len(csp_analysis["issues"]) == 0:
        if "default-src" in csp_analysis["directives"] and csp_analysis["directives"]["default-src"] == "'none'" or csp_analysis["directives"]["default-src"] == "'self'":
            csp_analysis["strength"] = "strong"
        else:
            csp_analysis["strength"] = "moderate"
    elif len(csp_analysis["issues"]) <= 2:
        csp_analysis["strength"] = "moderate"
    
    return csp_analysis

def analyze_cors(headers):
    """
    Analyze Cross-Origin Resource Sharing headers.
    
    Args:
        headers (dict): The response headers
        
    Returns:
        dict: CORS analysis results
    """
    cors_analysis = {
        "enabled": False,
        "policy": "restrictive",
        "allow_credentials": False,
        "issues": []
    }
    
    # Check for CORS headers
    acao_header = None
    for header in headers:
        if header.lower() == "access-control-allow-origin":
            acao_header = headers[header]
            cors_analysis["enabled"] = True
            break
    
    if not cors_analysis["enabled"]:
        return cors_analysis
    
    # Check ACAO value
    if acao_header == "*":
        cors_analysis["policy"] = "permissive"
        cors_analysis["issues"].append("Access-Control-Allow-Origin: * is overly permissive")
    
    # Check for Allow-Credentials
    for header in headers:
        if header.lower() == "access-control-allow-credentials":
            cors_analysis["allow_credentials"] = headers[header].lower() == "true"
            
            # Check for dangerous combination
            if cors_analysis["allow_credentials"] and acao_header == "*":
                cors_analysis["issues"].append("CRITICAL: Allow-Credentials: true with wildcard origin is insecure")
    
    # Check for other CORS headers
    cors_headers = {
        "access-control-allow-methods": None,
        "access-control-allow-headers": None,
        "access-control-expose-headers": None,
        "access-control-max-age": None
    }
    
    for cors_header in cors_headers:
        for header in headers:
            if header.lower() == cors_header:
                cors_headers[cors_header] = headers[header]
                break
    
    # Add header values to analysis if present
    for header, value in cors_headers.items():
        if value:
            cors_analysis[header.replace("access-control-", "")] = value
            
            # Check for overly permissive methods
            if header == "access-control-allow-methods" and value == "*":
                cors_analysis["issues"].append("Allow-Methods: * is overly permissive")
            
            # Check for overly permissive headers
            if header == "access-control-allow-headers" and value == "*":
                cors_analysis["issues"].append("Allow-Headers: * is overly permissive")
    
    return cors_analysis

def analyze_hsts(hsts_value):
    """
    Analyze HTTP Strict Transport Security header in detail.
    
    Args:
        hsts_value (str): The HSTS header value
        
    Returns:
        dict: HSTS analysis results
    """
    hsts_analysis = {
        "max_age": None,
        "include_subdomains": False,
        "preload": False,
        "strength": "weak",
        "issues": []
    }
    
    # Parse directives
    directives = [d.strip().lower() for d in hsts_value.split(';')]
    
    for directive in directives:
        if directive.startswith('max-age='):
            try:
                hsts_analysis["max_age"] = int(directive.split('=')[1])
            except (ValueError, IndexError):
                hsts_analysis["issues"].append("Invalid max-age format")
        elif directive == "includesubdomains":
            hsts_analysis["include_subdomains"] = True
        elif directive == "preload":
            hsts_analysis["preload"] = True
    
    # Evaluate strength
    if hsts_analysis["max_age"] is None:
        hsts_analysis["issues"].append("Missing max-age directive")
    elif hsts_analysis["max_age"] < 86400:  # 1 day
        hsts_analysis["issues"].append(f"max-age too short: {hsts_analysis['max_age']} seconds")
    elif hsts_analysis["max_age"] < 15768000:  # 6 months
        hsts_analysis["issues"].append(f"max-age less than recommended 6 months: {hsts_analysis['max_age']} seconds")
    
    if not hsts_analysis["include_subdomains"]:
        hsts_analysis["issues"].append("Missing includeSubDomains directive")
    
    if not hsts_analysis["preload"]:
        hsts_analysis["issues"].append("Missing preload directive")
    
    # Determine strength
    if hsts_analysis["max_age"] and hsts_analysis["max_age"] >= 15768000 and hsts_analysis["include_subdomains"] and hsts_analysis["preload"]:
        hsts_analysis["strength"] = "strong"
    elif hsts_analysis["max_age"] and hsts_analysis["max_age"] >= 86400 and hsts_analysis["include_subdomains"]:
        hsts_analysis["strength"] = "moderate"
    
    return hsts_analysis

def check_mixed_content(html_content, url):
    """
    Check for mixed content on an HTTPS page.
    
    Args:
        html_content (str): The HTML content of the page
        url (str): The URL of the page
        
    Returns:
        dict: Mixed content analysis
    """
    mixed_content = {
        "found": False,
        "active_content": [],
        "passive_content": [],
        "count": 0
    }
    
    if not url.startswith("https://"):
        return mixed_content
    
    # Simple regex-based checks for common mixed content patterns
    import re
    
    # Check for HTTP URLs in various contexts
    http_src_pattern = re.compile(r'(src|href)\s*=\s*[\'"]http://[^\'"]+[\'"]', re.IGNORECASE)
    http_css_pattern = re.compile(r'url\s*\(\s*[\'"]?http://[^\'"]+[\'"]?\s*\)', re.IGNORECASE)
    
    # Find all instances
    http_src_matches = http_src_pattern.findall(html_content)
    http_css_matches = http_css_pattern.findall(html_content)
    
    # Extract full URLs
    for match in http_src_pattern.finditer(html_content):
        full_match = match.group(0)
        attr_type = match.group(1).lower()
        
        # Extract URL
        url_match = re.search(r'http://[^\'"]+', full_match)
        if url_match:
            mixed_url = url_match.group(0)
            
            # Categorize as active or passive content
            if attr_type == "src":
                # Check if it's script, iframe, object, embed (active)
                context_match = re.search(r'<(script|iframe|object|embed|frame)[^>]*' + re.escape(full_match), html_content, re.IGNORECASE)
                if context_match:
                    mixed_content["active_content"].append(mixed_url)
                else:
                    mixed_content["passive_content"].append(mixed_url)
            else:  # href
                # Check if it's link stylesheet (can be active)
                context_match = re.search(r'<link[^>]*rel\s*=\s*[\'"]stylesheet[\'"][^>]*' + re.escape(full_match), html_content, re.IGNORECASE)
                if context_match:
                    mixed_content["active_content"].append(mixed_url)
                else:
                    mixed_content["passive_content"].append(mixed_url)
    
    # Add CSS urls
    for match in http_css_pattern.finditer(html_content):
        full_match = match.group(0)
        url_match = re.search(r'http://[^\'")\s]+', full_match)
        if url_match:
            mixed_content["passive_content"].append(url_match.group(0))
    
    # Update count and found flag
    mixed_content["count"] = len(mixed_content["active_content"]) + len(mixed_content["passive_content"])
    mixed_content["found"] = mixed_content["count"] > 0
    
    return mixed_content

def calculate_security_score(results):
    """
    Calculate an overall security score based on header implementation.
    
    Args:
        results (dict): The analysis results to update
    """
    # Base score
    score = 0
    max_score = 100
    deductions = 0
    
    # Core headers worth more points
    core_headers = {
        "Content-Security-Policy": 15,
        "X-Content-Type-Options": 10,
        "X-Frame-Options": 10,
        "Strict-Transport-Security": 15,
    }
    
    # Secondary headers worth fewer points
    secondary_headers = {
        "Referrer-Policy": 5,
        "Permissions-Policy": 5,
        "X-XSS-Protection": 5,
        "Cross-Origin-Embedder-Policy": 5,
        "Cross-Origin-Opener-Policy": 5,
        "Cross-Origin-Resource-Policy": 5,
    }
    
    # Check core headers
    for header, points in core_headers.items():
        if header in results["detailed_analysis"]:
            analysis = results["detailed_analysis"][header]
            if analysis["present"]:
                if analysis["secure"]:
                    score += points
                else:
                    score += points / 2  # Partial credit for present but insecure
            else:
                deductions += points
    
    # Check secondary headers
    for header, points in secondary_headers.items():
        if header in results["detailed_analysis"]:
            analysis = results["detailed_analysis"][header]
            if analysis["present"] and analysis["secure"]:
                score += points
    
    # HTTPS bonus
    if results["is_https"]:
        score += 10
    else:
        deductions += 20  # Severe penalty for no HTTPS
    
    # Redirect to HTTPS bonus
    if not results["is_https"] and results["redirected_to_https"]:
        score += 5
    
    # CSP analysis adjustments
    if results["csp_analysis"]:
        if results["csp_analysis"]["strength"] == "strong":
            score += 5
        elif results["csp_analysis"]["strength"] == "weak":
            deductions += 5
    
    # HSTS analysis adjustments
    if results["hsts_analysis"]:
        if results["hsts_analysis"]["strength"] == "strong":
            score += 5
        elif results["hsts_analysis"]["strength"] == "weak":
            deductions += 5
    
    # Mixed content penalty
    if results.get("mixed_content", {}).get("found", False):
        mixed_content = results["mixed_content"]
        active_count = len(mixed_content["active_content"])
        passive_count = len(mixed_content["passive_content"])
        
        # Active mixed content is a severe issue
        if active_count > 0:
            deductions += min(20, active_count * 5)
        
        # Passive mixed content is less severe
        if passive_count > 0:
            deductions += min(10, passive_count * 2)
    
    # Calculate final score, ensuring it stays within 0-100
    final_score = max(0, min(100, score - deductions))
    results["security_score"] = final_score
    
    # Add a rating based on the score
    if final_score >= 90:
        results["security_rating"] = "Excellent"
    elif final_score >= 75:
        results["security_rating"] = "Good"
    elif final_score >= 50:
        results["security_rating"] = "Moderate"
    elif final_score >= 25:
        results["security_rating"] = "Poor"
    else:
        results["security_rating"] = "Very Poor"

def generate_recommendations(results):
    """
    Generate security recommendations based on analysis.
    
    Args:
        results (dict): The analysis results to update
    """
    # Start with HTTPS recommendation if needed
    if not results["is_https"]:
        results["recommendations"].append({
            "title": "Enable HTTPS",
            "description": "HTTPS is essential for security. Obtain an SSL/TLS certificate and configure your server to use HTTPS.",
            "priority": "critical"
        })
    
    # Add recommendations for missing headers
    for header in results["missing_headers"]:
        header_info = SECURITY_HEADERS[header]
        
        if header_info["importance"] == "high":
            priority = "high"
        elif header_info["importance"] == "medium":
            priority = "medium"
        else:
            priority = "low"
        
        results["recommendations"].append({
            "title": f"Add {header} header",
            "description": f"{header_info['description']}. Recommended value: {header_info['secure_value']}",
            "priority": priority,
            "example": f"{header}: {header_info['secure_value']}",
            "link": header_info["link"]
        })
    
    # Add recommendations for insecure headers
    for header in results["insecure_headers"]:
        header_info = SECURITY_HEADERS[header]
        header_analysis = results["detailed_analysis"][header]
        
        if header_info["importance"] == "high":
            priority = "high"
        elif header_info["importance"] == "medium":
            priority = "medium"
        else:
            priority = "low"
        
        issues = "; ".join(header_analysis["issues"])
        
        results["recommendations"].append({
            "title": f"Improve {header} configuration",
            "description": f"Current value is not secure. Issues: {issues}",
            "priority": priority,
            "current": f"{header}: {header_analysis['value']}",
            "recommended": f"{header}: {header_info['secure_value']}",
            "link": header_info["link"]
        })
    
    # Add specific recommendations for CSP
    if results["csp_analysis"] and results["csp_analysis"]["issues"]:
        results["recommendations"].append({
            "title": "Improve Content Security Policy",
            "description": "Your CSP has the following issues: " + "; ".join(results["csp_analysis"]["issues"]),
            "priority": "high",
            "example": "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
            "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
        })
    
    # Add specific recommendations for HSTS
    if results["hsts_analysis"] and results["hsts_analysis"]["issues"]:
        results["recommendations"].append({
            "title": "Improve HTTP Strict Transport Security",
            "description": "Your HSTS has the following issues: " + "; ".join(results["hsts_analysis"]["issues"]),
            "priority": "high",
            "example": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
        })
    
    # Add recommendations for mixed content if found
    if results.get("mixed_content", {}).get("found", False):
        mixed_content = results["mixed_content"]
        if mixed_content["active_content"]:
            results["recommendations"].append({
                "title": "Fix active mixed content",
                "description": f"Found {len(mixed_content['active_content'])} instances of active mixed content. This is a critical security issue that will be blocked by browsers.",
                "priority": "critical",
                "examples": mixed_content["active_content"][:3],  # Show first 3 examples
                "link": "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"
            })
        
        if mixed_content["passive_content"]:
            results["recommendations"].append({
                "title": "Fix passive mixed content",
                "description": f"Found {len(mixed_content['passive_content'])} instances of passive mixed content. This may trigger warnings in browsers.",
                "priority": "medium",
                "examples": mixed_content["passive_content"][:3],  # Show first 3 examples
                "link": "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"
            })
    
    # Add CORS recommendations if needed
    if results["cors_analysis"] and results["cors_analysis"]["issues"]:
        results["recommendations"].append({
            "title": "Improve CORS configuration",
            "description": "Your CORS configuration has the following issues: " + "; ".join(results["cors_analysis"]["issues"]),
            "priority": "high",
            "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
        })
    
    # Add overall recommendation based on security score
    if results["security_score"] < 50:
        results["recommendations"].append({
            "title": "Implement security headers",
            "description": f"Your security header implementation score is {results['security_score']}/100 ({results['security_rating']}). Adding the recommended headers will significantly improve your website's security posture.",
            "priority": "high"
        })

if __name__ == "__main__":
    # Example usage
    results = analyze_enhanced_headers("https://example.com")
    print(json.dumps(results, indent=2))