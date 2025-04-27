"""Module for analyzing HTTP security features including HSTS."""

import logging
import requests
import validators
import re
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def analyze_http_security(url):
    """
    Analyze HTTP security features for a URL including HSTS.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Analysis of HTTP security features
    """
    logger.debug(f"Analyzing HTTP security for URL: {url}")
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    if not validators.url(url):
        raise ValueError(f"Invalid URL: {url}")
    
    try:
        # Fetch URL with headers
        response = requests.get(url, timeout=10)
        headers = response.headers
        
        # Extract security headers
        security_headers = _extract_security_headers(headers)
        
        # Analyze HSTS
        hsts_analysis = _analyze_hsts(headers)
        
        # Analyze Content-Security-Policy
        csp_analysis = _analyze_csp(headers)
        
        # Check for HTTPS
        is_https = url.startswith('https://')
        
        # Check for mixed content
        mixed_content = _check_mixed_content(response.text, url) if is_https else {
            'has_mixed_content': 'N/A',
            'reason': 'Site not using HTTPS'
        }
        
        # Check for HTTPS redirects
        https_redirect = _check_https_redirect(url)
        
        # Analyze CORS configuration
        cors_analysis = _analyze_cors(headers)
        
        # Create overall security score
        security_score = _calculate_security_score(
            is_https,
            https_redirect.get('redirects_to_https', False),
            hsts_analysis,
            security_headers,
            csp_analysis,
            mixed_content,
            cors_analysis
        )
        
        result = {
            'url': url,
            'https': {
                'enabled': is_https,
                'redirect': https_redirect
            },
            'security_headers': security_headers,
            'hsts': hsts_analysis,
            'content_security_policy': csp_analysis,
            'mixed_content': mixed_content,
            'cors': cors_analysis,
            'security_score': security_score
        }
        
        logger.debug(f"HTTP security analysis result: {result}")
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL: {e}")
        raise

def _extract_security_headers(headers):
    """Extract and analyze HTTP security headers."""
    security_headers = {
        'strict_transport_security': headers.get('Strict-Transport-Security'),
        'content_security_policy': headers.get('Content-Security-Policy'),
        'content_security_policy_report_only': headers.get('Content-Security-Policy-Report-Only'),
        'x_content_type_options': headers.get('X-Content-Type-Options'),
        'x_frame_options': headers.get('X-Frame-Options'),
        'x_xss_protection': headers.get('X-XSS-Protection'),
        'referrer_policy': headers.get('Referrer-Policy'),
        'feature_policy': headers.get('Feature-Policy'),
        'permissions_policy': headers.get('Permissions-Policy'),
        'expect_ct': headers.get('Expect-CT')
    }
    
    # Create a presence map for easier processing
    presence = {key: value is not None for key, value in security_headers.items()}
    
    # Analyze recommendations
    recommendations = []
    
    if not presence['strict_transport_security']:
        recommendations.append({
            'header': 'Strict-Transport-Security',
            'severity': 'high',
            'recommendation': 'Implement HSTS with a max-age of at least 31536000 (1 year)'
        })
    
    if not presence['content_security_policy'] and not presence['content_security_policy_report_only']:
        recommendations.append({
            'header': 'Content-Security-Policy',
            'severity': 'high',
            'recommendation': 'Implement a Content Security Policy to protect against XSS and data injection attacks'
        })
    
    if not presence['x_content_type_options']:
        recommendations.append({
            'header': 'X-Content-Type-Options',
            'severity': 'medium',
            'recommendation': 'Add X-Content-Type-Options: nosniff to prevent MIME type sniffing'
        })
    
    if not presence['x_frame_options']:
        recommendations.append({
            'header': 'X-Frame-Options',
            'severity': 'medium',
            'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking'
        })
    
    if not presence['referrer_policy']:
        recommendations.append({
            'header': 'Referrer-Policy',
            'severity': 'medium',
            'recommendation': 'Add Referrer-Policy: strict-origin-when-cross-origin to control referrer information'
        })
    
    return {
        'headers': security_headers,
        'present': presence,
        'missing': [key for key, value in presence.items() if not value],
        'recommendations': recommendations
    }

def _analyze_hsts(headers):
    """Analyze the HSTS header configuration."""
    hsts_header = headers.get('Strict-Transport-Security')
    
    if not hsts_header:
        return {
            'enabled': False,
            'reason': 'HSTS header not present',
            'recommendation': 'Implement HSTS with a max-age of at least 31536000 (1 year)'
        }
    
    # Extract max-age
    max_age_match = re.search(r'max-age=(\d+)', hsts_header)
    max_age = int(max_age_match.group(1)) if max_age_match else 0
    
    # Check for includeSubDomains
    include_subdomains = 'includeSubDomains' in hsts_header
    
    # Check for preload
    preload = 'preload' in hsts_header
    
    # Analyze max-age
    if max_age < 31536000:  # Less than 1 year
        max_age_quality = 'insufficient'
    elif max_age < 63072000:  # Less than 2 years
        max_age_quality = 'acceptable'
    else:
        max_age_quality = 'good'
    
    # Determine overall quality
    if max_age_quality == 'good' and include_subdomains and preload:
        quality = 'excellent'
    elif max_age_quality in ['good', 'acceptable'] and include_subdomains:
        quality = 'good'
    elif max_age_quality in ['good', 'acceptable']:
        quality = 'moderate'
    else:
        quality = 'poor'
    
    # Generate recommendations
    recommendations = []
    
    if max_age_quality == 'insufficient':
        recommendations.append('Increase max-age to at least 31536000 (1 year)')
    
    if not include_subdomains:
        recommendations.append('Add includeSubDomains directive for better protection')
    
    if not preload:
        recommendations.append('Consider adding preload directive for maximum protection')
    
    return {
        'enabled': True,
        'header': hsts_header,
        'max_age': max_age,
        'max_age_description': f"{max_age} seconds ({max_age/86400:.1f} days)",
        'include_subdomains': include_subdomains,
        'preload': preload,
        'quality': quality,
        'recommendations': recommendations
    }

def _analyze_csp(headers):
    """Analyze the Content-Security-Policy header."""
    csp_header = headers.get('Content-Security-Policy')
    csp_ro_header = headers.get('Content-Security-Policy-Report-Only')
    
    if not csp_header and not csp_ro_header:
        return {
            'enabled': False,
            'reason': 'CSP header not present',
            'recommendation': 'Implement a Content Security Policy'
        }
    
    # Use the actual CSP header or the report-only if actual is missing
    header_to_analyze = csp_header or csp_ro_header
    report_only = bool(csp_ro_header and not csp_header)
    
    # Parse directives
    directives = {}
    for part in header_to_analyze.split(';'):
        part = part.strip()
        if not part:
            continue
            
        if ' ' in part:
            directive, value = part.split(' ', 1)
            directives[directive] = value.strip()
        else:
            directives[part] = ""
    
    # Check for unsafe directives
    unsafe_directives = []
    
    if 'default-src' in directives and "'unsafe-inline'" in directives['default-src']:
        unsafe_directives.append('default-src allows unsafe-inline')
        
    if 'script-src' in directives and "'unsafe-inline'" in directives['script-src']:
        unsafe_directives.append('script-src allows unsafe-inline')
        
    if 'script-src' in directives and "'unsafe-eval'" in directives['script-src']:
        unsafe_directives.append('script-src allows unsafe-eval')
        
    if 'default-src' in directives and "'unsafe-eval'" in directives['default-src']:
        unsafe_directives.append('default-src allows unsafe-eval')
    
    # Check for wildcard sources
    wildcard_directives = []
    
    for directive, value in directives.items():
        if '*' in value:
            wildcard_directives.append(f"{directive} uses wildcard (*)")
    
    # Determine overall quality
    has_default_src = 'default-src' in directives
    uses_nonce_or_hash = any(("'nonce-" in value or "'sha" in value) for value in directives.values())
    has_report_uri = 'report-uri' in directives or 'report-to' in directives
    
    if not has_default_src:
        quality = 'poor'
    elif not unsafe_directives and not wildcard_directives and uses_nonce_or_hash:
        quality = 'excellent'
    elif not unsafe_directives and len(wildcard_directives) <= 1:
        quality = 'good'
    elif len(unsafe_directives) <= 1 and has_report_uri:
        quality = 'moderate'
    else:
        quality = 'poor'
    
    # Generate recommendations
    recommendations = []
    
    if not has_default_src:
        recommendations.append('Add a default-src directive')
    
    if unsafe_directives:
        recommendations.append('Remove unsafe-inline and unsafe-eval directives')
    
    if wildcard_directives:
        recommendations.append('Replace wildcard (*) sources with specific sources')
    
    if not uses_nonce_or_hash and ('script-src' in directives or 'default-src' in directives):
        recommendations.append('Use nonces or hashes for scripts instead of unsafe-inline')
    
    if not has_report_uri:
        recommendations.append('Add a report-uri or report-to directive for CSP violation reporting')
    
    if report_only:
        recommendations.append('Switch from Report-Only to enforcement mode once testing is complete')
    
    return {
        'enabled': True,
        'report_only': report_only,
        'directives': directives,
        'directive_count': len(directives),
        'has_unsafe_directives': bool(unsafe_directives),
        'unsafe_directives': unsafe_directives,
        'wildcard_sources': wildcard_directives,
        'quality': quality,
        'recommendations': recommendations
    }

def _check_mixed_content(html_content, url):
    """Check for mixed content on an HTTPS page."""
    if not url.startswith('https://'):
        return {
            'has_mixed_content': 'N/A',
            'reason': 'Site not using HTTPS'
        }
    
    # Get the base domain
    domain = urlparse(url).netloc
    
    # Look for HTTP resources
    mixed_content = []
    
    # Check for HTTP scripts
    script_pattern = re.compile(r'<script[^>]*\bsrc=[\'"](http:\/\/[^\'"]*)[\'"](.*?)>', re.IGNORECASE)
    for match in script_pattern.finditer(html_content):
        if not match.group(1).startswith(f'http://{domain}'):  # Ignore same-domain
            mixed_content.append({
                'type': 'script',
                'resource': match.group(1),
                'severity': 'high'
            })
    
    # Check for HTTP stylesheets
    css_pattern = re.compile(r'<link[^>]*\brel=[\'"]stylesheet[\'"](.*?)\bhref=[\'"](http:\/\/[^\'"]*)[\'"](.*?)>', re.IGNORECASE)
    for match in css_pattern.finditer(html_content):
        if not match.group(2).startswith(f'http://{domain}'):  # Ignore same-domain
            mixed_content.append({
                'type': 'stylesheet',
                'resource': match.group(2),
                'severity': 'high'
            })
    
    # Check for HTTP images
    img_pattern = re.compile(r'<img[^>]*\bsrc=[\'"](http:\/\/[^\'"]*)[\'"](.*?)>', re.IGNORECASE)
    for match in img_pattern.finditer(html_content):
        if not match.group(1).startswith(f'http://{domain}'):  # Ignore same-domain
            mixed_content.append({
                'type': 'image',
                'resource': match.group(1),
                'severity': 'medium'
            })
    
    # Check for HTTP iframes
    iframe_pattern = re.compile(r'<iframe[^>]*\bsrc=[\'"](http:\/\/[^\'"]*)[\'"](.*?)>', re.IGNORECASE)
    for match in iframe_pattern.finditer(html_content):
        if not match.group(1).startswith(f'http://{domain}'):  # Ignore same-domain
            mixed_content.append({
                'type': 'iframe',
                'resource': match.group(1),
                'severity': 'high'
            })
    
    # Generate recommendations
    recommendations = []
    if mixed_content:
        recommendations.append('Update all resources to use HTTPS URLs instead of HTTP')
        recommendations.append('Consider implementing an upgrade-insecure-requests CSP directive')
    
    return {
        'has_mixed_content': bool(mixed_content),
        'mixed_content_count': len(mixed_content),
        'mixed_content': mixed_content,
        'recommendations': recommendations
    }

def _check_https_redirect(url):
    """Check if HTTP URLs redirect to HTTPS."""
    if url.startswith('https://'):
        # Convert to HTTP for testing
        http_url = url.replace('https://', 'http://', 1)
    else:
        # Already HTTP
        http_url = url
        
    try:
        response = requests.get(http_url, timeout=10, allow_redirects=False)
        
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get('Location', '')
            redirects_to_https = location.startswith('https://')
            
            return {
                'redirects_to_https': redirects_to_https,
                'status_code': response.status_code,
                'location': location
            }
        else:
            return {
                'redirects_to_https': False,
                'status_code': response.status_code,
                'reason': 'HTTP URL does not redirect'
            }
    except requests.exceptions.RequestException:
        return {
            'redirects_to_https': False,
            'error': 'Failed to check HTTP redirect'
        }

def _analyze_cors(headers):
    """Analyze Cross-Origin Resource Sharing (CORS) configuration."""
    cors_headers = {
        'access_control_allow_origin': headers.get('Access-Control-Allow-Origin'),
        'access_control_allow_methods': headers.get('Access-Control-Allow-Methods'),
        'access_control_allow_headers': headers.get('Access-Control-Allow-Headers'),
        'access_control_allow_credentials': headers.get('Access-Control-Allow-Credentials'),
        'access_control_expose_headers': headers.get('Access-Control-Expose-Headers'),
        'access_control_max_age': headers.get('Access-Control-Max-Age')
    }
    
    # Check if CORS is implemented
    has_cors = any(cors_headers.values())
    
    # Check for overly permissive configuration
    acao = cors_headers['access_control_allow_origin']
    acac = cors_headers['access_control_allow_credentials']
    
    overly_permissive = acao == '*' and acac == 'true'
    
    # Generate recommendations
    recommendations = []
    
    if not has_cors:
        return {
            'enabled': False,
            'headers': cors_headers
        }
    
    if acao == '*':
        recommendations.append('Consider restricting Access-Control-Allow-Origin to specific origins instead of *')
    
    if overly_permissive:
        recommendations.append('Avoid using Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true')
    
    return {
        'enabled': has_cors,
        'headers': cors_headers,
        'overly_permissive': overly_permissive,
        'recommendations': recommendations
    }

def _calculate_security_score(is_https, redirects_to_https, hsts, security_headers, csp, mixed_content, cors):
    """Calculate an overall HTTP security score."""
    score = 0
    max_score = 100
    
    # HTTPS (25 points)
    if is_https:
        score += 20
        if redirects_to_https:
            score += 5
    
    # HSTS (20 points)
    if hsts.get('enabled', False):
        if hsts.get('quality') == 'excellent':
            score += 20
        elif hsts.get('quality') == 'good':
            score += 15
        elif hsts.get('quality') == 'moderate':
            score += 10
        else:
            score += 5
    
    # Security Headers (25 points)
    present_headers = sum(security_headers['present'].values())
    total_headers = len(security_headers['present'])
    header_score = round((present_headers / total_headers) * 25)
    score += header_score
    
    # CSP (20 points)
    if csp.get('enabled', False):
        if not csp.get('report_only', True):  # Actual enforcing CSP
            if csp.get('quality') == 'excellent':
                score += 20
            elif csp.get('quality') == 'good':
                score += 15
            elif csp.get('quality') == 'moderate':
                score += 10
            else:
                score += 5
        else:  # Report-only CSP
            score += 5
    
    # Mixed Content (10 points)
    if not mixed_content.get('has_mixed_content', True):
        score += 10
    elif mixed_content.get('mixed_content_count', 0) < 3:
        score += 5
    
    # Calculate grade
    grade = 'A+' if score >= 95 else 'A' if score >= 90 else 'B' if score >= 80 else 'C' if score >= 70 else 'D' if score >= 60 else 'F'
    
    # Calculate description
    if score >= 90:
        description = 'Excellent'
    elif score >= 80:
        description = 'Good'
    elif score >= 70:
        description = 'Fair'
    elif score >= 60:
        description = 'Poor'
    else:
        description = 'Very Poor'
    
    return {
        'score': score,
        'max_score': max_score,
        'percentage': score,
        'grade': grade,
        'description': description
    }