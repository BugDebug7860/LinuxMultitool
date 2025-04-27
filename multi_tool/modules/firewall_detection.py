"""Module for detecting and analyzing web application firewalls."""

import logging
import requests
import validators
import re
import time
import random
import socket
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def detect_firewall(url):
    """
    Detect and analyze web application firewalls (WAFs) on a website.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Firewall detection results
    """
    logger.debug(f"Detecting firewalls for URL: {url}")
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    if not validators.url(url):
        raise ValueError(f"Invalid URL: {url}")
    
    try:
        # Extract domain for additional checks
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Get server information
        server_info = _get_server_info(url)
        
        # Get initial response to establish baseline
        baseline_response = _get_baseline(url)
        
        # Check for firewall fingerprints in headers and cookies
        header_signatures = _check_header_signatures(baseline_response)
        
        # Perform active detection tests
        active_tests = _perform_active_tests(url, baseline_response)
        
        # Check for cloud-based security services
        cloud_security = _check_cloud_security(domain, server_info)
        
        # Combine and analyze results
        detected_firewalls = header_signatures['firewalls'] + active_tests['firewalls'] + cloud_security['firewalls']
        detected_firewalls = list(set(detected_firewalls))  # Remove duplicates
        
        # Determine confidence level
        if detected_firewalls:
            if len(detected_firewalls) >= 2 or active_tests['confidence'] == 'high':
                confidence = 'high'
            elif active_tests['confidence'] == 'medium' or header_signatures['confidence'] == 'high':
                confidence = 'medium'
            else:
                confidence = 'low'
        else:
            confidence = 'none'
        
        result = {
            'url': url,
            'domain': domain,
            'server_info': server_info,
            'header_analysis': header_signatures,
            'active_tests': active_tests,
            'cloud_security': cloud_security,
            'detected_firewalls': detected_firewalls,
            'firewall_detected': len(detected_firewalls) > 0,
            'detection_confidence': confidence
        }
        
        logger.debug(f"Firewall detection result: {result}")
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL: {e}")
        raise

def _get_server_info(url):
    """Get server information from HTTP headers."""
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        
        server = headers.get('Server', 'Not disclosed')
        powered_by = headers.get('X-Powered-By', 'Not disclosed')
        
        return {
            'server': server,
            'powered_by': powered_by,
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds()
        }
    except requests.exceptions.RequestException as e:
        logger.debug(f"Error getting server info: {e}")
        return {
            'server': 'Unknown',
            'powered_by': 'Unknown',
            'status_code': None,
            'response_time': None,
            'error': str(e)
        }

def _get_baseline(url):
    """Get baseline response for comparison."""
    try:
        response = requests.get(url, timeout=10)
        return {
            'headers': dict(response.headers),
            'cookies': dict(response.cookies),
            'status_code': response.status_code,
            'content_length': len(response.content),
            'response_time': response.elapsed.total_seconds()
        }
    except requests.exceptions.RequestException as e:
        logger.debug(f"Error getting baseline: {e}")
        return {
            'headers': {},
            'cookies': {},
            'status_code': None,
            'content_length': 0,
            'response_time': 0,
            'error': str(e)
        }

def _check_header_signatures(baseline):
    """Check for firewall signatures in HTTP headers and cookies."""
    headers = baseline.get('headers', {})
    cookies = baseline.get('cookies', {})
    
    # Known firewall signatures in headers
    waf_signatures = {
        'Cloudflare': [
            {'header': 'CF-Cache-Status', 'pattern': '.+'},
            {'header': 'CF-Ray', 'pattern': '.+'},
            {'header': 'Server', 'pattern': 'cloudflare'}
        ],
        'Akamai': [
            {'header': 'X-Akamai-Transformed', 'pattern': '.+'},
            {'header': 'Server', 'pattern': 'AkamaiGHost'}
        ],
        'AWS WAF': [
            {'header': 'X-AMZ-CF-ID', 'pattern': '.+'},
        ],
        'Sucuri': [
            {'header': 'X-Sucuri-ID', 'pattern': '.+'},
            {'header': 'Server', 'pattern': 'Sucuri/Cloudproxy'}
        ],
        'Incapsula': [
            {'header': 'X-Iinfo', 'pattern': '.+'},
            {'header': 'X-CDN', 'pattern': 'Incapsula'},
            {'header': 'Set-Cookie', 'pattern': 'incap_ses_'}
        ],
        'Fastly': [
            {'header': 'X-Served-By', 'pattern': 'cache-.*-fastly'},
            {'header': 'X-Cache', 'pattern': '.+'},
            {'header': 'Fastly-Debug-Digest', 'pattern': '.+'}
        ],
        'F5 BIG-IP': [
            {'header': 'Server', 'pattern': 'BigIP'},
            {'header': 'Set-Cookie', 'pattern': 'BIGipServer'}
        ],
        'Barracuda': [
            {'header': 'Set-Cookie', 'pattern': 'barra_counter_session='}
        ],
        'Reblaze': [
            {'header': 'Set-Cookie', 'pattern': 'rbzid='},
        ],
        'Varnish': [
            {'header': 'X-Varnish', 'pattern': '.+'},
            {'header': 'Via', 'pattern': 'varnish'}
        ],
        'Nginx': [
            {'header': 'Server', 'pattern': 'nginx'},
            {'header': 'X-NginX-Proxy', 'pattern': '.+'}
        ],
        'ModSecurity': [
            {'header': 'Server', 'pattern': 'mod_security|NOYB'},
            {'header': 'X-Mod-Security', 'pattern': '.+'}
        ],
        'Imperva': [
            {'header': 'X-Iinfo', 'pattern': '.+'},
            {'header': 'Set-Cookie', 'pattern': 'incap_ses_|visid_incap_'}
        ],
        'Distil Networks': [
            {'header': 'X-Distil-CS', 'pattern': '.+'}
        ],
        'Citrix ADC': [
            {'header': 'Via', 'pattern': 'NS-CACHE'},
            {'header': 'Set-Cookie', 'pattern': 'citrix_ns_id'}
        ]
    }
    
    detected_firewalls = []
    matched_signatures = []
    
    for waf, signatures in waf_signatures.items():
        for signature in signatures:
            header_name = signature['header']
            pattern = signature['pattern']
            
            # Check in standard headers
            if header_name in headers:
                header_value = headers[header_name]
                if re.search(pattern, header_value, re.IGNORECASE):
                    if waf not in detected_firewalls:
                        detected_firewalls.append(waf)
                    matched_signatures.append({
                        'waf': waf,
                        'header': header_name,
                        'value': header_value,
                        'pattern': pattern
                    })
            
            # Special case for Set-Cookie header which might be in headers dict in a different format
            elif header_name == 'Set-Cookie':
                for cookie_name, cookie_value in cookies.items():
                    if re.search(pattern, f"{cookie_name}={cookie_value}", re.IGNORECASE):
                        if waf not in detected_firewalls:
                            detected_firewalls.append(waf)
                        matched_signatures.append({
                            'waf': waf,
                            'cookie': cookie_name,
                            'value': cookie_value,
                            'pattern': pattern
                        })
    
    # Determine confidence level
    if len(matched_signatures) >= 2:
        confidence = 'high'
    elif len(matched_signatures) == 1:
        confidence = 'medium'
    else:
        confidence = 'low'
    
    return {
        'firewalls': detected_firewalls,
        'matched_signatures': matched_signatures,
        'confidence': confidence
    }

def _perform_active_tests(url, baseline):
    """Perform active tests to detect firewalls by triggering security rules."""
    # Collection of tests to trigger firewall responses
    tests = [
        {
            'name': 'SQL Injection Test',
            'path': "?id=1' OR '1'='1",
            'expected_block': True,
            'target_wafs': ['ModSecurity', 'Cloudflare', 'Imperva', 'AWS WAF']
        },
        {
            'name': 'XSS Test',
            'path': "?test=<script>alert(1)</script>",
            'expected_block': True,
            'target_wafs': ['ModSecurity', 'Cloudflare', 'Imperva', 'AWS WAF']
        },
        {
            'name': 'Path Traversal Test',
            'path': "?file=../../../etc/passwd",
            'expected_block': True,
            'target_wafs': ['ModSecurity', 'Cloudflare', 'Imperva', 'F5 BIG-IP']
        },
        {
            'name': 'Command Injection Test',
            'path': "?cmd=cat%20/etc/passwd",
            'expected_block': True,
            'target_wafs': ['ModSecurity', 'Cloudflare', 'Imperva', 'AWS WAF']
        },
        {
            'name': 'User Agent Test',
            'headers': {'User-Agent': 'sqlmap/1.0'},
            'expected_block': True,
            'target_wafs': ['ModSecurity', 'Cloudflare', 'Imperva', 'AWS WAF']
        }
    ]
    
    detected_firewalls = []
    test_results = []
    
    # Convert URL to base URL
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    for test in tests:
        test_url = url
        extra_headers = {}
        
        # Add path for path-based tests
        if 'path' in test:
            test_url = f"{base_url}{test['path']}"
        
        # Add headers for header-based tests
        if 'headers' in test:
            extra_headers = test['headers']
        
        try:
            # Add a slight delay to avoid rate limiting
            time.sleep(random.uniform(0.5, 1.0))
            
            # Send the test request
            response = requests.get(test_url, headers=extra_headers, timeout=10, allow_redirects=False)
            
            # Check for signs of blocking
            is_blocked = (
                response.status_code in [403, 406, 429, 503] or  # Common blocking status codes
                'denied' in response.text.lower() or
                'blocked' in response.text.lower() or
                'security' in response.text.lower() or
                'protect' in response.text.lower() or
                'captcha' in response.text.lower() or
                'suspicious' in response.text.lower() or
                'waf' in response.text.lower()
            )
            
            # Check for specific WAF response headers
            for waf in test['target_wafs']:
                if waf not in detected_firewalls and is_blocked:
                    detected_firewalls.append(waf)
            
            test_results.append({
                'test_name': test['name'],
                'url': test_url,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'expected_block': test['expected_block'],
                'is_blocked': is_blocked,
                'content_length': len(response.content)
            })
        except requests.exceptions.RequestException as e:
            logger.debug(f"Error during active test {test['name']}: {e}")
            test_results.append({
                'test_name': test['name'],
                'url': test_url,
                'error': str(e)
            })
    
    # Determine confidence level
    blocked_tests = [test for test in test_results if test.get('is_blocked', False)]
    if len(blocked_tests) >= 3:
        confidence = 'high'
    elif len(blocked_tests) >= 1:
        confidence = 'medium'
    else:
        confidence = 'low'
    
    return {
        'firewalls': detected_firewalls,
        'test_results': test_results,
        'blocked_tests': len(blocked_tests),
        'total_tests': len(tests),
        'confidence': confidence
    }

def _check_cloud_security(domain, server_info):
    """Check for cloud-based security services using DNS and server info."""
    detected_firewalls = []
    
    # Check for CDN and cloud security services via DNS
    try:
        ip_addresses = socket.gethostbyname_ex(domain)[2]
        
        # Known CDN and security service IP ranges (simplified for demonstration)
        cdn_ip_ranges = {
            'Cloudflare': ['172.64.', '172.65.', '172.66.', '172.67.', '104.16.', '104.17.', '104.18.'],
            'Akamai': ['23.72.', '23.73.', '23.0.', '23.1.', '23.2.', '23.3.'],
            'Fastly': ['151.101.', '199.232.'],
            'AWS CloudFront': ['13.32.', '13.33.', '13.34.', '13.35.', '13.224.', '13.225.', '13.226.', '13.227.'],
            'Sucuri': ['192.124.249.', '66.248.200.']
        }
        
        for ip in ip_addresses:
            for cdn, ip_prefixes in cdn_ip_ranges.items():
                if any(ip.startswith(prefix) for prefix in ip_prefixes):
                    if cdn not in detected_firewalls:
                        detected_firewalls.append(cdn)
    except socket.gaierror:
        pass
    
    # Check server info for additional clues
    server = server_info.get('server', '').lower()
    powered_by = server_info.get('powered_by', '').lower()
    
    if 'cloudflare' in server:
        if 'Cloudflare' not in detected_firewalls:
            detected_firewalls.append('Cloudflare')
    
    if 'akamai' in server:
        if 'Akamai' not in detected_firewalls:
            detected_firewalls.append('Akamai')
    
    if 'sucuri' in server:
        if 'Sucuri' not in detected_firewalls:
            detected_firewalls.append('Sucuri')
    
    # Check for additional CNAME records that might indicate security services
    try:
        import dns.resolver
        cname_records = dns.resolver.resolve(domain, 'CNAME')
        for record in cname_records:
            cname = str(record.target).lower()
            
            if 'cloudflare' in cname:
                if 'Cloudflare' not in detected_firewalls:
                    detected_firewalls.append('Cloudflare')
            
            if 'akamaiedge' in cname:
                if 'Akamai' not in detected_firewalls:
                    detected_firewalls.append('Akamai')
            
            if 'fastly' in cname:
                if 'Fastly' not in detected_firewalls:
                    detected_firewalls.append('Fastly')
            
            if 'cloudfront' in cname:
                if 'AWS CloudFront' not in detected_firewalls:
                    detected_firewalls.append('AWS CloudFront')
    except Exception as e:
        logger.debug(f"Error checking CNAME records: {e}")
    
    return {
        'firewalls': detected_firewalls,
        'ip_addresses': locals().get('ip_addresses', []),
        'confidence': 'medium' if detected_firewalls else 'low'
    }