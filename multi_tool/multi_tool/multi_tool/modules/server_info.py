"""Module for retrieving and analyzing server information."""

import logging
import requests
import validators
import socket
import re
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_server_info(url):
    """
    Get detailed information about a server hosting a website.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Server information
    """
    logger.debug(f"Getting server information for URL: {url}")
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    if not validators.url(url):
        raise ValueError(f"Invalid URL: {url}")
    
    # Parse domain from URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    try:
        # Fetch website
        response = requests.get(url, timeout=10)
        headers = dict(response.headers)
        
        # Basic server info from headers
        server = headers.get('Server', 'Not disclosed')
        powered_by = headers.get('X-Powered-By', None)
        content_type = headers.get('Content-Type', None)
        
        # CDN detection
        cdn_info = _detect_cdn(headers, domain)
        
        # IP address and hostname information
        network_info = _get_network_info(domain)
        
        # Extract software/framework hints
        software_hints = _detect_software(headers, response.text, url)
        
        # Detect server OS (based on hints and patterns)
        os_info = _detect_os(server, powered_by, headers)
        
        # Detect web server version
        server_version = _extract_server_version(server)
        
        # HTTP/2 or HTTP/3 support
        protocol_version = _detect_protocol_version(headers)
        
        # Additional headers of interest
        interesting_headers = _extract_interesting_headers(headers)
        
        result = {
            'url': url,
            'domain': domain,
            'server': {
                'name': server,
                'version': server_version,
                'powered_by': powered_by,
                'operating_system': os_info,
                'protocol': protocol_version
            },
            'content': {
                'type': content_type,
                'encoding': headers.get('Content-Encoding', None),
                'language': headers.get('Content-Language', None)
            },
            'network': network_info,
            'cdn': cdn_info,
            'software': software_hints,
            'headers': interesting_headers
        }
        
        logger.debug(f"Server info result: {result}")
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL: {e}")
        raise

def _detect_cdn(headers, domain):
    """Detect if the site is using a CDN and which one."""
    cdn_headers = {
        'X-CDN': None,
        'X-Cache': None,
        'X-Served-By': None,
        'X-Edge-Location': None,
        'CF-Cache-Status': None,  # Cloudflare
        'X-Amz-Cf-Id': None,  # Amazon CloudFront
        'X-Fastly-Request-ID': None,  # Fastly
        'X-Cache-Hits': None,  # Akamai
        'X-Akamai-Transformed': None,  # Akamai
        'X-Varnish': None  # Varnish
    }
    
    for header in cdn_headers:
        cdn_headers[header] = headers.get(header, None)
    
    # Check for specific CDN signatures
    cdn_name = None
    
    if headers.get('CF-Cache-Status') or headers.get('CF-Ray'):
        cdn_name = 'Cloudflare'
    elif headers.get('X-Amz-Cf-Id'):
        cdn_name = 'Amazon CloudFront'
    elif headers.get('X-Fastly-Request-ID'):
        cdn_name = 'Fastly'
    elif headers.get('X-Cache') and ('Akamai' in headers.get('Server', '')):
        cdn_name = 'Akamai'
    elif headers.get('X-Varnish'):
        cdn_name = 'Varnish (possibly through a CDN)'
    elif 'Sucuri/Shield' in headers.get('Server', ''):
        cdn_name = 'Sucuri'
    elif 'X-Cache' in headers and ('HIT' in headers.get('X-Cache', '') or 'MISS' in headers.get('X-Cache', '')):
        cdn_name = 'Generic CDN (specific provider unknown)'
    
    return {
        'using_cdn': cdn_name is not None,
        'cdn_provider': cdn_name,
        'cdn_headers': {k: v for k, v in cdn_headers.items() if v is not None}
    }

def _get_network_info(domain):
    """Get network information for a domain."""
    try:
        # Get primary IP address
        ip_address = socket.gethostbyname(domain)
        
        # Try to get all IP addresses
        all_ips = []
        try:
            addr_info = socket.getaddrinfo(domain, None)
            for info in addr_info:
                if info[4][0] not in all_ips and info[4][0] != ip_address:
                    all_ips.append(info[4][0])
        except socket.gaierror:
            pass
        
        # Try to get hostname from IP
        hostname = None
        try:
            hostname_info = socket.gethostbyaddr(ip_address)
            hostname = hostname_info[0]
        except (socket.herror, socket.gaierror):
            hostname = None
        
        return {
            'ip_address': ip_address,
            'additional_ips': all_ips,
            'hostname': hostname
        }
    except socket.gaierror:
        return {
            'ip_address': None,
            'additional_ips': [],
            'hostname': None,
            'error': 'Could not resolve domain'
        }

def _detect_software(headers, content, url):
    """Detect software and frameworks from headers and content."""
    software = {'detected': []}
    
    # Check headers for framework hints
    if 'X-Powered-By' in headers:
        if 'PHP' in headers['X-Powered-By']:
            software['detected'].append({'name': 'PHP', 'type': 'Language', 'confidence': 'High'})
            php_version = re.search(r'PHP/([0-9.]+)', headers['X-Powered-By'])
            if php_version:
                software['detected'][-1]['version'] = php_version.group(1)
        
        if 'ASP.NET' in headers['X-Powered-By']:
            software['detected'].append({'name': 'ASP.NET', 'type': 'Framework', 'confidence': 'High'})
            aspnet_version = re.search(r'ASP\.NET[^0-9]*([0-9.]+)', headers['X-Powered-By'])
            if aspnet_version:
                software['detected'][-1]['version'] = aspnet_version.group(1)
    
    # Check for JavaScript frameworks in content
    if content:
        if 'react' in content.lower() and 'reactdom' in content.lower():
            software['detected'].append({'name': 'React', 'type': 'JavaScript Framework', 'confidence': 'Medium'})
        
        if 'angular' in content.lower():
            software['detected'].append({'name': 'Angular', 'type': 'JavaScript Framework', 'confidence': 'Medium'})
        
        if 'vue' in content.lower() and ('vuejs' in content.lower() or 'vue.js' in content.lower()):
            software['detected'].append({'name': 'Vue.js', 'type': 'JavaScript Framework', 'confidence': 'Medium'})
        
        if 'jquery' in content.lower():
            software['detected'].append({'name': 'jQuery', 'type': 'JavaScript Library', 'confidence': 'Medium'})
            
        if 'bootstrap' in content.lower():
            software['detected'].append({'name': 'Bootstrap', 'type': 'CSS Framework', 'confidence': 'Medium'})
            
        if 'wordpress' in content.lower():
            software['detected'].append({'name': 'WordPress', 'type': 'CMS', 'confidence': 'Medium'})
            
        if 'drupal' in content.lower():
            software['detected'].append({'name': 'Drupal', 'type': 'CMS', 'confidence': 'Medium'})
            
        if 'joomla' in content.lower():
            software['detected'].append({'name': 'Joomla', 'type': 'CMS', 'confidence': 'Medium'})
    
    # Check headers for caching software
    if 'X-Varnish' in headers:
        software['detected'].append({'name': 'Varnish', 'type': 'Cache', 'confidence': 'High'})
    
    if 'X-Drupal-Cache' in headers:
        software['detected'].append({'name': 'Drupal', 'type': 'CMS', 'confidence': 'High'})
    
    if 'X-Powered-CMS' in headers:
        software['detected'].append({'name': headers['X-Powered-CMS'], 'type': 'CMS', 'confidence': 'High'})
    
    # Check for WordPress by checking for wp-json endpoint
    try:
        wp_check = requests.head(f"{url.rstrip('/')}/wp-json/", timeout=5)
        if wp_check.status_code in (200, 301, 302, 308):
            if not any(sw['name'] == 'WordPress' for sw in software['detected']):
                software['detected'].append({'name': 'WordPress', 'type': 'CMS', 'confidence': 'High'})
    except:
        pass
    
    return software

def _detect_os(server, powered_by, headers):
    """Detect the server's operating system based on hints."""
    os_info = {'name': 'Unknown', 'confidence': 'Low'}
    
    # Check server header for OS hints
    if server:
        if 'win' in server.lower():
            os_info = {'name': 'Windows', 'confidence': 'Medium'}
        elif 'ubuntu' in server.lower():
            os_info = {'name': 'Ubuntu', 'confidence': 'High'}
        elif 'debian' in server.lower():
            os_info = {'name': 'Debian', 'confidence': 'High'}
        elif 'centos' in server.lower():
            os_info = {'name': 'CentOS', 'confidence': 'High'}
        elif 'fedora' in server.lower():
            os_info = {'name': 'Fedora', 'confidence': 'High'}
        elif 'red hat' in server.lower() or 'redhat' in server.lower():
            os_info = {'name': 'Red Hat', 'confidence': 'High'}
        elif 'unix' in server.lower():
            os_info = {'name': 'Unix-based', 'confidence': 'Medium'}
        elif 'linux' in server.lower():
            os_info = {'name': 'Linux', 'confidence': 'Medium'}
    
    # Check X-Powered-By for OS hints
    if powered_by:
        if 'win' in powered_by.lower():
            os_info = {'name': 'Windows', 'confidence': 'Medium'}
        elif 'ubuntu' in powered_by.lower():
            os_info = {'name': 'Ubuntu', 'confidence': 'High'}
        elif 'debian' in powered_by.lower():
            os_info = {'name': 'Debian', 'confidence': 'High'}
        elif 'centos' in powered_by.lower():
            os_info = {'name': 'CentOS', 'confidence': 'High'}
        elif 'fedora' in powered_by.lower():
            os_info = {'name': 'Fedora', 'confidence': 'High'}
        elif 'red hat' in powered_by.lower() or 'redhat' in powered_by.lower():
            os_info = {'name': 'Red Hat', 'confidence': 'High'}
        elif 'unix' in powered_by.lower():
            os_info = {'name': 'Unix-based', 'confidence': 'Medium'}
        elif 'linux' in powered_by.lower():
            os_info = {'name': 'Linux', 'confidence': 'Medium'}
    
    # Infer OS from server software (less reliable)
    if os_info['name'] == 'Unknown' and server:
        if 'apache' in server.lower():
            os_info = {'name': 'Likely Linux/Unix', 'confidence': 'Low'}
        elif 'nginx' in server.lower():
            os_info = {'name': 'Likely Linux/Unix', 'confidence': 'Low'}
        elif 'iis' in server.lower() or 'microsoft' in server.lower():
            os_info = {'name': 'Windows', 'confidence': 'Medium'}
    
    return os_info

def _extract_server_version(server):
    """Extract the version from the server header if available."""
    if not server:
        return None
    
    # Common patterns for server versions
    patterns = [
        r'Apache/([0-9.]+)',
        r'nginx/([0-9.]+)',
        r'Microsoft-IIS/([0-9.]+)',
        r'LiteSpeed/([0-9.]+)',
        r'lighttpd/([0-9.]+)',
        r'Caddy/([0-9.]+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, server)
        if match:
            return match.group(1)
    
    return None

def _detect_protocol_version(headers):
    """Detect the HTTP protocol version used."""
    # Headers doesn't directly tell us HTTP/2 or HTTP/3
    # In a real implementation, you'd need to check during the connection
    # This is a placeholder that returns a default value
    return {
        'http_version': 'HTTP/1.1',  # Default assumption
        'note': 'HTTP/2 and HTTP/3 detection requires connection-level inspection not available through this tool'
    }

def _extract_interesting_headers(headers):
    """Extract interesting headers for security and configuration analysis."""
    interesting = {}
    
    # Security headers
    security_headers = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Feature-Policy',
        'Permissions-Policy'
    ]
    
    # Caching and performance headers
    caching_headers = [
        'Cache-Control',
        'Expires',
        'Last-Modified',
        'ETag',
        'Vary'
    ]
    
    # Server configuration headers
    config_headers = [
        'Accept-Ranges',
        'Connection',
        'Keep-Alive',
        'Transfer-Encoding',
        'Upgrade'
    ]
    
    # Add security headers if present
    interesting['security'] = {header: headers[header] for header in security_headers if header in headers}
    
    # Add caching headers if present
    interesting['caching'] = {header: headers[header] for header in caching_headers if header in headers}
    
    # Add configuration headers if present
    interesting['configuration'] = {header: headers[header] for header in config_headers if header in headers}
    
    return interesting