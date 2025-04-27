"""Module for checking server status and availability."""

import logging
import requests
import validators
import socket
import time
import statistics
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_server_status(url, num_requests=3, timeout=10):
    """
    Check the status and availability of a server.
    
    Args:
        url (str): The URL to check
        num_requests (int, optional): Number of requests to make for averaging. Defaults to 3.
        timeout (int, optional): Request timeout in seconds. Defaults to 10.
        
    Returns:
        dict: Server status information
    """
    logger.debug(f"Checking server status for URL: {url}")
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    if not validators.url(url):
        raise ValueError(f"Invalid URL: {url}")
    
    # Parse domain from URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    try:
        # Resolve IP address
        try:
            ip_address = socket.gethostbyname(domain)
        except socket.gaierror:
            ip_address = None
        
        # Check port availability
        port = 443 if url.startswith('https://') else 80
        port_open = _check_port_open(domain, port)
        
        # Measure response times
        response_times = []
        statuses = []
        headers_list = []
        
        for _ in range(num_requests):
            try:
                start_time = time.time()
                response = requests.get(url, timeout=timeout, allow_redirects=False)
                response_time = time.time() - start_time
                
                response_times.append(response_time)
                statuses.append(response.status_code)
                headers_list.append(dict(response.headers))
                
                # Small delay to prevent overloading the server
                time.sleep(0.5)
                
            except requests.exceptions.RequestException as e:
                logger.debug(f"Request error: {e}")
        
        # Calculate statistics
        if response_times:
            avg_response_time = statistics.mean(response_times)
            min_response_time = min(response_times)
            max_response_time = max(response_times)
        else:
            avg_response_time = min_response_time = max_response_time = None
        
        # Check HTTP status
        if statuses:
            latest_status = statuses[-1]
            status_ok = 200 <= latest_status < 400
            redirecting = 300 <= latest_status < 400
            status_description = _get_status_description(latest_status)
        else:
            latest_status = None
            status_ok = False
            redirecting = False
            status_description = "Unable to connect"
        
        # Get latest headers
        latest_headers = headers_list[-1] if headers_list else {}
        
        # Analyze headers for server info
        server_info = {
            'server': latest_headers.get('Server'),
            'powered_by': latest_headers.get('X-Powered-By'),
            'content_type': latest_headers.get('Content-Type')
        }
        
        result = {
            'url': url,
            'domain': domain,
            'ip_address': ip_address,
            'port': port,
            'port_open': port_open,
            'connectivity': {
                'status_code': latest_status,
                'status_description': status_description,
                'successful': status_ok,
                'redirecting': redirecting,
                'redirect_location': latest_headers.get('Location', None) if redirecting else None
            },
            'performance': {
                'average_response_time': round(avg_response_time, 3) if avg_response_time is not None else None,
                'min_response_time': round(min_response_time, 3) if min_response_time is not None else None,
                'max_response_time': round(max_response_time, 3) if max_response_time is not None else None,
                'reliability': _calculate_reliability(statuses)
            },
            'server_info': server_info
        }
        
        # Provide a simple health rating
        result['health_rating'] = _calculate_health_rating(
            has_ip=ip_address is not None,
            port_open=port_open,
            status_ok=status_ok,
            avg_response_time=avg_response_time,
            reliability=result['performance']['reliability']
        )
        
        logger.debug(f"Server status result: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error checking server status: {e}")
        raise

def _check_port_open(host, port, timeout=3):
    """Check if a port is open on the host."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error, OSError):
        return False

def _get_status_description(status_code):
    """Get a description for an HTTP status code."""
    descriptions = {
        200: "OK",
        201: "Created",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found (Temporary Redirect)",
        303: "See Other",
        304: "Not Modified",
        307: "Temporary Redirect",
        308: "Permanent Redirect",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout"
    }
    return descriptions.get(status_code, f"Status code {status_code}")

def _calculate_reliability(statuses):
    """Calculate a reliability score based on status codes."""
    if not statuses:
        return {
            'score': 0,
            'description': "Not accessible"
        }
        
    # Count successful responses
    successful = sum(1 for status in statuses if 200 <= status < 400)
    success_rate = (successful / len(statuses)) * 100
    
    if success_rate == 100:
        return {
            'score': 10,
            'description': "Excellent"
        }
    elif success_rate >= 90:
        return {
            'score': 9,
            'description': "Very Good"
        }
    elif success_rate >= 80:
        return {
            'score': 8,
            'description': "Good"
        }
    elif success_rate >= 70:
        return {
            'score': 7,
            'description': "Fair"
        }
    elif success_rate >= 50:
        return {
            'score': 5,
            'description': "Poor"
        }
    else:
        return {
            'score': 3,
            'description': "Very Poor"
        }

def _calculate_health_rating(has_ip, port_open, status_ok, avg_response_time, reliability):
    """Calculate an overall health rating."""
    rating = 0
    max_rating = 10
    description = ""
    
    # IP resolution
    if has_ip:
        rating += 2
    
    # Port open
    if port_open:
        rating += 2
    
    # Status OK
    if status_ok:
        rating += 2
    
    # Response time
    if avg_response_time is not None:
        if avg_response_time < 0.5:  # Less than 500ms
            rating += 2
        elif avg_response_time < 1.0:  # Less than 1 second
            rating += 1.5
        elif avg_response_time < 2.0:  # Less than 2 seconds
            rating += 1
        elif avg_response_time < 5.0:  # Less than 5 seconds
            rating += 0.5
    
    # Reliability score (max 2 points)
    if reliability['score'] == 10:
        rating += 2
    elif reliability['score'] >= 8:
        rating += 1.5
    elif reliability['score'] >= 5:
        rating += 1
    elif reliability['score'] > 0:
        rating += 0.5
    
    # Determine description
    if rating >= 9:
        description = "Excellent"
    elif rating >= 7:
        description = "Good"
    elif rating >= 5:
        description = "Fair"
    elif rating >= 3:
        description = "Poor"
    else:
        description = "Critical"
    
    return {
        'score': round(rating, 1),
        'max_score': max_rating,
        'percentage': round((rating / max_rating) * 100),
        'description': description
    }