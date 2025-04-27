"""Module for analyzing crawl rules (robots.txt and similar)."""

import logging
import requests
import validators
from urllib.parse import urljoin
import re

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def analyze_crawl_rules(url):
    """
    Analyze crawl rules (robots.txt, meta robots, etc.) for a website.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Analysis of crawl rules
    """
    logger.debug(f"Analyzing crawl rules for URL: {url}")
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    if not validators.url(url):
        raise ValueError(f"Invalid URL: {url}")
    
    try:
        # Extract the domain from the URL
        domain_parts = url.split('/')
        base_url = f"{domain_parts[0]}//{domain_parts[2]}"
        
        # Get robots.txt
        robots_txt_url = urljoin(base_url, "/robots.txt")
        robots_txt_content = fetch_robots_txt(robots_txt_url)
        
        # Get main page for meta robots
        meta_robots = get_meta_robots(url)
        
        # Analyze robots.txt content
        robots_txt_analysis = analyze_robots_txt(robots_txt_content) if robots_txt_content else {
            'present': False,
            'content': None,
            'user_agents': [],
            'disallowed_paths': [],
            'allowed_paths': [],
            'sitemaps': [],
            'crawl_delay': None
        }
        
        result = {
            'url': url,
            'robots_txt': {
                'url': robots_txt_url,
                'accessible': robots_txt_content is not None,
                'analysis': robots_txt_analysis
            },
            'meta_robots': meta_robots
        }
        
        logger.debug(f"Crawl rules result: {result}")
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL: {e}")
        raise

def fetch_robots_txt(url):
    """
    Fetch robots.txt content.
    
    Args:
        url (str): The robots.txt URL
        
    Returns:
        str or None: Content of robots.txt, or None if not accessible
    """
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.text
        return None
    except requests.exceptions.RequestException:
        return None

def get_meta_robots(url):
    """
    Get meta robots tags from the URL.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Meta robots information
    """
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return {'present': False}
            
        content = response.text.lower()
        
        # Search for meta robots tags
        meta_robots_matches = re.findall(r'<meta[^>]*name=["\']robots["\'][^>]*content=["\']([^"\']*)["\']', content)
        meta_robots_matches.extend(re.findall(r'<meta[^>]*content=["\']([^"\']*)["\'][^>]*name=["\']robots["\']', content))
        
        # Search for noindex, nofollow in HTTP headers
        x_robots_tag = response.headers.get('X-Robots-Tag', '')
        
        result = {
            'present': bool(meta_robots_matches) or 'x-robots-tag' in response.headers,
            'meta_tags': meta_robots_matches,
            'x_robots_tag': x_robots_tag,
            'blocks_indexing': any('noindex' in tag for tag in meta_robots_matches) or 'noindex' in x_robots_tag.lower(),
            'blocks_following': any('nofollow' in tag for tag in meta_robots_matches) or 'nofollow' in x_robots_tag.lower()
        }
        
        return result
        
    except requests.exceptions.RequestException:
        return {'present': False, 'error': 'Failed to fetch URL'}

def analyze_robots_txt(content):
    """
    Analyze robots.txt content.
    
    Args:
        content (str): The robots.txt content
        
    Returns:
        dict: Analysis of robots.txt
    """
    if not content:
        return {'present': False}
        
    lines = content.split('\n')
    analysis = {
        'present': True,
        'content': content,
        'user_agents': [],
        'disallowed_paths': [],
        'allowed_paths': [],
        'sitemaps': [],
        'crawl_delay': None
    }
    
    current_agent = None
    
    for line in lines:
        line = line.strip()
        
        # Skip comments and empty lines
        if not line or line.startswith('#'):
            continue
            
        # Check for directives
        if ':' in line:
            directive, value = line.split(':', 1)
            directive = directive.strip().lower()
            value = value.strip()
            
            if directive == 'user-agent':
                current_agent = value
                if value not in analysis['user_agents']:
                    analysis['user_agents'].append(value)
            elif directive == 'disallow' and value:
                analysis['disallowed_paths'].append({
                    'user_agent': current_agent,
                    'path': value
                })
            elif directive == 'allow' and value:
                analysis['allowed_paths'].append({
                    'user_agent': current_agent,
                    'path': value
                })
            elif directive == 'sitemap' and value:
                analysis['sitemaps'].append(value)
            elif directive == 'crawl-delay' and value:
                try:
                    analysis['crawl_delay'] = float(value)
                except ValueError:
                    pass
    
    return analysis