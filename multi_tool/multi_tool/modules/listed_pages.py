"""Module for extracting and analyzing pages listed on a website."""

import logging
import requests
import validators
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def extract_listed_pages(url, max_pages=100):
    """
    Extract and analyze pages listed on a website.
    
    Args:
        url (str): The URL to analyze
        max_pages (int, optional): Maximum number of pages to extract. Defaults to 100.
        
    Returns:
        dict: Listed pages and their analysis
    """
    logger.debug(f"Extracting listed pages for URL: {url}")
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    if not validators.url(url):
        raise ValueError(f"Invalid URL: {url}")
    
    try:
        # Fetch URL
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        # Parse with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract page links
        page_links = _extract_page_links(soup, url, max_pages)
        
        # Categorize links
        categorized_links = _categorize_links(page_links, url)
        
        # Extract navigation structure
        navigation = _extract_navigation(soup, url)
        
        # Identify important pages
        important_pages = _identify_important_pages(soup, page_links, url)
        
        # Analyze link distribution
        link_distribution = _analyze_link_distribution(categorized_links)
        
        result = {
            'url': url,
            'total_links': len(page_links),
            'categorized_links': categorized_links,
            'navigation': navigation,
            'important_pages': important_pages,
            'link_distribution': link_distribution
        }
        
        logger.debug(f"Listed pages result: {result}")
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL: {e}")
        raise

def _extract_page_links(soup, base_url, max_pages):
    """Extract all page links from the HTML content."""
    parsed_url = urlparse(base_url)
    base_domain = parsed_url.netloc
    
    links = []
    link_tags = soup.find_all('a', href=True)
    
    # Process each link
    for link in link_tags:
        href = link.get('href', '')
        
        # Skip empty links, javascript, and anchors
        if not href or href.startswith(('javascript:', '#', 'mailto:', 'tel:')):
            continue
        
        # Normalize URL
        absolute_url = urljoin(base_url, href)
        
        # Parse URL
        parsed_link = urlparse(absolute_url)
        
        # Skip non-HTTP links
        if not parsed_link.scheme in ('http', 'https'):
            continue
        
        # Get link text and title
        link_text = link.get_text(strip=True) or None
        link_title = link.get('title') or None
        
        # Determine if it's an internal link
        is_internal = parsed_link.netloc == base_domain
        
        # Determine link type based on content
        link_type = _determine_link_type(link, parsed_link.path)
        
        links.append({
            'url': absolute_url,
            'text': link_text,
            'title': link_title,
            'internal': is_internal,
            'type': link_type,
            'path': parsed_link.path
        })
        
        # Limit the number of links
        if len(links) >= max_pages:
            break
    
    return links

def _determine_link_type(link_tag, path):
    """Determine the type of link based on content."""
    link_text = link_tag.get_text(strip=True).lower()
    link_class = ' '.join(link_tag.get('class', [])).lower()
    link_id = link_tag.get('id', '').lower()
    
    # Check for specific link types
    if re.search(r'(home|homepage|main page)', link_text):
        return 'homepage'
    elif re.search(r'(about|about us|company|who we are)', link_text):
        return 'about'
    elif re.search(r'(contact|get in touch|reach us)', link_text):
        return 'contact'
    elif re.search(r'(product|service|solution)', link_text):
        return 'product'
    elif re.search(r'(blog|article|news|post)', link_text) or '/blog/' in path:
        return 'blog'
    elif re.search(r'(privacy|privacy policy)', link_text) or 'privacy' in path:
        return 'privacy'
    elif re.search(r'(terms|terms of service|tos|terms and conditions)', link_text) or 'terms' in path:
        return 'terms'
    elif re.search(r'(login|sign in|signin|log in)', link_text) or any(x in path for x in ['/login', '/signin']):
        return 'login'
    elif re.search(r'(register|sign up|signup|create account)', link_text) or any(x in path for x in ['/register', '/signup']):
        return 'register'
    elif re.search(r'(faq|help|support)', link_text) or any(x in path for x in ['/faq', '/help', '/support']):
        return 'support'
    elif 'search' in link_text or 'search' in link_class or 'search' in link_id or '/search' in path:
        return 'search'
    elif re.search(r'(cart|basket|checkout)', link_text) or any(x in path for x in ['/cart', '/basket', '/checkout']):
        return 'cart'
    
    # Default to 'general' for other links
    return 'general'

def _categorize_links(links, base_url):
    """Categorize links into internal and external."""
    parsed_url = urlparse(base_url)
    base_domain = parsed_url.netloc
    
    # Internal links
    internal_links = [link for link in links if link['internal']]
    
    # External links
    external_links = [link for link in links if not link['internal']]
    
    # Group internal links by type
    internal_by_type = {}
    for link in internal_links:
        link_type = link['type']
        if link_type not in internal_by_type:
            internal_by_type[link_type] = []
        internal_by_type[link_type].append(link)
    
    # Group by directory structure
    directory_structure = {}
    for link in internal_links:
        path = link['path']
        parts = path.strip('/').split('/')
        
        if not parts[0]:
            continue
            
        top_dir = parts[0]
        if top_dir not in directory_structure:
            directory_structure[top_dir] = []
        directory_structure[top_dir].append(link)
    
    return {
        'internal': {
            'count': len(internal_links),
            'by_type': internal_by_type,
            'by_directory': directory_structure
        },
        'external': {
            'count': len(external_links),
            'links': external_links
        }
    }

def _extract_navigation(soup, base_url):
    """Extract navigation structure from the page."""
    # Look for common navigation elements
    nav_elements = soup.find_all('nav') or soup.find_all(class_=re.compile('nav|menu'))
    
    if not nav_elements:
        # Try to find header or main menus if no nav elements found
        nav_elements = soup.find_all(class_=re.compile('header')) or soup.find_all(id=re.compile('menu|nav'))
    
    navigation = []
    
    for nav in nav_elements:
        nav_items = []
        links = nav.find_all('a', href=True)
        
        for link in links:
            href = link.get('href', '')
            
            # Skip empty links and javascript
            if not href or href.startswith(('javascript:', 'mailto:', 'tel:')):
                continue
            
            # Normalize URL
            absolute_url = urljoin(base_url, href)
            
            nav_items.append({
                'text': link.get_text(strip=True),
                'url': absolute_url,
                'current': link.get('aria-current') == 'page' or 'active' in link.get('class', [])
            })
        
        if nav_items:
            navigation.append({
                'items': nav_items,
                'location': _determine_nav_location(nav)
            })
    
    return navigation

def _determine_nav_location(nav_element):
    """Determine the location of navigation in the page layout."""
    # Get position relative to page
    parent_tags = []
    for parent in nav_element.parents:
        if parent.name:
            parent_tags.append(parent.name)
    
    if 'header' in parent_tags:
        return 'header'
    elif 'footer' in parent_tags:
        return 'footer'
    elif 'aside' in parent_tags or 'sidebar' in nav_element.get('class', []):
        return 'sidebar'
    else:
        return 'main'

def _identify_important_pages(soup, links, base_url):
    """Identify important pages based on prominence and link frequency."""
    # Count link occurrences
    link_counts = {}
    
    for link in links:
        if link['internal']:
            url = link['url']
            if url not in link_counts:
                link_counts[url] = 0
            link_counts[url] += 1
    
    # Find prominent links (those in navigation, header, etc.)
    prominent_links = []
    
    # Look for links in header
    header = soup.find('header')
    if header:
        for link in header.find_all('a', href=True):
            href = link.get('href', '')
            if href and not href.startswith(('javascript:', '#')):
                absolute_url = urljoin(base_url, href)
                prominent_links.append(absolute_url)
    
    # Look for links in navigation
    nav_elements = soup.find_all('nav')
    for nav in nav_elements:
        for link in nav.find_all('a', href=True):
            href = link.get('href', '')
            if href and not href.startswith(('javascript:', '#')):
                absolute_url = urljoin(base_url, href)
                prominent_links.append(absolute_url)
    
    # Sort links by frequency and prominence
    important_pages = []
    
    # First add prominent internal links
    parsed_url = urlparse(base_url)
    base_domain = parsed_url.netloc
    
    for url in prominent_links:
        parsed_link = urlparse(url)
        if parsed_link.netloc == base_domain:
            link_obj = next((link for link in links if link['url'] == url), None)
            if link_obj and url not in [page['url'] for page in important_pages]:
                important_pages.append({
                    'url': url,
                    'text': link_obj['text'],
                    'type': link_obj['type'],
                    'prominence': 'high',
                    'frequency': link_counts.get(url, 1)
                })
    
    # Then add frequently occurring links
    for url, count in sorted(link_counts.items(), key=lambda x: x[1], reverse=True):
        if url not in [page['url'] for page in important_pages] and count > 1:
            link_obj = next((link for link in links if link['url'] == url), None)
            if link_obj:
                important_pages.append({
                    'url': url,
                    'text': link_obj['text'],
                    'type': link_obj['type'],
                    'prominence': 'medium' if count >= 3 else 'low',
                    'frequency': count
                })
    
    # Limit to top 20 important pages
    return important_pages[:20]

def _analyze_link_distribution(categorized_links):
    """Analyze the distribution of links on the page."""
    # Calculate percentages
    total_links = categorized_links['internal']['count'] + categorized_links['external']['count']
    
    if total_links == 0:
        return {
            'internal_ratio': 0,
            'external_ratio': 0,
            'distribution_quality': 'No links found'
        }
    
    internal_ratio = round((categorized_links['internal']['count'] / total_links) * 100)
    external_ratio = round((categorized_links['external']['count'] / total_links) * 100)
    
    # Analyze internal link types
    internal_types = categorized_links['internal']['by_type']
    type_distribution = {}
    
    for link_type, links in internal_types.items():
        type_distribution[link_type] = round((len(links) / total_links) * 100)
    
    # Assess distribution quality
    if categorized_links['internal']['count'] > 0 and len(internal_types) >= 5:
        distribution_quality = 'Good - diverse internal link types'
    elif categorized_links['internal']['count'] > 0 and len(internal_types) >= 3:
        distribution_quality = 'Fair - moderate internal link diversity'
    elif categorized_links['internal']['count'] > 0:
        distribution_quality = 'Poor - limited internal link diversity'
    else:
        distribution_quality = 'No internal links found'
    
    return {
        'internal_ratio': internal_ratio,
        'external_ratio': external_ratio,
        'internal_type_distribution': type_distribution,
        'distribution_quality': distribution_quality
    }