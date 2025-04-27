"""Module for analyzing linked pages from a website."""

import logging
import requests
import validators
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import time
from collections import Counter

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def analyze_linked_pages(url, max_pages=5, depth=1):
    """
    Analyze pages linked from a website, with optional crawling.
    
    Args:
        url (str): The URL to analyze
        max_pages (int, optional): Maximum number of pages to crawl. Defaults to 5.
        depth (int, optional): Crawl depth. Defaults to 1.
        
    Returns:
        dict: Analysis of linked pages
    """
    logger.debug(f"Analyzing linked pages for URL: {url}")
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    if not validators.url(url):
        raise ValueError(f"Invalid URL: {url}")
    
    try:
        # Initialize crawler state
        visited = set()
        to_visit = [{'url': url, 'depth': 0, 'parent': None}]
        pages_data = []
        link_graph = []
        
        # Extract domain for internal/external classification
        parsed_url = urlparse(url)
        base_domain = parsed_url.netloc
        
        # Crawl pages
        while to_visit and len(visited) < max_pages:
            # Get next URL to visit
            current = to_visit.pop(0)
            current_url = current['url']
            current_depth = current['depth']
            
            # Skip if already visited
            if current_url in visited:
                continue
            
            # Mark as visited
            visited.add(current_url)
            
            try:
                # Fetch page
                response = requests.get(current_url, timeout=10)
                content_type = response.headers.get('Content-Type', '')
                
                # Skip non-HTML content
                if 'text/html' not in content_type:
                    continue
                
                # Parse with BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract page data
                page_data = _extract_page_data(soup, current_url, base_domain)
                page_data['status_code'] = response.status_code
                page_data['content_type'] = content_type
                page_data['depth'] = current_depth
                pages_data.append(page_data)
                
                # If we haven't reached max depth, add child links to visit
                if current_depth < depth:
                    links = _extract_links(soup, current_url, base_domain)
                    
                    # Add link relationships to graph
                    for link in links:
                        link_graph.append({
                            'from': current_url,
                            'to': link['url'],
                            'text': link['text'],
                            'type': 'internal' if link['internal'] else 'external'
                        })
                    
                    # Add new internal links to visit
                    internal_links = [link for link in links if link['internal']]
                    for link in internal_links:
                        if link['url'] not in visited:
                            to_visit.append({
                                'url': link['url'],
                                'depth': current_depth + 1,
                                'parent': current_url
                            })
                
                # Respect crawl delay
                time.sleep(1)
                
            except requests.exceptions.RequestException as e:
                logger.debug(f"Error fetching {current_url}: {e}")
                # Add error information
                page_data = {
                    'url': current_url,
                    'error': str(e),
                    'depth': current_depth
                }
                pages_data.append(page_data)
        
        # Analyze crawl results
        analysis = _analyze_crawl_results(pages_data, link_graph, base_domain)
        
        result = {
            'url': url,
            'pages_crawled': len(pages_data),
            'pages': pages_data,
            'link_graph': link_graph,
            'analysis': analysis
        }
        
        logger.debug(f"Linked pages analysis result: {result}")
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL: {e}")
        raise

def _extract_page_data(soup, url, base_domain):
    """Extract data from a page."""
    # Get page title
    title = soup.title.text.strip() if soup.title else None
    
    # Get meta description
    meta_desc = soup.find('meta', attrs={'name': 'description'})
    description = meta_desc['content'] if meta_desc else None
    
    # Get H1
    h1 = soup.find('h1')
    h1_text = h1.get_text(strip=True) if h1 else None
    
    # Count links
    links = soup.find_all('a', href=True)
    internal_links = []
    external_links = []
    
    parsed_url = urlparse(url)
    for link in links:
        href = link.get('href', '')
        if not href or href.startswith(('javascript:', '#')):
            continue
            
        absolute_url = urljoin(url, href)
        parsed_link = urlparse(absolute_url)
        
        link_data = {
            'url': absolute_url,
            'text': link.get_text(strip=True)
        }
        
        if parsed_link.netloc == base_domain:
            internal_links.append(link_data)
        else:
            external_links.append(link_data)
    
    # Get canonical URL if specified
    canonical = soup.find('link', rel='canonical')
    canonical_url = canonical['href'] if canonical else None
    
    # Check for pagination links
    next_link = soup.find('link', rel='next') or soup.find('a', rel='next')
    prev_link = soup.find('link', rel='prev') or soup.find('a', rel='prev')
    
    has_pagination = bool(next_link or prev_link)
    
    return {
        'url': url,
        'title': title,
        'description': description,
        'h1': h1_text,
        'links': {
            'internal': len(internal_links),
            'external': len(external_links),
            'total': len(internal_links) + len(external_links)
        },
        'canonical': canonical_url,
        'pagination': has_pagination
    }

def _extract_links(soup, url, base_domain):
    """Extract links from a page."""
    links = []
    link_tags = soup.find_all('a', href=True)
    
    for link in link_tags:
        href = link.get('href', '')
        
        # Skip empty links, javascript, and anchors
        if not href or href.startswith(('javascript:', '#', 'mailto:', 'tel:')):
            continue
        
        # Normalize URL
        absolute_url = urljoin(url, href)
        
        # Parse URL
        parsed_link = urlparse(absolute_url)
        
        # Skip non-HTTP links
        if parsed_link.scheme not in ('http', 'https'):
            continue
        
        # Get link text
        link_text = link.get_text(strip=True) or None
        
        # Determine if it's an internal link
        is_internal = parsed_link.netloc == base_domain
        
        links.append({
            'url': absolute_url,
            'text': link_text,
            'internal': is_internal
        })
    
    return links

def _analyze_crawl_results(pages_data, link_graph, base_domain):
    """Analyze the results of the crawl."""
    # Count successful vs. error pages
    successful_pages = [page for page in pages_data if 'error' not in page]
    error_pages = [page for page in pages_data if 'error' in page]
    
    # Identify most linked pages (link popularity)
    link_targets = [link['to'] for link in link_graph]
    popular_pages = Counter(link_targets).most_common(5)
    
    # Check for duplicate titles and descriptions
    page_titles = [page.get('title') for page in successful_pages if page.get('title')]
    duplicate_titles = [title for title, count in Counter(page_titles).items() if count > 1]
    
    page_descriptions = [page.get('description') for page in successful_pages if page.get('description')]
    duplicate_descriptions = [desc for desc, count in Counter(page_descriptions).items() if count > 1]
    
    # Check for broken internal links
    internal_links = [link for link in link_graph if link['type'] == 'internal']
    broken_links = []
    
    for link in internal_links:
        to_url = link['to']
        target_page = next((page for page in pages_data if page['url'] == to_url), None)
        if target_page and target_page.get('status_code', 200) >= 400:
            broken_links.append({
                'from': link['from'],
                'to': to_url,
                'status_code': target_page.get('status_code'),
                'text': link['text']
            })
    
    # Calculate average links per page
    avg_internal_links = sum(page['links']['internal'] for page in successful_pages) / len(successful_pages) if successful_pages else 0
    avg_external_links = sum(page['links']['external'] for page in successful_pages) / len(successful_pages) if successful_pages else 0
    
    # Check canonicalization issues
    canonicalization_issues = []
    for page in successful_pages:
        canonical = page.get('canonical')
        if canonical and canonical != page['url']:
            canonicalization_issues.append({
                'page': page['url'],
                'canonical': canonical
            })
    
    return {
        'summary': {
            'successful_pages': len(successful_pages),
            'error_pages': len(error_pages),
            'average_internal_links': round(avg_internal_links, 1),
            'average_external_links': round(avg_external_links, 1)
        },
        'popular_pages': [{'url': url, 'count': count} for url, count in popular_pages],
        'issues': {
            'broken_internal_links': broken_links,
            'duplicate_titles': duplicate_titles,
            'duplicate_descriptions': duplicate_descriptions,
            'canonicalization_issues': canonicalization_issues
        }
    }