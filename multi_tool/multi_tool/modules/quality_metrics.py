"""Module for assessing quality metrics of a website."""

import logging
import requests
import validators
import re
from bs4 import BeautifulSoup
import time

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def assess_quality_metrics(url, detailed=False):
    """
    Assess quality metrics for a website.
    
    Args:
        url (str): The URL to analyze
        detailed (bool, optional): Whether to perform detailed analysis. Defaults to False.
        
    Returns:
        dict: Quality metrics assessment
    """
    logger.debug(f"Assessing quality metrics for URL: {url}")
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    if not validators.url(url):
        raise ValueError(f"Invalid URL: {url}")
    
    try:
        # Fetch URL
        start_time = time.time()
        response = requests.get(url, timeout=30)
        response_time = time.time() - start_time
        response.raise_for_status()
        
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')
        
        # Base metrics assessment
        result = {
            'url': url,
            'performance': {
                'response_time': response_time,
                'page_size': len(content),
                'status_code': response.status_code
            },
            'seo': assess_seo_metrics(soup, url),
            'accessibility': assess_accessibility(soup),
            'security': assess_security(response),
            'mobile_friendliness': assess_mobile_friendliness(soup, response)
        }
        
        # Detailed content assessment
        if detailed:
            result['content_quality'] = assess_content_quality(soup)
        
        logger.debug(f"Quality metrics result: {result}")
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL: {e}")
        raise

def assess_seo_metrics(soup, url):
    """
    Assess SEO metrics for a website.
    
    Args:
        soup (BeautifulSoup): Parsed HTML content
        url (str): The URL being analyzed
        
    Returns:
        dict: SEO metrics assessment
    """
    title = soup.title.text.strip() if soup.title else None
    meta_description = soup.find('meta', attrs={'name': 'description'})
    meta_description = meta_description['content'] if meta_description else None
    
    h1_tags = soup.find_all('h1')
    h2_tags = soup.find_all('h2')
    h3_tags = soup.find_all('h3')
    
    # Check canonical URL
    canonical = soup.find('link', attrs={'rel': 'canonical'})
    canonical_url = canonical['href'] if canonical else None
    
    # Check image alt attributes
    images = soup.find_all('img')
    images_with_alt = [img for img in images if img.get('alt')]
    
    # Extract all links
    links = soup.find_all('a', href=True)
    internal_links = [link for link in links if link['href'].startswith('/') or url in link['href']]
    external_links = [link for link in links if not link['href'].startswith('/') and url not in link['href']]
    
    # Assess issues
    issues = []
    
    if not title or len(title) < 10:
        issues.append({
            'severity': 'high',
            'issue': 'Missing or short page title',
            'recommendation': 'Add a descriptive page title between 50-60 characters'
        })
        
    if not meta_description or len(meta_description) < 50:
        issues.append({
            'severity': 'medium',
            'issue': 'Missing or short meta description',
            'recommendation': 'Add a descriptive meta description between 150-160 characters'
        })
        
    if not h1_tags:
        issues.append({
            'severity': 'medium',
            'issue': 'Missing H1 tag',
            'recommendation': 'Add an H1 tag containing your main keyword'
        })
        
    if len(h1_tags) > 1:
        issues.append({
            'severity': 'low',
            'issue': 'Multiple H1 tags',
            'recommendation': 'Use only one H1 tag per page'
        })
    
    return {
        'title': {
            'present': title is not None,
            'content': title,
            'length': len(title) if title else 0
        },
        'meta_description': {
            'present': meta_description is not None,
            'content': meta_description,
            'length': len(meta_description) if meta_description else 0
        },
        'headings': {
            'h1_count': len(h1_tags),
            'h2_count': len(h2_tags),
            'h3_count': len(h3_tags)
        },
        'canonical': {
            'present': canonical_url is not None,
            'url': canonical_url
        },
        'images': {
            'total': len(images),
            'with_alt': len(images_with_alt),
            'without_alt': len(images) - len(images_with_alt)
        },
        'links': {
            'internal': len(internal_links),
            'external': len(external_links)
        },
        'issues': issues
    }

def assess_accessibility(soup):
    """
    Assess accessibility metrics for a website.
    
    Args:
        soup (BeautifulSoup): Parsed HTML content
        
    Returns:
        dict: Accessibility assessment
    """
    # Check for language
    html_tag = soup.find('html')
    lang_attr = html_tag.get('lang') if html_tag else None
    
    # Check for ARIA landmarks
    aria_landmarks = soup.find_all(attrs={'role': True})
    
    # Check form controls with labels
    inputs = soup.find_all('input')
    inputs_with_label = []
    inputs_without_label = []
    
    for inp in inputs:
        # Skip hidden inputs
        if inp.get('type') == 'hidden':
            continue
            
        # Check for id with associated label
        if inp.get('id'):
            label = soup.find('label', attrs={'for': inp['id']})
            if label:
                inputs_with_label.append(inp)
                continue
                
        # Check for aria-label
        if inp.get('aria-label'):
            inputs_with_label.append(inp)
            continue
            
        # Check for aria-labelledby
        if inp.get('aria-labelledby'):
            inputs_with_label.append(inp)
            continue
            
        # If we got here, the input has no label
        inputs_without_label.append(inp)
    
    # Check for color contrast (simple detection of potential issues)
    style_tags = soup.find_all('style')
    inline_styles = soup.find_all(style=True)
    
    # Issues list
    issues = []
    
    if not lang_attr:
        issues.append({
            'severity': 'medium',
            'issue': 'Missing language attribute',
            'recommendation': 'Add a lang attribute to the html tag (e.g., <html lang="en">)'
        })
    
    if len(inputs_without_label) > 0:
        issues.append({
            'severity': 'high',
            'issue': f'{len(inputs_without_label)} input elements without labels found',
            'recommendation': 'Add labels for all form controls'
        })
    
    return {
        'language': {
            'specified': lang_attr is not None,
            'value': lang_attr
        },
        'aria': {
            'landmarks': len(aria_landmarks)
        },
        'forms': {
            'inputs_with_label': len(inputs_with_label),
            'inputs_without_label': len(inputs_without_label)
        },
        'issues': issues
    }

def assess_security(response):
    """
    Assess security metrics for a website.
    
    Args:
        response (requests.Response): The HTTP response
        
    Returns:
        dict: Security assessment
    """
    headers = response.headers
    
    # Check security headers
    security_headers = {
        'strict-transport-security': headers.get('Strict-Transport-Security'),
        'content-security-policy': headers.get('Content-Security-Policy'),
        'x-content-type-options': headers.get('X-Content-Type-Options'),
        'x-frame-options': headers.get('X-Frame-Options'),
        'x-xss-protection': headers.get('X-XSS-Protection'),
        'referrer-policy': headers.get('Referrer-Policy')
    }
    
    # Check for HTTPS
    is_https = response.url.startswith('https://')
    
    # Issues list
    issues = []
    
    if not is_https:
        issues.append({
            'severity': 'high',
            'issue': 'Website not served over HTTPS',
            'recommendation': 'Configure your website to use HTTPS'
        })
    
    if not security_headers['strict-transport-security'] and is_https:
        issues.append({
            'severity': 'medium',
            'issue': 'Missing Strict-Transport-Security header',
            'recommendation': 'Add a Strict-Transport-Security header with appropriate values'
        })
    
    if not security_headers['content-security-policy']:
        issues.append({
            'severity': 'medium',
            'issue': 'Missing Content-Security-Policy header',
            'recommendation': 'Implement a Content Security Policy to prevent XSS attacks'
        })
    
    if not security_headers['x-frame-options']:
        issues.append({
            'severity': 'low',
            'issue': 'Missing X-Frame-Options header',
            'recommendation': 'Add an X-Frame-Options header to prevent clickjacking'
        })
    
    return {
        'https': is_https,
        'security_headers': security_headers,
        'issues': issues
    }

def assess_mobile_friendliness(soup, response):
    """
    Assess mobile-friendliness metrics for a website.
    
    Args:
        soup (BeautifulSoup): Parsed HTML content
        response (requests.Response): The HTTP response
        
    Returns:
        dict: Mobile-friendliness assessment
    """
    # Check viewport meta tag
    viewport = soup.find('meta', attrs={'name': 'viewport'})
    viewport_content = viewport['content'] if viewport else None
    
    # Check for responsive design indicators
    media_queries_present = False
    style_tags = soup.find_all('style')
    for style in style_tags:
        if style.string and '@media' in style.string:
            media_queries_present = True
            break
    
    # Check for mobile-specific elements
    touch_icons = soup.find_all('link', attrs={'rel': re.compile(r'apple-touch-icon|icon')})
    
    # Check for large tap targets (simplified)
    buttons = soup.find_all('button')
    small_buttons = []
    
    # Issues list
    issues = []
    
    if not viewport:
        issues.append({
            'severity': 'high',
            'issue': 'Missing viewport meta tag',
            'recommendation': 'Add a viewport meta tag: <meta name="viewport" content="width=device-width, initial-scale=1">'
        })
    
    return {
        'viewport': {
            'present': viewport is not None,
            'content': viewport_content
        },
        'responsive_design': {
            'media_queries': media_queries_present
        },
        'touch_icons': len(touch_icons),
        'issues': issues
    }

def assess_content_quality(soup):
    """
    Assess content quality metrics for a website.
    
    Args:
        soup (BeautifulSoup): Parsed HTML content
        
    Returns:
        dict: Content quality assessment
    """
    # Extract main content (simple heuristic)
    main_content = soup.find('main') or soup.find('article') or soup.find('div', class_=re.compile(r'content|main|article'))
    
    if not main_content:
        # Fallback to body if no content container found
        main_content = soup.body
    
    # Extract text content
    paragraphs = main_content.find_all('p') if main_content else []
    text_content = ' '.join([p.get_text(strip=True) for p in paragraphs])
    
    # Word count
    word_count = len(text_content.split()) if text_content else 0
    
    # Reading time estimate (average reading speed: 200-250 words per minute)
    reading_time_minutes = round(word_count / 200) if word_count > 0 else 0
    
    # Check for media elements
    images = main_content.find_all('img') if main_content else []
    videos = main_content.find_all(['video', 'iframe']) if main_content else []
    
    return {
        'text': {
            'word_count': word_count,
            'paragraph_count': len(paragraphs),
            'estimated_reading_time_minutes': reading_time_minutes
        },
        'media': {
            'images': len(images),
            'videos': len(videos)
        }
    }