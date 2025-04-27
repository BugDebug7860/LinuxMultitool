"""Module for detecting website features and technologies."""

import logging
import requests
import validators
from bs4 import BeautifulSoup
import re
import json
from urllib.parse import urljoin, urlparse

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def detect_site_features(url):
    """
    Detect features and technologies used on a website.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Features and technologies detected
    """
    logger.debug(f"Detecting site features for URL: {url}")
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    if not validators.url(url):
        raise ValueError(f"Invalid URL: {url}")
    
    try:
        # Fetch the website
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        content = response.text
        headers = response.headers
        
        # Parse with BeautifulSoup
        soup = BeautifulSoup(content, 'html.parser')
        
        # Detect features
        results = {
            'url': url,
            'basic_features': _detect_basic_features(soup, headers),
            'functionality': _detect_functionality(soup, url),
            'social_integration': _detect_social_integration(soup),
            'user_interaction': _detect_user_interaction(soup),
            'performance_features': _detect_performance_features(soup, headers),
            'analytics': _detect_analytics(soup),
            'languages': _detect_languages(soup, headers),
            'accessibility': _detect_accessibility_features(soup)
        }
        
        logger.debug(f"Site features result: {results}")
        return results
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL: {e}")
        raise

def _detect_basic_features(soup, headers):
    """Detect basic website features."""
    features = {
        'favicon': bool(soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')),
        'responsive_design': bool(soup.find('meta', attrs={'name': 'viewport'})),
        'structured_data': _has_structured_data(soup),
        'canonical_url': bool(soup.find('link', rel='canonical')),
        'preloading': bool(soup.find('link', rel='preload')),
        'async_javascript': bool(soup.find('script', attrs={'async': True})),
        'external_stylesheets': len(soup.find_all('link', rel='stylesheet')),
        'inline_styles': len(soup.find_all('style')),
        'external_scripts': len(soup.find_all('script', src=True)),
        'inline_scripts': len([s for s in soup.find_all('script') if not s.get('src')]),
        'images': len(soup.find_all('img')),
        'videos': len(soup.find_all(['video', 'iframe'])),
        'meta_description': bool(soup.find('meta', attrs={'name': 'description'})),
        'meta_keywords': bool(soup.find('meta', attrs={'name': 'keywords'})),
        'open_graph': bool(soup.find('meta', property=re.compile(r'^og:'))),
        'twitter_cards': bool(soup.find('meta', attrs={'name': re.compile(r'^twitter:')}))
    }
    
    # Check for modern HTML5 elements
    html5_elements = ['header', 'footer', 'nav', 'main', 'section', 'article', 'aside']
    features['html5_semantic'] = any(soup.find(tag) for tag in html5_elements)
    
    # Check for RSS/Atom feeds
    features['feeds'] = bool(soup.find('link', type=re.compile(r'application/(rss|atom)')) or 
                           soup.find('link', href=re.compile(r'\.(rss|xml)$')))
    
    return features

def _has_structured_data(soup):
    """Check if the page contains structured data (JSON-LD, microdata, RDFa)."""
    # Check for JSON-LD
    json_ld = soup.find_all('script', type='application/ld+json')
    if json_ld:
        return True
    
    # Check for microdata
    microdata = soup.find_all(itemtype=True)
    if microdata:
        return True
    
    # Check for RDFa
    rdfa = soup.find_all(property=re.compile(r'^[a-z]+:[a-z]+'))
    if rdfa:
        return True
    
    return False

def _detect_functionality(soup, base_url):
    """Detect website functionality features."""
    parsed_url = urlparse(base_url)
    base_domain = parsed_url.netloc
    
    # Forms
    forms = soup.find_all('form')
    
    # Search functionality
    search_forms = [form for form in forms if re.search(r'search', str(form), re.IGNORECASE)]
    
    # Login/authentication
    login_indicators = ['login', 'signin', 'log in', 'sign in', 'account']
    login_forms = [form for form in forms if any(re.search(indicator, str(form), re.IGNORECASE) for indicator in login_indicators)]
    login_links = soup.find_all('a', href=re.compile('|'.join(login_indicators), re.IGNORECASE))
    
    # Registration
    register_indicators = ['register', 'signup', 'sign up', 'create account']
    register_forms = [form for form in forms if any(re.search(indicator, str(form), re.IGNORECASE) for indicator in register_indicators)]
    register_links = soup.find_all('a', href=re.compile('|'.join(register_indicators), re.IGNORECASE))
    
    # E-commerce
    ecommerce_indicators = ['cart', 'basket', 'checkout', 'shop', 'product', 'price', 'add to']
    ecommerce_elements = soup.find_all(text=re.compile('|'.join(ecommerce_indicators), re.IGNORECASE))
    
    # Blog
    blog_indicators = ['blog', 'article', 'post', 'news']
    blog_links = soup.find_all('a', href=re.compile('|'.join(blog_indicators), re.IGNORECASE))
    
    # Contact
    contact_indicators = ['contact', 'email us', 'get in touch']
    contact_links = soup.find_all('a', href=re.compile('|'.join(contact_indicators), re.IGNORECASE))
    contact_forms = [form for form in forms if any(re.search(indicator, str(form), re.IGNORECASE) for indicator in contact_indicators)]
    
    # Multilingual support
    language_selectors = soup.find_all('select', id=re.compile('lang', re.IGNORECASE)) or \
                         soup.find_all('ul', class_=re.compile('lang', re.IGNORECASE))
    
    # Check for hreflang tags
    hreflang_tags = soup.find_all('link', rel='alternate', hreflang=True)
    
    return {
        'forms': len(forms),
        'search': bool(search_forms),
        'authentication': {
            'login_form': bool(login_forms),
            'login_links': len(login_links),
            'has_authentication': bool(login_forms or login_links)
        },
        'registration': {
            'register_form': bool(register_forms),
            'register_links': len(register_links),
            'has_registration': bool(register_forms or register_links)
        },
        'ecommerce': {
            'has_ecommerce': len(ecommerce_elements) > 3,  # Threshold to avoid false positives
            'elements_count': len(ecommerce_elements)
        },
        'blog': {
            'has_blog': len(blog_links) > 0,
            'links_count': len(blog_links)
        },
        'contact': {
            'has_contact': bool(contact_links or contact_forms),
            'links_count': len(contact_links),
            'has_form': bool(contact_forms)
        },
        'multilingual': {
            'has_language_selector': bool(language_selectors),
            'has_hreflang': bool(hreflang_tags),
            'supported_languages': len(hreflang_tags)
        }
    }

def _detect_social_integration(soup):
    """Detect social media integration features."""
    # Social sharing buttons
    sharing_indicators = ['share', 'tweet', 'facebook', 'twitter', 'linkedin', 'pinterest']
    sharing_elements = soup.find_all(class_=re.compile('|'.join(sharing_indicators), re.IGNORECASE)) or \
                      soup.find_all(id=re.compile('|'.join(sharing_indicators), re.IGNORECASE))
    
    # Social links
    social_domains = ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'youtube.com', 
                     'pinterest.com', 'tiktok.com', 'snapchat.com', 'reddit.com', 'tumblr.com']
    social_links = [a for a in soup.find_all('a', href=True) if any(domain in a['href'] for domain in social_domains)]
    
    # Social widgets/embeds
    social_widgets = soup.find_all('iframe', src=re.compile('|'.join([
        'facebook.com/plugins',
        'platform.twitter.com',
        'instagram.com/embed',
        'linkedin.com/embed',
        'youtube.com/embed'
    ])))
    
    # Social comments
    comments_systems = {
        'disqus': bool(soup.find_all(text=re.compile('disqus', re.IGNORECASE)) or 
                    soup.find('script', src=re.compile('disqus.com'))),
        'facebook_comments': bool(soup.find_all(class_=re.compile('fb-comments')) or 
                              soup.find('script', src=re.compile('facebook.com/plugins/comments'))),
        'livefyre': bool(soup.find_all(text=re.compile('livefyre', re.IGNORECASE))),
        'custom_comments': bool(soup.find_all(class_=re.compile('comment')))
    }
    
    return {
        'sharing': {
            'has_sharing': bool(sharing_elements),
            'elements_count': len(sharing_elements)
        },
        'social_links': {
            'has_social_links': bool(social_links),
            'links_count': len(social_links),
            'platforms': [domain.split('.')[0] for social in social_links for domain in social_domains if domain in social['href']]
        },
        'social_widgets': {
            'has_widgets': bool(social_widgets),
            'widgets_count': len(social_widgets)
        },
        'comments': {
            'has_comments': any(comments_systems.values()),
            'systems': [system for system, present in comments_systems.items() if present]
        }
    }

def _detect_user_interaction(soup):
    """Detect user interaction features."""
    # Detect forms
    forms = soup.find_all('form')
    
    # Form input types
    input_types = {}
    for form in forms:
        inputs = form.find_all('input')
        for input_field in inputs:
            input_type = input_field.get('type', 'text')
            input_types[input_type] = input_types.get(input_type, 0) + 1
    
    # Interactive elements
    buttons = soup.find_all('button') + soup.find_all('input', type=['submit', 'button'])
    dropdown_menus = soup.find_all('select')
    
    # Check for popups
    popup_indicators = ['popup', 'modal', 'overlay', 'lightbox']
    potential_popups = soup.find_all(class_=re.compile('|'.join(popup_indicators), re.IGNORECASE)) or \
                      soup.find_all(id=re.compile('|'.join(popup_indicators), re.IGNORECASE))
    
    # Check for rich media elements
    audio_elements = soup.find_all('audio')
    video_elements = soup.find_all('video')
    
    # Check for maps
    map_indicators = ['map', 'google.maps', 'leaflet']
    potential_maps = soup.find_all(class_=re.compile('|'.join(map_indicators), re.IGNORECASE)) or \
                    soup.find_all(id=re.compile('|'.join(map_indicators), re.IGNORECASE)) or \
                    soup.find_all('script', src=re.compile('maps.(googleapis|google).com'))
    
    # Check for sliders/carousels
    slider_indicators = ['slider', 'carousel', 'slideshow', 'swiper']
    potential_sliders = soup.find_all(class_=re.compile('|'.join(slider_indicators), re.IGNORECASE)) or \
                        soup.find_all(id=re.compile('|'.join(slider_indicators), re.IGNORECASE))
    
    # Check for tabs
    tab_indicators = ['tab', 'tabs', 'tabbed']
    potential_tabs = soup.find_all(class_=re.compile('|'.join(tab_indicators), re.IGNORECASE)) or \
                    soup.find_all(id=re.compile('|'.join(tab_indicators), re.IGNORECASE))
    
    return {
        'forms': {
            'count': len(forms),
            'input_types': input_types
        },
        'buttons': len(buttons),
        'dropdowns': len(dropdown_menus),
        'popups': len(potential_popups),
        'rich_media': {
            'audio': len(audio_elements),
            'video': len(video_elements)
        },
        'interactive_elements': {
            'maps': len(potential_maps),
            'sliders': len(potential_sliders),
            'tabs': len(potential_tabs)
        }
    }

def _detect_performance_features(soup, headers):
    """Detect performance-related features."""
    # Check for resource hints
    preconnect = soup.find_all('link', rel='preconnect')
    dns_prefetch = soup.find_all('link', rel='dns-prefetch')
    preload = soup.find_all('link', rel='preload')
    prefetch = soup.find_all('link', rel='prefetch')
    
    # Check for image optimization
    img_tags = soup.find_all('img')
    lazy_loading = [img for img in img_tags if img.get('loading') == 'lazy']
    webp_images = [img for img in img_tags if img.get('src', '').endswith('.webp')]
    responsive_images = [img for img in img_tags if img.get('srcset')]
    
    # Check for script loading optimizations
    scripts = soup.find_all('script')
    async_scripts = [script for script in scripts if script.has_attr('async')]
    defer_scripts = [script for script in scripts if script.get('defer')]
    module_scripts = [script for script in scripts if script.get('type') == 'module']
    
    # Check for HTTP/2 push
    link_header = headers.get('Link', '')
    has_http_push = 'rel=preload' in link_header
    
    # Check for CDN usage
    cdn_indicators = ['cloudflare', 'cloudfront', 'akamai', 'fastly', 'cdn']
    potential_cdn_usage = any(cdn in headers.get('Server', '').lower() for cdn in cdn_indicators) or \
                         any(cdn in headers.get('X-Served-By', '').lower() for cdn in cdn_indicators) or \
                         any(cdn in headers.get('X-Cache', '').lower() for cdn in cdn_indicators)
    
    return {
        'resource_hints': {
            'preconnect': len(preconnect),
            'dns_prefetch': len(dns_prefetch),
            'preload': len(preload),
            'prefetch': len(prefetch)
        },
        'image_optimization': {
            'lazy_loading': len(lazy_loading),
            'webp_usage': len(webp_images),
            'responsive_images': len(responsive_images)
        },
        'script_loading': {
            'async': len(async_scripts),
            'defer': len(defer_scripts),
            'module': len(module_scripts)
        },
        'http_push': has_http_push,
        'potential_cdn': potential_cdn_usage
    }

def _detect_analytics(soup):
    """Detect analytics and tracking tools."""
    analytics_systems = {
        'google_analytics': bool(soup.find('script', text=re.compile('google-analytics.com|gtag|ga')) or 
                             soup.find('script', src=re.compile('google-analytics.com|googletagmanager'))),
        'google_tag_manager': bool(soup.find('script', text=re.compile('gtm.js|googletagmanager')) or 
                                soup.find('script', src=re.compile('googletagmanager.com/gtm.js'))),
        'matomo_piwik': bool(soup.find('script', text=re.compile('matomo|piwik')) or 
                         soup.find('script', src=re.compile('matomo|piwik'))),
        'facebook_pixel': bool(soup.find('script', text=re.compile('fbq\\(')) or 
                           soup.find('script', src=re.compile('connect.facebook.net'))),
        'hotjar': bool(soup.find('script', text=re.compile('hotjar|_hjSettings')) or 
                    soup.find('script', src=re.compile('hotjar.com'))),
        'mixpanel': bool(soup.find('script', text=re.compile('mixpanel')) or 
                     soup.find('script', src=re.compile('mixpanel.com'))),
        'segment': bool(soup.find('script', text=re.compile('segment|analytics.load')) or 
                    soup.find('script', src=re.compile('segment.com'))),
        'amplitude': bool(soup.find('script', text=re.compile('amplitude')) or 
                      soup.find('script', src=re.compile('amplitude.com'))),
        'chartbeat': bool(soup.find('script', text=re.compile('chartbeat')) or 
                      soup.find('script', src=re.compile('chartbeat.com'))),
        'crazyegg': bool(soup.find('script', text=re.compile('crazyegg')) or 
                     soup.find('script', src=re.compile('crazyegg.com')))
    }
    
    return {
        'has_analytics': any(analytics_systems.values()),
        'detected_systems': [system for system, present in analytics_systems.items() if present],
        'systems_count': sum(1 for present in analytics_systems.values() if present)
    }

def _detect_languages(soup, headers):
    """Detect languages and localization features."""
    # Check HTML lang attribute
    html_tag = soup.find('html')
    html_lang = html_tag.get('lang') if html_tag else None
    
    # Check Content-Language header
    content_language = headers.get('Content-Language')
    
    # Check hreflang tags
    hreflang_tags = soup.find_all('link', rel='alternate', hreflang=True)
    hreflang_values = [tag.get('hreflang') for tag in hreflang_tags]
    
    # Check for language selectors
    language_selectors = soup.find_all('select', id=re.compile('lang', re.IGNORECASE)) or \
                        soup.find_all('ul', class_=re.compile('lang', re.IGNORECASE))
    
    # Check for multilingual meta tags
    meta_language = soup.find('meta', attrs={'http-equiv': 'content-language'})
    meta_language_value = meta_language.get('content') if meta_language else None
    
    # Try to detect RTL support
    rtl_indicators = ['rtl', 'right-to-left', 'direction:rtl', 'dir="rtl"']
    potential_rtl = bool(html_tag and html_tag.get('dir') == 'rtl') or \
                   bool(soup.find_all(dir='rtl')) or \
                   bool(soup.find_all(text=re.compile('|'.join(rtl_indicators), re.IGNORECASE)))
    
    return {
        'primary_language': html_lang or meta_language_value or content_language,
        'declared_languages': {
            'html_lang': html_lang,
            'content_language_header': content_language,
            'meta_content_language': meta_language_value
        },
        'multilingual': {
            'has_hreflang': bool(hreflang_tags),
            'hreflang_values': hreflang_values,
            'has_language_selector': bool(language_selectors)
        },
        'rtl_support': potential_rtl
    }

def _detect_accessibility_features(soup):
    """Detect accessibility features."""
    # Check for ARIA landmarks
    aria_landmarks = soup.find_all(attrs={'role': True})
    
    # Check for alt text on images
    img_tags = soup.find_all('img')
    imgs_with_alt = [img for img in img_tags if img.get('alt') is not None]
    
    # Check for form labels
    inputs = soup.find_all('input', type=lambda t: t != 'hidden')
    inputs_with_labels = []
    
    for input_field in inputs:
        input_id = input_field.get('id')
        if input_id:
            label = soup.find('label', attrs={'for': input_id})
            if label:
                inputs_with_labels.append(input_field)
        else:
            # Check if input is inside a label
            parent_label = input_field.find_parent('label')
            if parent_label:
                inputs_with_labels.append(input_field)
    
    # Check for skip links
    skip_links = soup.find_all('a', href='#content') or \
                soup.find_all('a', href='#main') or \
                soup.find_all('a', text=re.compile('skip to (main|content)'))
    
    # Check for semantic HTML5
    semantic_elements = ['header', 'nav', 'main', 'footer', 'section', 'article', 'aside']
    used_semantic_elements = [elem for elem in semantic_elements if soup.find(elem)]
    
    return {
        'aria': {
            'landmarks': len(aria_landmarks),
            'has_landmarks': bool(aria_landmarks)
        },
        'images': {
            'total': len(img_tags),
            'with_alt': len(imgs_with_alt),
            'alt_text_ratio': round(len(imgs_with_alt) / len(img_tags), 2) if img_tags else 0
        },
        'forms': {
            'inputs': len(inputs),
            'labeled_inputs': len(inputs_with_labels),
            'labeled_ratio': round(len(inputs_with_labels) / len(inputs), 2) if inputs else 0
        },
        'navigation': {
            'has_skip_links': bool(skip_links)
        },
        'semantic_html': {
            'used_elements': used_semantic_elements,
            'count': len(used_semantic_elements),
            'coverage': round(len(used_semantic_elements) / len(semantic_elements), 2)
        }
    }