"""Module for analyzing social media tags and integration."""

import logging
import requests
import validators
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def analyze_social_tags(url):
    """
    Analyze social media tags and integration on a website.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Analysis of social media tags and integration
    """
    logger.debug(f"Analyzing social tags for URL: {url}")
    
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
        
        # Extract Open Graph tags
        og_tags = _extract_og_tags(soup)
        
        # Extract Twitter Card tags
        twitter_tags = _extract_twitter_tags(soup)
        
        # Extract JSON-LD structured data
        structured_data = _extract_structured_data(soup)
        
        # Extract social links
        social_links = _extract_social_links(soup, url)
        
        # Extract social sharing buttons
        sharing_buttons = _extract_sharing_buttons(soup)
        
        # Check for social widgets/embeds
        social_widgets = _detect_social_widgets(soup)
        
        # Analyze results
        analysis = _analyze_social_integration(
            og_tags, 
            twitter_tags, 
            structured_data, 
            social_links, 
            sharing_buttons, 
            social_widgets
        )
        
        result = {
            'url': url,
            'open_graph': og_tags,
            'twitter_card': twitter_tags,
            'structured_data': structured_data,
            'social_links': social_links,
            'sharing_buttons': sharing_buttons,
            'social_widgets': social_widgets,
            'analysis': analysis
        }
        
        logger.debug(f"Social tags analysis result: {result}")
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL: {e}")
        raise

def _extract_og_tags(soup):
    """Extract Open Graph tags from the page."""
    og_tags = {}
    
    # Extract all Open Graph meta tags
    og_meta_tags = soup.find_all('meta', property=re.compile('^og:'))
    
    for tag in og_meta_tags:
        property_name = tag.get('property', '').replace('og:', '')
        content = tag.get('content', '')
        og_tags[property_name] = content
    
    # Check for basic required Open Graph properties
    basic_properties = ['title', 'type', 'image', 'url']
    missing_properties = [prop for prop in basic_properties if prop not in og_tags]
    
    return {
        'tags': og_tags,
        'count': len(og_tags),
        'missing_properties': missing_properties,
        'has_basic_tags': len(missing_properties) == 0
    }

def _extract_twitter_tags(soup):
    """Extract Twitter Card tags from the page."""
    twitter_tags = {}
    
    # Extract all Twitter Card meta tags
    twitter_meta_tags = soup.find_all('meta', attrs={'name': re.compile('^twitter:')})
    
    for tag in twitter_meta_tags:
        property_name = tag.get('name', '').replace('twitter:', '')
        content = tag.get('content', '')
        twitter_tags[property_name] = content
    
    # Check for card type
    card_type = twitter_tags.get('card')
    
    # Check for basic required Twitter Card properties based on card type
    missing_properties = []
    
    if card_type:
        if card_type == 'summary':
            required_props = ['title', 'description']
            if 'image' in twitter_tags:
                required_props.append('image:alt')
        elif card_type == 'summary_large_image':
            required_props = ['title', 'description', 'image']
            if 'image' in twitter_tags:
                required_props.append('image:alt')
        elif card_type == 'app':
            required_props = ['app:id:iphone', 'app:id:googleplay']
        elif card_type == 'player':
            required_props = ['title', 'player', 'player:width', 'player:height']
        else:
            required_props = ['title', 'description']
            
        missing_properties = [prop for prop in required_props if prop not in twitter_tags]
    else:
        missing_properties = ['card']
    
    return {
        'tags': twitter_tags,
        'count': len(twitter_tags),
        'card_type': card_type,
        'missing_properties': missing_properties,
        'has_basic_tags': 'card' in twitter_tags
    }

def _extract_structured_data(soup):
    """Extract JSON-LD structured data from the page."""
    structured_data = []
    
    # Find all script tags with type application/ld+json
    json_ld_scripts = soup.find_all('script', type='application/ld+json')
    
    # Count social-relevant types
    social_types = ['Person', 'Organization', 'WebSite', 'WebPage', 'Article', 'SocialMediaPosting']
    social_type_count = 0
    
    for script in json_ld_scripts:
        try:
            # Get script content (we're not actually parsing the JSON here to keep it simpler)
            content = script.string
            
            # Check for social media relevant types
            for social_type in social_types:
                if f'"@type"\\s*:\\s*"{social_type}"' in content or f'"@type": "{social_type}"' in content:
                    social_type_count += 1
                    break
            
            structured_data.append(content)
        except Exception as e:
            logger.debug(f"Error extracting JSON-LD: {e}")
    
    return {
        'count': len(structured_data),
        'social_relevant_types': social_type_count > 0,
        'has_structured_data': len(structured_data) > 0
    }

def _extract_social_links(soup, base_url):
    """Extract social media links from the page."""
    social_platforms = {
        'facebook': {'domain': 'facebook.com', 'pattern': r'facebook\.com'},
        'twitter': {'domain': 'twitter.com', 'pattern': r'twitter\.com|x\.com'},
        'instagram': {'domain': 'instagram.com', 'pattern': r'instagram\.com'},
        'linkedin': {'domain': 'linkedin.com', 'pattern': r'linkedin\.com'},
        'youtube': {'domain': 'youtube.com', 'pattern': r'youtube\.com|youtu\.be'},
        'pinterest': {'domain': 'pinterest.com', 'pattern': r'pinterest\.com'},
        'tiktok': {'domain': 'tiktok.com', 'pattern': r'tiktok\.com'},
        'snapchat': {'domain': 'snapchat.com', 'pattern': r'snapchat\.com'},
        'reddit': {'domain': 'reddit.com', 'pattern': r'reddit\.com'},
        'tumblr': {'domain': 'tumblr.com', 'pattern': r'tumblr\.com'},
        'whatsapp': {'domain': 'whatsapp.com', 'pattern': r'whatsapp\.com|wa\.me'},
        'telegram': {'domain': 'telegram.me', 'pattern': r'telegram\.me|t\.me'},
        'discord': {'domain': 'discord.com', 'pattern': r'discord\.com|discord\.gg'},
        'medium': {'domain': 'medium.com', 'pattern': r'medium\.com'},
        'github': {'domain': 'github.com', 'pattern': r'github\.com'}
    }
    
    social_links = {}
    
    # Find all links
    links = soup.find_all('a', href=True)
    
    for platform, info in social_platforms.items():
        platform_links = []
        
        for link in links:
            href = link.get('href', '')
            if href and re.search(info['pattern'], href, re.IGNORECASE):
                # Normalize URL
                absolute_url = urljoin(base_url, href)
                platform_links.append({
                    'url': absolute_url,
                    'text': link.get_text(strip=True) or None
                })
        
        if platform_links:
            social_links[platform] = platform_links
    
    return {
        'platforms': list(social_links.keys()),
        'count': len(social_links),
        'links': social_links,
        'has_social_links': len(social_links) > 0
    }

def _extract_sharing_buttons(soup):
    """Extract social media sharing buttons from the page."""
    sharing_indicators = {
        'classes': [
            'share', 'social-share', 'share-buttons', 'social-buttons',
            'facebook-share', 'twitter-share', 'linkedin-share', 'pinterest-share',
            'share-facebook', 'share-twitter', 'share-linkedin', 'share-pinterest'
        ],
        'ids': [
            'share', 'social-share', 'share-buttons', 'social-buttons'
        ],
        'text': [
            'Share on', 'Share this', 'Share via', 'Share with', 'Tweet', 'Pin it', 'Share'
        ]
    }
    
    sharing_elements = []
    
    # Find elements with sharing-related classes
    for class_name in sharing_indicators['classes']:
        elements = soup.find_all(class_=re.compile(class_name, re.IGNORECASE))
        for element in elements:
            sharing_elements.append({
                'type': 'class',
                'value': class_name,
                'html': str(element)[:100] + ('...' if len(str(element)) > 100 else '')
            })
    
    # Find elements with sharing-related IDs
    for id_name in sharing_indicators['ids']:
        elements = soup.find_all(id=re.compile(id_name, re.IGNORECASE))
        for element in elements:
            sharing_elements.append({
                'type': 'id',
                'value': id_name,
                'html': str(element)[:100] + ('...' if len(str(element)) > 100 else '')
            })
    
    # Find links with sharing-related text
    for share_text in sharing_indicators['text']:
        elements = soup.find_all('a', text=re.compile(share_text, re.IGNORECASE))
        for element in elements:
            sharing_elements.append({
                'type': 'text',
                'value': element.get_text(strip=True),
                'url': element.get('href', ''),
                'html': str(element)[:100] + ('...' if len(str(element)) > 100 else '')
            })
    
    # Look for AddThis, ShareThis, AddToAny
    sharing_tools = {
        'addthis': bool(soup.find_all(class_=re.compile('addthis', re.IGNORECASE)) or 
                       soup.find_all('script', src=re.compile('addthis.com', re.IGNORECASE))),
        'sharethis': bool(soup.find_all(class_=re.compile('sharethis', re.IGNORECASE)) or 
                         soup.find_all('script', src=re.compile('sharethis.com', re.IGNORECASE))),
        'addtoany': bool(soup.find_all(class_=re.compile('addtoany', re.IGNORECASE)) or 
                        soup.find_all('script', src=re.compile('addtoany.com', re.IGNORECASE)))
    }
    
    return {
        'elements': sharing_elements,
        'count': len(sharing_elements),
        'has_sharing_buttons': len(sharing_elements) > 0,
        'sharing_tools': sharing_tools
    }

def _detect_social_widgets(soup):
    """Detect social media widgets and embeds on the page."""
    widgets = {
        'facebook': {
            'like_button': bool(soup.find_all('div', class_=re.compile('fb-like', re.IGNORECASE)) or 
                               soup.find_all('iframe', src=re.compile('facebook.com/plugins/like', re.IGNORECASE))),
            'comments': bool(soup.find_all('div', class_=re.compile('fb-comments', re.IGNORECASE)) or 
                            soup.find_all('iframe', src=re.compile('facebook.com/plugins/comments', re.IGNORECASE))),
            'page': bool(soup.find_all('div', class_=re.compile('fb-page', re.IGNORECASE)) or 
                        soup.find_all('iframe', src=re.compile('facebook.com/plugins/page', re.IGNORECASE)))
        },
        'twitter': {
            'timeline': bool(soup.find_all('a', class_=re.compile('twitter-timeline', re.IGNORECASE)) or 
                            soup.find_all('iframe', src=re.compile('twitter.com/widgets', re.IGNORECASE))),
            'tweet_button': bool(soup.find_all('a', class_=re.compile('twitter-share-button', re.IGNORECASE)))
        },
        'instagram': {
            'embed': bool(soup.find_all('blockquote', class_=re.compile('instagram-media', re.IGNORECASE)) or 
                         soup.find_all('iframe', src=re.compile('instagram.com/embed', re.IGNORECASE)))
        },
        'youtube': {
            'embed': bool(soup.find_all('iframe', src=re.compile('youtube.com/embed', re.IGNORECASE)))
        },
        'linkedin': {
            'share_button': bool(soup.find_all('script', src=re.compile('platform.linkedin.com', re.IGNORECASE)))
        },
        'pinterest': {
            'pin_it': bool(soup.find_all('a', href=re.compile('pinterest.com/pin/create', re.IGNORECASE)))
        }
    }
    
    # Count total widgets
    total_widgets = sum(sum(platform.values()) for platform in widgets.values())
    
    return {
        'widgets': widgets,
        'count': total_widgets,
        'has_widgets': total_widgets > 0
    }

def _analyze_social_integration(og_tags, twitter_tags, structured_data, social_links, sharing_buttons, social_widgets):
    """Analyze the social media integration on the page."""
    # Calculate overall social media integration score (0-100)
    score = 0
    max_score = 100
    
    # Open Graph tags (20 points)
    if og_tags['has_basic_tags']:
        score += 20
    elif og_tags['count'] > 0:
        score += 10
    
    # Twitter Card tags (20 points)
    if twitter_tags['has_basic_tags']:
        if not twitter_tags['missing_properties']:
            score += 20
        else:
            score += 15
    elif twitter_tags['count'] > 0:
        score += 10
    
    # Structured data (10 points)
    if structured_data['has_structured_data']:
        if structured_data['social_relevant_types']:
            score += 10
        else:
            score += 5
    
    # Social links (20 points)
    if social_links['has_social_links']:
        platforms_count = len(social_links['platforms'])
        if platforms_count >= 4:
            score += 20
        elif platforms_count >= 2:
            score += 15
        else:
            score += 10
    
    # Sharing buttons (15 points)
    if sharing_buttons['has_sharing_buttons']:
        if sharing_buttons['count'] >= 3:
            score += 15
        else:
            score += 10
    
    # Social widgets (15 points)
    if social_widgets['has_widgets']:
        widgets_count = social_widgets['count']
        if widgets_count >= 3:
            score += 15
        elif widgets_count >= 2:
            score += 10
        else:
            score += 5
    
    # Calculate grade and description
    if score >= 90:
        grade = 'A+'
        description = 'Excellent'
    elif score >= 80:
        grade = 'A'
        description = 'Very Good'
    elif score >= 70:
        grade = 'B'
        description = 'Good'
    elif score >= 60:
        grade = 'C'
        description = 'Fair'
    elif score >= 50:
        grade = 'D'
        description = 'Poor'
    else:
        grade = 'F'
        description = 'Very Poor'
    
    # Generate recommendations
    recommendations = []
    
    if not og_tags['has_basic_tags']:
        recommendations.append({
            'priority': 'high',
            'recommendation': 'Add basic Open Graph tags (og:title, og:type, og:image, og:url)'
        })
    
    if not twitter_tags['has_basic_tags']:
        recommendations.append({
            'priority': 'high',
            'recommendation': 'Add Twitter Card tags, starting with twitter:card'
        })
    
    if not social_links['has_social_links']:
        recommendations.append({
            'priority': 'medium',
            'recommendation': 'Add links to social media profiles'
        })
    
    if not sharing_buttons['has_sharing_buttons']:
        recommendations.append({
            'priority': 'medium',
            'recommendation': 'Add social sharing buttons to encourage content sharing'
        })
    
    return {
        'score': score,
        'max_score': max_score,
        'percentage': score,
        'grade': grade,
        'description': description,
        'recommendations': recommendations
    }