"""Module for estimating carbon footprint of a website."""

import logging
import requests
import validators
from bs4 import BeautifulSoup
import time
import statistics

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants for carbon calculations
# These are simplified estimates based on industry averages
BYTES_PER_KWH = 1024 * 1024 * 200  # Approx. 200MB per kWh (simplified)
CARBON_PER_KWH = 475  # Average gCO2/kWh (global average, simplified)
AVERAGE_SESSION_PAGE_VIEWS = 3  # Average pages per session
BYTES_TO_MB = 1024 * 1024

def estimate_carbon_footprint(url):
    """
    Estimate the carbon footprint of a website.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Carbon footprint information
    """
    logger.debug(f"Estimating carbon footprint for URL: {url}")
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    if not validators.url(url):
        raise ValueError(f"Invalid URL: {url}")
    
    try:
        # Collect data about the page
        page_size, dom_elements, asset_counts = _analyze_page_size(url)
        
        # Calculate energy and carbon metrics
        energy_per_view_kwh = page_size / BYTES_PER_KWH
        carbon_per_view_g = energy_per_view_kwh * CARBON_PER_KWH
        
        # Estimate for 10,000 page views (monthly)
        monthly_views = 10000
        monthly_carbon_kg = (carbon_per_view_g * monthly_views) / 1000
        
        # Compare to real-world equivalents
        # Average emissions for driving 1 km in a standard car is ~120g CO2
        driving_km_equivalent = monthly_carbon_kg * 1000 / 120
        
        # Average tree absorbs ~21 kg CO2 per year (~1.75 kg per month)
        trees_needed = monthly_carbon_kg / 1.75
        
        result = {
            'url': url,
            'page_analysis': {
                'page_size_bytes': page_size,
                'page_size_mb': round(page_size / BYTES_TO_MB, 2),
                'dom_elements': dom_elements,
                'asset_counts': asset_counts
            },
            'energy_metrics': {
                'energy_per_view_kwh': energy_per_view_kwh,
                'carbon_per_view_g': round(carbon_per_view_g, 2)
            },
            'monthly_estimates': {
                'page_views': monthly_views,
                'carbon_emissions_kg': round(monthly_carbon_kg, 2),
                'equivalent_car_km': round(driving_km_equivalent, 2),
                'trees_to_offset': round(trees_needed, 1)
            },
            'optimization_potential': _suggest_optimizations(page_size, dom_elements, asset_counts)
        }
        
        # Add a cleanliness score (0-100)
        result['cleanliness_score'] = _calculate_cleanliness_score(page_size, dom_elements, asset_counts)
        
        logger.debug(f"Carbon footprint result: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error estimating carbon footprint: {e}")
        raise

def _analyze_page_size(url):
    """Analyze page size, DOM elements, and asset counts."""
    try:
        # Fetch main page
        response = requests.get(url, timeout=10)
        content = response.text
        total_size = len(response.content)  # Initial HTML size
        
        # Parse with BeautifulSoup
        soup = BeautifulSoup(content, 'html.parser')
        
        # Count DOM elements
        all_elements = soup.find_all()
        dom_elements = len(all_elements)
        
        # Count assets by type
        scripts = soup.find_all('script', src=True)
        stylesheets = soup.find_all('link', rel='stylesheet')
        images = soup.find_all('img')
        fonts = soup.find_all('link', rel=lambda r: r and 'font' in r)
        videos = soup.find_all(['video', 'iframe'])
        
        asset_counts = {
            'scripts': len(scripts),
            'stylesheets': len(stylesheets),
            'images': len(images),
            'fonts': len(fonts),
            'videos': len(videos)
        }
        
        # For a more accurate estimate, we would need to download each asset
        # This is simplified for demonstration purposes
        # In a real implementation, you might want to fetch each asset
        
        # Estimate additional asset sizes based on typical sizes
        avg_script_size = 75 * 1024  # ~75KB per script
        avg_stylesheet_size = 50 * 1024  # ~50KB per stylesheet
        avg_image_size = 200 * 1024  # ~200KB per image
        avg_font_size = 30 * 1024  # ~30KB per font
        avg_video_size = 500 * 1024  # ~500KB for video player (not the video itself)
        
        estimated_total_size = total_size + \
            (len(scripts) * avg_script_size) + \
            (len(stylesheets) * avg_stylesheet_size) + \
            (len(images) * avg_image_size) + \
            (len(fonts) * avg_font_size) + \
            (len(videos) * avg_video_size)
        
        return estimated_total_size, dom_elements, asset_counts
        
    except Exception as e:
        logger.error(f"Error analyzing page size: {e}")
        # Return default values if analysis fails
        return 1000000, 100, {'scripts': 5, 'stylesheets': 2, 'images': 10, 'fonts': 2, 'videos': 0}

def _suggest_optimizations(page_size, dom_elements, asset_counts):
    """Suggest optimizations based on page analysis."""
    suggestions = []
    
    # Check page size
    if page_size > 3 * BYTES_TO_MB:  # Greater than 3MB
        suggestions.append({
            'area': 'page_size',
            'severity': 'high',
            'suggestion': 'Reduce overall page size to improve load time and carbon footprint'
        })
    elif page_size > 1.5 * BYTES_TO_MB:  # Greater than 1.5MB
        suggestions.append({
            'area': 'page_size',
            'severity': 'medium',
            'suggestion': 'Consider reducing page size for better performance and lower emissions'
        })
    
    # Check DOM complexity
    if dom_elements > 1500:
        suggestions.append({
            'area': 'dom_complexity',
            'severity': 'high',
            'suggestion': 'Simplify HTML structure by reducing DOM elements'
        })
    elif dom_elements > 1000:
        suggestions.append({
            'area': 'dom_complexity',
            'severity': 'medium',
            'suggestion': 'Consider simplifying the page DOM structure'
        })
    
    # Check asset counts
    if asset_counts['scripts'] > 15:
        suggestions.append({
            'area': 'scripts',
            'severity': 'high',
            'suggestion': 'Reduce number of JavaScript files by bundling or removing unused scripts'
        })
    elif asset_counts['scripts'] > 8:
        suggestions.append({
            'area': 'scripts',
            'severity': 'medium',
            'suggestion': 'Consider consolidating JavaScript files'
        })
    
    if asset_counts['stylesheets'] > 5:
        suggestions.append({
            'area': 'stylesheets',
            'severity': 'medium',
            'suggestion': 'Combine CSS files to reduce HTTP requests'
        })
    
    if asset_counts['images'] > 20:
        suggestions.append({
            'area': 'images',
            'severity': 'high',
            'suggestion': 'Optimize images and consider using next-gen formats like WebP'
        })
    elif asset_counts['images'] > 10:
        suggestions.append({
            'area': 'images',
            'severity': 'medium',
            'suggestion': 'Consider optimizing images for web delivery'
        })
    
    if asset_counts['fonts'] > 3:
        suggestions.append({
            'area': 'fonts',
            'severity': 'medium',
            'suggestion': 'Reduce custom font usage or use variable fonts'
        })
    
    if asset_counts['videos'] > 0:
        suggestions.append({
            'area': 'videos',
            'severity': 'info',
            'suggestion': 'Use efficient video delivery with proper compression and lazy loading'
        })
    
    return suggestions

def _calculate_cleanliness_score(page_size, dom_elements, asset_counts):
    """Calculate a cleanliness score based on page metrics."""
    # Start with a perfect score
    score = 100
    
    # Deduct points for large page size
    # Scale: Up to -30 points for page size
    if page_size > 5 * BYTES_TO_MB:  # > 5MB
        score -= 30
    elif page_size > 3 * BYTES_TO_MB:  # > 3MB
        score -= 20
    elif page_size > 1.5 * BYTES_TO_MB:  # > 1.5MB
        score -= 10
    elif page_size > 0.75 * BYTES_TO_MB:  # > 750KB
        score -= 5
    
    # Deduct for DOM complexity
    # Scale: Up to -20 points for DOM complexity
    if dom_elements > 2000:
        score -= 20
    elif dom_elements > 1500:
        score -= 15
    elif dom_elements > 1000:
        score -= 10
    elif dom_elements > 750:
        score -= 5
    
    # Deduct for excessive assets
    # Scale: Up to -50 points for excessive assets
    total_deduction = 0
    
    # Scripts
    if asset_counts['scripts'] > 20:
        total_deduction += 15
    elif asset_counts['scripts'] > 12:
        total_deduction += 10
    elif asset_counts['scripts'] > 8:
        total_deduction += 5
    
    # Stylesheets
    if asset_counts['stylesheets'] > 8:
        total_deduction += 10
    elif asset_counts['stylesheets'] > 5:
        total_deduction += 5
    elif asset_counts['stylesheets'] > 3:
        total_deduction += 2
    
    # Images
    if asset_counts['images'] > 30:
        total_deduction += 15
    elif asset_counts['images'] > 20:
        total_deduction += 10
    elif asset_counts['images'] > 10:
        total_deduction += 5
    
    # Fonts
    if asset_counts['fonts'] > 5:
        total_deduction += 10
    elif asset_counts['fonts'] > 3:
        total_deduction += 5
    
    # Cap total asset deductions at 50
    total_deduction = min(total_deduction, 50)
    score -= total_deduction
    
    # Ensure score is between 0 and 100
    score = max(0, min(100, score))
    
    # Get a description for the score
    description = "Excellent"
    if score < 60:
        description = "Poor"
    elif score < 70:
        description = "Fair"
    elif score < 80:
        description = "Good"
    elif score < 90:
        description = "Very Good"
    
    return {
        'score': round(score),
        'description': description,
        'grade': 'A+' if score >= 95 else 'A' if score >= 90 else 'B' if score >= 80 else 'C' if score >= 70 else 'D' if score >= 60 else 'F'
    }