"""Module for capturing screenshots of websites."""

import logging
import os
import validators
import tempfile
from datetime import datetime
from PIL import Image
import base64
import io

# Choose the right screenshot library based on availability
# Try to use pyppeteer first (headless Chrome)
try:
    import asyncio
    from pyppeteer import launch
    SCREENSHOT_LIBRARY = "pyppeteer"
except ImportError:
    # Fall back to selenium if pyppeteer is not available
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        SCREENSHOT_LIBRARY = "selenium"
    except ImportError:
        SCREENSHOT_LIBRARY = None

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def _capture_with_pyppeteer(url, width=1280, height=800, full_page=True, wait_time=5):
    """Capture screenshot using pyppeteer (headless Chrome)."""
    logger.debug(f"Capturing screenshot with pyppeteer: {url}")
    
    browser = None
    try:
        browser = await launch(
            headless=True,
            args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
        )
        page = await browser.newPage()
        await page.setViewport({'width': width, 'height': height})
        await page.goto(url, {'waitUntil': 'networkidle2', 'timeout': 60000})
        
        # Wait for content to load
        await asyncio.sleep(wait_time)
        
        # Take screenshot
        screenshot_data = await page.screenshot({'fullPage': full_page})
        
        return screenshot_data
    finally:
        if browser:
            await browser.close()

def _capture_with_selenium(url, width=1280, height=800, full_page=True, wait_time=5):
    """Capture screenshot using selenium with Chrome/Chromium."""
    logger.debug(f"Capturing screenshot with selenium: {url}")
    
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument(f"--window-size={width},{height}")
    
    driver = None
    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        
        # Wait for content to load
        import time
        time.sleep(wait_time)
        
        # Take screenshot
        screenshot_data = driver.get_screenshot_as_png()
        
        return screenshot_data
    finally:
        if driver:
            driver.quit()

def capture_screenshot(url, width=1280, height=800, full_page=True, 
                      output_format='png', output_path=None, 
                      include_base64=True, wait_time=5):
    """
    Capture a screenshot of a website.
    
    Args:
        url (str): The URL to capture
        width (int): Viewport width
        height (int): Viewport height
        full_page (bool): Whether to capture the full page or just viewport
        output_format (str): Output format ('png' or 'jpg')
        output_path (str): Path to save the screenshot (optional)
        include_base64 (bool): Whether to include base64 encoded image in result
        wait_time (int): Time to wait for page to load in seconds
        
    Returns:
        dict: Screenshot information including path and optionally base64 data
    """
    logger.debug(f"Capturing screenshot for URL: {url}")
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    if not validators.url(url):
        raise ValueError(f"Invalid URL: {url}")
    
    # Check if we have a supported library
    if not SCREENSHOT_LIBRARY:
        raise RuntimeError("No supported screenshot library available. "
                          "Please install either pyppeteer or selenium.")
    
    # Capture screenshot
    screenshot_data = None
    try:
        if SCREENSHOT_LIBRARY == "pyppeteer":
            # Run in async event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            screenshot_data = loop.run_until_complete(
                _capture_with_pyppeteer(url, width, height, full_page, wait_time)
            )
        elif SCREENSHOT_LIBRARY == "selenium":
            screenshot_data = _capture_with_selenium(url, width, height, full_page, wait_time)
    except Exception as e:
        logger.error(f"Error capturing screenshot: {e}")
        raise
    
    # Process the screenshot
    if not screenshot_data:
        raise RuntimeError("Failed to capture screenshot")
    
    # Convert to desired format if needed
    img = Image.open(io.BytesIO(screenshot_data))
    
    # Save to file if output_path is specified
    if output_path:
        img.save(output_path, format=output_format.upper())
        file_path = os.path.abspath(output_path)
    else:
        # Create a temp file with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"screenshot_{timestamp}.{output_format}"
        temp_dir = tempfile.gettempdir()
        file_path = os.path.join(temp_dir, filename)
        img.save(file_path, format=output_format.upper())
    
    # Prepare result
    result = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'dimensions': {
            'width': img.width,
            'height': img.height
        },
        'file_path': file_path,
        'file_format': output_format,
        'file_size_bytes': os.path.getsize(file_path)
    }
    
    # Add base64 data if requested
    if include_base64:
        buffered = io.BytesIO()
        img.save(buffered, format=output_format.upper())
        img_str = base64.b64encode(buffered.getvalue()).decode()
        result['base64_data'] = f"data:image/{output_format};base64,{img_str}"
        
    return result