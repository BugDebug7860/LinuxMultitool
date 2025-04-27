"""Module for retrieving server location information."""

import logging
import socket
import os
import requests

logger = logging.getLogger(__name__)

def get_server_location(domain):
    """
    Get server location information for a domain.
    
    Args:
        domain (str): The domain to analyze
        
    Returns:
        dict: Server location information
    """
    logger.debug(f"Getting server location for domain: {domain}")
    
    result = {
        "domain": domain,
        "ip": None,
        "location": {},
        "error": None
    }
    
    try:
        # Resolve domain to IP address
        ip_address = socket.gethostbyname(domain)
        result["ip"] = ip_address
        
        # Get location data from ipinfo.io
        token = os.getenv("IPINFO_TOKEN", "")
        
        # Prepare URL with token if available
        url = f"https://ipinfo.io/{ip_address}/json"
        if token:
            url += f"?token={token}"
            
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract location data
            if "loc" in data:
                lat, lon = data.get("loc", "").split(",")
                result["location"] = {
                    "latitude": lat,
                    "longitude": lon,
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "timezone": data.get("timezone", "Unknown"),
                    "postal": data.get("postal", "Unknown")
                }
            
            # Add network information
            result["network"] = {
                "asn": data.get("asn", "Unknown"),
                "organization": data.get("org", "Unknown")
            }
            
        else:
            logger.warning(f"Failed to get location data: HTTP {response.status_code}")
            result["error"] = f"Failed to get location data: HTTP {response.status_code}"
    
    except socket.gaierror:
        logger.error(f"Could not resolve domain: {domain}")
        result["error"] = f"Could not resolve domain: {domain}"
    except requests.RequestException as e:
        logger.error(f"Request error: {str(e)}")
        result["error"] = f"Request error: {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        result["error"] = f"Unexpected error: {str(e)}"
    
    logger.debug(f"Server location result: {result}")
    return result
