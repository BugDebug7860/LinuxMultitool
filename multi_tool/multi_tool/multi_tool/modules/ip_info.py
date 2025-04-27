"""Module for retrieving information about an IP address."""

import os
import logging
import socket
import requests
import ipaddress

logger = logging.getLogger(__name__)

def get_ip_info(ip_address):
    """
    Get information about an IP address.
    
    Args:
        ip_address (str): The IP address to analyze
        
    Returns:
        dict: Information about the IP address
    """
    logger.debug(f"Getting information for IP: {ip_address}")
    
    # Validate IP address
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        # If not a valid IP, try to resolve domain
        try:
            logger.debug(f"Not a valid IP, attempting to resolve domain: {ip_address}")
            ip_address = socket.gethostbyname(ip_address)
            logger.debug(f"Resolved to IP: {ip_address}")
        except socket.gaierror:
            return {"error": f"Invalid IP address or hostname: {ip_address}"}
    
    result = {
        "ip": ip_address,
        "hostname": None,
        "location": {},
        "network": {}
    }
    
    # Try to get hostname from IP
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        result["hostname"] = hostname
    except (socket.herror, socket.gaierror):
        result["hostname"] = "Unknown"
    
    # Get more details from ipinfo.io
    try:
        # Get API token from environment variable
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
                    "timezone": data.get("timezone", "Unknown")
                }
            
            # Extract network data
            result["network"] = {
                "organization": data.get("org", "Unknown"),
                "asn": data.get("asn", "Unknown"),
                "isp": data.get("org", "Unknown").split(" ")[1] if data.get("org", "").count(" ") >= 1 else "Unknown"
            }
            
            # Add any other data that might be useful
            result.update({k: v for k, v in data.items() if k not in result and k not in ["loc", "readme"]})
            
        else:
            logger.warning(f"Failed to get data from ipinfo.io: {response.status_code}")
            result["ipinfo_error"] = f"HTTP {response.status_code}"
            
    except requests.RequestException as e:
        logger.error(f"Request to ipinfo.io failed: {str(e)}")
        result["ipinfo_error"] = str(e)
    
    logger.debug(f"IP info result: {result}")
    return result
