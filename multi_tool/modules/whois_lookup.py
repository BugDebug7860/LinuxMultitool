"""Module for performing WHOIS lookups."""

import logging
import whois
import datetime

logger = logging.getLogger(__name__)

def perform_whois_lookup(domain):
    """
    Perform a WHOIS lookup for a domain.
    
    Args:
        domain (str): The domain to look up
        
    Returns:
        dict: WHOIS information for the domain
    """
    logger.debug(f"Performing WHOIS lookup for domain: {domain}")
    
    result = {
        "domain": domain,
        "error": None
    }
    
    try:
        # Perform WHOIS lookup
        whois_info = whois.whois(domain)
        
        # Process the results
        if whois_info:
            # Convert dates to string representation for easier serialization
            processed_info = {}
            for key, value in whois_info.items():
                if isinstance(value, datetime.datetime):
                    processed_info[key] = value.isoformat()
                elif isinstance(value, list) and value and isinstance(value[0], datetime.datetime):
                    processed_info[key] = [item.isoformat() if isinstance(item, datetime.datetime) else item 
                                          for item in value]
                else:
                    processed_info[key] = value
            
            # Map common WHOIS fields
            result.update({
                "registrar": processed_info.get("registrar"),
                "creation_date": processed_info.get("creation_date"),
                "expiration_date": processed_info.get("expiration_date"),
                "updated_date": processed_info.get("updated_date"),
                "name_servers": processed_info.get("name_servers"),
                "status": processed_info.get("status"),
                "emails": processed_info.get("emails"),
                "dnssec": processed_info.get("dnssec"),
                "raw": whois_info.text  # Include the raw WHOIS text
            })
            
            # Calculate days until expiration if expiration_date is available
            if "expiration_date" in processed_info and processed_info["expiration_date"]:
                try:
                    if isinstance(processed_info["expiration_date"], list):
                        expiry = datetime.datetime.fromisoformat(processed_info["expiration_date"][0])
                    else:
                        expiry = datetime.datetime.fromisoformat(processed_info["expiration_date"])
                    
                    days_until_expiry = (expiry - datetime.datetime.now()).days
                    result["days_until_expiry"] = days_until_expiry
                except (ValueError, TypeError) as e:
                    logger.error(f"Error calculating expiry days: {str(e)}")
                    result["days_until_expiry_error"] = str(e)
        else:
            result["error"] = "No WHOIS information found"
    
    except Exception as e:
        logger.error(f"WHOIS lookup error: {str(e)}")
        result["error"] = f"WHOIS lookup error: {str(e)}"
    
    logger.debug(f"WHOIS lookup result: {result}")
    return result
