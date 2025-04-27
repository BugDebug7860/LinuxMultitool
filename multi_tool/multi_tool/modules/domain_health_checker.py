#!/usr/bin/env python3
"""Module for checking domain health including registration and expiry details."""

import logging
import json
import re
import socket
import time
import whois
import tldextract
import validators
import requests
from datetime import datetime, timedelta
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def check_domain_health(domain):
    """
    Check domain health including registration, expiration, and reputation.
    
    Args:
        domain (str): The domain to analyze
        
    Returns:
        dict: Domain health analysis results
    """
    logger.debug(f"Starting domain health check for {domain}")
    
    # Process and validate domain
    if validators.url(domain):
        parsed_url = urlparse(domain)
        domain = parsed_url.netloc
    
    # Remove leading www if present
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Check if domain is valid
    if not validators.domain(domain):
        return {
            "error": "Invalid domain. Please provide a valid domain name.",
            "domain": domain
        }
    
    # Initialize results
    results = {
        "domain": domain,
        "analysis_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "registration": {},
        "expiry": {},
        "nameservers": [],
        "domain_age": None,
        "is_registered": True,
        "registrar": None,
        "registrant": {},
        "domain_status": [],
        "privacy_protection": False,
        "reputation": {},
        "potential_issues": [],
        "typosquatting": {
            "risk_level": "low",
            "similar_domains": []
        },
        "recommendations": []
    }
    
    try:
        # Get WHOIS information
        whois_info = get_whois_information(domain)
        
        if whois_info:
            # Process registration information
            process_registration_info(whois_info, results)
            
            # Check domain privacy
            check_domain_privacy(whois_info, results)
            
            # Check domain status
            if "status" in whois_info and whois_info["status"]:
                if isinstance(whois_info["status"], list):
                    results["domain_status"] = whois_info["status"]
                else:
                    results["domain_status"] = [whois_info["status"]]
        else:
            results["is_registered"] = False
            results["potential_issues"].append("Domain not registered or WHOIS information unavailable")
        
        # Get nameservers
        if "name_servers" in whois_info and whois_info["name_servers"]:
            if isinstance(whois_info["name_servers"], list):
                results["nameservers"] = [ns.lower() for ns in whois_info["name_servers"]]
            else:
                results["nameservers"] = [whois_info["name_servers"].lower()]
        
        # Check reputation
        results["reputation"] = check_domain_reputation(domain)
        
        # Check for potential typosquatting domains
        results["typosquatting"] = check_typosquatting(domain)
        
        # Generate recommendations
        results["recommendations"] = generate_recommendations(results)
        
    except Exception as e:
        logger.error(f"Error checking domain health: {str(e)}")
        results["error"] = f"Analysis error: {str(e)}"
    
    return results

def get_whois_information(domain):
    """
    Get WHOIS information for a domain.
    
    Args:
        domain (str): The domain to query
        
    Returns:
        dict: WHOIS information
    """
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        logger.error(f"Error retrieving WHOIS information: {str(e)}")
        return None

def process_registration_info(whois_info, results):
    """
    Process domain registration and expiration information.
    
    Args:
        whois_info (dict): WHOIS information
        results (dict): The results dictionary to update
    """
    # Extract creation date
    if "creation_date" in whois_info:
        creation_date = whois_info["creation_date"]
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            results["registration"]["date"] = creation_date.strftime("%Y-%m-%d")
            
            # Calculate domain age
            domain_age_days = (datetime.now() - creation_date).days
            domain_age_years = domain_age_days / 365.25
            
            results["domain_age"] = {
                "days": domain_age_days,
                "years": round(domain_age_years, 2)
            }
    
    # Extract expiration date
    if "expiration_date" in whois_info:
        expiry_date = whois_info["expiration_date"]
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]
        
        if expiry_date:
            results["expiry"]["date"] = expiry_date.strftime("%Y-%m-%d")
            
            # Calculate days until expiry
            days_to_expiry = (expiry_date - datetime.now()).days
            results["expiry"]["days_remaining"] = days_to_expiry
            
            # Determine expiry status
            if days_to_expiry <= 0:
                results["expiry"]["status"] = "expired"
                results["potential_issues"].append("Domain has expired")
            elif days_to_expiry <= 30:
                results["expiry"]["status"] = "critical"
                results["potential_issues"].append(f"Domain will expire in {days_to_expiry} days")
            elif days_to_expiry <= 90:
                results["expiry"]["status"] = "warning"
                results["potential_issues"].append(f"Domain will expire in {days_to_expiry} days")
            else:
                results["expiry"]["status"] = "good"
    
    # Extract registrar information
    if "registrar" in whois_info and whois_info["registrar"]:
        results["registrar"] = whois_info["registrar"]
    
    # Extract registrant information
    registrant_fields = {
        "name": ["registrant_name", "org", "organization", "registrant_org"],
        "email": ["registrant_email", "email"],
        "country": ["registrant_country", "country"],
        "state": ["registrant_state", "state"],
        "city": ["registrant_city", "city"]
    }
    
    for result_field, whois_fields in registrant_fields.items():
        for field in whois_fields:
            if field in whois_info and whois_info[field]:
                value = whois_info[field]
                if isinstance(value, list):
                    value = value[0]
                results["registrant"][result_field] = value
                break

def check_domain_privacy(whois_info, results):
    """
    Check if domain has privacy protection enabled.
    
    Args:
        whois_info (dict): WHOIS information
        results (dict): The results dictionary to update
    """
    privacy_keywords = [
        "privacy", "private", "protect", "proxy", "guard", "redacted", "withheld"
    ]
    
    # Look for privacy service in registrant fields
    for field in ["registrant_name", "org", "organization", "registrant_org", "email", "registrant_email"]:
        if field in whois_info and whois_info[field]:
            value = str(whois_info[field]).lower()
            if isinstance(value, list):
                value = " ".join([str(v).lower() for v in value])
            
            if any(keyword in value for keyword in privacy_keywords):
                results["privacy_protection"] = True
                return
    
    # Check for redacted/private information patterns
    privacy_patterns = [
        r"privacy", r"private", r"proxy", r"protect",
        r"redacted\s+for\s+privacy", r"personal\s+data", r"gdpr",
        r"withheld"
    ]
    
    whois_text = str(whois_info).lower()
    for pattern in privacy_patterns:
        if re.search(pattern, whois_text):
            results["privacy_protection"] = True
            return

def check_domain_reputation(domain):
    """
    Check domain reputation using various sources.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        dict: Domain reputation information
    """
    reputation = {
        "score": None,
        "category": None,
        "malicious": False,
        "suspicious": False,
        "age_factor": None,
        "checks": {},
        "sources": []
    }
    
    try:
        # Check if domain resolves (basic availability check)
        try:
            socket.gethostbyname(domain)
            reputation["checks"]["resolves"] = True
        except socket.gaierror:
            reputation["checks"]["resolves"] = False
            reputation["suspicious"] = True
        
        # Use domain age as a reputation factor if available
        if domain_age := extract_domain_age(domain):
            age_years = domain_age / 365.25
            if age_years < 0.25:  # Less than 3 months
                reputation["age_factor"] = "very_new"
                reputation["suspicious"] = True
            elif age_years < 1:  # Less than 1 year
                reputation["age_factor"] = "new"
            elif age_years < 3:  # Less than 3 years
                reputation["age_factor"] = "established"
            else:
                reputation["age_factor"] = "mature"
        
        # Try Google Safe Browsing API (simulated for this example)
        # In a real implementation, you would need an API key
        reputation["checks"]["safe_browsing"] = "unknown"
        
        # Simulate Phishing Database check
        phishing_score = simulate_phishing_check(domain)
        reputation["checks"]["phishing_score"] = phishing_score
        if phishing_score > 80:
            reputation["malicious"] = True
        elif phishing_score > 50:
            reputation["suspicious"] = True
        
        # Overall reputation score calculation (simplified)
        if reputation["malicious"]:
            reputation["score"] = 0  # Very bad
            reputation["category"] = "malicious"
        elif reputation["suspicious"]:
            reputation["score"] = 40 + (100 - phishing_score)  # Range: 20-50
            reputation["category"] = "suspicious"
        else:
            # Calculate based on age
            if reputation["age_factor"] == "mature":
                base_score = 90
            elif reputation["age_factor"] == "established":
                base_score = 75
            elif reputation["age_factor"] == "new":
                base_score = 60
            else:  # very_new
                base_score = 40
            
            reputation["score"] = base_score
            
            if reputation["score"] >= 80:
                reputation["category"] = "good"
            elif reputation["score"] >= 60:
                reputation["category"] = "moderate"
            else:
                reputation["category"] = "questionable"
        
    except Exception as e:
        logger.error(f"Error checking domain reputation: {str(e)}")
        reputation["error"] = str(e)
    
    return reputation

def extract_domain_age(domain):
    """
    Extract domain age in days from WHOIS information.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        int or None: Domain age in days, or None if unavailable
    """
    try:
        w = whois.whois(domain)
        if "creation_date" in w:
            creation_date = w["creation_date"]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                return (datetime.now() - creation_date).days
    
    except Exception:
        pass
    
    return None

def simulate_phishing_check(domain):
    """
    Simulate a phishing database check.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        int: Phishing risk score (0-100)
    """
    # Factors that might indicate phishing
    suspicious_factors = 0
    
    # 1. Domain name length (very long domains are suspicious)
    if len(domain) > 30:
        suspicious_factors += 1
    
    # 2. Contains brand names (simulated check)
    common_brands = ["paypal", "apple", "amazon", "google", "microsoft", "netflix", "bank", "secure", "login"]
    for brand in common_brands:
        if brand in domain.lower():
            suspicious_factors += 2
    
    # 3. Contains suspicious terms
    suspicious_terms = ["secure", "account", "login", "signin", "verify", "auth", "banking", "confirm"]
    for term in suspicious_terms:
        if term in domain.lower():
            suspicious_factors += 1
    
    # 4. Contains numbers (can indicate randomization)
    if re.search(r'\d', domain):
        suspicious_factors += 1
    
    # 5. Contains hyphens (often used in phishing domains)
    if domain.count('-') > 1:
        suspicious_factors += 1
    
    # Calculate score - this is just a simple simulation
    base_score = suspicious_factors * 12
    
    # Add some randomness to the score
    import random
    random_factor = random.randint(-10, 10)
    
    score = max(0, min(100, base_score + random_factor))
    return score

def check_typosquatting(domain):
    """
    Check for potential typosquatting domains.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        dict: Typosquatting analysis
    """
    result = {
        "risk_level": "low",
        "similar_domains": [],
        "total_found": 0
    }
    
    try:
        # Extract the domain without TLD for manipulation
        ext = tldextract.extract(domain)
        domain_name = ext.domain
        tld = ext.suffix
        
        if not tld:
            tld = "com"  # Default if no TLD found
        
        # Generate common typo variations
        variations = generate_typo_variations(domain_name, tld)
        
        # Check if the variations exist (simplified)
        existing_variations = []
        high_risk_count = 0
        
        for var in variations[:10]:  # Limit to 10 checks for performance
            if domain_exists(var):
                risk = "high" if is_high_risk_typo(domain, var) else "medium"
                var_info = {
                    "domain": var,
                    "risk": risk,
                    "registrable": True
                }
                existing_variations.append(var_info)
                
                if risk == "high":
                    high_risk_count += 1
        
        # Update results
        result["similar_domains"] = existing_variations
        result["total_found"] = len(existing_variations)
        
        # Determine overall risk level
        if high_risk_count > 0:
            result["risk_level"] = "high"
        elif len(existing_variations) > 0:
            result["risk_level"] = "medium"
        
    except Exception as e:
        logger.error(f"Error checking typosquatting: {str(e)}")
        result["error"] = str(e)
    
    return result

def generate_typo_variations(domain_name, tld):
    """
    Generate typo variations of a domain name.
    
    Args:
        domain_name (str): The domain name without TLD
        tld (str): The TLD
        
    Returns:
        list: Typo variations
    """
    variations = []
    
    # 1. Character swapping
    for i in range(len(domain_name) - 1):
        swapped = domain_name[:i] + domain_name[i+1] + domain_name[i] + domain_name[i+2:]
        variations.append(f"{swapped}.{tld}")
    
    # 2. Character omission
    for i in range(len(domain_name)):
        omitted = domain_name[:i] + domain_name[i+1:]
        variations.append(f"{omitted}.{tld}")
    
    # 3. Character replacement (common mistakes)
    replacements = {
        'a': ['e', 's', 'q', 'z'],
        'b': ['v', 'g', 'h', 'n'],
        'c': ['v', 'x', 'd'],
        'd': ['s', 'e', 'f', 'c'],
        'e': ['w', 'r', 'd', 'f'],
        'f': ['d', 'r', 'g', 'v'],
        'g': ['f', 't', 'h', 'b', 'v'],
        'h': ['g', 'y', 'j', 'n'],
        'i': ['u', 'o', 'k', 'j'],
        'j': ['h', 'u', 'k', 'n'],
        'k': ['j', 'i', 'l', 'm'],
        'l': ['k', 'o', 'p'],
        'm': ['n', 'j', 'k'],
        'n': ['b', 'h', 'j', 'm'],
        'o': ['i', 'p', 'l', '0'],
        'p': ['o', 'l'],
        'q': ['w', 'a'],
        'r': ['e', 'f', 't'],
        's': ['a', 'w', 'd', 'z'],
        't': ['r', 'g', 'y'],
        'u': ['y', 'i', 'j'],
        'v': ['c', 'f', 'g', 'b'],
        'w': ['q', 'e', 's'],
        'x': ['z', 'c'],
        'y': ['t', 'u', 'h'],
        'z': ['a', 's', 'x']
    }
    
    for i, char in enumerate(domain_name):
        if char.lower() in replacements:
            for replacement in replacements[char.lower()]:
                replaced = domain_name[:i] + replacement + domain_name[i+1:]
                variations.append(f"{replaced}.{tld}")
    
    # 4. Character insertion (common mistakes)
    letters = 'abcdefghijklmnopqrstuvwxyz0123456789-'
    for i in range(len(domain_name) + 1):
        for letter in letters[:6]:  # Limit to a few letters for performance
            inserted = domain_name[:i] + letter + domain_name[i:]
            variations.append(f"{inserted}.{tld}")
    
    # 5. Character duplication
    for i in range(len(domain_name)):
        duplicated = domain_name[:i+1] + domain_name[i:]
        variations.append(f"{duplicated}.{tld}")
    
    # 6. Common TLD variations
    common_tlds = ['com', 'net', 'org', 'co', 'io', 'info', 'biz']
    for common_tld in common_tlds:
        if common_tld != tld:
            variations.append(f"{domain_name}.{common_tld}")
    
    # 7. Homoglyphs (look-alike characters)
    homoglyphs = {
        'a': ['à', 'á', 'â', 'ã', 'ä', 'å', 'а'],
        'b': ['d', 'lb', 'ib', 'ʙ', 'Ь', 'ß', 'β'],
        'c': ['ϲ', 'с', 'ƈ'],
        'd': ['b', 'cl', 'dl', 'ԁ'],
        'e': ['é', 'ê', 'ë', 'ē', 'ė', 'ę', 'е', 'ë'],
        'g': ['q', 'ɢ', 'ɡ', 'қ'],
        'h': ['һ', 'հ'],
        'i': ['1', 'l', '|', 'ı', 'í', 'ï', 'ī', 'ı'],
        'j': ['ј', 'ʝ'],
        'k': ['κ', 'к'],
        'l': ['1', 'i', '|', 'ł', 'ӏ'],
        'm': ['n', 'nn', 'rn', 'rr', 'ṃ', 'ᴍ', 'м'],
        'n': ['m', 'r', 'ń', 'ñ', 'ṇ', 'ṅ'],
        'o': ['0', 'ο', 'о', 'ө', 'ō', 'ο'],
        'p': ['ρ', 'р', 'ṗ', 'ƿ'],
        'q': ['g', 'զ'],
        'r': ['ʀ', 'ʁ', 'ɾ', 'ɼ', 'ɽ'],
        's': ['ß', 'ѕ', 'ś', 'ş'],
        'u': ['μ', 'υ', 'ц', 'ս', 'ü', 'ù', 'ú', 'û'],
        'v': ['ν', 'υ', 'ѵ'],
        'w': ['vv', 'ѡ', 'ԝ'],
        'y': ['ý', 'ÿ', 'ỳ', 'ү', 'υ'],
        'z': ['ʐ', 'ż', 'ź', 'ʐ']
    }
    
    for i, char in enumerate(domain_name):
        if char.lower() in homoglyphs:
            for homoglyph in homoglyphs[char.lower()][:2]:  # Limit to 2 homoglyphs for performance
                replaced = domain_name[:i] + homoglyph + domain_name[i+1:]
                variations.append(f"{replaced}.{tld}")
    
    # Return unique variations
    return list(set(variations))

def domain_exists(domain):
    """
    Check if a domain exists by attempting a DNS resolution.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        bool: True if the domain exists
    """
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def is_high_risk_typo(original_domain, typo_domain):
    """
    Determine if a typo domain is high risk.
    
    Args:
        original_domain (str): The original domain
        typo_domain (str): The typo domain to check
        
    Returns:
        bool: True if the typo is high risk
    """
    # Extract domain parts
    original_parts = tldextract.extract(original_domain)
    typo_parts = tldextract.extract(typo_domain)
    
    # High risk if only one character difference
    if len(original_parts.domain) == len(typo_parts.domain):
        diff_count = sum(1 for a, b in zip(original_parts.domain, typo_parts.domain) if a != b)
        if diff_count == 1:
            return True
    
    # High risk if common TLD variation
    if original_parts.domain == typo_parts.domain and original_parts.suffix != typo_parts.suffix:
        return True
    
    # High risk if homoglyph attack
    homoglyph_count = 0
    for a, b in zip(original_parts.domain, typo_parts.domain):
        if a != b and ord(b) > 127:  # Non-ASCII character
            homoglyph_count += 1
    
    if homoglyph_count > 0:
        return True
    
    return False

def generate_recommendations(results):
    """
    Generate recommendations based on domain health analysis.
    
    Args:
        results (dict): The analysis results
        
    Returns:
        list: Recommendations
    """
    recommendations = []
    
    # Check domain expiration
    if "expiry" in results and "days_remaining" in results["expiry"]:
        days_remaining = results["expiry"]["days_remaining"]
        
        if days_remaining <= 0:
            recommendations.append({
                "title": "Renew domain immediately",
                "description": "Your domain has expired. Renew it immediately to prevent it from being released and potentially registered by someone else.",
                "priority": "critical"
            })
        elif days_remaining <= 30:
            recommendations.append({
                "title": "Renew domain soon",
                "description": f"Your domain will expire in {days_remaining} days. Renew it soon to avoid service interruption.",
                "priority": "high"
            })
        elif days_remaining <= 90:
            recommendations.append({
                "title": "Plan for domain renewal",
                "description": f"Your domain will expire in {days_remaining} days. Plan to renew it within the next month.",
                "priority": "medium"
            })
    
    # Check domain lock status
    if "domain_status" in results:
        statuses = [status.lower() for status in results["domain_status"]]
        has_transfer_lock = any("clienttransferprohibited" in status for status in statuses)
        
        if not has_transfer_lock:
            recommendations.append({
                "title": "Enable domain transfer lock",
                "description": "Your domain doesn't have a transfer lock enabled. Enable it to prevent unauthorized transfers.",
                "priority": "high"
            })
    
    # Check privacy protection
    if not results["privacy_protection"]:
        recommendations.append({
            "title": "Enable WHOIS privacy protection",
            "description": "Your domain doesn't have WHOIS privacy protection. Your personal information is publicly visible, which could lead to spam and social engineering attempts.",
            "priority": "medium"
        })
    
    # Check nameservers redundancy
    if len(results["nameservers"]) < 2:
        recommendations.append({
            "title": "Add redundant nameservers",
            "description": "Your domain has fewer than two nameservers. Add additional nameservers to improve DNS reliability.",
            "priority": "medium"
        })
    
    # Check for typosquatting risk
    typosquatting = results["typosquatting"]
    if typosquatting["risk_level"] in ["medium", "high"]:
        typo_domains = [d["domain"] for d in typosquatting["similar_domains"][:3]]
        recommendations.append({
            "title": "Monitor for typosquatting domains",
            "description": f"There are {typosquatting['total_found']} domains similar to yours that could be used for typosquatting. Consider monitoring or registering domains like: {', '.join(typo_domains)}.",
            "priority": "medium" if typosquatting["risk_level"] == "medium" else "high"
        })
    
    # Check domain reputation
    reputation = results["reputation"]
    if reputation["suspicious"] or reputation["malicious"]:
        recommendations.append({
            "title": "Investigate domain reputation issues",
            "description": f"Your domain has a {reputation['category']} reputation with a score of {reputation['score']}. Investigate potential security issues affecting your domain's reputation.",
            "priority": "high" if reputation["malicious"] else "medium"
        })
    
    # General recommendations
    recommendations.append({
        "title": "Set up auto-renewal",
        "description": "Ensure your domain is set to auto-renew to prevent accidental expiration.",
        "priority": "medium"
    })
    
    recommendations.append({
        "title": "Verify contact information",
        "description": "Ensure the contact information for your domain is current, even if using privacy protection.",
        "priority": "medium"
    })
    
    # Sort recommendations by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    recommendations.sort(key=lambda x: priority_order.get(x["priority"], 4))
    
    return recommendations

if __name__ == "__main__":
    # Example usage
    results = check_domain_health("example.com")
    print(json.dumps(results, indent=2))