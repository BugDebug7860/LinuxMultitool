"""Module for identifying hosts associated with a domain."""

import logging
import requests
import dns.resolver
import validators
import tldextract
import whois
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def identify_associated_hosts(domain):
    """
    Identify hosts associated with a domain.
    
    Args:
        domain (str): The domain to analyze
        
    Returns:
        dict: Associated hosts information
    """
    logger.debug(f"Identifying hosts associated with domain: {domain}")
    
    # Extract the base domain
    extracted = tldextract.extract(domain)
    base_domain = f"{extracted.domain}.{extracted.suffix}"
    
    # Identify subdomains (using DNS)
    subdomains = find_common_subdomains(base_domain)
    
    # Identify related domains
    related_domains = find_related_domains(base_domain)
    
    # DNS-based association
    dns_associations = find_dns_associations(base_domain)
    
    result = {
        'domain': domain,
        'base_domain': base_domain,
        'subdomains': subdomains,
        'related_domains': related_domains,
        'dns_associations': dns_associations
    }
    
    logger.debug(f"Associated hosts result: {result}")
    return result

def find_common_subdomains(domain):
    """
    Find common subdomains by checking DNS records.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        list: Found subdomains
    """
    common_prefixes = [
        'www', 'mail', 'blog', 'shop', 'store', 'portal', 'api',
        'app', 'dev', 'staging', 'test', 'demo', 'admin', 'login',
        'webmail', 'cdn', 'media', 'static', 'docs', 'support'
    ]
    
    found_subdomains = []
    
    for prefix in common_prefixes:
        subdomain = f"{prefix}.{domain}"
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            if answers:
                ip_addresses = [answer.address for answer in answers]
                found_subdomains.append({
                    'subdomain': subdomain,
                    'ip_addresses': ip_addresses
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            continue
    
    return found_subdomains

def find_related_domains(domain):
    """
    Find domains related to the base domain through various means.
    
    Args:
        domain (str): The base domain
        
    Returns:
        dict: Related domains information
    """
    # Extract domain parts
    extracted = tldextract.extract(domain)
    domain_name = extracted.domain
    
    # Try common TLDs
    common_tlds = [
        'com', 'org', 'net', 'io', 'co', 'app', 'dev', 'info',
        'biz', 'us', 'uk', 'eu', 'ca', 'au', 'de', 'fr'
    ]
    
    found_domains = []
    
    for tld in common_tlds:
        if f".{tld}" == f".{extracted.suffix}":
            continue  # Skip the original domain's TLD
            
        related_domain = f"{domain_name}.{tld}"
        try:
            # Check if domain exists by attempting to resolve it
            answers = dns.resolver.resolve(related_domain, 'A')
            if answers:
                registration_info = get_domain_registration(related_domain)
                found_domains.append({
                    'domain': related_domain,
                    'ip_addresses': [answer.address for answer in answers],
                    'registration': registration_info
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            continue
    
    return found_domains

def find_dns_associations(domain):
    """
    Find domain associations through DNS records.
    
    Args:
        domain (str): The domain to analyze
        
    Returns:
        dict: DNS associations
    """
    dns_associations = {
        'mx_records': [],
        'ns_records': [],
        'txt_records': [],
        'spf_records': [],
        'dmarc_records': []
    }
    
    # Get MX records (mail servers)
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        dns_associations['mx_records'] = [
            {'preference': answer.preference, 'exchange': str(answer.exchange)} 
            for answer in answers
        ]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    
    # Get NS records (name servers)
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        dns_associations['ns_records'] = [str(answer) for answer in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    
    # Get TXT records
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        dns_associations['txt_records'] = [str(answer) for answer in answers]
        
        # Look for SPF records in TXT records
        dns_associations['spf_records'] = [
            txt for txt in dns_associations['txt_records'] 
            if txt.startswith('v=spf1')
        ]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    
    # Get DMARC record
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        dns_associations['dmarc_records'] = [str(answer) for answer in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    
    return dns_associations

def get_domain_registration(domain):
    """
    Get domain registration information.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        dict: Registration information
    """
    try:
        w = whois.whois(domain)
        
        # Extract creation and expiration dates
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        
        # Handle different types of date responses
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
            
        # Convert to string representations if dates are available
        creation_str = creation_date.strftime('%Y-%m-%d') if creation_date else None
        expiration_str = expiration_date.strftime('%Y-%m-%d') if expiration_date else None
        
        return {
            'registrar': w.registrar,
            'creation_date': creation_str,
            'expiration_date': expiration_str,
            'status': w.status if isinstance(w.status, list) else [w.status] if w.status else []
        }
    except Exception as e:
        logger.debug(f"Error getting whois information for {domain}: {e}")
        return {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'status': []
        }