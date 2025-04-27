"""Module for gathering comprehensive domain information."""

import logging
import requests
import validators
import socket
import dns.resolver
import tldextract
import whois
from datetime import datetime
import re

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_domain_info(domain):
    """
    Get comprehensive information about a domain.
    
    Args:
        domain (str): The domain to analyze
        
    Returns:
        dict: Comprehensive domain information
    """
    logger.debug(f"Getting domain information for: {domain}")
    
    # Validate domain
    if domain.startswith(('http://', 'https://')):
        # Extract domain from URL
        domain = domain.split('//')[1].split('/')[0]
    
    if not validators.domain(domain):
        raise ValueError(f"Invalid domain: {domain}")
    
    try:
        # Extract domain components
        extracted = tldextract.extract(domain)
        
        # Get registration information
        registration_info = _get_registration_info(domain)
        
        # Get DNS information
        dns_info = _get_dns_info(domain)
        
        # Get SSL/TLS status
        ssl_info = _check_ssl_status(domain)
        
        # Get name server configuration quality
        ns_quality = _check_nameserver_quality(dns_info.get('ns_records', []))
        
        # Perform reputation checks
        reputation = _check_domain_reputation(domain)
        
        # Check if the domain is a subdomain
        is_subdomain = bool(extracted.subdomain)
        parent_domain = f"{extracted.domain}.{extracted.suffix}" if is_subdomain else None
        
        # Check for typosquatting potential
        typosquatting_info = _check_typosquatting_potential(domain)
        
        result = {
            'domain': domain,
            'components': {
                'subdomain': extracted.subdomain,
                'domain': extracted.domain,
                'suffix': extracted.suffix,
                'is_subdomain': is_subdomain,
                'parent_domain': parent_domain
            },
            'registration': registration_info,
            'dns': dns_info,
            'ssl': ssl_info,
            'nameservers': {
                'quality': ns_quality
            },
            'reputation': reputation,
            'typosquatting': typosquatting_info
        }
        
        logger.debug(f"Domain info result: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error getting domain information: {e}")
        raise

def _get_registration_info(domain):
    """Get domain registration information."""
    try:
        w = whois.whois(domain)
        
        # Handle different date formats
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        updated_date = w.updated_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if isinstance(updated_date, list):
            updated_date = updated_date[0]
            
        # Format dates as strings if they exist
        creation_str = creation_date.strftime('%Y-%m-%d') if creation_date else None
        expiration_str = expiration_date.strftime('%Y-%m-%d') if expiration_date else None
        updated_str = updated_date.strftime('%Y-%m-%d') if updated_date else None
        
        # Calculate days until expiration
        days_until_expiration = None
        if expiration_date:
            try:
                days_until_expiration = (expiration_date - datetime.now()).days
            except:
                pass
        
        # Calculate domain age
        domain_age_days = None
        if creation_date:
            try:
                domain_age_days = (datetime.now() - creation_date).days
            except:
                pass
        
        result = {
            'registrar': w.registrar,
            'organization': w.org,
            'creation_date': creation_str,
            'expiration_date': expiration_str,
            'last_updated': updated_str,
            'days_until_expiration': days_until_expiration,
            'domain_age_days': domain_age_days,
            'status': w.status if isinstance(w.status, list) else [w.status] if w.status else [],
            'dnssec': w.dnssec if hasattr(w, 'dnssec') else None,
            'privacy': 'Privacy service detected' if any('privacy' in str(s).lower() for s in w.status if s) else 'No privacy service detected'
        }
        
        # Determine if the domain is at risk (expiring soon)
        if days_until_expiration is not None:
            if days_until_expiration <= 30:
                result['expiration_risk'] = 'Critical - expires in less than 30 days'
            elif days_until_expiration <= 90:
                result['expiration_risk'] = 'Warning - expires in less than 90 days'
            else:
                result['expiration_risk'] = 'Good - more than 90 days until expiration'
        
        return result
    except Exception as e:
        logger.debug(f"Error getting whois information: {e}")
        return {
            'error': str(e),
            'available': _check_domain_availability(domain)
        }

def _get_dns_info(domain):
    """Get DNS information for the domain."""
    result = {
        'a_records': [],
        'aaaa_records': [],
        'mx_records': [],
        'ns_records': [],
        'txt_records': [],
        'cname_records': [],
        'dmarc_records': [],
        'spf_records': []
    }
    
    # Get A records
    try:
        answers = dns.resolver.resolve(domain, 'A')
        result['a_records'] = [answer.address for answer in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    
    # Get AAAA records (IPv6)
    try:
        answers = dns.resolver.resolve(domain, 'AAAA')
        result['aaaa_records'] = [answer.address for answer in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    
    # Get MX records
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        result['mx_records'] = [
            {'preference': answer.preference, 'exchange': str(answer.exchange)} 
            for answer in answers
        ]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    
    # Get NS records
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        result['ns_records'] = [str(answer).rstrip('.') for answer in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    
    # Get TXT records
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                txt = txt_string.decode('utf-8', errors='ignore')
                result['txt_records'].append(txt)
                
                # Check for SPF record
                if txt.startswith('v=spf1'):
                    result['spf_records'].append(txt)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    
    # Get CNAME records
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        result['cname_records'] = [str(answer) for answer in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    
    # Get DMARC record
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                dmarc = txt_string.decode('utf-8', errors='ignore')
                if dmarc.startswith('v=DMARC1'):
                    result['dmarc_records'].append(dmarc)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    
    # Add record counts
    result['record_counts'] = {
        'a': len(result['a_records']),
        'aaaa': len(result['aaaa_records']),
        'mx': len(result['mx_records']),
        'ns': len(result['ns_records']),
        'txt': len(result['txt_records']),
        'cname': len(result['cname_records']),
        'dmarc': len(result['dmarc_records']),
        'spf': len(result['spf_records'])
    }
    
    return result

def _check_ssl_status(domain):
    """Check if the domain has a valid SSL certificate."""
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        return {
            'has_ssl': True,
            'status_code': response.status_code
        }
    except requests.exceptions.SSLError:
        return {
            'has_ssl': False,
            'error': 'SSL certificate error'
        }
    except requests.exceptions.RequestException as e:
        return {
            'has_ssl': False,
            'error': str(e)
        }

def _check_nameserver_quality(nameservers):
    """Check the quality of the domain's nameserver configuration."""
    # Count unique nameserver providers
    providers = set()
    for ns in nameservers:
        provider = _extract_ns_provider(ns)
        providers.add(provider)
    
    # Check if nameservers are spread across multiple providers
    diverse_providers = len(providers) > 1
    
    # Check if enough nameservers are configured
    enough_nameservers = len(nameservers) >= 2
    
    # Determine quality rating
    if diverse_providers and enough_nameservers:
        quality = "Excellent"
    elif not diverse_providers and enough_nameservers:
        quality = "Good"
    elif not enough_nameservers:
        quality = "Poor"
    else:
        quality = "Fair"
    
    return {
        'count': len(nameservers),
        'unique_providers': len(providers),
        'providers': list(providers),
        'quality_rating': quality,
        'resilient': diverse_providers and enough_nameservers
    }

def _extract_ns_provider(nameserver):
    """Extract the provider from a nameserver hostname."""
    nameserver = nameserver.lower()
    
    provider_patterns = {
        'cloudflare': r'cloudflare',
        'google': r'(google|googledomains)',
        'amazon/aws': r'(aws|amazon)',
        'godaddy': r'(godaddy|domaincontrol)',
        'namecheap': r'namecheap',
        'route53': r'awsdns',
        'digitalocean': r'digitalocean',
        'dnsmadeeasy': r'dnsmadeeasy',
        'dyn': r'dyn',
        'easydns': r'easydns',
        'linode': r'linode',
        'ns1': r'^ns1\.',
        'rackspace': r'rackspace',
        'vultr': r'vultr',
        'hetzner': r'hetzner',
        'ovh': r'ovh',
        'name.com': r'name\.com',
        'netlify': r'netlify',
        'vercel': r'vercel',
        'azure': r'azure'
    }
    
    for provider, pattern in provider_patterns.items():
        if re.search(pattern, nameserver):
            return provider
    
    # Extract the TLD part as a fallback
    extracted = tldextract.extract(nameserver)
    return f"Unknown ({extracted.domain}.{extracted.suffix})"

def _check_domain_reputation(domain):
    """Perform basic domain reputation checks."""
    # Note: This is a simplified implementation
    # In a real tool, you would integrate with reputation services

    # Check domain age (older domains are generally more trustworthy)
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        age_days = (datetime.now() - creation_date).days if creation_date else 0
        
        # Determine age-based reputation
        if age_days > 365 * 5:  # Older than 5 years
            age_reputation = "Excellent"
        elif age_days > 365 * 2:  # Older than 2 years
            age_reputation = "Good"
        elif age_days > 365:  # Older than 1 year
            age_reputation = "Fair"
        else:
            age_reputation = "New domain"
        
        return {
            'age_based': {
                'days': age_days,
                'rating': age_reputation
            }
        }
    except Exception as e:
        logger.debug(f"Error checking domain age: {e}")
        return {
            'age_based': {
                'error': str(e)
            }
        }

def _check_domain_availability(domain):
    """Check if a domain is available for registration."""
    try:
        socket.gethostbyname(domain)
        return False  # Domain resolves, so it's not available
    except:
        try:
            # Check WHOIS data
            w = whois.whois(domain)
            # If domain exists, it will have registration data
            return not bool(w.domain_name)
        except:
            # If WHOIS lookup fails, domain might be available
            return True

def _check_typosquatting_potential(domain):
    """Check if the domain has potential for typosquatting."""
    # Extract domain parts
    extracted = tldextract.extract(domain)
    domain_name = extracted.domain
    domain_suffix = extracted.suffix
    
    # Skip non-meaningful domain names
    if len(domain_name) <= 3:
        return {
            'risk': 'Low',
            'reason': 'Domain name too short for significant typosquatting risk'
        }
    
    # Check for common typosquatting techniques
    common_typos = []
    
    # Character replacement (e.g., 'o' to '0')
    for i, char in enumerate(domain_name):
        if char in 'aeiou':
            common_typos.append(f"{domain_name[:i]}{'0' if char=='o' else 'i' if char=='l' else char}{domain_name[i+1:]}.{domain_suffix}")
    
    # Character omission
    for i in range(len(domain_name)):
        common_typos.append(f"{domain_name[:i]}{domain_name[i+1:]}.{domain_suffix}")
    
    # Character swapping
    for i in range(len(domain_name) - 1):
        swapped = list(domain_name)
        swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
        common_typos.append(f"{''.join(swapped)}.{domain_suffix}")
    
    # Character duplication
    for i, char in enumerate(domain_name):
        common_typos.append(f"{domain_name[:i]}{char}{char}{domain_name[i+1:]}.{domain_suffix}")
    
    # Determine risk level based on domain characteristics
    risk_level = "Medium"  # Default
    
    # Popular TLDs are at higher risk
    high_risk_tlds = ['com', 'net', 'org']
    if domain_suffix in high_risk_tlds:
        risk_level = "High"
    
    # Very short domains or very long domains have different risks
    if len(domain_name) < 5:
        risk_level = "Low"  # Short domains have fewer typo possibilities
    elif len(domain_name) > 15:
        risk_level = "Low"  # Long domains are less likely to be targets
    
    return {
        'risk': risk_level,
        'common_typo_examples': common_typos[:5],  # Limit to 5 examples
        'typo_count': len(common_typos)
    }