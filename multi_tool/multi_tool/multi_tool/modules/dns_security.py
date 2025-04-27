"""Module for checking DNS Security Extensions (DNSSEC) implementation."""

import logging
import dns.resolver
import dns.dnssec
import dns.name
import dns.message
import dns.query
import dns.rdatatype
import validators

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_dnssec(domain):
    """
    Check DNS Security Extensions (DNSSEC) implementation for a domain.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        dict: DNSSEC information
    """
    logger.debug(f"Checking DNSSEC for domain: {domain}")
    
    # Validate domain
    if domain.startswith(('http://', 'https://')):
        # Extract domain from URL
        domain = domain.split('//')[1].split('/')[0]
    
    if not validators.domain(domain):
        raise ValueError(f"Invalid domain: {domain}")
    
    try:
        # Get DNSKEY records
        dnskey_records = []
        try:
            answers = dns.resolver.resolve(domain, 'DNSKEY')
            dnskey_records = [{'flags': answer.flags, 'protocol': answer.protocol, 'algorithm': answer.algorithm} for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
            logger.debug(f"Error getting DNSKEY records: {e}")
        
        # Get DS records
        ds_records = []
        try:
            parent_domain = _get_parent_domain(domain)
            answers = dns.resolver.resolve(domain, 'DS')
            ds_records = [{'key_tag': answer.key_tag, 'algorithm': answer.algorithm, 'digest_type': answer.digest_type} for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
            logger.debug(f"Error getting DS records: {e}")
        
        # Check if DNSSEC is enabled
        dnssec_enabled = bool(dnskey_records and ds_records)
        
        # Check if DNSSEC validation succeeds
        validation_status = _check_dnssec_validation(domain) if dnssec_enabled else {'status': 'Not applicable', 'details': 'DNSSEC not enabled'}
        
        # Check for common misconfigurations
        misconfigurations = _check_for_misconfigurations(domain, dnskey_records, ds_records)
        
        result = {
            'domain': domain,
            'dnssec_enabled': dnssec_enabled,
            'dnskey_records': {
                'count': len(dnskey_records),
                'records': dnskey_records
            },
            'ds_records': {
                'count': len(ds_records),
                'records': ds_records
            },
            'validation': validation_status,
            'misconfigurations': misconfigurations
        }
        
        # Add a security recommendation
        if not dnssec_enabled:
            result['recommendation'] = 'Consider implementing DNSSEC to protect against DNS spoofing attacks'
        elif misconfigurations:
            result['recommendation'] = 'Address DNSSEC misconfigurations to ensure proper protection'
        else:
            result['recommendation'] = 'DNSSEC is properly configured, maintain regular key rotation'
        
        logger.debug(f"DNSSEC check result: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error checking DNSSEC: {e}")
        raise

def _get_parent_domain(domain):
    """Get the parent domain for a given domain."""
    parts = domain.split('.')
    if len(parts) > 2:
        return '.'.join(parts[1:])
    return domain

def _check_dnssec_validation(domain):
    """Check if DNSSEC validation succeeds for a domain."""
    try:
        # Create a resolver that forces DNSSEC validation
        resolver = dns.resolver.Resolver()
        resolver.edns = True
        resolver.dnssec = True
        
        # Try to resolve the domain with validation
        try:
            resolver.resolve(domain, 'A')
            return {
                'status': 'Success',
                'details': 'DNSSEC validation successful'
            }
        except dns.resolver.DNSError as e:
            if 'SERVFAIL' in str(e):
                return {
                    'status': 'Failed',
                    'details': 'DNSSEC validation failed, received SERVFAIL'
                }
            else:
                return {
                    'status': 'Unknown',
                    'details': f'Error during validation: {str(e)}'
                }
        
    except Exception as e:
        return {
            'status': 'Error',
            'details': f'Error performing DNSSEC validation: {str(e)}'
        }

def _check_for_misconfigurations(domain, dnskey_records, ds_records):
    """Check for common DNSSEC misconfigurations."""
    misconfigurations = []
    
    # Check if DNSKEY exists but no DS records
    if dnskey_records and not ds_records:
        misconfigurations.append({
            'severity': 'high',
            'issue': 'DNSKEY records exist but no DS records found',
            'impact': 'DNSSEC chain of trust is broken, validation will fail'
        })
    
    # Check if DS exists but no DNSKEY records
    if ds_records and not dnskey_records:
        misconfigurations.append({
            'severity': 'high',
            'issue': 'DS records exist but no DNSKEY records found',
            'impact': 'DNSSEC chain of trust is broken, validation will fail'
        })
    
    # Check for DNSKEY with correct flags
    if dnskey_records:
        has_ksk = any(record['flags'] == 257 for record in dnskey_records)
        has_zsk = any(record['flags'] == 256 for record in dnskey_records)
        
        if not has_ksk:
            misconfigurations.append({
                'severity': 'high',
                'issue': 'No Key Signing Key (KSK) found',
                'impact': 'DNSSEC chain of trust cannot be established'
            })
            
        if not has_zsk:
            misconfigurations.append({
                'severity': 'high',
                'issue': 'No Zone Signing Key (ZSK) found',
                'impact': 'Records in the zone cannot be validated'
            })
    
    # Check if NS records are signed
    try:
        # Get SOA record
        resolver = dns.resolver.Resolver()
        resolver.edns = True
        resolver.dnssec = True
        
        try:
            answer = resolver.resolve(domain, 'SOA', raise_on_no_answer=False)
            if not answer.response.flags & dns.flags.AD:
                misconfigurations.append({
                    'severity': 'medium',
                    'issue': 'SOA record not authenticated by DNSSEC',
                    'impact': 'Zone authority information cannot be validated'
                })
        except dns.exception.DNSException:
            pass
    except Exception as e:
        logger.debug(f"Error checking SOA signature: {e}")
    
    return misconfigurations