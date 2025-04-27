"""Module for retrieving TXT records and analyzing them."""

import logging
import dns.resolver
import validators
import re

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_txt_records(domain):
    """
    Retrieve TXT records for a domain and analyze them.
    
    Args:
        domain (str): The domain to analyze
        
    Returns:
        dict: TXT records and their analysis
    """
    logger.debug(f"Getting TXT records for domain: {domain}")
    
    # Validate domain
    if domain.startswith(('http://', 'https://')):
        # Extract domain from URL
        domain = domain.split('//')[1].split('/')[0]
    
    if not validators.domain(domain):
        raise ValueError(f"Invalid domain: {domain}")
    
    try:
        # Get TXT records
        txt_records = []
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt_records.append(txt_string.decode('utf-8', errors='ignore'))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
            logger.debug(f"Error resolving TXT records: {e}")
        
        # Get specific records
        spf_records = []
        dkim_records = []
        dmarc_records = []
        google_site_verification = []
        ms_site_verification = []
        other_verification = []
        other_records = []
        
        # Analyze each TXT record
        for record in txt_records:
            if record.startswith('v=spf1'):
                spf_records.append(record)
            elif record.startswith('v=DKIM1'):
                dkim_records.append(record)
            elif 'google-site-verification=' in record:
                google_site_verification.append(record)
            elif 'MS=' in record or 'ms=' in record:
                ms_site_verification.append(record)
            elif re.search(r'(site-verification|verification|verify)', record, re.IGNORECASE):
                other_verification.append(record)
            else:
                other_records.append(record)
        
        # Get DMARC record
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in answers:
                for txt_string in rdata.strings:
                    dmarc_record = txt_string.decode('utf-8', errors='ignore')
                    if dmarc_record.startswith('v=DMARC1'):
                        dmarc_records.append(dmarc_record)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
            logger.debug(f"Error resolving DMARC records: {e}")
        
        # Analyze SPF records
        spf_analysis = []
        for spf in spf_records:
            mechanisms = spf.split(' ')
            includes = [m for m in mechanisms if m.startswith('include:')]
            ips = [m for m in mechanisms if m.startswith('ip4:') or m.startswith('ip6:')]
            all_mechanism = next((m for m in mechanisms if m in ['+all', '-all', '~all', '?all']), None)
            
            spf_analysis.append({
                'record': spf,
                'includes': includes,
                'ip_addresses': ips,
                'all_mechanism': all_mechanism,
                'policy': 'strict' if all_mechanism == '-all' else 'soft fail' if all_mechanism == '~all' else 'neutral' if all_mechanism == '?all' else 'allow' if all_mechanism == '+all' else 'unspecified'
            })
        
        # Analyze DMARC records
        dmarc_analysis = []
        for dmarc in dmarc_records:
            tags = dict(tag.split('=', 1) for tag in dmarc.split(';') if '=' in tag)
            dmarc_analysis.append({
                'record': dmarc,
                'policy': tags.get('p', 'none').strip(),
                'subdomain_policy': tags.get('sp', tags.get('p', 'none')).strip(),
                'percentage': tags.get('pct', '100').strip(),
                'reporting_email': tags.get('rua', '').strip(),
                'forensic_email': tags.get('ruf', '').strip()
            })
        
        result = {
            'domain': domain,
            'txt_records': {
                'all': txt_records,
                'count': len(txt_records)
            },
            'spf': {
                'records': spf_records,
                'count': len(spf_records),
                'analysis': spf_analysis
            },
            'dmarc': {
                'records': dmarc_records,
                'count': len(dmarc_records),
                'analysis': dmarc_analysis
            },
            'dkim': {
                'records': dkim_records,
                'count': len(dkim_records)
            },
            'verification': {
                'google': google_site_verification,
                'microsoft': ms_site_verification,
                'other': other_verification
            },
            'other': other_records
        }
        
        # Analyze email security posture
        result['email_security'] = {
            'spf_implemented': len(spf_records) > 0,
            'dmarc_implemented': len(dmarc_records) > 0,
            'dkim_records_found': len(dkim_records) > 0,
            'spf_policy': spf_analysis[0]['policy'] if spf_analysis else 'not implemented',
            'dmarc_policy': dmarc_analysis[0]['policy'] if dmarc_analysis else 'not implemented',
            'email_security_score': _calculate_email_security_score(spf_analysis, dmarc_analysis, len(dkim_records) > 0)
        }
        
        logger.debug(f"TXT records result: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error analyzing TXT records: {e}")
        raise

def _calculate_email_security_score(spf_analysis, dmarc_analysis, has_dkim):
    """Calculate an email security score based on SPF, DKIM, and DMARC configurations."""
    score = 0
    max_score = 10
    
    # Check SPF
    if spf_analysis:
        score += 3  # Basic SPF present
        if spf_analysis[0]['policy'] == 'strict':
            score += 1  # Strict SPF policy
    
    # Check DKIM
    if has_dkim:
        score += 2  # DKIM present
    
    # Check DMARC
    if dmarc_analysis:
        score += 2  # Basic DMARC present
        if dmarc_analysis[0]['policy'] == 'reject':
            score += 2  # Strict DMARC policy
        elif dmarc_analysis[0]['policy'] == 'quarantine':
            score += 1  # Moderate DMARC policy
    
    return {
        'score': score,
        'max_score': max_score,
        'percentage': round((score / max_score) * 100),
        'rating': 'Excellent' if score >= 8 else 'Good' if score >= 6 else 'Fair' if score >= 4 else 'Poor'
    }