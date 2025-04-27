"""Module for analyzing email configuration security."""

import logging
import dns.resolver
import validators
import re
import socket
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def analyze_email_config(domain):
    """
    Analyze email security configuration for a domain.
    
    Args:
        domain (str): The domain to analyze
        
    Returns:
        dict: Email configuration analysis
    """
    logger.debug(f"Analyzing email configuration for domain: {domain}")
    
    # Validate domain
    if domain.startswith(('http://', 'https://')):
        # Extract domain from URL
        domain = urlparse(domain).netloc
    
    if not validators.domain(domain):
        raise ValueError(f"Invalid domain: {domain}")
    
    try:
        # Get MX records
        mx_records = _get_mx_records(domain)
        
        # Get SPF record
        spf_record = _get_spf_record(domain)
        
        # Get DMARC record
        dmarc_record = _get_dmarc_record(domain)
        
        # Get DKIM records (only check for existence)
        dkim_exists = _check_dkim_existence(domain)
        
        # Check for BIMI record
        bimi_record = _get_bimi_record(domain)
        
        # Check MTA-STS
        mta_sts = _check_mta_sts(domain)
        
        # Analyze email security
        security_analysis = _analyze_email_security(mx_records, spf_record, dmarc_record, dkim_exists, bimi_record, mta_sts)
        
        result = {
            'domain': domain,
            'mx_records': mx_records,
            'spf': spf_record,
            'dmarc': dmarc_record,
            'dkim_exists': dkim_exists,
            'bimi': bimi_record,
            'mta_sts': mta_sts,
            'security_analysis': security_analysis
        }
        
        logger.debug(f"Email configuration analysis result: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error analyzing email configuration: {e}")
        raise

def _get_mx_records(domain):
    """Get MX records for a domain."""
    mx_servers = []
    
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            mx_host = str(rdata.exchange).rstrip('.')
            # Additional info about the mail server
            mail_server_info = {
                'host': mx_host,
                'preference': rdata.preference
            }
            
            # Try to resolve IP(s) for each MX record
            try:
                ip_addresses = []
                answers = dns.resolver.resolve(mx_host, 'A')
                for record in answers:
                    ip_addresses.append(record.address)
                mail_server_info['ip_addresses'] = ip_addresses
            except Exception:
                mail_server_info['ip_addresses'] = []
            
            mx_servers.append(mail_server_info)
            
        # Sort by preference (lowest first)
        mx_servers.sort(key=lambda x: x['preference'])
        
        if mx_servers:
            return {
                'records': mx_servers,
                'count': len(mx_servers),
                'has_mx': True
            }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
        logger.debug(f"Error getting MX records: {e}")
    
    return {
        'records': [],
        'count': 0,
        'has_mx': False
    }

def _get_spf_record(domain):
    """Get SPF record for a domain."""
    spf_record = None
    
    try:
        # SPF records are stored as TXT records
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            record = ''.join(str(txt) for txt in rdata.strings)
            if record.startswith('v=spf1'):
                spf_record = record
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
        logger.debug(f"Error getting SPF record: {e}")
    
    if not spf_record:
        return {
            'record': None,
            'has_spf': False
        }
    
    # Analyze SPF record
    spf_version = None
    spf_mechanisms = []
    spf_all = None
    ip_mechanisms = []
    include_mechanisms = []
    
    if spf_record:
        # Extract version
        version_match = re.search(r'v=spf1', spf_record)
        if version_match:
            spf_version = version_match.group(0)
        
        # Extract mechanisms
        parts = spf_record.split(' ')
        for part in parts:
            part = part.strip()
            if part and part != spf_version:
                spf_mechanisms.append(part)
                
                # Extract all directive
                if part in ['+all', '-all', '~all', '?all']:
                    spf_all = part
                
                # Extract IP mechanisms
                if part.startswith(('ip4:', 'ip6:')):
                    ip_mechanisms.append(part)
                
                # Extract include mechanisms
                if part.startswith('include:'):
                    include_mechanisms.append(part)
    
    # Determine policy strength
    if spf_all == '-all':
        policy = 'Fail'
        policy_strength = 'Strong'
    elif spf_all == '~all':
        policy = 'SoftFail'
        policy_strength = 'Medium'
    elif spf_all == '?all':
        policy = 'Neutral'
        policy_strength = 'Weak'
    elif spf_all == '+all':
        policy = 'Pass'
        policy_strength = 'Dangerous (allows spoofing)'
    else:
        policy = 'None'
        policy_strength = 'Nonexistent'
    
    return {
        'record': spf_record,
        'has_spf': True,
        'version': spf_version,
        'mechanisms': spf_mechanisms,
        'policy': policy,
        'policy_strength': policy_strength,
        'ip_mechanisms': ip_mechanisms,
        'include_mechanisms': include_mechanisms
    }

def _get_dmarc_record(domain):
    """Get DMARC record for a domain."""
    dmarc_record = None
    
    try:
        # DMARC records are at _dmarc.domain.com
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            record = ''.join(str(txt) for txt in rdata.strings)
            if record.startswith('v=DMARC1'):
                dmarc_record = record
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
        logger.debug(f"Error getting DMARC record: {e}")
    
    if not dmarc_record:
        return {
            'record': None,
            'has_dmarc': False
        }
    
    # Parse DMARC record
    dmarc_tags = {}
    parts = dmarc_record.split(';')
    
    for part in parts:
        part = part.strip()
        if '=' in part:
            tag, value = part.split('=', 1)
            dmarc_tags[tag.strip()] = value.strip()
    
    # Extract policy
    policy = dmarc_tags.get('p', 'none')
    
    # Extract subdomain policy
    sub_policy = dmarc_tags.get('sp', policy)  # Defaults to same as main policy
    
    # Extract reporting configuration
    aggregate_reports = dmarc_tags.get('rua')
    forensic_reports = dmarc_tags.get('ruf')
    
    # Extract percentage
    pct = dmarc_tags.get('pct', '100')
    
    # Determine policy strength
    if policy == 'reject':
        policy_strength = 'Strong'
    elif policy == 'quarantine':
        policy_strength = 'Medium'
    else:  # none or other
        policy_strength = 'Weak'
    
    return {
        'record': dmarc_record,
        'has_dmarc': True,
        'tags': dmarc_tags,
        'policy': policy,
        'subdomain_policy': sub_policy,
        'policy_strength': policy_strength,
        'aggregate_reports': aggregate_reports,
        'forensic_reports': forensic_reports,
        'percentage': pct
    }

def _check_dkim_existence(domain):
    """Check for DKIM records for a domain."""
    # DKIM selectors are not standardized, but some common ones
    common_selectors = ['default', 'selector1', 'selector2', 'dkim', 'mail', 'k1', 'google']
    
    for selector in common_selectors:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            for rdata in answers:
                record = ''.join(str(txt) for txt in rdata.strings)
                if 'v=DKIM1' in record or 'k=rsa' in record:
                    return {
                        'exists': True,
                        'selector': selector,
                        'domain': dkim_domain
                    }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            pass
    
    return {
        'exists': False
    }

def _get_bimi_record(domain):
    """Check for BIMI (Brand Indicators for Message Identification) record."""
    bimi_record = None
    
    try:
        # BIMI records are at default._bimi.domain.com
        answers = dns.resolver.resolve(f"default._bimi.{domain}", 'TXT')
        for rdata in answers:
            record = ''.join(str(txt) for txt in rdata.strings)
            if 'v=BIMI1' in record:
                bimi_record = record
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
        logger.debug(f"Error getting BIMI record: {e}")
    
    if not bimi_record:
        return {
            'record': None,
            'has_bimi': False
        }
    
    # Parse BIMI record
    bimi_tags = {}
    parts = bimi_record.split(';')
    
    for part in parts:
        part = part.strip()
        if '=' in part:
            tag, value = part.split('=', 1)
            bimi_tags[tag.strip()] = value.strip()
    
    # Extract logo URL
    logo_url = bimi_tags.get('l')
    
    # Extract VMC URL (Verified Mark Certificate)
    vmc_url = bimi_tags.get('a')
    
    return {
        'record': bimi_record,
        'has_bimi': True,
        'tags': bimi_tags,
        'logo_url': logo_url,
        'vmc_url': vmc_url
    }

def _check_mta_sts(domain):
    """Check for MTA-STS (SMTP MTA Strict Transport Security) support."""
    # Check for MTA-STS policy
    sts_policy_exists = False
    sts_txt_record = None
    
    try:
        # Check for MTA-STS TXT record
        answers = dns.resolver.resolve(f"_mta-sts.{domain}", 'TXT')
        for rdata in answers:
            record = ''.join(str(txt) for txt in rdata.strings)
            if 'v=STSv1' in record:
                sts_txt_record = record
                sts_policy_exists = True
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
        logger.debug(f"Error getting MTA-STS TXT record: {e}")
    
    # Check for MTA-STS policy host
    sts_policy_host_exists = False
    try:
        socket.gethostbyname(f"mta-sts.{domain}")
        sts_policy_host_exists = True
    except socket.gaierror:
        pass
    
    if not sts_txt_record:
        return {
            'has_mta_sts': False,
            'record': None,
            'policy_host_exists': sts_policy_host_exists
        }
    
    # Parse MTA-STS record
    sts_tags = {}
    parts = sts_txt_record.split(';')
    
    for part in parts:
        part = part.strip()
        if '=' in part:
            tag, value = part.split('=', 1)
            sts_tags[tag.strip()] = value.strip()
    
    return {
        'has_mta_sts': sts_policy_exists,
        'record': sts_txt_record,
        'policy_host_exists': sts_policy_host_exists,
        'tags': sts_tags,
        'version': sts_tags.get('v'),
        'id': sts_tags.get('id')
    }

def _analyze_email_security(mx_records, spf, dmarc, dkim, bimi, mta_sts):
    """Analyze the overall email security posture."""
    score = 0
    max_score = 100
    issues = []
    recommendations = []
    
    # Check MX records (10 points)
    if mx_records['has_mx']:
        if mx_records['count'] >= 2:
            score += 10  # Multiple MX records for redundancy
        else:
            score += 8  # At least one MX record
            recommendations.append({
                'priority': 'medium',
                'recommendation': 'Add a secondary MX record for redundancy'
            })
    else:
        issues.append({
            'severity': 'critical',
            'issue': 'No MX records found'
        })
        recommendations.append({
            'priority': 'high',
            'recommendation': 'Configure MX records to receive email'
        })
    
    # Check SPF (25 points)
    if spf['has_spf']:
        if spf['policy_strength'] == 'Strong':
            score += 25
        elif spf['policy_strength'] == 'Medium':
            score += 20
            recommendations.append({
                'priority': 'medium',
                'recommendation': 'Consider strengthening SPF policy from SoftFail (~all) to Fail (-all)'
            })
        elif spf['policy_strength'] == 'Weak':
            score += 10
            issues.append({
                'severity': 'medium',
                'issue': 'Weak SPF policy (Neutral)'
            })
            recommendations.append({
                'priority': 'high',
                'recommendation': 'Strengthen SPF policy to at least SoftFail (~all) or Fail (-all)'
            })
        elif spf['policy_strength'] == 'Dangerous (allows spoofing)':
            score += 5
            issues.append({
                'severity': 'high',
                'issue': 'Dangerous SPF policy (+all) allows email spoofing'
            })
            recommendations.append({
                'priority': 'high',
                'recommendation': 'Remove +all directive and replace with -all'
            })
        else:
            score += 5
            issues.append({
                'severity': 'medium',
                'issue': 'SPF record missing all directive'
            })
            recommendations.append({
                'priority': 'high',
                'recommendation': 'Add -all directive to SPF record'
            })
    else:
        issues.append({
            'severity': 'high',
            'issue': 'No SPF record found'
        })
        recommendations.append({
            'priority': 'high',
            'recommendation': 'Implement SPF record to prevent email spoofing'
        })
    
    # Check DMARC (25 points)
    if dmarc['has_dmarc']:
        if dmarc['policy_strength'] == 'Strong':
            score += 25
        elif dmarc['policy_strength'] == 'Medium':
            score += 20
            recommendations.append({
                'priority': 'medium',
                'recommendation': 'Consider strengthening DMARC policy from quarantine to reject'
            })
        else:  # Weak
            score += 10
            issues.append({
                'severity': 'medium',
                'issue': 'Weak DMARC policy (none)'
            })
            recommendations.append({
                'priority': 'high',
                'recommendation': 'Strengthen DMARC policy to quarantine or reject'
            })
        
        # Check for reporting
        if not dmarc.get('aggregate_reports'):
            issues.append({
                'severity': 'low',
                'issue': 'No DMARC aggregate reporting configured'
            })
            recommendations.append({
                'priority': 'medium',
                'recommendation': 'Configure DMARC aggregate reporting (rua tag)'
            })
    else:
        issues.append({
            'severity': 'high',
            'issue': 'No DMARC record found'
        })
        recommendations.append({
            'priority': 'high',
            'recommendation': 'Implement DMARC record to enhance email authentication'
        })
    
    # Check DKIM (20 points)
    if dkim['exists']:
        score += 20
    else:
        issues.append({
            'severity': 'medium',
            'issue': 'No DKIM record found for common selectors'
        })
        recommendations.append({
            'priority': 'high',
            'recommendation': 'Implement DKIM signing for email authentication'
        })
    
    # Check MTA-STS (15 points)
    if mta_sts['has_mta_sts'] and mta_sts['policy_host_exists']:
        score += 15
    elif mta_sts['has_mta_sts'] and not mta_sts['policy_host_exists']:
        score += 5
        issues.append({
            'severity': 'medium',
            'issue': 'MTA-STS TXT record exists but policy host (mta-sts.domain.com) is not configured'
        })
        recommendations.append({
            'priority': 'medium',
            'recommendation': 'Complete MTA-STS setup by configuring mta-sts.domain.com host'
        })
    else:
        issues.append({
            'severity': 'low',
            'issue': 'MTA-STS not configured'
        })
        recommendations.append({
            'priority': 'medium',
            'recommendation': 'Implement MTA-STS for secure email transport'
        })
    
    # Check BIMI (5 points bonus)
    if bimi['has_bimi']:
        score += 5
    
    # Ensure score doesn't exceed max
    score = min(score, max_score)
    
    # Calculate grade
    if score >= 90:
        grade = 'A+'
        description = 'Excellent'
    elif score >= 85:
        grade = 'A'
        description = 'Very Good'
    elif score >= 75:
        grade = 'B'
        description = 'Good'
    elif score >= 65:
        grade = 'C'
        description = 'Fair'
    elif score >= 50:
        grade = 'D'
        description = 'Poor'
    else:
        grade = 'F'
        description = 'Very Poor'
    
    return {
        'score': score,
        'max_score': max_score,
        'percentage': score,
        'grade': grade,
        'description': description,
        'issues': issues,
        'recommendations': recommendations
    }