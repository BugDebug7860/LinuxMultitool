"""Module for analyzing DNS server configuration and performance."""

import logging
import dns.resolver
import dns.reversename
import dns.name
import dns.message
import dns.query
import dns.rdatatype
import validators
import socket
import time
import random
import string
import statistics

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def analyze_dns_servers(domain):
    """
    Analyze DNS servers configuration and performance for a domain.
    
    Args:
        domain (str): The domain to analyze
        
    Returns:
        dict: DNS servers analysis
    """
    logger.debug(f"Analyzing DNS servers for domain: {domain}")
    
    # Validate domain
    if domain.startswith(('http://', 'https://')):
        # Extract domain from URL
        domain = domain.split('//')[1].split('/')[0]
    
    if not validators.domain(domain):
        raise ValueError(f"Invalid domain: {domain}")
    
    try:
        # Get nameservers for the domain
        nameservers = _get_nameservers(domain)
        
        # Determine authoritative nameservers
        auth_nameservers = _get_authoritative_nameservers(domain)
        
        # Test nameserver performance
        performance = _test_nameserver_performance(domain, auth_nameservers)
        
        # Check for common misconfigurations
        misconfigurations = _check_dns_misconfigurations(domain, nameservers, auth_nameservers)
        
        # Test DNS record propagation
        propagation = _test_dns_propagation(domain, auth_nameservers)
        
        # Check DNS server software (if possible)
        server_software = _identify_dns_software(domain, auth_nameservers)
        
        # Check configuration quality
        quality = _assess_dns_quality(nameservers, auth_nameservers, performance, misconfigurations)
        
        result = {
            'domain': domain,
            'nameservers': {
                'configured': nameservers,
                'authoritative': auth_nameservers
            },
            'performance': performance,
            'propagation': propagation,
            'server_software': server_software,
            'misconfigurations': misconfigurations,
            'quality': quality
        }
        
        logger.debug(f"DNS servers analysis result: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error analyzing DNS servers: {e}")
        raise

def _get_nameservers(domain):
    """Get configured nameservers for a domain."""
    nameservers = []
    
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        nameservers = [str(rdata.target).rstrip('.') for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
        logger.debug(f"Error getting nameservers: {e}")
    
    return nameservers

def _get_authoritative_nameservers(domain):
    """Get authoritative nameservers for a domain."""
    auth_nameservers = []
    
    try:
        # First get the nameservers for the domain
        nameservers = _get_nameservers(domain)
        
        for ns in nameservers:
            # Get IP addresses for each nameserver
            try:
                answers = dns.resolver.resolve(ns, 'A')
                for rdata in answers:
                    ip = rdata.address
                    
                    # Check if this server is actually authoritative
                    if _check_if_authoritative(domain, ip):
                        auth_nameservers.append({
                            'nameserver': ns,
                            'ip': ip,
                            'authoritative': True
                        })
                    else:
                        auth_nameservers.append({
                            'nameserver': ns,
                            'ip': ip,
                            'authoritative': False
                        })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                auth_nameservers.append({
                    'nameserver': ns,
                    'ip': None,
                    'authoritative': False,
                    'error': 'Could not resolve IP'
                })
    except Exception as e:
        logger.debug(f"Error getting authoritative nameservers: {e}")
    
    return auth_nameservers

def _check_if_authoritative(domain, nameserver_ip):
    """Check if a nameserver is authoritative for a domain."""
    try:
        domain_obj = dns.name.from_text(domain)
        
        # Send query directly to the nameserver
        request = dns.message.make_query(domain_obj, dns.rdatatype.SOA)
        response = dns.query.udp(request, nameserver_ip, timeout=5)
        
        # Check for AA (Authoritative Answer) flag
        return bool(response.flags & dns.flags.AA)
    except Exception:
        return False

def _test_nameserver_performance(domain, nameservers):
    """Test nameserver performance."""
    performance_data = []
    
    for ns in nameservers:
        if not ns.get('ip'):
            continue
            
        nameserver_ip = ns['ip']
        
        # Measure response times for different record types
        response_times = {
            'a_record': [],
            'ns_record': [],
            'mx_record': []
        }
        
        # Test A record resolution
        for _ in range(3):  # 3 tests for averages
            try:
                start_time = time.time()
                query = dns.message.make_query(domain, dns.rdatatype.A)
                dns.query.udp(query, nameserver_ip, timeout=5)
                response_time = time.time() - start_time
                response_times['a_record'].append(response_time)
            except Exception:
                pass
        
        # Test NS record resolution
        for _ in range(3):
            try:
                start_time = time.time()
                query = dns.message.make_query(domain, dns.rdatatype.NS)
                dns.query.udp(query, nameserver_ip, timeout=5)
                response_time = time.time() - start_time
                response_times['ns_record'].append(response_time)
            except Exception:
                pass
        
        # Test MX record resolution
        for _ in range(3):
            try:
                start_time = time.time()
                query = dns.message.make_query(domain, dns.rdatatype.MX)
                dns.query.udp(query, nameserver_ip, timeout=5)
                response_time = time.time() - start_time
                response_times['mx_record'].append(response_time)
            except Exception:
                pass
        
        # Calculate averages
        avg_times = {}
        for record_type, times in response_times.items():
            if times:
                avg_times[record_type] = statistics.mean(times)
            else:
                avg_times[record_type] = None
        
        # Calculate overall average
        all_times = [t for times in response_times.values() for t in times if t is not None]
        overall_avg = statistics.mean(all_times) if all_times else None
        
        # Determine performance rating
        if overall_avg is not None:
            if overall_avg < 0.05:  # Less than 50ms
                rating = 'Excellent'
            elif overall_avg < 0.1:  # Less than 100ms
                rating = 'Good'
            elif overall_avg < 0.25:  # Less than 250ms
                rating = 'Fair'
            else:
                rating = 'Poor'
        else:
            rating = 'Unknown'
        
        performance_data.append({
            'nameserver': ns['nameserver'],
            'ip': nameserver_ip,
            'average_response_time': overall_avg,
            'response_times': avg_times,
            'performance_rating': rating
        })
    
    return performance_data

def _check_dns_misconfigurations(domain, nameservers, auth_nameservers):
    """Check for common DNS misconfigurations."""
    misconfigurations = []
    
    # Check for missing nameservers
    if not nameservers:
        misconfigurations.append({
            'severity': 'critical',
            'issue': 'No nameservers configured',
            'impact': 'Domain is unreachable'
        })
        return misconfigurations
    
    # Check for non-responsive nameservers
    non_responsive_ns = [ns['nameserver'] for ns in auth_nameservers if ns.get('ip') is None]
    if non_responsive_ns:
        misconfigurations.append({
            'severity': 'high',
            'issue': f"Non-responsive nameservers: {', '.join(non_responsive_ns)}",
            'impact': 'Degraded DNS redundancy'
        })
    
    # Check for non-authoritative nameservers
    non_auth_ns = [ns['nameserver'] for ns in auth_nameservers if not ns.get('authoritative', False) and ns.get('ip') is not None]
    if non_auth_ns:
        misconfigurations.append({
            'severity': 'high',
            'issue': f"Non-authoritative nameservers: {', '.join(non_auth_ns)}",
            'impact': 'Potentially incorrect DNS configuration'
        })
    
    # Check for minimum number of nameservers
    if len(nameservers) < 2:
        misconfigurations.append({
            'severity': 'high',
            'issue': 'Less than 2 nameservers configured',
            'impact': 'No DNS redundancy'
        })
    
    # Check for lame delegation
    lame_delegation = False
    for ns in auth_nameservers:
        if ns.get('ip') and not ns.get('authoritative', False):
            lame_delegation = True
            break
            
    if lame_delegation:
        misconfigurations.append({
            'severity': 'high',
            'issue': 'Lame delegation detected',
            'impact': 'DNS resolution may fail'
        })
    
    # Check for all nameservers on same network
    ips = [ns.get('ip') for ns in auth_nameservers if ns.get('ip')]
    if len(ips) >= 2:
        same_network = True
        # Simple check: first two octets the same (class B network)
        first_two_octets = '.'.join(ips[0].split('.')[:2])
        for ip in ips[1:]:
            if '.'.join(ip.split('.')[:2]) != first_two_octets:
                same_network = False
                break
                
        if same_network:
            misconfigurations.append({
                'severity': 'medium',
                'issue': 'All nameservers on same network',
                'impact': 'Reduced DNS resilience'
            })
    
    return misconfigurations

def _test_dns_propagation(domain, auth_nameservers):
    """Test DNS record propagation across nameservers."""
    # Check if we can perform the test
    viable_nameservers = [ns for ns in auth_nameservers if ns.get('ip') and ns.get('authoritative', False)]
    
    if len(viable_nameservers) < 2:
        return {
            'status': 'skipped',
            'reason': 'Not enough authoritative nameservers to test propagation'
        }
    
    # Get A records from each nameserver
    propagation_data = []
    
    for ns in viable_nameservers:
        try:
            # Query this specific nameserver for A records
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ns['ip']]
            
            a_records = []
            try:
                answers = resolver.resolve(domain, 'A')
                a_records = [rdata.address for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                pass
            
            propagation_data.append({
                'nameserver': ns['nameserver'],
                'ip': ns['ip'],
                'a_records': a_records
            })
        except Exception as e:
            logger.debug(f"Error testing propagation for {ns['nameserver']}: {e}")
    
    # Check if all nameservers have the same records
    if propagation_data:
        first_ns_records = set(propagation_data[0]['a_records'])
        fully_propagated = True
        
        for ns_data in propagation_data[1:]:
            if set(ns_data['a_records']) != first_ns_records:
                fully_propagated = False
                break
        
        return {
            'status': 'completed',
            'fully_propagated': fully_propagated,
            'nameserver_data': propagation_data
        }
    else:
        return {
            'status': 'failed',
            'reason': 'Could not retrieve data from nameservers'
        }

def _identify_dns_software(domain, auth_nameservers):
    """Try to identify the DNS server software."""
    software_data = []
    
    for ns in auth_nameservers:
        if not ns.get('ip'):
            continue
            
        nameserver_ip = ns['ip']
        
        # Try to detect software from version.bind query
        software = 'Unknown'
        version = None
        
        try:
            # Create a query for version.bind CH TXT
            qname = dns.name.from_text('version.bind')
            q = dns.message.make_query(qname, dns.rdatatype.TXT, dns.rdataclass.CH)
            
            # Send the query
            response = dns.query.udp(q, nameserver_ip, timeout=2)
            
            # Process the response
            if response.answer:
                for rrset in response.answer:
                    for rdata in rrset:
                        version_str = rdata.to_text()
                        
                        # Remove quotes from the TXT record
                        version_str = version_str.strip('"')
                        
                        # Try to identify software from version string
                        if 'bind' in version_str.lower():
                            software = 'BIND'
                        elif 'unbound' in version_str.lower():
                            software = 'Unbound'
                        elif 'power' in version_str.lower():
                            software = 'PowerDNS'
                        elif 'knot' in version_str.lower():
                            software = 'Knot DNS'
                        elif 'nsd' in version_str.lower():
                            software = 'NSD'
                        
                        version = version_str
        except Exception as e:
            logger.debug(f"Error identifying DNS software for {ns['nameserver']}: {e}")
        
        software_data.append({
            'nameserver': ns['nameserver'],
            'ip': nameserver_ip,
            'software': software,
            'version': version
        })
    
    return software_data

def _assess_dns_quality(nameservers, auth_nameservers, performance, misconfigurations):
    """Assess the overall quality of DNS configuration."""
    score = 0
    max_score = 100
    
    # Criteria:
    # 1. Number of nameservers (20 points)
    # 2. Nameserver authoritativeness (20 points)
    # 3. Nameserver performance (20 points)
    # 4. Nameserver distribution (20 points)
    # 5. Absence of misconfigurations (20 points)
    
    # 1. Number of nameservers
    ns_count = len(nameservers)
    if ns_count >= 4:
        score += 20
    elif ns_count == 3:
        score += 15
    elif ns_count == 2:
        score += 10
    elif ns_count == 1:
        score += 5
    
    # 2. Nameserver authoritativeness
    auth_count = sum(1 for ns in auth_nameservers if ns.get('authoritative', False))
    if auth_count == ns_count and ns_count > 0:
        score += 20
    elif auth_count > 0:
        score += round((auth_count / max(1, ns_count)) * 20)
    
    # 3. Nameserver performance
    if performance:
        perf_ratings = [p.get('performance_rating') for p in performance]
        excellent_count = perf_ratings.count('Excellent')
        good_count = perf_ratings.count('Good')
        fair_count = perf_ratings.count('Fair')
        
        if excellent_count == len(perf_ratings) and len(perf_ratings) > 0:
            score += 20
        elif excellent_count + good_count == len(perf_ratings) and len(perf_ratings) > 0:
            score += 15
        elif good_count + fair_count == len(perf_ratings) and len(perf_ratings) > 0:
            score += 10
        elif fair_count > 0:
            score += 5
    
    # 4. Nameserver distribution
    # Check for different networks/providers
    unique_networks = set()
    for ns in auth_nameservers:
        if ns.get('ip'):
            # Simple approach: use first two octets as network identifier
            network = '.'.join(ns['ip'].split('.')[:2])
            unique_networks.add(network)
    
    network_diversity = len(unique_networks)
    if network_diversity >= 3:
        score += 20
    elif network_diversity == 2:
        score += 15
    elif network_diversity == 1 and len(auth_nameservers) > 1:
        score += 5
    
    # 5. Absence of misconfigurations
    if not misconfigurations:
        score += 20
    else:
        critical_count = sum(1 for m in misconfigurations if m.get('severity') == 'critical')
        high_count = sum(1 for m in misconfigurations if m.get('severity') == 'high')
        medium_count = sum(1 for m in misconfigurations if m.get('severity') == 'medium')
        
        if critical_count == 0 and high_count == 0 and medium_count <= 1:
            score += 15
        elif critical_count == 0 and high_count <= 1:
            score += 10
        elif critical_count == 0:
            score += 5
    
    # Convert score to grade and description
    grade = 'A+' if score >= 95 else 'A' if score >= 90 else 'B' if score >= 80 else 'C' if score >= 70 else 'D' if score >= 60 else 'F'
    
    if score >= 90:
        description = 'Excellent'
    elif score >= 80:
        description = 'Good'
    elif score >= 70:
        description = 'Fair'
    elif score >= 60:
        description = 'Poor'
    else:
        description = 'Very Poor'
    
    return {
        'score': score,
        'max_score': max_score,
        'percentage': score,
        'grade': grade,
        'description': description
    }