"""Module for retrieving DNS records."""

import logging
import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

# Define record types to query if 'ALL' is specified
ALL_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA', 'DNSKEY', 'DS']

def get_dns_records(domain, record_type='ALL'):
    """
    Retrieve DNS records for a domain.
    
    Args:
        domain (str): The domain to look up
        record_type (str, optional): The record type to retrieve (A, AAAA, MX, TXT, etc.
                                    or ALL for all types). Defaults to 'ALL'.
        
    Returns:
        dict: DNS records for the domain
    """
    logger.debug(f"Getting DNS records for domain: {domain}, type: {record_type}")
    
    result = {
        "domain": domain,
        "records": {}
    }
    
    # Determine which record types to query
    if record_type == 'ALL':
        record_types = ALL_RECORD_TYPES
    else:
        record_types = [record_type]
    
    # Create a resolver with default settings
    resolver = dns.resolver.Resolver()
    
    # Query each record type
    for rtype in record_types:
        try:
            logger.debug(f"Querying record type: {rtype}")
            answers = resolver.resolve(domain, rtype)
            
            # Process the answers based on record type
            if rtype == 'A' or rtype == 'AAAA':
                result["records"][rtype] = [str(answer) for answer in answers]
            
            elif rtype == 'MX':
                mx_records = []
                for answer in answers:
                    mx_records.append({
                        "preference": answer.preference,
                        "exchange": str(answer.exchange)
                    })
                result["records"][rtype] = mx_records
            
            elif rtype == 'NS':
                result["records"][rtype] = [str(answer) for answer in answers]
            
            elif rtype == 'TXT':
                txt_records = []
                for answer in answers:
                    txt_data = [txt.decode('utf-8', errors='replace') for txt in answer.strings]
                    txt_records.append(" ".join(txt_data))
                result["records"][rtype] = txt_records
            
            elif rtype == 'SOA':
                soa_records = []
                for answer in answers:
                    soa_records.append({
                        "mname": str(answer.mname),
                        "rname": str(answer.rname),
                        "serial": answer.serial,
                        "refresh": answer.refresh,
                        "retry": answer.retry,
                        "expire": answer.expire,
                        "minimum": answer.minimum
                    })
                result["records"][rtype] = soa_records
            
            elif rtype == 'CNAME':
                result["records"][rtype] = [str(answer) for answer in answers]
            
            elif rtype == 'SRV':
                srv_records = []
                for answer in answers:
                    srv_records.append({
                        "priority": answer.priority,
                        "weight": answer.weight,
                        "port": answer.port,
                        "target": str(answer.target)
                    })
                result["records"][rtype] = srv_records
            
            elif rtype == 'CAA':
                caa_records = []
                for answer in answers:
                    caa_records.append({
                        "flag": answer.flags,
                        "tag": answer.tag.decode('utf-8'),
                        "value": answer.value.decode('utf-8')
                    })
                result["records"][rtype] = caa_records
            
            elif rtype == 'DNSKEY' or rtype == 'DS':
                # These are more complex records, so we'll just store them as strings
                result["records"][rtype] = [str(answer) for answer in answers]
            
            else:
                # For any other record types, just convert to string
                result["records"][rtype] = [str(answer) for answer in answers]
        
        except dns.resolver.NoAnswer:
            logger.debug(f"No {rtype} records found for {domain}")
            result["records"][rtype] = []
        
        except dns.resolver.NXDOMAIN:
            logger.error(f"Domain {domain} does not exist")
            result["error"] = f"Domain {domain} does not exist"
            return result
        
        except dns.exception.DNSException as e:
            logger.error(f"DNS error for {domain}, record type {rtype}: {str(e)}")
            result["records"][rtype] = {"error": str(e)}
    
    logger.debug(f"DNS records result: {result}")
    return result
