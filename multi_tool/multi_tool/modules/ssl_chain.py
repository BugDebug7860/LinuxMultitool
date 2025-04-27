"""Module for analyzing SSL certificate chains."""

import logging
import socket
import ssl
from datetime import datetime
import OpenSSL.crypto as crypto

logger = logging.getLogger(__name__)

def analyze_ssl_chain(domain, port=443):
    """
    Analyze the SSL certificate chain for a domain.
    
    Args:
        domain (str): The domain to analyze
        port (int, optional): The port to connect to. Defaults to 443.
        
    Returns:
        dict: Information about the SSL certificate chain
    """
    logger.debug(f"Analyzing SSL chain for domain: {domain}")
    
    result = {
        "domain": domain,
        "port": port,
        "valid": False,
        "error": None,
        "certificate": {},
        "chain": [],
        "chain_issues": []
    }
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect to the server
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get certificate
                cert_binary = ssock.getpeercert(True)
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_binary)
                
                # Get the certificate chain
                ssl_info = ssock.getpeercert()
                
                # Parse certificate details
                result["valid"] = True
                result["certificate"] = _parse_certificate(x509)
                
                # Get certificate chain
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.load_default_certs()
                    
                    with socket.create_connection((domain, port), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            der_cert = ssock.getpeercert(True)
                            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
                            
                            # Use OpenSSL to get the certificate chain
                            cert_store = crypto.X509Store()
                            cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
                            
                            # Get certificate chain (simplified - in a real-world scenario, 
                            # we would recursively get each certificate in the chain)
                            result["chain"].append(_parse_certificate(cert))
                            
                            # Check the chain for issues
                            # This is simplified - a real implementation would check validity,
                            # trusted CAs, revocation status, etc.
                            now = datetime.now()
                            if now > result["certificate"]["not_after"]:
                                result["chain_issues"].append("Certificate has expired")
                            if now < result["certificate"]["not_before"]:
                                result["chain_issues"].append("Certificate is not yet valid")
                
                except Exception as e:
                    logger.error(f"Error getting certificate chain: {str(e)}")
                    result["chain_error"] = str(e)
    
    except socket.gaierror:
        logger.error(f"Could not resolve domain: {domain}")
        result["error"] = f"Could not resolve domain: {domain}"
    except socket.error as e:
        logger.error(f"Socket error: {str(e)}")
        result["error"] = f"Socket error: {str(e)}"
    except ssl.SSLError as e:
        logger.error(f"SSL error: {str(e)}")
        result["error"] = f"SSL error: {str(e)}"
    except Exception as e:
        logger.error(f"Error during SSL analysis: {str(e)}")
        result["error"] = f"Error during SSL analysis: {str(e)}"
    
    logger.debug(f"SSL chain analysis result: {result}")
    return result

def _parse_certificate(x509):
    """Parse an X509 certificate and extract relevant information."""
    cert = {}
    
    # Basic certificate info
    cert["subject"] = _parse_x509_name(x509.get_subject())
    cert["issuer"] = _parse_x509_name(x509.get_issuer())
    cert["version"] = x509.get_version() + 1  # OpenSSL uses 0-based indexing
    cert["serial_number"] = str(x509.get_serial_number())
    
    # Validity period
    cert["not_before"] = datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
    cert["not_after"] = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
    
    # Calculate days until expiry
    days_remaining = (cert["not_after"] - datetime.now()).days
    cert["days_remaining"] = days_remaining
    
    # Signature algorithm
    cert["signature_algorithm"] = x509.get_signature_algorithm().decode('utf-8')
    
    # Public key information
    pubkey = x509.get_pubkey()
    cert["key_type"] = {
        crypto.TYPE_RSA: "RSA",
        crypto.TYPE_DSA: "DSA",
        crypto.TYPE_EC: "EC"
    }.get(pubkey.type(), "Unknown")
    cert["key_size"] = pubkey.bits()
    
    # Extensions
    cert["extensions"] = []
    extensions_count = x509.get_extension_count()
    for i in range(extensions_count):
        ext = x509.get_extension(i)
        cert["extensions"].append({
            "name": ext.get_short_name().decode('utf-8'),
            "critical": ext.get_critical() == 1
        })
    
    # Get Subject Alternative Names (SANs)
    san_extension = None
    for i in range(extensions_count):
        ext = x509.get_extension(i)
        if ext.get_short_name().decode('utf-8') == 'subjectAltName':
            san_extension = ext
            break
    
    if san_extension:
        san_data = san_extension.get_data()
        cert["subject_alt_names"] = str(san_data)  # This is simplified
    
    return cert

def _parse_x509_name(name):
    """Parse an X509Name object and extract the components."""
    result = {}
    for key, value in name.get_components():
        key = key.decode('utf-8')
        value = value.decode('utf-8')
        result[key] = value
    return result
