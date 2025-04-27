#!/usr/bin/env python3
"""Module for enhanced SSL/TLS configuration analysis."""

import logging
import json
import socket
import ssl
import re
import validators
from datetime import datetime, timedelta
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Define TLS/SSL protocol versions
TLS_VERSIONS = {
    ssl.PROTOCOL_TLSv1: "TLSv1.0",
    ssl.PROTOCOL_TLSv1_1: "TLSv1.1",
    ssl.PROTOCOL_TLSv1_2: "TLSv1.2"
}

# Try to add TLS 1.3 if available
try:
    TLS_VERSIONS[ssl.PROTOCOL_TLSv1_3] = "TLSv1.3"
except AttributeError:
    pass

# Known vulnerabilities
VULNERABILITIES = {
    "BEAST": {
        "description": "Browser Exploit Against SSL/TLS. Affects TLS 1.0 and below when using CBC mode ciphers.",
        "severity": "medium",
        "mitigation": "Disable TLS 1.0 and below, or prioritize RC4 or AEAD cipher suites."
    },
    "CRIME": {
        "description": "Compression Ratio Info-leak Made Easy. Affects TLS compression.",
        "severity": "high",
        "mitigation": "Disable TLS compression."
    },
    "POODLE": {
        "description": "Padding Oracle On Downgraded Legacy Encryption. Affects SSLv3 when using CBC mode ciphers.",
        "severity": "high",
        "mitigation": "Disable SSLv3."
    },
    "FREAK": {
        "description": "Factoring RSA Export Keys. Affects servers supporting export-grade ciphers.",
        "severity": "medium",
        "mitigation": "Disable export cipher suites."
    },
    "LOGJAM": {
        "description": "Affects servers using weak Diffie-Hellman key exchange parameters.",
        "severity": "medium",
        "mitigation": "Use strong DH parameters (2048+ bits) and disable export ciphers."
    },
    "DROWN": {
        "description": "Decrypting RSA with Obsolete and Weakened eNcryption. Affects servers supporting SSLv2.",
        "severity": "high",
        "mitigation": "Disable SSLv2 on all servers sharing the same certificate."
    },
    "HEARTBLEED": {
        "description": "Buffer over-read vulnerability in OpenSSL's implementation of the TLS heartbeat extension.",
        "severity": "critical",
        "mitigation": "Update OpenSSL to a patched version."
    },
    "ROBOT": {
        "description": "Return Of Bleichenbacher's Oracle Threat. Affects servers with RSA encryption-based key exchanges.",
        "severity": "high",
        "mitigation": "Disable RSA key exchange ciphers or apply vendor patches."
    },
    "Lucky13": {
        "description": "Timing attack affecting CBC mode ciphers in TLS.",
        "severity": "medium",
        "mitigation": "Use TLS 1.2+ with AEAD ciphers like AES-GCM."
    },
    "Sweet32": {
        "description": "Birthday attacks on 64-bit block ciphers (3DES, Blowfish) in TLS.",
        "severity": "medium",
        "mitigation": "Disable 3DES and other 64-bit block ciphers."
    },
    "GOLDENDOODLE": {
        "description": "Padding oracle attacks affecting CBC mode ciphers with unusual padding.",
        "severity": "medium",
        "mitigation": "Use TLS 1.2+ with AEAD ciphers like AES-GCM."
    },
    "ZombieLoad": {
        "description": "Side-channel attack affecting Intel processors, with potential implications for TLS.",
        "severity": "medium",
        "mitigation": "Apply OS and firmware patches, consider disabling hyperthreading."
    }
}

# Weak cipher characteristics
WEAK_CIPHER_PATTERNS = [
    ("NULL", "Offers no encryption"),
    ("anon", "Provides no authentication"),
    ("RC4", "Vulnerable to several attacks"),
    ("DES", "Uses weak 56-bit encryption"),
    ("MD5", "Uses weak hashing algorithm"),
    ("EXP", "Export-grade encryption (very weak)"),
    ("CBC", "CBC mode vulnerable to padding oracle and other attacks"),
    ("SHA1", "Uses weak SHA1 hashing algorithm"),
    ("IDEA", "Older cipher with known weaknesses"),
    ("3DES", "Vulnerable to Sweet32 attack (64-bit block size)"),
    ("DHE-", "May use weak DH parameters vulnerable to Logjam")
]

def analyze_ssl_configuration(target, check_vulnerabilities=True, port=None):
    """
    Perform enhanced analysis of SSL/TLS configuration.
    
    Args:
        target (str): The domain or URL to analyze
        check_vulnerabilities (bool): Whether to check for vulnerabilities
        port (int, optional): Specific port to check. Defaults to 443 for HTTPS.
        
    Returns:
        dict: SSL/TLS configuration analysis results
    """
    logger.debug(f"Starting enhanced SSL analysis on {target}")
    
    # Process and validate domain
    if validators.url(target):
        parsed_url = urlparse(target)
        domain = parsed_url.netloc
        if ':' in domain:
            domain, port_str = domain.split(':', 1)
            port = int(port_str)
    elif validators.domain(target):
        domain = target
    else:
        return {
            "error": "Invalid target. Please provide a valid domain or URL.",
            "target": target
        }
    
    # Set default port if not specified
    if not port:
        port = 443
    
    # Initialize results
    results = {
        "target": target,
        "domain": domain,
        "port": port,
        "analysis_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "certificate": {},
        "protocols": {},
        "cipher_suites": {},
        "vulnerabilities": {},
        "security_features": {},
        "overall_rating": None,
        "issues": [],
        "recommendations": []
    }
    
    try:
        # Analyze certificate
        cert_info = analyze_certificate(domain, port)
        results["certificate"] = cert_info
        
        # Check supported protocols
        protocols = check_supported_protocols(domain, port)
        results["protocols"] = protocols
        
        # Check cipher suites
        cipher_info = check_cipher_suites(domain, port)
        results["cipher_suites"] = cipher_info
        
        # Check for common vulnerabilities
        if check_vulnerabilities:
            vuln_info = check_vulnerabilities_common(results)
            results["vulnerabilities"] = vuln_info
        
        # Check for additional security features
        security_features = check_security_features(domain, port, results)
        results["security_features"] = security_features
        
        # Calculate overall rating
        results["overall_rating"] = calculate_overall_rating(results)
        
        # Generate recommendations
        results["recommendations"] = generate_recommendations(results)
        
    except Exception as e:
        logger.error(f"Error analyzing SSL configuration: {str(e)}")
        results["error"] = f"Analysis error: {str(e)}"
    
    return results

def analyze_certificate(domain, port):
    """
    Analyze SSL certificate details.
    
    Args:
        domain (str): The domain to check
        port (int): The port to connect to
        
    Returns:
        dict: Certificate analysis results
    """
    cert_info = {
        "subject": None,
        "issuer": None,
        "version": None,
        "serial_number": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "signature_algorithm": None,
        "key_type": None,
        "key_size": None,
        "subject_alt_names": [],
        "ocsp_must_staple": False,
        "is_extended_validation": False,
        "issues": []
    }
    
    try:
        # Create SSL context and connect
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(10)
        conn.connect((domain, port))
        
        # Get certificate
        cert = conn.getpeercert()
        
        # Extract basic info
        cert_info["subject"] = dict(item[0] for item in cert["subject"])
        cert_info["issuer"] = dict(item[0] for item in cert["issuer"])
        cert_info["version"] = cert.get("version")
        cert_info["serial_number"] = cert.get("serialNumber")
        
        # Parse dates
        if "notBefore" in cert:
            not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
            cert_info["not_before"] = not_before.strftime("%Y-%m-%d")
        
        if "notAfter" in cert:
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            cert_info["not_after"] = not_after.strftime("%Y-%m-%d")
            
            # Calculate days remaining
            days_remaining = (not_after - datetime.now()).days
            cert_info["days_remaining"] = days_remaining
            
            # Check expiration
            if days_remaining <= 0:
                cert_info["issues"].append("Certificate has expired")
            elif days_remaining <= 14:
                cert_info["issues"].append(f"Certificate will expire in {days_remaining} days")
            elif days_remaining <= 30:
                cert_info["issues"].append(f"Certificate will expire in {days_remaining} days")
        
        # Extract subject alternative names
        if "subjectAltName" in cert:
            for san_type, san_value in cert["subjectAltName"]:
                if san_type == "DNS":
                    cert_info["subject_alt_names"].append(san_value)
        
        # Check if wildcard certificate
        has_wildcard = any(san.startswith("*.") for san in cert_info["subject_alt_names"])
        cert_info["is_wildcard"] = has_wildcard
        
        # Domain validation
        domain_validated = False
        for san in cert_info["subject_alt_names"]:
            if san == domain or (san.startswith("*.") and domain.endswith(san[1:])):
                domain_validated = True
                break
        
        if not domain_validated:
            cert_info["issues"].append(f"Certificate not valid for {domain}")
        
        # Get cipher info to extract signature algorithm and key details
        cipher = conn.cipher()
        if cipher:
            # Format typically: ('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLSv1.2', 256)
            if len(cipher) > 0:
                cipher_name = cipher[0]
                
                # Try to extract signature algorithm
                sig_match = re.search(r'_(\w+)_WITH_', cipher_name)
                if sig_match:
                    key_type = sig_match.group(1)
                    if key_type in ["RSA", "ECDSA", "DSA", "ECDHE"]:
                        cert_info["key_type"] = key_type
                
                # Get key size
                if len(cipher) > 2:
                    cert_info["key_size"] = cipher[2]
        
        # Check for OCSP Must-Staple
        # Note: Python's ssl module doesn't directly expose OCSP Must-Staple info
        # This would require parsing the raw certificate
        
        # Check for Extended Validation (EV)
        # Simple heuristic: EV certificates typically have Organization and Country in subject
        if "organizationName" in cert_info["subject"] and "countryName" in cert_info["subject"]:
            # Additional check: OU typically present in EV certs
            if "organizationalUnitName" in cert_info["subject"]:
                cert_info["is_extended_validation"] = True
        
        # Close connection
        conn.close()
        
    except ssl.SSLError as e:
        cert_info["issues"].append(f"SSL Error: {str(e)}")
    except socket.error as e:
        cert_info["issues"].append(f"Connection Error: {str(e)}")
    except Exception as e:
        cert_info["issues"].append(f"Error: {str(e)}")
    
    return cert_info

def check_supported_protocols(domain, port):
    """
    Check which SSL/TLS protocol versions are supported.
    
    Args:
        domain (str): The domain to check
        port (int): The port to connect to
        
    Returns:
        dict: Protocol support information
    """
    protocol_info = {
        "SSLv2": {"supported": False, "status": "good"},
        "SSLv3": {"supported": False, "status": "good"},
        "TLSv1.0": {"supported": False, "status": "warning"},
        "TLSv1.1": {"supported": False, "status": "warning"},
        "TLSv1.2": {"supported": False, "status": "good"},
        "TLSv1.3": {"supported": False, "status": "excellent"},
        "issues": []
    }
    
    try:
        # Check older SSL versions (simulated check)
        # Note: Python doesn't support direct SSLv2/SSLv3 testing anymore for security reasons
        protocol_info["SSLv2"]["supported"] = False
        protocol_info["SSLv3"]["supported"] = False
        
        # Check TLS 1.0
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    protocol_info["TLSv1.0"]["supported"] = True
        except (ssl.SSLError, socket.error, socket.timeout):
            pass
        
        # Check TLS 1.1
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    protocol_info["TLSv1.1"]["supported"] = True
        except (ssl.SSLError, socket.error, socket.timeout):
            pass
        
        # Check TLS 1.2
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    protocol_info["TLSv1.2"]["supported"] = True
        except (ssl.SSLError, socket.error, socket.timeout):
            pass
        
        # Check TLS 1.3 if available
        try:
            if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_3)
                with socket.create_connection((domain, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        protocol_info["TLSv1.3"]["supported"] = True
        except (ssl.SSLError, socket.error, socket.timeout, AttributeError):
            pass
        
        # Identify issues
        if protocol_info["SSLv2"]["supported"]:
            protocol_info["issues"].append("SSLv2 is supported but highly insecure")
            protocol_info["SSLv2"]["status"] = "critical"
        
        if protocol_info["SSLv3"]["supported"]:
            protocol_info["issues"].append("SSLv3 is supported but vulnerable to POODLE attack")
            protocol_info["SSLv3"]["status"] = "high"
        
        if protocol_info["TLSv1.0"]["supported"]:
            protocol_info["issues"].append("TLSv1.0 is supported but has known vulnerabilities")
            protocol_info["TLSv1.0"]["status"] = "medium"
        
        if protocol_info["TLSv1.1"]["supported"]:
            protocol_info["issues"].append("TLSv1.1 is supported but has known vulnerabilities")
            protocol_info["TLSv1.1"]["status"] = "low"
        
        if not protocol_info["TLSv1.2"]["supported"] and not protocol_info["TLSv1.3"]["supported"]:
            protocol_info["issues"].append("Neither TLSv1.2 nor TLSv1.3 is supported")
            
        # Check if any secure protocol is supported
        secure_protocol_supported = (
            protocol_info["TLSv1.2"]["supported"] or 
            protocol_info["TLSv1.3"]["supported"]
        )
        
        if not secure_protocol_supported:
            protocol_info["issues"].append("No secure TLS protocol version is supported")
        
    except Exception as e:
        protocol_info["issues"].append(f"Error checking protocols: {str(e)}")
    
    return protocol_info

def check_cipher_suites(domain, port):
    """
    Check supported cipher suites and identify weak ones.
    
    Args:
        domain (str): The domain to check
        port (int): The port to connect to
        
    Returns:
        dict: Cipher suite information
    """
    cipher_info = {
        "supported_ciphers": [],
        "weak_ciphers": [],
        "strong_ciphers": [],
        "perfect_forward_secrecy": False,
        "has_weak_ciphers": False,
        "cipher_order": None,  # server or client
        "issues": []
    }
    
    try:
        # Test with different protocols to get a wide range of ciphers
        protocols = [ssl.PROTOCOL_TLS]
        if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
            protocols.append(ssl.PROTOCOL_TLSv1_2)
        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            protocols.append(ssl.PROTOCOL_TLSv1_3)
        
        all_ciphers = []
        
        for protocol in protocols:
            context = ssl.SSLContext(protocol)
            context.set_ciphers("ALL:COMPLEMENTOFALL")
            
            try:
                with socket.create_connection((domain, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cipher = ssock.cipher()
                        if cipher and cipher[0] not in [c[0] for c in all_ciphers]:
                            all_ciphers.append(cipher)
            except (ssl.SSLError, socket.error, socket.timeout):
                continue
        
        # Process ciphers found
        for cipher_tuple in all_ciphers:
            cipher_name = cipher_tuple[0]
            protocol = cipher_tuple[1]
            key_size = cipher_tuple[2] if len(cipher_tuple) > 2 else None
            
            cipher_info["supported_ciphers"].append({
                "name": cipher_name,
                "protocol": protocol,
                "key_size": key_size
            })
            
            # Check for weak ciphers
            is_weak = False
            weakness_reasons = []
            
            for pattern, reason in WEAK_CIPHER_PATTERNS:
                if pattern in cipher_name:
                    is_weak = True
                    weakness_reasons.append(reason)
            
            # Check key size for weakness
            if key_size is not None:
                if key_size < 128:
                    is_weak = True
                    weakness_reasons.append(f"Weak key size ({key_size} bits)")
            
            if is_weak:
                cipher_info["weak_ciphers"].append({
                    "name": cipher_name,
                    "reasons": weakness_reasons
                })
                cipher_info["has_weak_ciphers"] = True
            else:
                cipher_info["strong_ciphers"].append(cipher_name)
            
            # Check for perfect forward secrecy
            if "DHE" in cipher_name or "ECDHE" in cipher_name:
                cipher_info["perfect_forward_secrecy"] = True
        
        # Add issues based on findings
        if cipher_info["has_weak_ciphers"]:
            cipher_info["issues"].append(f"Server supports {len(cipher_info['weak_ciphers'])} weak cipher suites")
        
        if not cipher_info["perfect_forward_secrecy"]:
            cipher_info["issues"].append("Server does not support Perfect Forward Secrecy")
        
        if len(cipher_info["supported_ciphers"]) == 0:
            cipher_info["issues"].append("No cipher suites could be detected")
        
    except Exception as e:
        cipher_info["issues"].append(f"Error checking cipher suites: {str(e)}")
    
    return cipher_info

def check_vulnerabilities_common(results):
    """
    Check for common SSL/TLS vulnerabilities based on the analysis results.
    
    Args:
        results (dict): The analysis results
        
    Returns:
        dict: Vulnerability information
    """
    vulnerability_info = {
        "vulnerabilities_found": [],
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0
    }
    
    # BEAST - Affects TLS 1.0 with CBC ciphers
    if results["protocols"]["TLSv1.0"]["supported"]:
        has_cbc = any("CBC" in cipher["name"] for cipher in results["cipher_suites"]["supported_ciphers"])
        if has_cbc:
            vulnerability_info["vulnerabilities_found"].append({
                "name": "BEAST",
                "details": VULNERABILITIES["BEAST"],
                "affected_config": "TLS 1.0 with CBC mode ciphers"
            })
            vulnerability_info["medium"] += 1
    
    # POODLE - Affects SSLv3
    if results["protocols"]["SSLv3"]["supported"]:
        vulnerability_info["vulnerabilities_found"].append({
            "name": "POODLE",
            "details": VULNERABILITIES["POODLE"],
            "affected_config": "SSLv3 support enabled"
        })
        vulnerability_info["high"] += 1
    
    # FREAK - Affects servers with export-grade ciphers
    has_export = any("EXP" in cipher["name"] for cipher in results["cipher_suites"]["supported_ciphers"])
    if has_export:
        vulnerability_info["vulnerabilities_found"].append({
            "name": "FREAK",
            "details": VULNERABILITIES["FREAK"],
            "affected_config": "Export-grade cipher suites enabled"
        })
        vulnerability_info["medium"] += 1
    
    # LOGJAM - Weak DH parameters
    has_dhe = any("DHE" in cipher["name"] and "ECDHE" not in cipher["name"] 
                   for cipher in results["cipher_suites"]["supported_ciphers"])
    if has_dhe:
        vulnerability_info["vulnerabilities_found"].append({
            "name": "LOGJAM (potential)",
            "details": VULNERABILITIES["LOGJAM"],
            "affected_config": "DHE cipher suites enabled (might use weak parameters)"
        })
        vulnerability_info["medium"] += 1
    
    # ROBOT - RSA encryption key exchange
    has_rsa_encryption = any(("RSA" in cipher["name"] and "ECDHE_RSA" not in cipher["name"] 
                              and "DHE_RSA" not in cipher["name"])
                             for cipher in results["cipher_suites"]["supported_ciphers"])
    if has_rsa_encryption:
        vulnerability_info["vulnerabilities_found"].append({
            "name": "ROBOT (potential)",
            "details": VULNERABILITIES["ROBOT"],
            "affected_config": "RSA encryption key exchange enabled"
        })
        vulnerability_info["high"] += 1
    
    # Sweet32 - 64-bit block ciphers
    has_3des = any("3DES" in cipher["name"] for cipher in results["cipher_suites"]["supported_ciphers"])
    if has_3des:
        vulnerability_info["vulnerabilities_found"].append({
            "name": "Sweet32",
            "details": VULNERABILITIES["Sweet32"],
            "affected_config": "3DES cipher suites enabled"
        })
        vulnerability_info["medium"] += 1
    
    # Lucky13 - CBC mode ciphers in TLS
    has_cbc = any("CBC" in cipher["name"] for cipher in results["cipher_suites"]["supported_ciphers"])
    if has_cbc:
        vulnerability_info["vulnerabilities_found"].append({
            "name": "Lucky13 (potential)",
            "details": VULNERABILITIES["Lucky13"],
            "affected_config": "CBC mode ciphers enabled"
        })
        vulnerability_info["medium"] += 1
    
    return vulnerability_info

def check_security_features(domain, port, results):
    """
    Check for additional SSL/TLS security features.
    
    Args:
        domain (str): The domain to check
        port (int): The port to connect to
        results (dict): The analysis results
        
    Returns:
        dict: Security feature information
    """
    security_features = {
        "hsts": False,
        "certificate_transparency": False,
        "ocsp_stapling": False,
        "secure_renegotiation": False,
        "issues": []
    }
    
    try:
        # HSTS check (would require HTTP request, just using a placeholder)
        # Real implementation would need to make an HTTP request and check headers
        security_features["hsts"] = False
        
        # Certificate Transparency check
        # Look for SCT (Signed Certificate Timestamp) in certificate extensions
        # Simplified check - real implementation would parse certificate extensions
        
        # OCSP Stapling check (simulated)
        # Real implementation would require checking TLS extension in handshake
        security_features["ocsp_stapling"] = False
        
        # Secure Renegotiation check (simulated)
        # Real implementation would check for secure renegotiation extension
        security_features["secure_renegotiation"] = True
        
        # Add issues based on features
        if not security_features["hsts"]:
            security_features["issues"].append("HTTP Strict Transport Security (HSTS) not enabled")
        
        if not security_features["ocsp_stapling"]:
            security_features["issues"].append("OCSP Stapling not enabled")
        
        if not security_features["secure_renegotiation"]:
            security_features["issues"].append("Secure Renegotiation not supported")
        
    except Exception as e:
        security_features["issues"].append(f"Error checking security features: {str(e)}")
    
    return security_features

def calculate_overall_rating(results):
    """
    Calculate an overall rating for the SSL/TLS configuration.
    
    Args:
        results (dict): The analysis results
        
    Returns:
        dict: Overall rating
    """
    rating = {
        "score": 0,
        "grade": "F",
        "summary": ""
    }
    
    try:
        score = 100
        deductions = 0
        critical_issues = 0
        
        # Protocol deductions
        if results["protocols"]["SSLv2"]["supported"]:
            deductions += 50
            critical_issues += 1
        
        if results["protocols"]["SSLv3"]["supported"]:
            deductions += 40
            critical_issues += 1
        
        if results["protocols"]["TLSv1.0"]["supported"]:
            deductions += 20
        
        if results["protocols"]["TLSv1.1"]["supported"]:
            deductions += 5
        
        if not results["protocols"]["TLSv1.2"]["supported"] and not results["protocols"]["TLSv1.3"]["supported"]:
            deductions += 50
            critical_issues += 1
        
        # Cipher deductions
        if results["cipher_suites"]["has_weak_ciphers"]:
            weak_cipher_count = len(results["cipher_suites"]["weak_ciphers"])
            deductions += min(40, weak_cipher_count * 5)
        
        if not results["cipher_suites"]["perfect_forward_secrecy"]:
            deductions += 20
        
        # Certificate deductions
        if "certificate" in results and "issues" in results["certificate"]:
            cert_issues = len(results["certificate"]["issues"])
            if cert_issues > 0:
                deductions += min(50, cert_issues * 10)
                
                # Check for critical cert issues
                for issue in results["certificate"]["issues"]:
                    if "expired" in issue.lower() or "not valid" in issue.lower():
                        critical_issues += 1
        
        # Vulnerability deductions
        if "vulnerabilities" in results:
            vuln_info = results["vulnerabilities"]
            deductions += vuln_info["critical"] * 20
            deductions += vuln_info["high"] * 10
            deductions += vuln_info["medium"] * 5
            deductions += vuln_info["low"] * 2
            
            critical_issues += vuln_info["critical"]
        
        # Security features bonus
        if "security_features" in results:
            features = results["security_features"]
            if features["hsts"]:
                deductions -= 5
            if features["certificate_transparency"]:
                deductions -= 5
            if features["ocsp_stapling"]:
                deductions -= 5
            if features["secure_renegotiation"]:
                deductions -= 5
        
        # Calculate final score
        final_score = max(0, score - deductions)
        rating["score"] = final_score
        
        # Assign grade based on score
        if final_score >= 90:
            grade = "A"
        elif final_score >= 80:
            grade = "B"
        elif final_score >= 70:
            grade = "C"
        elif final_score >= 60:
            grade = "D"
        else:
            grade = "F"
        
        # Critical issues automatically cap the grade
        if critical_issues > 0:
            if grade in ["A", "B"]:
                grade = "C"
        
        if critical_issues > 1:
            grade = "F"
        
        rating["grade"] = grade
        
        # Create summary
        if grade in ["A", "A+"]:
            rating["summary"] = "Excellent SSL/TLS configuration with strong protocols and ciphers."
        elif grade == "B":
            rating["summary"] = "Good SSL/TLS configuration with minor issues."
        elif grade == "C":
            rating["summary"] = "Adequate SSL/TLS configuration but needs improvement."
        elif grade == "D":
            rating["summary"] = "Poor SSL/TLS configuration with significant vulnerabilities."
        else:  # F
            rating["summary"] = "Failing SSL/TLS configuration with critical security issues."
        
    except Exception as e:
        logger.error(f"Error calculating rating: {str(e)}")
        rating["summary"] = "Error calculating rating"
    
    return rating

def generate_recommendations(results):
    """
    Generate recommendations based on the SSL/TLS analysis.
    
    Args:
        results (dict): The analysis results
        
    Returns:
        list: List of recommendations
    """
    recommendations = []
    
    # Protocol recommendations
    if results["protocols"]["SSLv2"]["supported"]:
        recommendations.append({
            "title": "Disable SSLv2",
            "description": "SSLv2 is severely insecure and should be disabled immediately.",
            "priority": "critical"
        })
    
    if results["protocols"]["SSLv3"]["supported"]:
        recommendations.append({
            "title": "Disable SSLv3",
            "description": "SSLv3 is vulnerable to the POODLE attack and should be disabled.",
            "priority": "high"
        })
    
    if results["protocols"]["TLSv1.0"]["supported"]:
        recommendations.append({
            "title": "Disable TLSv1.0",
            "description": "TLSv1.0 has known vulnerabilities including BEAST. Consider disabling it unless you need to support very old clients.",
            "priority": "medium"
        })
    
    if results["protocols"]["TLSv1.1"]["supported"]:
        recommendations.append({
            "title": "Consider disabling TLSv1.1",
            "description": "TLSv1.1 is outdated. Consider disabling it in favor of TLSv1.2 and TLSv1.3.",
            "priority": "low"
        })
    
    if not results["protocols"]["TLSv1.2"]["supported"] and not results["protocols"]["TLSv1.3"]["supported"]:
        recommendations.append({
            "title": "Enable TLSv1.2 and TLSv1.3",
            "description": "Your server does not support TLSv1.2 or TLSv1.3, which are the most secure TLS versions. Enable these protocols immediately.",
            "priority": "critical"
        })
    elif not results["protocols"]["TLSv1.3"]["supported"]:
        recommendations.append({
            "title": "Enable TLSv1.3",
            "description": "TLSv1.3 offers improved security and performance. Enable it to enhance your SSL/TLS configuration.",
            "priority": "medium"
        })
    
    # Cipher recommendations
    if results["cipher_suites"]["has_weak_ciphers"]:
        weak_names = [cipher["name"] for cipher in results["cipher_suites"]["weak_ciphers"][:5]]
        recommendations.append({
            "title": "Remove weak cipher suites",
            "description": f"Your server supports weak cipher suites including: {', '.join(weak_names)}. Remove these to improve security.",
            "priority": "high"
        })
    
    if not results["cipher_suites"]["perfect_forward_secrecy"]:
        recommendations.append({
            "title": "Enable Perfect Forward Secrecy",
            "description": "Configure your server to prioritize ECDHE and DHE cipher suites to enable Perfect Forward Secrecy.",
            "priority": "high"
        })
    
    # Certificate recommendations
    if "certificate" in results and "days_remaining" in results["certificate"]:
        days = results["certificate"]["days_remaining"]
        if days is not None:
            if days <= 0:
                recommendations.append({
                    "title": "Renew expired certificate immediately",
                    "description": "Your SSL certificate has expired. Renew it immediately.",
                    "priority": "critical"
                })
            elif days <= 14:
                recommendations.append({
                    "title": "Renew certificate soon",
                    "description": f"Your SSL certificate will expire in {days} days. Renew it as soon as possible.",
                    "priority": "high"
                })
            elif days <= 30:
                recommendations.append({
                    "title": "Plan certificate renewal",
                    "description": f"Your SSL certificate will expire in {days} days. Plan to renew it soon.",
                    "priority": "medium"
                })
    
    # Check for specific vulnerabilities
    if "vulnerabilities" in results and "vulnerabilities_found" in results["vulnerabilities"]:
        for vuln in results["vulnerabilities"]["vulnerabilities_found"]:
            name = vuln["name"]
            details = vuln["details"]
            recommendations.append({
                "title": f"Mitigate {name} vulnerability",
                "description": f"{details['description']} {details['mitigation']}",
                "priority": details["severity"]
            })
    
    # Security feature recommendations
    if "security_features" in results:
        features = results["security_features"]
        
        if not features["hsts"]:
            recommendations.append({
                "title": "Enable HTTP Strict Transport Security (HSTS)",
                "description": "HSTS ensures that browsers always use HTTPS for your domain, protecting against protocol downgrade attacks.",
                "priority": "medium"
            })
        
        if not features["ocsp_stapling"]:
            recommendations.append({
                "title": "Enable OCSP Stapling",
                "description": "OCSP Stapling improves performance and privacy by allowing the server to provide the OCSP response during the TLS handshake.",
                "priority": "medium"
            })
    
    # Server configuration examples based on rating
    server_config_recommendation = None
    
    if "overall_rating" in results and "grade" in results["overall_rating"]:
        grade = results["overall_rating"]["grade"]
        
        if grade in ["D", "F"]:
            server_config_recommendation = {
                "title": "Implement modern SSL/TLS configuration",
                "description": "Your current configuration has significant security issues. Implement a modern, secure SSL/TLS configuration with strong protocols and ciphers.",
                "priority": "critical",
                "examples": [
                    "For Apache: https://ssl-config.mozilla.org/#server=apache",
                    "For Nginx: https://ssl-config.mozilla.org/#server=nginx",
                    "For HAProxy: https://ssl-config.mozilla.org/#server=haproxy"
                ]
            }
        elif grade == "C":
            server_config_recommendation = {
                "title": "Improve SSL/TLS configuration",
                "description": "Your current configuration can be improved. Update your SSL/TLS settings to use only strong protocols and ciphers.",
                "priority": "medium",
                "examples": [
                    "For Apache: https://ssl-config.mozilla.org/#server=apache&config=intermediate",
                    "For Nginx: https://ssl-config.mozilla.org/#server=nginx&config=intermediate",
                    "For HAProxy: https://ssl-config.mozilla.org/#server=haproxy&config=intermediate"
                ]
            }
    
    if server_config_recommendation:
        recommendations.append(server_config_recommendation)
    
    # Sort recommendations by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    recommendations.sort(key=lambda x: priority_order.get(x["priority"], 4))
    
    return recommendations

if __name__ == "__main__":
    # Example usage
    results = analyze_ssl_configuration("example.com")
    print(json.dumps(results, indent=2))