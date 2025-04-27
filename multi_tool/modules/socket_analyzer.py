#!/usr/bin/env python3
"""Module for analyzing open sockets on a target server."""

import logging
import socket
import json
import re
import concurrent.futures
import time
import validators
from urllib.parse import urlparse
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Common port definitions
COMMON_PORTS = {
    # Web Services
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    
    # Email
    25: "SMTP",
    587: "SMTP-Submission",
    465: "SMTPS",
    110: "POP3",
    995: "POP3S",
    143: "IMAP",
    993: "IMAPS",
    
    # File Transfer
    21: "FTP",
    22: "SSH/SFTP",
    69: "TFTP",
    
    # Databases
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MS-SQL",
    1521: "Oracle",
    27017: "MongoDB",
    6379: "Redis",
    
    # Remote Access
    3389: "RDP",
    5900: "VNC",
    
    # Directory Services
    389: "LDAP",
    636: "LDAPS",
    
    # DNS
    53: "DNS",
    
    # Other Common Services
    161: "SNMP",
    162: "SNMP-Trap",
    123: "NTP",
    179: "BGP",
    445: "SMB",
    548: "AFP",
    3000: "Node.js (Common)",
    5000: "Python (Common)",
    8000: "Python/Django (Common)",
    8888: "Jupyter Notebook",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "Elasticsearch Nodes"
}

# Common vulnerability concerns
VULNERABILITY_CONCERNS = {
    21: "Unencrypted FTP can expose credentials. Consider using SFTP (SSH) instead.",
    23: "Telnet is unencrypted and vulnerable to MITM attacks. Use SSH instead.",
    25: "Unencrypted SMTP can expose email content. Consider using port 587 with STARTTLS or 465 with SSL.",
    110: "Unencrypted POP3 can expose email content. Consider using port 995 with SSL.",
    143: "Unencrypted IMAP can expose email content. Consider using port 993 with SSL.",
    161: "SNMP v1/v2 have known security issues. Use SNMPv3 with authentication and encryption.",
    445: "SMB should be firewalled from public networks due to numerous historical vulnerabilities.",
    1433: "MS-SQL should not be directly exposed to the internet. Use a VPN or SSH tunnel.",
    3306: "MySQL should not be directly exposed to the internet. Use a VPN or SSH tunnel.",
    3389: "RDP has had numerous vulnerabilities. Limit access and use Network Level Authentication.",
    5432: "PostgreSQL should not be directly exposed to the internet. Use a VPN or SSH tunnel.",
    5900: "VNC without proper encryption is vulnerable to MITM attacks.",
    6379: "Redis without authentication should never be exposed to the internet.",
    27017: "MongoDB without authentication should never be exposed to the internet."
}

def scan_sockets(target, port_range='1-1000', scan_speed='normal'):
    """
    Scan for open sockets on a target server.
    
    Args:
        target (str): The URL or domain to scan
        port_range (str): Range of ports to scan (e.g., '1-1000' or '22,80,443')
        scan_speed (str): Scan speed - 'slow', 'normal', or 'fast'
        
    Returns:
        dict: Socket scan results
    """
    logger.debug(f"Starting socket scan on {target} with port range {port_range}")
    
    # Convert domain/URL to hostname
    if validators.url(target):
        parsed_url = urlparse(target)
        hostname = parsed_url.netloc
    elif validators.domain(target):
        hostname = target
    else:
        try:
            # Try to resolve as IP address
            socket.inet_aton(target)
            hostname = target
        except socket.error:
            return {
                "error": "Invalid target. Please provide a valid URL, domain, or IP address.",
                "target": target
            }
    
    # Remove port from hostname if present
    if ':' in hostname:
        hostname = hostname.split(':', 1)[0]
    
    # Parse port range
    ports_to_scan = []
    
    if ',' in port_range:
        # Comma-separated list of ports
        for part in port_range.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-', 1)
                try:
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    ports_to_scan.extend(range(start_port, end_port + 1))
                except ValueError:
                    return {"error": f"Invalid port range: {part}"}
            else:
                try:
                    port = int(part)
                    ports_to_scan.append(port)
                except ValueError:
                    return {"error": f"Invalid port: {part}"}
    elif '-' in port_range:
        # Range notation (e.g., "1-1000")
        start, end = port_range.split('-', 1)
        try:
            start_port = int(start.strip())
            end_port = int(end.strip())
            ports_to_scan = list(range(start_port, end_port + 1))
        except ValueError:
            return {"error": f"Invalid port range: {port_range}"}
    else:
        # Single port
        try:
            port = int(port_range.strip())
            ports_to_scan = [port]
        except ValueError:
            return {"error": f"Invalid port: {port_range}"}
    
    # Check for valid port range
    if any(port < 1 or port > 65535 for port in ports_to_scan):
        return {"error": "Ports must be between 1 and 65535"}
    
    # Set scan parameters based on speed
    if scan_speed == 'slow':
        timeout = 3.0
        max_workers = 10
    elif scan_speed == 'fast':
        timeout = 0.5
        max_workers = 100
    else:  # normal
        timeout = 1.0
        max_workers = 50
    
    # Initialize results
    results = {
        "target": target,
        "hostname": hostname,
        "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "port_range": port_range,
        "scan_speed": scan_speed,
        "open_ports": [],
        "vulnerabilities": [],
        "summary": {
            "total_ports_scanned": len(ports_to_scan),
            "open_ports_count": 0,
            "vulnerability_count": 0
        },
        "recommendations": []
    }
    
    try:
        # Try to get IP address
        try:
            ip_address = socket.gethostbyname(hostname)
            results["ip_address"] = ip_address
        except socket.gaierror:
            results["error"] = f"Could not resolve hostname: {hostname}"
            return results
        
        # Scan ports using thread pool for speed
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(check_port_open, hostname, port, timeout): port
                for port in ports_to_scan
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, service_info = future.result()
                    if is_open:
                        # Port is open, add to results
                        service_name = COMMON_PORTS.get(port, "Unknown")
                        
                        port_info = {
                            "port": port,
                            "service": service_name,
                            "protocol": "tcp",  # We're only scanning TCP in this implementation
                            "state": "open",
                            "version": service_info
                        }
                        
                        results["open_ports"].append(port_info)
                        results["summary"]["open_ports_count"] += 1
                        
                        # Check for vulnerability concerns
                        if port in VULNERABILITY_CONCERNS:
                            vulnerability = {
                                "port": port,
                                "service": service_name,
                                "severity": get_vulnerability_severity(port),
                                "description": VULNERABILITY_CONCERNS[port]
                            }
                            results["vulnerabilities"].append(vulnerability)
                            results["summary"]["vulnerability_count"] += 1
                            
                except Exception as e:
                    logger.error(f"Error scanning port {port}: {str(e)}")
        
        # Sort open ports by port number
        results["open_ports"] = sorted(results["open_ports"], key=lambda x: x["port"])
        
        # Generate recommendations based on scan results
        results["recommendations"] = generate_recommendations(results)
        
    except Exception as e:
        logger.error(f"Error during socket scan: {str(e)}")
        results["error"] = f"Scan error: {str(e)}"
    
    return results

def check_port_open(hostname, port, timeout):
    """
    Check if a specific port is open on the target hostname.
    
    Args:
        hostname (str): The hostname to check
        port (int): The port number to check
        timeout (float): Connection timeout in seconds
        
    Returns:
        tuple: (is_open, service_info)
    """
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    service_info = ""
    
    try:
        # Try to connect to the port
        result = sock.connect_ex((hostname, port))
        
        if result == 0:
            # Port is open, try to get banner for service identification
            try:
                # Send a stimulating message based on the port
                if port == 80:
                    sock.send(b"HEAD / HTTP/1.1\r\nHost: " + hostname.encode() + b"\r\n\r\n")
                elif port == 25 or port == 587:
                    # SMTP
                    sock.send(b"EHLO multi-tool.local\r\n")
                elif port == 22:
                    # SSH usually sends banner automatically
                    pass
                elif port == 21:
                    # FTP usually sends banner automatically
                    pass
                elif port == 110:
                    # POP3
                    sock.send(b"CAPA\r\n")
                elif port == 143:
                    # IMAP
                    sock.send(b"A1 CAPABILITY\r\n")
                else:
                    # Generic request that might elicit a response
                    sock.send(b"\r\n")
                
                # Wait for response with timeout
                sock.settimeout(1.0)
                banner = sock.recv(1024)
                
                # Process banner to extract version info
                service_info = extract_version_from_banner(banner, port)
                
            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                # No banner received or connection was reset
                pass
            
            return True, service_info
        
        return False, ""
        
    except Exception:
        return False, ""
        
    finally:
        sock.close()

def extract_version_from_banner(banner, port):
    """
    Extract version information from service banner.
    
    Args:
        banner (bytes): The banner received from the service
        port (int): The port number
        
    Returns:
        str: Version information if found, otherwise empty string
    """
    try:
        # Convert to string, handling potential encoding issues
        banner_str = banner.decode('utf-8', errors='replace')
    except (UnicodeDecodeError, AttributeError):
        return ""
    
    # Look for version information based on service type
    if port == 22:  # SSH
        # SSH banners typically follow the format: SSH-2.0-OpenSSH_8.4p1
        ssh_match = re.search(r'SSH-\d+\.\d+-(.*)', banner_str)
        if ssh_match:
            return ssh_match.group(1)
    elif port == 21:  # FTP
        # FTP banners often include version: 220 ProFTPD 1.3.5e Server
        ftp_match = re.search(r'220[- ](.*?)(?:\r|\n|$)', banner_str)
        if ftp_match:
            return ftp_match.group(1)
    elif port == 25 or port == 587:  # SMTP
        # SMTP banners: 220 mail.example.com ESMTP Postfix
        smtp_match = re.search(r'220[- ]([^\r\n]*)', banner_str)
        if smtp_match:
            return smtp_match.group(1)
    elif port == 80 or port == 443:  # HTTP/HTTPS
        # HTTP responses include server info: Server: Apache/2.4.41 (Ubuntu)
        http_match = re.search(r'Server: ([^\r\n]*)', banner_str)
        if http_match:
            return http_match.group(1)
    elif port == 3306:  # MySQL
        mysql_match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+)', banner_str)
        if mysql_match:
            return f"MySQL {mysql_match.group(1)}"
    elif port == 5432:  # PostgreSQL
        pgsql_match = re.search(r'postgresql', banner_str, re.IGNORECASE)
        if pgsql_match:
            ver_match = re.search(r'([0-9]+(?:\.[0-9]+)?)', banner_str)
            if ver_match:
                return f"PostgreSQL {ver_match.group(1)}"
            return "PostgreSQL"
    
    # General pattern matching for version numbers
    version_match = re.search(r'([a-zA-Z0-9_-]+)[/\s]([0-9]+(?:\.[0-9]+)+)', banner_str)
    if version_match:
        return f"{version_match.group(1)} {version_match.group(2)}"
    
    return banner_str.strip()[:50]  # Return first 50 chars of banner as fallback

def get_vulnerability_severity(port):
    """
    Determine the severity of a vulnerability associated with an open port.
    
    Args:
        port (int): The port number
        
    Returns:
        str: Severity level ('critical', 'high', 'medium', or 'low')
    """
    # Ports with potentially critical vulnerabilities if exposed
    critical_ports = [21, 23, 445, 3389, 6379, 27017]
    
    # Ports with high severity risks
    high_ports = [25, 110, 143, 1433, 3306, 5432, 5900]
    
    # Ports with medium severity risks
    medium_ports = [53, 161, 389, 8080]
    
    if port in critical_ports:
        return "critical"
    elif port in high_ports:
        return "high"
    elif port in medium_ports:
        return "medium"
    else:
        return "low"

def generate_recommendations(results):
    """
    Generate recommendations based on the socket scan results.
    
    Args:
        results (dict): The scan results
        
    Returns:
        list: List of recommendations
    """
    recommendations = []
    
    # Group open ports by service categories
    web_ports = []
    db_ports = []
    admin_ports = []
    email_ports = []
    unencrypted_ports = []
    
    for port_info in results["open_ports"]:
        port = port_info["port"]
        service = port_info["service"].lower()
        
        # Categorize by service type
        if service in ["http", "https", "http-alt", "https-alt"]:
            web_ports.append(port)
        elif "sql" in service or service in ["mongodb", "redis", "cassandra", "couchdb"]:
            db_ports.append(port)
        elif service in ["ssh", "rdp", "vnc", "telnet"]:
            admin_ports.append(port)
        elif service in ["smtp", "pop3", "imap", "pop3s", "imaps", "smtps"]:
            email_ports.append(port)
        
        # Check for unencrypted services
        unencrypted_services = ["ftp", "telnet", "pop3", "imap", "smtp", "vnc", "snmp"]
        if any(svc in service for svc in unencrypted_services) and "s" not in service:
            unencrypted_ports.append(port)
    
    # Security recommendations based on open port categories
    if db_ports:
        recommendations.append({
            "title": "Database ports exposed",
            "description": f"Database ports {', '.join(map(str, db_ports))} are accessible. These should typically not be directly exposed to the internet. Consider using a VPN, SSH tunnel, or firewall rules to restrict access.",
            "severity": "high"
        })
    
    if admin_ports and 22 not in admin_ports:  # SSH is relatively secure, so we exclude it
        recommendations.append({
            "title": "Administrative access ports exposed",
            "description": f"Administrative ports {', '.join(map(str, admin_ports))} are accessible. These should be restricted to trusted IP addresses using firewall rules.",
            "severity": "high"
        })
    
    if unencrypted_ports:
        recommendations.append({
            "title": "Unencrypted services detected",
            "description": f"Ports {', '.join(map(str, unencrypted_ports))} are running services that may transmit data without encryption. Consider replacing these with encrypted alternatives.",
            "severity": "high"
        })
    
    # Check for unnecessary exposed services
    if len(results["open_ports"]) > 5:
        recommendations.append({
            "title": "Reduce attack surface",
            "description": f"There are {len(results['open_ports'])} open ports, which presents a large attack surface. Consider closing unnecessary services to reduce risk.",
            "severity": "medium"
        })
    
    # Add specific recommendations for common vulnerable services
    for vuln in results["vulnerabilities"]:
        if vuln["port"] == 21:  # FTP
            recommendations.append({
                "title": "Replace FTP with SFTP",
                "description": "FTP transmits credentials and data in plaintext. Replace with SFTP (SSH File Transfer Protocol) for secure file transfers.",
                "severity": "high"
            })
        elif vuln["port"] == 23:  # Telnet
            recommendations.append({
                "title": "Replace Telnet with SSH",
                "description": "Telnet transmits all data including passwords in plaintext. Replace with SSH for secure remote administration.",
                "severity": "critical"
            })
        elif vuln["port"] == 3389:  # RDP
            recommendations.append({
                "title": "Secure RDP access",
                "description": "Remote Desktop Protocol has been the target of numerous attacks. Enable Network Level Authentication (NLA), use complex passwords, and consider implementing multi-factor authentication.",
                "severity": "high"
            })
        elif vuln["port"] in [27017, 6379]:  # MongoDB, Redis
            recommendations.append({
                "title": "Secure NoSQL database access",
                "description": f"NoSQL database on port {vuln['port']} is exposed. These services should never be directly accessible from the internet without proper authentication and encryption.",
                "severity": "critical"
            })
    
    # General firewall recommendation if there are vulnerabilities
    if results["vulnerabilities"]:
        recommendations.append({
            "title": "Implement proper firewall rules",
            "description": "Configure host-based and network firewalls to restrict access to services based on source IP addresses and necessary business functions.",
            "severity": "high"
        })
    
    return recommendations

if __name__ == "__main__":
    # Example usage
    results = scan_sockets("example.com", port_range="1-1000", scan_speed="normal")
    print(json.dumps(results, indent=2))