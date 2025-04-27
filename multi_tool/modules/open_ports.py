"""Module for scanning open ports on a host."""

import logging
import socket
import time
import re
import concurrent.futures

logger = logging.getLogger(__name__)

# Common service names for well-known ports
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    115: "SFTP",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP (Submission)",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP (Alternative)",
    8443: "HTTPS (Alternative)"
}

def scan_open_ports(host, port_range='1-1000', max_workers=100, timeout=1):
    """
    Scan for open ports on a host.
    
    Args:
        host (str): The host to scan
        port_range (str, optional): Port range to scan (e.g., '1-1000'). Defaults to '1-1000'.
        max_workers (int, optional): Maximum number of parallel workers. Defaults to 100.
        timeout (int, optional): Connection timeout in seconds. Defaults to 1.
        
    Returns:
        dict: Open ports and services on the host
    """
    logger.debug(f"Scanning open ports on host: {host}, range: {port_range}")
    
    result = {
        "host": host,
        "ip": None,
        "open_ports": [],
        "error": None
    }
    
    try:
        # Resolve the hostname to IP address
        try:
            ip_address = socket.gethostbyname(host)
            result["ip"] = ip_address
        except socket.gaierror:
            logger.error(f"Could not resolve host: {host}")
            result["error"] = f"Could not resolve host: {host}"
            return result
        
        # Parse the port range
        try:
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
                ports = range(start_port, end_port + 1)
            elif ',' in port_range:
                ports = [int(p) for p in port_range.split(',')]
            else:
                ports = [int(port_range)]
        except ValueError:
            logger.error(f"Invalid port range: {port_range}")
            result["error"] = f"Invalid port range: {port_range}"
            return result
        
        # Scan ports in parallel for efficiency
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {
                executor.submit(_check_port, ip_address, port, timeout): port for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, banner = future.result()
                    if is_open:
                        service = COMMON_PORTS.get(port, "Unknown")
                        result["open_ports"].append({
                            "port": port,
                            "service": service,
                            "banner": banner
                        })
                except Exception as exc:
                    logger.error(f"Error checking port {port}: {str(exc)}")
        
        # Sort open ports by port number
        result["open_ports"] = sorted(result["open_ports"], key=lambda x: x["port"])
        
        # Add scan metadata
        scan_time = time.time() - start_time
        result["scan_metadata"] = {
            "scan_time_seconds": round(scan_time, 2),
            "ports_scanned": len(ports),
            "open_ports_count": len(result["open_ports"])
        }
    
    except Exception as e:
        logger.error(f"Error scanning ports: {str(e)}")
        result["error"] = str(e)
    
    logger.debug(f"Port scan result: {result}")
    return result

def _check_port(ip, port, timeout=1):
    """Check if a port is open and try to get a service banner."""
    logger.debug(f"Checking port {port} on {ip}")
    
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Try to connect to the port
        result = sock.connect_ex((ip, port))
        
        if result == 0:  # Port is open
            banner = _get_banner(sock)
            sock.close()
            return True, banner
        else:
            sock.close()
            return False, None
    
    except (socket.timeout, socket.error) as e:
        logger.debug(f"Socket error on port {port}: {str(e)}")
        return False, None

def _get_banner(sock):
    """Try to get a service banner from an open port."""
    banner = ""
    try:
        # Some services send a banner immediately upon connection
        sock.settimeout(1)
        banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
    except (socket.timeout, socket.error):
        # If no banner is received, try sending some common protocol greetings
        try:
            # HTTP
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
        except (socket.timeout, socket.error):
            try:
                # SMTP
                sock.sendall(b"HELO example.com\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
            except (socket.timeout, socket.error):
                pass
    
    # Clean up the banner (remove control characters)
    banner = re.sub(r'[\x00-\x1F\x7F]', '', banner)
    return banner if banner else None
