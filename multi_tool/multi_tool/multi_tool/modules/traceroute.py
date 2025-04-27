"""Module for executing traceroute operations."""

import logging
import socket
import subprocess
import platform
import re

logger = logging.getLogger(__name__)

def execute_traceroute(host, max_hops=30):
    """
    Execute a traceroute to a specified host.
    
    Args:
        host (str): The host to trace the route to
        max_hops (int, optional): Maximum number of hops. Defaults to 30.
        
    Returns:
        dict: Traceroute results
    """
    logger.debug(f"Executing traceroute to host: {host}, max_hops: {max_hops}")
    
    result = {
        "host": host,
        "hops": [],
        "error": None
    }
    
    try:
        # Resolve the hostname to IP address
        try:
            ip_address = socket.gethostbyname(host)
            result["ip"] = ip_address
        except socket.gaierror:
            logger.warning(f"Could not resolve host: {host}")
            result["ip"] = None
        
        # Determine the traceroute command based on the platform
        system = platform.system().lower()
        
        if system == "windows":
            cmd = ["tracert", "-d", "-h", str(max_hops), host]
        elif system in ["linux", "darwin"]:  # Linux or macOS
            cmd = ["traceroute", "-n", "-m", str(max_hops), host]
        else:
            result["error"] = f"Unsupported platform: {system}"
            return result
        
        # Execute the traceroute command
        logger.debug(f"Executing command: {' '.join(cmd)}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            logger.error(f"Traceroute failed with return code {process.returncode}: {stderr}")
            result["error"] = f"Traceroute command failed: {stderr}"
            return result
        
        # Parse the output based on the platform
        if system == "windows":
            result["hops"] = _parse_windows_traceroute(stdout)
        else:  # Linux or macOS
            result["hops"] = _parse_unix_traceroute(stdout)
        
    except Exception as e:
        logger.error(f"Error executing traceroute: {str(e)}")
        result["error"] = str(e)
    
    logger.debug(f"Traceroute result: {result}")
    return result

def _parse_windows_traceroute(output):
    """Parse the output of the Windows tracert command."""
    hops = []
    
    # Regular expression to match hop lines in the Windows tracert output
    hop_pattern = re.compile(r'^\s*(\d+)\s+(\*|\d+\s+ms)\s+(\*|\d+\s+ms)\s+(\*|\d+\s+ms)\s+(.+)?$')
    
    for line in output.splitlines():
        match = hop_pattern.match(line)
        if match:
            hop_num = int(match.group(1))
            
            # Extract the RTT values (convert * to None)
            rtt1 = None if match.group(2) == '*' else float(match.group(2).replace(' ms', ''))
            rtt2 = None if match.group(3) == '*' else float(match.group(3).replace(' ms', ''))
            rtt3 = None if match.group(4) == '*' else float(match.group(4).replace(' ms', ''))
            
            # Calculate average RTT (ignore None values)
            rtts = [r for r in [rtt1, rtt2, rtt3] if r is not None]
            avg_rtt = sum(rtts) / len(rtts) if rtts else None
            
            # Extract the IP address or hostname
            ip_or_host = match.group(5).strip() if match.group(5) else "Request timed out"
            
            hops.append({
                "hop": hop_num,
                "rtt1": rtt1,
                "rtt2": rtt2,
                "rtt3": rtt3,
                "avg_rtt": avg_rtt,
                "ip_or_host": ip_or_host
            })
    
    return hops

def _parse_unix_traceroute(output):
    """Parse the output of the Unix/Linux traceroute command."""
    hops = []
    
    # Skip the first line which is just the header
    lines = output.splitlines()[1:]
    
    for line in lines:
        # Split by whitespace
        parts = line.split()
        
        if len(parts) >= 4:  # Basic validation
            hop_num = int(parts[0])
            
            # Extract the host/IP and RTT values
            ip_or_host = parts[1]
            if ip_or_host == '*':
                ip_or_host = "Request timed out"
            
            # Extract RTT values (convert * to None)
            rtts = []
            for i in range(2, min(5, len(parts))):
                if parts[i] == '*':
                    rtts.append(None)
                else:
                    try:
                        rtts.append(float(parts[i].replace('ms', '')))
                    except ValueError:
                        rtts.append(None)
            
            # Pad RTT list if we don't have 3 values
            while len(rtts) < 3:
                rtts.append(None)
            
            # Calculate average RTT (ignore None values)
            valid_rtts = [r for r in rtts if r is not None]
            avg_rtt = sum(valid_rtts) / len(valid_rtts) if valid_rtts else None
            
            hops.append({
                "hop": hop_num,
                "rtt1": rtts[0],
                "rtt2": rtts[1] if len(rtts) > 1 else None,
                "rtt3": rtts[2] if len(rtts) > 2 else None,
                "avg_rtt": avg_rtt,
                "ip_or_host": ip_or_host
            })
    
    return hops
