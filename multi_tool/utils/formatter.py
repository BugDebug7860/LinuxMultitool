"""Utility module for formatting output."""

import json
import logging
from tabulate import tabulate

logger = logging.getLogger(__name__)

def format_output(data, format_type='text'):
    """
    Format the output data in the specified format.
    
    Args:
        data (dict): The data to format
        format_type (str, optional): The output format (json, table, text). Defaults to 'text'.
        
    Returns:
        str: Formatted output
    """
    logger.debug(f"Formatting output as {format_type}")
    
    if format_type == 'json':
        return _format_as_json(data)
    elif format_type == 'table':
        return _format_as_table(data)
    else:  # text
        return _format_as_text(data)

def _format_as_json(data):
    """Format the data as JSON."""
    try:
        return json.dumps(data, indent=2, sort_keys=True)
    except Exception as e:
        logger.error(f"Error formatting as JSON: {str(e)}")
        return f"Error formatting as JSON: {str(e)}"

def _format_as_table(data):
    """Format the data as a table."""
    try:
        result = []
        
        # Add a header
        if "command" in data:
            result.append(f"# {data['command']} Results")
        
        # Handle the error case
        if "error" in data and data["error"]:
            result.append(f"Error: {data['error']}")
            return "\n".join(result)
        
        # Process different data structures
        if "open_ports" in data:  # Port scan results
            headers = ["Port", "Service", "Banner"]
            table_data = [[p["port"], p["service"], p.get("banner", "")] for p in data["open_ports"]]
            result.append(f"Host: {data['host']} ({data['ip'] or 'Unknown IP'})")
            result.append(tabulate(table_data, headers=headers, tablefmt="grid"))
            
            if "scan_metadata" in data:
                result.append(f"\nScan completed in {data['scan_metadata']['scan_time_seconds']} seconds")
                result.append(f"Scanned {data['scan_metadata']['ports_scanned']} ports, found {data['scan_metadata']['open_ports_count']} open")
        
        elif "hops" in data:  # Traceroute results
            headers = ["Hop", "IP/Host", "Avg RTT (ms)"]
            table_data = [[h["hop"], h["ip_or_host"], h["avg_rtt"] if h["avg_rtt"] else "*"] for h in data["hops"]]
            result.append(f"Traceroute to {data['host']} ({data.get('ip', 'Unknown')})")
            result.append(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        elif "records" in data:  # DNS records
            result.append(f"DNS Records for {data['domain']}")
            for record_type, records in data["records"].items():
                result.append(f"\n## {record_type} Records:")
                if isinstance(records, list):
                    if records:
                        if isinstance(records[0], dict):  # Complex records like MX, SOA
                            for record in records:
                                for key, value in record.items():
                                    result.append(f"  {key}: {value}")
                                result.append("")
                        else:  # Simple records like A, AAAA
                            for record in records:
                                result.append(f"  {record}")
                    else:
                        result.append("  No records found")
                else:
                    result.append(f"  Error: {records}")
        
        elif "redirect_chain" in data:  # Redirect chain
            headers = ["Step", "Status", "URL", "Type"]
            table_data = [
                [r["step"], r["status_code"], r["url"], r.get("type", "")]
                for r in data["redirect_chain"]
            ]
            result.append(f"Redirect Chain for {data['original_url']}")
            result.append(f"Final URL: {data['final_url']}")
            result.append(tabulate(table_data, headers=headers, tablefmt="grid"))
            
            if "redirect_loops" in data:
                result.append("\nRedirect loops detected at:")
                for url in data["redirect_loops"]:
                    result.append(f"  {url}")
        
        elif "technologies" in data:  # Tech stack analysis
            result.append(f"Technology Stack Analysis for {data['url']}")
            result.append("\n## Detected Technologies:")
            for tech in data["technologies"]:
                result.append(f"  - {tech}")
            
            if data["server"]:
                result.append(f"\nServer: {data['server']}")
            
            if data["cms"]:
                result.append(f"CMS: {data['cms']}")
            
            if data["frameworks"]:
                result.append("\n## Frameworks:")
                for framework in data["frameworks"]:
                    result.append(f"  - {framework}")
            
            if data["javascript_libraries"]:
                result.append("\n## JavaScript Libraries:")
                for lib in data["javascript_libraries"]:
                    result.append(f"  - {lib}")
            
            if data["analytics"]:
                result.append("\n## Analytics Tools:")
                for tool in data["analytics"]:
                    result.append(f"  - {tool}")
            
            if data["cdn"]:
                result.append(f"CDN: {data['cdn']}")
        
        elif "headers" in data:  # HTTP headers
            result.append(f"HTTP Headers Analysis for {data['url']}")
            result.append(f"Status Code: {data['status_code']}")
            
            result.append("\n## Response Headers:")
            headers_table = [[k, v] for k, v in data["headers"].items()]
            result.append(tabulate(headers_table, headers=["Header", "Value"], tablefmt="grid"))
            
            if "security_headers" in data and data["security_headers"]:
                result.append("\n## Security Headers:")
                security_table = [[k, v] for k, v in data["security_headers"].items()]
                result.append(tabulate(security_table, headers=["Header", "Value"], tablefmt="grid"))
            
            if "missing_security_headers" in data:
                result.append("\n## Missing Security Headers:")
                for header in data["missing_security_headers"]:
                    result.append(f"  - {header}")
        
        elif "location" in data and "ip" in data:  # Server location or IP info
            # Determine if this is IP info or server location data
            if "domain" in data:
                title = f"Server Location for {data['domain']} ({data['ip']})"
            else:
                title = f"IP Information for {data['ip']}"
                
            result.append(title)
            
            if data["location"]:
                location_table = [[k, v] for k, v in data["location"].items()]
                result.append(tabulate(location_table, headers=["Field", "Value"], tablefmt="grid"))
            
            if "network" in data:
                result.append("\n## Network Information:")
                network_table = [[k, v] for k, v in data["network"].items()]
                result.append(tabulate(network_table, headers=["Field", "Value"], tablefmt="grid"))
        
        else:  # Generic data structure
            # Just convert the data to a series of key-value pairs
            table_data = [[k, v] for k, v in data.items() if not isinstance(v, (dict, list))]
            if table_data:
                result.append(tabulate(table_data, headers=["Field", "Value"], tablefmt="grid"))
            
            # Process nested dictionaries
            for key, value in data.items():
                if isinstance(value, dict):
                    result.append(f"\n## {key}:")
                    nested_data = [[k, v] for k, v in value.items() if not isinstance(v, (dict, list))]
                    if nested_data:
                        result.append(tabulate(nested_data, headers=["Field", "Value"], tablefmt="grid"))
                
                elif isinstance(value, list) and value and isinstance(value[0], dict):
                    result.append(f"\n## {key}:")
                    # Extract keys from the first item to use as headers
                    headers = list(value[0].keys())
                    nested_data = [[item.get(h, "") for h in headers] for item in value]
                    result.append(tabulate(nested_data, headers=headers, tablefmt="grid"))
        
        return "\n".join(result)
    
    except Exception as e:
        logger.error(f"Error formatting as table: {str(e)}")
        return f"Error formatting as table: {str(e)}\nRaw data:\n{json.dumps(data, indent=2)}"

def _format_as_text(data):
    """Format the data as plain text."""
    try:
        result = []
        
        # Handle the error case
        if "error" in data and data["error"]:
            result.append(f"Error: {data['error']}")
            return "\n".join(result)
        
        # Process the data recursively
        _process_dict(data, result)
        
        return "\n".join(result)
    
    except Exception as e:
        logger.error(f"Error formatting as text: {str(e)}")
        return f"Error formatting as text: {str(e)}"

def _process_dict(data, result, level=0):
    """Process a dictionary recursively for text output."""
    indent = "  " * level
    
    for key, value in data.items():
        if isinstance(value, dict):
            result.append(f"{indent}{key}:")
            _process_dict(value, result, level + 1)
        
        elif isinstance(value, list):
            result.append(f"{indent}{key}:")
            for item in value:
                if isinstance(item, dict):
                    _process_dict(item, result, level + 1)
                    result.append("")  # Add a blank line between list items
                else:
                    result.append(f"{indent}  {item}")
        
        else:
            result.append(f"{indent}{key}: {value}")
