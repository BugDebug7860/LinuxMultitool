#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Multi-Tool: Interactive menu-based interface for the multi-tool package
"""

import sys
import logging
import os

# Import security module functions
from multi_tool.modules.vulnerability_scanner import scan_for_vulnerabilities
from multi_tool.modules.rate_limit_analyzer import analyze_rate_limits
from multi_tool.modules.socket_analyzer import scan_sockets
from multi_tool.modules.enhanced_header_analyzer import analyze_enhanced_headers
from multi_tool.modules.domain_health_checker import check_domain_health
from multi_tool.modules.enhanced_ssl_analyzer import analyze_ssl_configuration

# Import additional modules
from multi_tool.modules.screenshot_capture import capture_screenshot

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import Multi-Tool modules
try:
    # Original modules
    from multi_tool.modules.ip_info import get_ip_info
    from multi_tool.modules.ssl_chain import analyze_ssl_chain
    from multi_tool.modules.dns_records import get_dns_records
    from multi_tool.modules.http_headers import analyze_headers
    from multi_tool.modules.server_location import get_server_location
    from multi_tool.modules.whois_lookup import perform_whois_lookup
    from multi_tool.modules.redirect_chain import inspect_redirect_chain
    from multi_tool.modules.tech_stack import analyze_tech_stack
    from multi_tool.modules.traceroute import execute_traceroute
    from multi_tool.modules.open_ports import scan_open_ports
    
    # New modules
    from multi_tool.modules.cookies import get_cookies
    from multi_tool.modules.crawl_rules import analyze_crawl_rules
    from multi_tool.modules.quality_metrics import assess_quality_metrics
    from multi_tool.modules.associated_hosts import identify_associated_hosts
    from multi_tool.modules.txt_records import get_txt_records
    from multi_tool.modules.server_status import check_server_status
    from multi_tool.modules.carbon_footprint import estimate_carbon_footprint
    from multi_tool.modules.server_info import get_server_info
    from multi_tool.modules.domain_info import get_domain_info
    from multi_tool.modules.dns_security import check_dnssec
    from multi_tool.modules.site_features import detect_site_features
    from multi_tool.modules.http_security import analyze_http_security
    from multi_tool.modules.dns_server import analyze_dns_servers
    from multi_tool.modules.listed_pages import extract_listed_pages
    from multi_tool.modules.security_txt import check_security_txt
    from multi_tool.modules.linked_pages import analyze_linked_pages
    from multi_tool.modules.social_tags import analyze_social_tags
    from multi_tool.modules.email_config import analyze_email_config
    from multi_tool.modules.firewall_detection import detect_firewall
    
    # Utils
    from multi_tool.utils.formatter import format_output
except ImportError as e:
    logger.error(f"Failed to import multi_tool modules: {str(e)}")
    sys.exit(1)

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Print the tool header."""
    clear_screen()
    print("=" * 70)
    print(" MULTI-TOOL: Network Reconnaissance & Website Analysis Tool ")
    print("=" * 70)
    print()

def print_main_menu():
    """Print the main menu options."""
    print("\nPlease select a tool to use:")
    print("  1. IP Info - Information about an IP address")
    print("  2. SSL Chain - Analyze SSL certificate chain for a domain")
    print("  3. DNS Records - Retrieve DNS records for a domain")
    print("  4. Cookies - Analyze cookies from a website")
    print("  5. Crawl Rules - Analyze robots.txt and crawl directives")
    print("  6. Headers - Analyze HTTP headers for a URL")
    print("  7. Quality Metrics - Assess website quality and best practices")
    print("  8. Server Location - Get server location information")
    print("  9. Associated Hosts - Find hosts associated with a domain")
    print(" 10. Redirect Chain - Inspect redirect chain for a URL")
    print(" 11. TXT Records - Analyze TXT records (SPF, DMARC, etc.)")
    print(" 12. Server Status - Check server availability and performance")
    print(" 13. Open Ports - Scan for open ports on a host")
    print(" 14. Traceroute - Execute traceroute to a host")
    print(" 15. Carbon Footprint - Estimate website's environmental impact")
    print(" 16. Server Info - Get detailed server information")
    print(" 17. Whois Lookup - Retrieve domain registration information")
    print(" 18. Domain Info - Comprehensive domain analysis")
    print(" 19. DNS Security Extensions - Check DNSSEC implementation")
    print(" 20. Site Features - Detect website features and technologies")
    print(" 21. HTTP Security - Analyze HTTP security headers including HSTS")
    print(" 22. DNS Server - Analyze DNS server configuration")
    print(" 23. Tech Stack - Identify technology stack of a website")
    print(" 24. Listed Pages - Extract and analyze pages listed on a website")
    print(" 25. Security.txt - Check for security.txt file compliance")
    print(" 26. Linked Pages - Analyze linked pages from a website")
    print(" 27. Social Tags - Analyze social media tags and integration")
    print(" 28. Email Configuration - Analyze email security (SPF, DKIM, DMARC)")
    print(" 29. Firewall Detection - Detect web application firewalls")
    print(" 30. Vulnerability Scanner - Scan for known vulnerabilities using CVE database")
    print(" 31. Rate Limiting Checker - Test server rate limiting configurations")
    print(" 32. Socket Scanner - Scan for open sockets on a target server")
    print(" 33. Enhanced Header Analyzer - Detailed analysis of HTTP security headers")
    print(" 34. Domain Health Checker - Check domain health including registration and expiry")
    print(" 35. Enhanced SSL Analyzer - Comprehensive SSL/TLS configuration analysis")
    print(" 36. Screenshot Capture - Capture screenshots of websites")
    print()
    print("  0. Exit")
    print()

def print_output_format_menu():
    """Print the output format selection menu."""
    print("\nSelect output format:")
    print("  1. Text (default)")
    print("  2. Table")
    print("  3. JSON")
    print()

def get_output_format():
    """Get the selected output format from the user."""
    print_output_format_menu()
    while True:
        try:
            choice = input("Enter your choice [1-3] or press Enter for default: ").strip()
            
            if not choice:  # Default to text format
                return "text"
                
            choice = int(choice)
            if choice == 1:
                return "text"
            elif choice == 2:
                return "table"
            elif choice == 3:
                return "json"
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Please enter a number.")

def get_save_option():
    """Ask if the user wants to save output to a file."""
    while True:
        choice = input("\nDo you want to save the output to a file? (y/n): ").strip().lower()
        if choice in ('y', 'yes'):
            filename = input("Enter filename: ").strip()
            return filename
        elif choice in ('n', 'no'):
            return None
        else:
            print("Please enter 'y' or 'n'.")

def run_ip_info():
    """Run the IP information tool."""
    print_header()
    print("IP INFORMATION TOOL")
    print("-------------------")
    print("This tool provides information about an IP address including location, organization, etc.")
    print()
    
    ip = input("Enter IP address or hostname: ").strip()
    if not ip:
        print("IP address or hostname is required.")
        return
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nRetrieving IP information...\n")
    
    try:
        result = get_ip_info(ip)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_ssl_chain():
    """Run the SSL chain analysis tool."""
    print_header()
    print("SSL CHAIN ANALYSIS TOOL")
    print("----------------------")
    print("This tool analyzes the SSL certificate chain for a domain.")
    print()
    
    domain = input("Enter domain name: ").strip()
    if not domain:
        print("Domain name is required.")
        return
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nAnalyzing SSL certificate chain...\n")
    
    try:
        result = analyze_ssl_chain(domain)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_dns_records():
    """Run the DNS records tool."""
    print_header()
    print("DNS RECORDS TOOL")
    print("---------------")
    print("This tool retrieves DNS records for a domain.")
    print()
    
    domain = input("Enter domain name: ").strip()
    if not domain:
        print("Domain name is required.")
        return
    
    record_type = input("Enter record type (A, AAAA, MX, TXT, etc. or ALL for all types): ").strip().upper()
    if not record_type:
        record_type = "ALL"
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print(f"\nRetrieving {record_type} DNS records...\n")
    
    try:
        result = get_dns_records(domain, record_type)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_http_headers():
    """Run the HTTP headers analysis tool."""
    print_header()
    print("HTTP HEADERS ANALYSIS TOOL")
    print("-------------------------")
    print("This tool analyzes HTTP headers for a URL.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nAnalyzing HTTP headers...\n")
    
    try:
        result = analyze_headers(url)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_server_location():
    """Run the server location tool."""
    print_header()
    print("SERVER LOCATION TOOL")
    print("-------------------")
    print("This tool provides server location information for a domain.")
    print()
    
    domain = input("Enter domain name: ").strip()
    if not domain:
        print("Domain name is required.")
        return
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nRetrieving server location information...\n")
    
    try:
        result = get_server_location(domain)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_whois_lookup():
    """Run the WHOIS lookup tool."""
    print_header()
    print("WHOIS LOOKUP TOOL")
    print("----------------")
    print("This tool performs a WHOIS lookup for a domain.")
    print()
    
    domain = input("Enter domain name: ").strip()
    if not domain:
        print("Domain name is required.")
        return
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nPerforming WHOIS lookup...\n")
    
    try:
        result = perform_whois_lookup(domain)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_redirect_chain():
    """Run the redirect chain inspection tool."""
    print_header()
    print("REDIRECT CHAIN INSPECTION TOOL")
    print("-----------------------------")
    print("This tool inspects the redirect chain for a URL.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nInspecting redirect chain...\n")
    
    try:
        result = inspect_redirect_chain(url)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_tech_stack():
    """Run the technology stack analysis tool."""
    print_header()
    print("TECHNOLOGY STACK ANALYSIS TOOL")
    print("-----------------------------")
    print("This tool analyzes the technology stack of a website.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nAnalyzing technology stack...\n")
    
    try:
        result = analyze_tech_stack(url)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_traceroute():
    """Run the traceroute tool."""
    print_header()
    print("TRACEROUTE TOOL")
    print("--------------")
    print("This tool executes a traceroute to a host.")
    print()
    
    host = input("Enter host/domain: ").strip()
    if not host:
        print("Host/domain is required.")
        return
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nExecuting traceroute...\n")
    
    try:
        result = execute_traceroute(host)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_open_ports():
    """Run the open ports scanner tool."""
    print_header()
    print("OPEN PORTS SCANNER TOOL")
    print("----------------------")
    print("This tool scans for open ports on a host.")
    print()
    
    host = input("Enter host/domain: ").strip()
    if not host:
        print("Host/domain is required.")
        return
    
    port_range = input("Enter port range (e.g., '1-1000' or '80,443,8080'): ").strip()
    if not port_range:
        port_range = "1-1000"  # Default port range
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print(f"\nScanning ports {port_range}...\n")
    
    try:
        result = scan_open_ports(host, port_range)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

# Functions for additional tools

def run_cookies():
    """Run the cookies analysis tool."""
    print_header()
    print("COOKIES ANALYSIS TOOL")
    print("--------------------")
    print("This tool analyzes cookies from a website.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nAnalyzing cookies...\n")
    
    try:
        result = get_cookies(url)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_crawl_rules():
    """Run the crawl rules analysis tool."""
    print_header()
    print("CRAWL RULES ANALYSIS TOOL")
    print("------------------------")
    print("This tool analyzes robots.txt and crawl directives of a website.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nAnalyzing crawl rules...\n")
    
    try:
        result = analyze_crawl_rules(url)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_quality_metrics():
    """Run the quality metrics assessment tool."""
    print_header()
    print("QUALITY METRICS ASSESSMENT TOOL")
    print("------------------------------")
    print("This tool assesses the quality metrics of a website.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    detailed = input("Perform detailed analysis? (y/n): ").strip().lower()
    detailed = detailed in ('y', 'yes')
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nAssessing quality metrics...\n")
    
    try:
        result = assess_quality_metrics(url, detailed)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_associated_hosts():
    """Run the associated hosts tool."""
    print_header()
    print("ASSOCIATED HOSTS TOOL")
    print("--------------------")
    print("This tool identifies hosts associated with a domain.")
    print()
    
    domain = input("Enter domain: ").strip()
    if not domain:
        print("Domain is required.")
        return
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nIdentifying associated hosts...\n")
    
    try:
        result = identify_associated_hosts(domain)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_txt_records():
    """Run the TXT records analysis tool."""
    print_header()
    print("TXT RECORDS ANALYSIS TOOL")
    print("------------------------")
    print("This tool analyzes TXT records for a domain (SPF, DMARC, etc).")
    print()
    
    domain = input("Enter domain: ").strip()
    if not domain:
        print("Domain is required.")
        return
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nAnalyzing TXT records...\n")
    
    try:
        result = get_txt_records(domain)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_server_status():
    """Run the server status tool."""
    print_header()
    print("SERVER STATUS TOOL")
    print("-----------------")
    print("This tool checks server availability and performance.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    num_requests = input("Number of requests to make [default=3]: ").strip()
    if not num_requests:
        num_requests = 3
    else:
        try:
            num_requests = int(num_requests)
        except ValueError:
            print("Invalid number, using default: 3")
            num_requests = 3
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nChecking server status...\n")
    
    try:
        result = check_server_status(url, num_requests)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_carbon_footprint():
    """Run the carbon footprint tool."""
    print_header()
    print("CARBON FOOTPRINT TOOL")
    print("--------------------")
    print("This tool estimates the carbon footprint of a website.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nEstimating carbon footprint...\n")
    
    try:
        result = estimate_carbon_footprint(url)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_server_info():
    """Run the server info tool."""
    print_header()
    print("SERVER INFO TOOL")
    print("---------------")
    print("This tool provides detailed information about a server.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nGetting server information...\n")
    
    try:
        result = get_server_info(url)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_domain_info():
    """Run the domain info tool."""
    print_header()
    print("DOMAIN INFO TOOL")
    print("---------------")
    print("This tool provides comprehensive domain analysis.")
    print()
    
    domain = input("Enter domain: ").strip()
    if not domain:
        print("Domain is required.")
        return
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nGetting domain information...\n")
    
    try:
        result = get_domain_info(domain)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_dns_security():
    """Run the DNS security extensions tool."""
    print_header()
    print("DNS SECURITY EXTENSIONS TOOL")
    print("--------------------------")
    print("This tool checks DNSSEC implementation for a domain.")
    print()
    
    domain = input("Enter domain: ").strip()
    if not domain:
        print("Domain is required.")
        return
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nChecking DNS security extensions...\n")
    
    try:
        result = check_dnssec(domain)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_site_features():
    """Run the site features detection tool."""
    print_header()
    print("SITE FEATURES DETECTION TOOL")
    print("---------------------------")
    print("This tool detects features and technologies used on a website.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nDetecting site features...\n")
    
    try:
        result = detect_site_features(url)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_http_security():
    """Run the HTTP security tool."""
    print_header()
    print("HTTP SECURITY TOOL")
    print("-----------------")
    print("This tool analyzes HTTP security headers including HSTS.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nAnalyzing HTTP security...\n")
    
    try:
        result = analyze_http_security(url)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_dns_server():
    """Run the DNS server analysis tool."""
    print_header()
    print("DNS SERVER ANALYSIS TOOL")
    print("-----------------------")
    print("This tool analyzes DNS server configuration.")
    print()
    
    domain = input("Enter domain: ").strip()
    if not domain:
        print("Domain is required.")
        return
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nAnalyzing DNS servers...\n")
    
    try:
        result = analyze_dns_servers(domain)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_listed_pages():
    """Run the listed pages tool."""
    print_header()
    print("LISTED PAGES TOOL")
    print("----------------")
    print("This tool extracts and analyzes pages listed on a website.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    max_pages = input("Maximum number of pages to extract [default=100]: ").strip()
    if not max_pages:
        max_pages = 100
    else:
        try:
            max_pages = int(max_pages)
        except ValueError:
            print("Invalid number, using default: 100")
            max_pages = 100
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nExtracting listed pages...\n")
    
    try:
        result = extract_listed_pages(url, max_pages)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_security_txt():
    """Run the security.txt check tool."""
    print_header()
    print("SECURITY.TXT CHECK TOOL")
    print("----------------------")
    print("This tool checks for security.txt file compliance.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nChecking security.txt...\n")
    
    try:
        result = check_security_txt(url)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_linked_pages():
    """Run the linked pages analysis tool."""
    print_header()
    print("LINKED PAGES ANALYSIS TOOL")
    print("-------------------------")
    print("This tool analyzes linked pages from a website.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    max_pages = input("Maximum number of pages to crawl [default=5]: ").strip()
    if not max_pages:
        max_pages = 5
    else:
        try:
            max_pages = int(max_pages)
        except ValueError:
            print("Invalid number, using default: 5")
            max_pages = 5
    
    depth = input("Crawl depth [default=1]: ").strip()
    if not depth:
        depth = 1
    else:
        try:
            depth = int(depth)
        except ValueError:
            print("Invalid number, using default: 1")
            depth = 1
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nAnalyzing linked pages...\n")
    
    try:
        result = analyze_linked_pages(url, max_pages, depth)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_social_tags():
    """Run the social tags analysis tool."""
    print_header()
    print("SOCIAL TAGS ANALYSIS TOOL")
    print("------------------------")
    print("This tool analyzes social media tags and integration.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nAnalyzing social tags...\n")
    
    try:
        result = analyze_social_tags(url)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_email_config():
    """Run the email configuration analysis tool."""
    print_header()
    print("EMAIL CONFIGURATION ANALYSIS TOOL")
    print("--------------------------------")
    print("This tool analyzes email security (SPF, DKIM, DMARC).")
    print()
    
    domain = input("Enter domain: ").strip()
    if not domain:
        print("Domain is required.")
        return
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nAnalyzing email configuration...\n")
    
    try:
        result = analyze_email_config(domain)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_firewall_detection():
    """Run the firewall detection tool."""
    print_header()
    print("FIREWALL DETECTION TOOL")
    print("----------------------")
    print("This tool detects web application firewalls.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nDetecting firewalls...\n")
    
    try:
        result = detect_firewall(url)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_demo_analysis():
    """
    Run a demonstration of a simple analysis.
    This is used for non-interactive environments.
    """
    print_header()
    print("DEMONSTRATION OF MULTI-TOOL")
    print("---------------------------")
    print("Running a sample DNS lookup for 'example.com'...")
    print()
    
    try:
        # Run a simple DNS lookup
        result = get_dns_records("example.com", "A")
        output = format_output(result, "text")
        print(output)
        
        print("\n")
        print("Available output formats:")
        print()
        
        # Show JSON format example
        print("JSON FORMAT EXAMPLE:")
        print("-" * 20)
        output_json = format_output(result, "json")
        print(output_json[:200] + "...\n")  # Show just a snippet
        
        # Show Table format example
        print("TABLE FORMAT EXAMPLE:")
        print("-" * 20)
        output_table = format_output(result, "table")
        print("\n".join(output_table.split('\n')[:10]) + "\n...\n")  # Show just a snippet
        
        print("\nTOOLS AVAILABLE:")
        print("-" * 20)
        print("38 different network and website analysis tools are available in the interactive menu.")
        print("Run the tool in an interactive environment to access all features.")
        
    except Exception as e:
        print(f"Error during demo: {str(e)}")

def main(test_mode=False):
    """
    Main function to run the interactive CLI tool.
    
    Args:
        test_mode (bool): If True, run in a non-interactive test mode
    """
    try:
        if test_mode:
            # Run a simple demo for non-interactive environments
            print_header()
            print_main_menu()
            print("\nRunning in test mode. This would normally be an interactive menu.")
            print("Since this is a non-interactive environment, we'll demonstrate a sample analysis.")
            print()
            
            # Run a demo analysis
            run_demo_analysis()
            
            print("\nTo use the full interactive tool, run this program in an interactive terminal.")
            return 0
            
        while True:
            print_header()
            print_main_menu()
            
            try:
                choice = input("Enter your choice [0-35]: ").strip()
                
                if not choice.isdigit():
                    print("Please enter a number.")
                    input("\nPress Enter to continue...")
                    continue
                
                choice = int(choice)
                
                if choice == 0:
                    print("Exiting Multi-Tool. Goodbye!")
                    break
                elif choice == 1:
                    run_ip_info()
                elif choice == 2:
                    run_ssl_chain()
                elif choice == 3:
                    run_dns_records()
                elif choice == 4:
                    run_cookies()
                elif choice == 5:
                    run_crawl_rules()
                elif choice == 6:
                    run_http_headers()
                elif choice == 7:
                    run_quality_metrics()
                elif choice == 8:
                    run_server_location()
                elif choice == 9:
                    run_associated_hosts()
                elif choice == 10:
                    run_redirect_chain()
                elif choice == 11:
                    run_txt_records()
                elif choice == 12:
                    run_server_status()
                elif choice == 13:
                    run_open_ports()
                elif choice == 14:
                    run_traceroute()
                elif choice == 15:
                    run_carbon_footprint()
                elif choice == 16:
                    run_server_info()
                elif choice == 17:
                    run_whois_lookup()
                elif choice == 18:
                    run_domain_info()
                elif choice == 19:
                    run_dns_security()
                elif choice == 20:
                    run_site_features()
                elif choice == 21:
                    run_http_security()
                elif choice == 22:
                    run_dns_server()
                elif choice == 23:
                    run_tech_stack()
                elif choice == 24:
                    run_listed_pages()
                elif choice == 25:
                    run_security_txt()
                elif choice == 26:
                    run_linked_pages()
                elif choice == 27:
                    run_social_tags()
                elif choice == 28:
                    run_email_config()
                elif choice == 29:
                    run_firewall_detection()
                elif choice == 30:
                    run_vulnerability_scanner()
                elif choice == 31:
                    run_rate_limit_analyzer()
                elif choice == 32:
                    run_socket_analyzer()
                elif choice == 33:
                    run_enhanced_header_analyzer()
                elif choice == 34:
                    run_domain_health_checker()
                elif choice == 35:
                    run_enhanced_ssl_analyzer()
                else:
                    print("Invalid choice. Please try again.")
                
                input("\nPress Enter to return to the main menu...")
                
            except ValueError:
                print("Please enter a number.")
                input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                print("\nOperation cancelled by user.")
                input("\nPress Enter to return to the main menu...")
                
            except Exception as e:
                print(f"\nAn error occurred: {str(e)}")
                import traceback
                traceback.print_exc()
                input("\nPress Enter to return to the main menu...")
                
    except KeyboardInterrupt:
        print("\nExiting Multi-Tool. Goodbye!")
        
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        import traceback
        traceback.print_exc()
        
    return 0

def run_vulnerability_scanner():
    """Run the vulnerability scanner tool."""
    print_header()
    print("VULNERABILITY SCANNER TOOL")
    print("--------------------------")
    print("This tool scans for known vulnerabilities using CVE database.")
    print()
    
    target = input("Enter target URL or domain: ").strip()
    if not target:
        print("Target URL or domain is required.")
        return
    
    # Add http:// if not provided and doesn't look like a bare domain
    if not target.startswith(('http://', 'https://')) and '.' in target and not target.endswith('.'):
        target = 'https://' + target
    
    depth_options = {'1': 'light', '2': 'standard', '3': 'deep'}
    print("\nScan depth options:")
    print("  1. Light - Basic vulnerability checks (faster)")
    print("  2. Standard - Comprehensive checks (recommended)")
    print("  3. Deep - Exhaustive vulnerability analysis (slower)")
    
    while True:
        depth_choice = input("\nSelect scan depth [1-3] or press Enter for Standard: ").strip()
        if not depth_choice:
            depth = 'standard'
            break
        elif depth_choice in depth_options:
            depth = depth_options[depth_choice]
            break
        else:
            print("Invalid choice. Please try again.")
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print(f"\nScanning for vulnerabilities (depth: {depth})...\n")
    
    try:
        result = scan_for_vulnerabilities(target, depth)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_rate_limit_analyzer():
    """Run the rate limiting checker tool."""
    print_header()
    print("RATE LIMITING CHECKER TOOL")
    print("--------------------------")
    print("This tool tests server rate limiting configurations.")
    print("WARNING: This tool may trigger security systems. Use responsibly.")
    print()
    
    target = input("Enter target URL: ").strip()
    if not target:
        print("Target URL is required.")
        return
    
    # Add http:// if not provided
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    endpoint = input("Enter specific endpoint to test (or press Enter for root path): ").strip()
    
    intensity_options = {'1': 'low', '2': 'medium', '3': 'high'}
    print("\nTest intensity options:")
    print("  1. Low - Minimal requests (less detectable)")
    print("  2. Medium - Moderate request volume (recommended)")
    print("  3. High - High volume of requests (may trigger blocks)")
    
    while True:
        intensity_choice = input("\nSelect test intensity [1-3] or press Enter for Medium: ").strip()
        if not intensity_choice:
            intensity = 'medium'
            break
        elif intensity_choice in intensity_options:
            intensity = intensity_options[intensity_choice]
            break
        else:
            print("Invalid choice. Please try again.")
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print(f"\nTesting rate limits (intensity: {intensity})...\n")
    
    try:
        result = analyze_rate_limits(target, intensity, endpoint)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_socket_analyzer():
    """Run the socket scanner tool."""
    print_header()
    print("SOCKET SCANNER TOOL")
    print("------------------")
    print("This tool scans for open sockets on a target server.")
    print()
    
    target = input("Enter target URL, domain, or IP: ").strip()
    if not target:
        print("Target URL, domain, or IP is required.")
        return
    
    # Remove protocol if present
    if target.startswith(('http://', 'https://')):
        target = target.split('://', 1)[1].split('/', 1)[0]
    
    ports = input("Enter port range (e.g., '1-1000' or '22,80,443'): ").strip()
    if not ports:
        ports = '1-1000'  # Default port range
    
    speed_options = {'1': 'slow', '2': 'normal', '3': 'fast'}
    print("\nScan speed options:")
    print("  1. Slow - Less detectable, more accurate")
    print("  2. Normal - Balanced speed and accuracy (recommended)")
    print("  3. Fast - Quick scan, potentially less accurate")
    
    while True:
        speed_choice = input("\nSelect scan speed [1-3] or press Enter for Normal: ").strip()
        if not speed_choice:
            speed = 'normal'
            break
        elif speed_choice in speed_options:
            speed = speed_options[speed_choice]
            break
        else:
            print("Invalid choice. Please try again.")
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print(f"\nScanning ports {ports} (speed: {speed})...\n")
    
    try:
        result = scan_sockets(target, ports, speed)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_enhanced_header_analyzer():
    """Run the enhanced header analyzer tool."""
    print_header()
    print("ENHANCED HEADER ANALYZER TOOL")
    print("----------------------------")
    print("This tool performs detailed analysis of HTTP security headers.")
    print()
    
    url = input("Enter URL: ").strip()
    if not url:
        print("URL is required.")
        return
    
    # Add http:// if not provided
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nAnalyzing security headers...\n")
    
    try:
        result = analyze_enhanced_headers(url)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_domain_health_checker():
    """Run the domain health checker tool."""
    print_header()
    print("DOMAIN HEALTH CHECKER TOOL")
    print("-------------------------")
    print("This tool checks domain health including registration and expiry details.")
    print()
    
    domain = input("Enter domain name: ").strip()
    if not domain:
        print("Domain name is required.")
        return
    
    # Remove protocol and path if present
    if domain.startswith(('http://', 'https://')):
        domain = domain.split('://', 1)[1].split('/', 1)[0]
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nChecking domain health...\n")
    
    try:
        result = check_domain_health(domain)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

def run_enhanced_ssl_analyzer():
    """Run the enhanced SSL configuration analyzer tool."""
    print_header()
    print("ENHANCED SSL ANALYZER TOOL")
    print("-------------------------")
    print("This tool performs comprehensive SSL/TLS configuration analysis.")
    print()
    
    target = input("Enter domain or URL: ").strip()
    if not target:
        print("Domain or URL is required.")
        return
    
    # Remove protocol if present
    if target.startswith(('http://', 'https://')):
        target = target.split('://', 1)[1].split('/', 1)[0]
    
    port = input("Enter port (or press Enter for default 443): ").strip()
    if port and port.isdigit():
        port = int(port)
    else:
        port = None
    
    check_vulns = input("Check for known vulnerabilities? (y/n, default: y): ").strip().lower()
    check_vulnerabilities = False if check_vulns in ('n', 'no') else True
    
    format_type = get_output_format()
    output_file = get_save_option()
    
    print("\nAnalyzing SSL/TLS configuration...\n")
    
    try:
        result = analyze_ssl_configuration(target, check_vulnerabilities, port)
        output = format_output(result, format_type)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to '{output_file}'")
        
        print(output)
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    import argparse
    
    # Parse arguments for test mode
    parser = argparse.ArgumentParser(description="Multi-Tool Interactive Interface")
    parser.add_argument('--test', action='store_true', help='Run in test mode (for non-interactive environments)')
    args = parser.parse_args()
    
    # Run in test mode if the flag is provided
    main(test_mode=args.test)