#!/usr/bin/env python3
"""
Multi-Tool: A command-line wrapper for the multi-tool package with web interface
"""

import argparse
import logging
import sys
import os
import json
import datetime
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify, redirect, url_for

# Create Flask app for gunicorn to use
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "multi-tool-secret-key")

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import the tool modules
try:
    # Original core modules
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

    MODULES_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Failed to import all modules: {str(e)}")
    MODULES_AVAILABLE = False

# Tool information and mapping
TOOL_INFO = {
    'ipinfo': {'name': 'IP Information', 'function': get_ip_info if MODULES_AVAILABLE else None, 'requires_ip': True},
    'sslchain': {'name': 'SSL Chain Analysis', 'function': analyze_ssl_chain if MODULES_AVAILABLE else None, 'requires_domain': True},
    'dnsrecords': {'name': 'DNS Records', 'function': get_dns_records if MODULES_AVAILABLE else None, 'requires_domain': True},
    'headers': {'name': 'HTTP Headers', 'function': analyze_headers if MODULES_AVAILABLE else None, 'requires_url': True},
    'cookies': {'name': 'Cookies Analysis', 'function': get_cookies if MODULES_AVAILABLE else None, 'requires_url': True},
    'crawlrules': {'name': 'Crawl Rules Analysis', 'function': analyze_crawl_rules if MODULES_AVAILABLE else None, 'requires_url': True},
    'qualitymetrics': {'name': 'Quality Metrics', 'function': assess_quality_metrics if MODULES_AVAILABLE else None, 'requires_url': True},
    'serverlocation': {'name': 'Server Location', 'function': get_server_location if MODULES_AVAILABLE else None, 'requires_domain': True},
    'associatedhosts': {'name': 'Associated Hosts', 'function': identify_associated_hosts if MODULES_AVAILABLE else None, 'requires_domain': True},
    'redirectchain': {'name': 'Redirect Chain', 'function': inspect_redirect_chain if MODULES_AVAILABLE else None, 'requires_url': True},
    'txtrecords': {'name': 'TXT Records', 'function': get_txt_records if MODULES_AVAILABLE else None, 'requires_domain': True},
    'serverstatus': {'name': 'Server Status', 'function': check_server_status if MODULES_AVAILABLE else None, 'requires_url': True},
    'openports': {'name': 'Open Ports', 'function': scan_open_ports if MODULES_AVAILABLE else None, 'requires_host': True},
    'traceroute': {'name': 'Traceroute', 'function': execute_traceroute if MODULES_AVAILABLE else None, 'requires_host': True},
    'carbonfootprint': {'name': 'Carbon Footprint', 'function': estimate_carbon_footprint if MODULES_AVAILABLE else None, 'requires_url': True},
    'serverinfo': {'name': 'Server Information', 'function': get_server_info if MODULES_AVAILABLE else None, 'requires_url': True},
    'whois': {'name': 'WHOIS Lookup', 'function': perform_whois_lookup if MODULES_AVAILABLE else None, 'requires_domain': True},
    'domaininfo': {'name': 'Domain Information', 'function': get_domain_info if MODULES_AVAILABLE else None, 'requires_domain': True},
    'dnssecurity': {'name': 'DNS Security', 'function': check_dnssec if MODULES_AVAILABLE else None, 'requires_domain': True},
    'sitefeatures': {'name': 'Site Features', 'function': detect_site_features if MODULES_AVAILABLE else None, 'requires_url': True},
    'httpsecurity': {'name': 'HTTP Security', 'function': analyze_http_security if MODULES_AVAILABLE else None, 'requires_url': True},
    'dnsserver': {'name': 'DNS Server Analysis', 'function': analyze_dns_servers if MODULES_AVAILABLE else None, 'requires_domain': True},
    'techstack': {'name': 'Tech Stack', 'function': analyze_tech_stack if MODULES_AVAILABLE else None, 'requires_url': True},
    'listedpages': {'name': 'Listed Pages', 'function': extract_listed_pages if MODULES_AVAILABLE else None, 'requires_url': True},
    'securitytxt': {'name': 'Security.txt', 'function': check_security_txt if MODULES_AVAILABLE else None, 'requires_url': True},
    'linkedpages': {'name': 'Linked Pages', 'function': analyze_linked_pages if MODULES_AVAILABLE else None, 'requires_url': True},
    'socialtags': {'name': 'Social Tags', 'function': analyze_social_tags if MODULES_AVAILABLE else None, 'requires_url': True},
    'emailconfig': {'name': 'Email Configuration', 'function': analyze_email_config if MODULES_AVAILABLE else None, 'requires_domain': True},
    'firewall': {'name': 'Firewall Detection', 'function': detect_firewall if MODULES_AVAILABLE else None, 'requires_url': True},
}

def normalize_target(target, tool_id):
    """Normalize the target based on the tool requirements."""
    if not target:
        return target, "No target specified"

    tool_info = TOOL_INFO.get(tool_id)
    if not tool_info:
        return target, "Invalid tool specified"

    target = target.strip()

    # Check if we need a URL
    if tool_info.get('requires_url'):
        if not target.startswith('http://') and not target.startswith('https://'):
            target = 'https://' + target

    # Check if we need a domain
    elif tool_info.get('requires_domain'):
        # Remove protocol if present
        if target.startswith('http://') or target.startswith('https://'):
            parsed = urlparse(target)
            target = parsed.netloc

        # Remove path, query, etc. if present
        if '/' in target:
            target = target.split('/', 1)[0]

    return target, None

def format_results_for_web(results, tool_id):
    """Format results for web display."""
    web_results = ""
    table_results = ""
    text_results = ""

    try:
        # JSON format is straightforward
        json_results = json.dumps(results, indent=2)

        # Get table and text formats using the formatter
        if MODULES_AVAILABLE:
            table_results = format_output(results, 'table')
            text_results = format_output(results, 'text')
        else:
            table_results = "Module formatter not available"
            text_results = "Module formatter not available"

        # Create a simple web display based on the tool type
        if isinstance(results, dict):
            web_results = "<div class='result-container'>"
            for key, value in results.items():
                web_results += f"<div class='result-item mb-3'>"
                web_results += f"<h5>{key}</h5>"

                if isinstance(value, dict):
                    web_results += "<div class='card'><div class='card-body'>"
                    for sub_key, sub_value in value.items():
                        web_results += f"<div class='mb-2'><strong>{sub_key}:</strong> "
                        if isinstance(sub_value, list):
                            web_results += "<ul class='mb-0'>"
                            for item in sub_value:
                                web_results += f"<li>{item}</li>"
                            web_results += "</ul>"
                        else:
                            web_results += f"{sub_value}"
                        web_results += "</div>"
                    web_results += "</div></div>"
                elif isinstance(value, list):
                    web_results += "<ul class='list-group'>"
                    for item in value:
                        web_results += f"<li class='list-group-item'>{item}</li>"
                    web_results += "</ul>"
                else:
                    web_results += f"<p>{value}</p>"

                web_results += "</div>"
            web_results += "</div>"
        else:
            web_results = f"<pre>{str(results)}</pre>"

    except Exception as e:
        logger.error(f"Error formatting results: {str(e)}")
        web_results = f"<div class='alert alert-danger'>Error formatting results: {str(e)}</div>"
        json_results = json.dumps({"error": str(e)})
        table_results = f"Error: {str(e)}"
        text_results = f"Error: {str(e)}"

    return web_results, json_results, table_results, text_results


# Flask routes
@app.route('/')
def index():
    """Home page route."""
    return render_template('index.html')

@app.route('/about')
def about():
    """About page route."""
    return render_template('about.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Handle analysis form submission."""
    tool_id = request.form.get('tool')
    target = request.form.get('target')

    if not tool_id or not target:
        return render_template('index.html', error="Please provide both a tool and a target.")

    # Check if tool exists
    if tool_id not in TOOL_INFO:
        return render_template('index.html', error=f"Unknown tool: {tool_id}")

    # Normalize target based on tool needs
    normalized_target, error = normalize_target(target, tool_id)
    if error:
        return render_template('index.html', error=error)

    # Get the tool info and function
    tool_info = TOOL_INFO[tool_id]
    tool_function = tool_info['function']

    if not tool_function:
        return render_template('index.html', error="Tool modules not available.")

    try:
        # Execute the tool
        if tool_id == 'ipinfo':
            results = tool_function(normalized_target)
        elif tool_id == 'dnsrecords':
            results = tool_function(normalized_target, 'ALL')
        elif tool_id == 'openports':
            results = tool_function(normalized_target, '1-1000')
        elif tool_id == 'qualitymetrics':
            results = tool_function(normalized_target, False)
        elif tool_id == 'serverstatus':
            results = tool_function(normalized_target, 3)
        elif tool_id == 'listedpages':
            results = tool_function(normalized_target, 100)
        elif tool_id == 'linkedpages':
            results = tool_function(normalized_target, 5, 1)
        else:
            results = tool_function(normalized_target)

        # Format the results for different output types
        web_results, json_results, table_results, text_results = format_results_for_web(results, tool_id)

        # Get timestamp
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        return render_template(
            'results.html',
            tool_id=tool_id,
            tool_name=tool_info['name'],
            target=target,
            normalized_target=normalized_target,
            timestamp=timestamp,
            web_results=web_results,
            json_results=json_results,
            table_results=table_results,
            text_results=text_results
        )

    except Exception as e:
        logger.error(f"Error executing tool {tool_id}: {str(e)}")
        return render_template('index.html', error=f"Error executing {tool_info['name']}: {str(e)}")

@app.route('/api/<tool_id>', methods=['GET'])
def api_tool(tool_id):
    """API endpoint for tools."""
    target = request.args.get('target')
    output_format = request.args.get('format', 'json')

    if not target:
        return jsonify({"error": "No target specified"}), 400

    if tool_id not in TOOL_INFO:
        return jsonify({"error": f"Unknown tool: {tool_id}"}), 404

    # Normalize target based on tool needs
    normalized_target, error = normalize_target(target, tool_id)
    if error:
        return jsonify({"error": error}), 400

    # Get the tool info and function
    tool_info = TOOL_INFO[tool_id]
    tool_function = tool_info['function']

    if not tool_function:
        return jsonify({"error": "Tool modules not available."}), 500

    try:
        # Execute the tool
        if tool_id == 'ipinfo':
            results = tool_function(normalized_target)
        elif tool_id == 'dnsrecords':
            record_type = request.args.get('type', 'ALL')
            results = tool_function(normalized_target, record_type)
        elif tool_id == 'openports':
            ports = request.args.get('ports', '1-1000')
            results = tool_function(normalized_target, ports)
        elif tool_id == 'qualitymetrics':
            detailed = request.args.get('detailed', 'false').lower() == 'true'
            results = tool_function(normalized_target, detailed)
        elif tool_id == 'serverstatus':
            requests_count = int(request.args.get('requests', '3'))
            results = tool_function(normalized_target, requests_count)
        elif tool_id == 'listedpages':
            max_pages = int(request.args.get('max', '100'))
            results = tool_function(normalized_target, max_pages)
        elif tool_id == 'linkedpages':
            max_pages = int(request.args.get('max', '5'))
            depth = int(request.args.get('depth', '1'))
            results = tool_function(normalized_target, max_pages, depth)
        else:
            results = tool_function(normalized_target)

        # Return the appropriate format
        if output_format == 'json':
            return jsonify(results)
        elif output_format == 'text':
            if MODULES_AVAILABLE:
                text_output = format_output(results, 'text')
                return text_output, 200, {'Content-Type': 'text/plain'}
            else:
                return str(results), 200, {'Content-Type': 'text/plain'}
        elif output_format == 'table':
            if MODULES_AVAILABLE:
                table_output = format_output(results, 'table')
                return table_output, 200, {'Content-Type': 'text/plain'}
            else:
                return str(results), 200, {'Content-Type': 'text/plain'}
        else:
            return jsonify({"error": f"Unsupported format: {output_format}"}), 400

    except Exception as e:
        logger.error(f"API error executing tool {tool_id}: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Domain tool routes
@app.route('/domain/<tool>')
def domain_tool(tool):
    """Domain tools routes."""
    domain_tools = {
        'dns': {'id': 'dnsrecords', 'name': 'DNS Records'},
        'whois': {'id': 'whois', 'name': 'WHOIS Lookup'},
        'ssl': {'id': 'sslchain', 'name': 'SSL Chain Analysis'},
        'dnssec': {'id': 'dnssecurity', 'name': 'DNS Security Extensions'},
        'dnsserver': {'id': 'dnsserver', 'name': 'DNS Server Analysis'},
        'txtrecords': {'id': 'txtrecords', 'name': 'TXT Records Analysis'},
        'info': {'id': 'domaininfo', 'name': 'Domain Information'}
    }

    if tool not in domain_tools:
        return redirect(url_for('index'))

    tool_info = domain_tools[tool]
    return render_template('tool_form.html',
                          tool_id=tool_info['id'],
                          tool_name=tool_info['name'],
                          target_type='domain',
                          example='example.com')

# Web tool routes
@app.route('/web/<tool>')
def web_tool(tool):
    """Web tools routes."""
    web_tools = {
        'headers': {'id': 'headers', 'name': 'HTTP Headers Analysis'},
        'cookies': {'id': 'cookies', 'name': 'Cookies Analysis'},
        'crawlrules': {'id': 'crawlrules', 'name': 'Crawl Rules Analysis'},
        'techstack': {'id': 'techstack', 'name': 'Technology Stack Analysis'},
        'redirectchain': {'id': 'redirectchain', 'name': 'Redirect Chain Analysis'},
        'httpsecurity': {'id': 'httpsecurity', 'name': 'HTTP Security Analysis'},
        'securitytxt': {'id': 'securitytxt', 'name': 'Security.txt Check'},
        'firewall': {'id': 'firewall', 'name': 'Firewall Detection'}
    }

    if tool not in web_tools:
        return redirect(url_for('index'))

    tool_info = web_tools[tool]
    return render_template('tool_form.html',
                          tool_id=tool_info['id'],
                          tool_name=tool_info['name'],
                          target_type='url',
                          example='https://example.com')

# Server tool routes
@app.route('/server/<tool>')
def server_tool(tool):
    """Server tools routes."""
    server_tools = {
        'ip': {'id': 'ipinfo', 'name': 'IP Information'},
        'location': {'id': 'serverlocation', 'name': 'Server Location'},
        'status': {'id': 'serverstatus', 'name': 'Server Status'},
        'info': {'id': 'serverinfo', 'name': 'Server Information'},
        'openports': {'id': 'openports', 'name': 'Open Ports Scanning'},
        'traceroute': {'id': 'traceroute', 'name': 'Traceroute'}
    }

    if tool not in server_tools:
        return redirect(url_for('index'))

    tool_info = server_tools[tool]

    target_type = 'host'
    if tool_info['id'] == 'ipinfo':
        target_type = 'ip'
        example = '8.8.8.8'
    elif tool_info['id'] in ['serverlocation', 'serverinfo', 'serverstatus']:
        target_type = 'domain'
        example = 'example.com'
    else:
        example = 'example.com'

    return render_template('tool_form.html',
                          tool_id=tool_info['id'],
                          tool_name=tool_info['name'],
                          target_type=target_type,
                          example=example)

# Site analysis routes
@app.route('/site/<tool>')
def site_tool(tool):
    """Site analysis tools routes."""
    site_tools = {
        'features': {'id': 'sitefeatures', 'name': 'Site Features Detection'},
        'qualitymetrics': {'id': 'qualitymetrics', 'name': 'Quality Metrics Assessment'},
        'carbonfootprint': {'id': 'carbonfootprint', 'name': 'Carbon Footprint Estimation'},
        'socialtags': {'id': 'socialtags', 'name': 'Social Tags Analysis'},
        'listedpages': {'id': 'listedpages', 'name': 'Listed Pages Analysis'},
        'linkedpages': {'id': 'linkedpages', 'name': 'Linked Pages Analysis'}
    }

    if tool not in site_tools:
        return redirect(url_for('index'))

    tool_info = site_tools[tool]
    return render_template('tool_form.html',
                          tool_id=tool_info['id'],
                          tool_name=tool_info['name'],
                          target_type='url',
                          example='https://example.com')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)