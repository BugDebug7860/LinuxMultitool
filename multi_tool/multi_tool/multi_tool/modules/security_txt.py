"""Module for checking security.txt file compliance."""

import logging
import requests
import validators
from urllib.parse import urljoin
import re
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_security_txt(url):
    """
    Check for a valid security.txt file and analyze its content.
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: Security.txt information
    """
    logger.debug(f"Checking security.txt for URL: {url}")
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    if not validators.url(url):
        raise ValueError(f"Invalid URL: {url}")
    
    try:
        # Check both locations according to the RFC 9116
        well_known_location = urljoin(url, '/.well-known/security.txt')
        root_location = urljoin(url, '/security.txt')
        
        # Try the well-known location first (preferred)
        well_known_result = _fetch_security_txt(well_known_location)
        
        # If not found, try the root location
        if not well_known_result['found']:
            root_result = _fetch_security_txt(root_location)
            if root_result['found']:
                security_txt_content = root_result['content']
                location = root_location
                status_code = root_result['status_code']
            else:
                security_txt_content = None
                location = None
                status_code = None
        else:
            security_txt_content = well_known_result['content']
            location = well_known_location
            status_code = well_known_result['status_code']
        
        # If security.txt found, analyze it
        if security_txt_content:
            analysis = _analyze_security_txt(security_txt_content)
            compliance = _check_compliance(analysis)
        else:
            analysis = None
            compliance = {
                'compliant': False,
                'reason': 'No security.txt file found'
            }
        
        result = {
            'url': url,
            'found': security_txt_content is not None,
            'location': location,
            'status_code': status_code,
            'content': security_txt_content,
            'analysis': analysis,
            'compliance': compliance
        }
        
        logger.debug(f"Security.txt check result: {result}")
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching security.txt: {e}")
        raise

def _fetch_security_txt(url):
    """Fetch the security.txt file from a URL."""
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return {
                'found': True,
                'content': response.text,
                'status_code': response.status_code
            }
        return {
            'found': False,
            'content': None,
            'status_code': response.status_code
        }
    except requests.exceptions.RequestException:
        return {
            'found': False,
            'content': None,
            'status_code': None
        }

def _analyze_security_txt(content):
    """Analyze the content of a security.txt file."""
    # Extract fields according to RFC 9116
    fields = {
        'contact': [],
        'expires': None,
        'encryption': [],
        'acknowledgments': [],
        'canonical': [],
        'policy': [],
        'hiring': [],
        'lang': [],
        'other': {}
    }
    
    lines = content.split('\n')
    current_field = None
    for line in lines:
        line = line.strip()
        
        # Skip comments and empty lines
        if not line or line.startswith('#'):
            continue
        
        # Check if this is a field definition or continuation
        if ':' in line:
            # New field
            field_name, field_value = line.split(':', 1)
            field_name = field_name.strip().lower()
            field_value = field_value.strip()
            
            if field_name in fields:
                if isinstance(fields[field_name], list):
                    fields[field_name].append(field_value)
                else:
                    fields[field_name] = field_value
            else:
                fields['other'][field_name] = field_value
                
            current_field = field_name
        elif current_field and current_field in fields:
            # Continuation of previous field
            if isinstance(fields[current_field], list):
                if fields[current_field]:
                    fields[current_field][-1] += ' ' + line
            else:
                fields[current_field] += ' ' + line
    
    # Process expires date if present
    if fields['expires']:
        try:
            expires_datetime = datetime.strptime(fields['expires'], '%Y-%m-%dT%H:%M:%S%z')
            expires_timestamp = expires_datetime.timestamp()
            now_timestamp = datetime.now().timestamp()
            fields['expires_valid'] = expires_timestamp > now_timestamp
            fields['expires_datetime'] = expires_datetime.isoformat()
        except ValueError:
            fields['expires_valid'] = False
    
    return fields

def _check_compliance(analysis):
    """Check if the security.txt file complies with RFC 9116."""
    issues = []
    is_compliant = True
    
    # Check required fields
    if not analysis['contact']:
        issues.append({
            'severity': 'high',
            'issue': 'Missing required Contact field'
        })
        is_compliant = False
    
    if not analysis['expires']:
        issues.append({
            'severity': 'high',
            'issue': 'Missing required Expires field'
        })
        is_compliant = False
    elif not analysis.get('expires_valid', False):
        issues.append({
            'severity': 'high',
            'issue': 'Expires field is invalid or expired'
        })
        is_compliant = False
    
    # Check recommended fields
    if not analysis['encryption']:
        issues.append({
            'severity': 'medium',
            'issue': 'Missing recommended Encryption field'
        })
    
    if not analysis['acknowledgments']:
        issues.append({
            'severity': 'low',
            'issue': 'Missing recommended Acknowledgments field'
        })
    
    # Check contact URLs
    for contact in analysis['contact']:
        if not contact.startswith(('https://', 'http://', 'mailto:', 'tel:')):
            issues.append({
                'severity': 'medium',
                'issue': f'Contact value "{contact}" does not use a URI scheme'
            })
    
    # Check encryption URLs
    for encryption in analysis['encryption']:
        if not encryption.startswith(('https://', 'http://')):
            issues.append({
                'severity': 'medium',
                'issue': f'Encryption value "{encryption}" does not use a URI scheme'
            })
    
    # Return compliance status and issues
    return {
        'compliant': is_compliant,
        'issues': issues,
        'required_fields_present': bool(analysis['contact'] and analysis['expires'] and analysis.get('expires_valid', False))
    }