#!/usr/bin/env python3
"""
Insecure Network/HTTP Security Detection Module for UIPath Security Audit Tool
Detects insecure network configurations and HTTP usage in UIPath .xaml files

This module identifies patterns where sensitive data might be transmitted over
insecure connections or where security controls are bypassed.
"""

import re
import sys
import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse

# Add libraries path to sys.path to import config_helper
sys.path.insert(0, str(Path(__file__).parent.parent / 'libraries'))

try:
    from config_helper import resolve_in_config_value
    from highlight_helper import highlight_match
except ImportError as e:
    print(f"Error importing libraries: {e}")
    sys.exit(1)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Module description for the main audit tool
MODULE_DESCRIPTION = "Detects insecure network configurations including HTTP usage for sensitive data, certificate validation bypasses, and weak TLS settings."

# Network security patterns with severity levels
NETWORK_SECURITY_PATTERNS = {
    # HTTP URL patterns (context-dependent)
    'http_url': {
        'pattern': r'http://[^\s\'"<>]+',
        'severity': 'VARIABLE',  # Will be determined by context
        'description': 'HTTP URL detected - Potential insecure data transmission'
    },
    
    # SSL/TLS security bypasses
    'ssl_ignore': {
        'pattern': r'(?i)(IgnoreSSL|IgnoreCert|VerifySSL\s*=\s*[Ff]alse|VerifyCert\s*=\s*[Ff]alse)',
        'severity': 'HIGH',
        'description': 'SSL certificate validation bypass detected - Man-in-the-middle vulnerability'
    },
    'tls_ignore': {
        'pattern': r'(?i)(IgnoreTLS|TLSVerify\s*=\s*[Ff]alse|CheckTLS\s*=\s*[Ff]alse)',
        'severity': 'HIGH',
        'description': 'TLS verification bypass detected - Insecure connection'
    },
    'cert_validation_bypass': {
        'pattern': r'(?i)(ServerCertificateValidation\s*=\s*[Ff]alse|ValidateCertificate\s*=\s*[Ff]alse)',
        'severity': 'HIGH',
        'description': 'Certificate validation disabled - Security vulnerability'
    },
    'trust_all_certs': {
        'pattern': r'(?i)(TrustAllCertificates|AcceptAllCertificates|IgnoreInvalidCertificate)',
        'severity': 'HIGH',
        'description': 'All certificates trusted - Critical security vulnerability'
    },
    
    # Weak TLS/SSL versions
    'weak_tls_version': {
        'pattern': r'(?i)(TLS\s*1\.0|TLS\s*1\.1|SSL\s*2\.0|SSL\s*3\.0|SSLv2|SSLv3)',
        'severity': 'HIGH',
        'description': 'Weak TLS/SSL version detected - Use TLS 1.2 or higher'
    },
    'tls_version_setting': {
        'pattern': r'(?i)(SecurityProtocol\s*=.*Tls|SslProtocols\s*=.*Tls)',
        'severity': 'MEDIUM',
        'description': 'TLS version configuration detected - Verify strong version is used'
    },
    
    # Insecure authentication over HTTP
    'http_auth': {
        'pattern': r'http://[^\s\'"<>]*(?:login|auth|signin|logon|password|credential)',
        'severity': 'HIGH',
        'description': 'Authentication endpoint over HTTP - Credentials at risk'
    },
    'http_api_key': {
        'pattern': r'http://[^\s\'"<>]*(?:api[_-]?key|token|secret|auth)',
        'severity': 'HIGH',
        'description': 'API authentication over HTTP - API keys/tokens at risk'
    },
    
    # Payment and sensitive data over HTTP
    'http_payment': {
        'pattern': r'http://[^\s\'"<>]*(?:payment|pay|billing|credit|card|bank)',
        'severity': 'HIGH',
        'description': 'Payment endpoint over HTTP - Financial data at risk'
    },
    'http_personal_data': {
        'pattern': r'http://[^\s\'"<>]*(?:personal|profile|user|customer|patient|medical)',
        'severity': 'MEDIUM',
        'description': 'Personal data endpoint over HTTP - Privacy risk'
    },
    
    # Insecure protocols
    'ftp_protocol': {
        'pattern': r'ftp://[^\s\'"<>]+',
        'severity': 'MEDIUM',
        'description': 'FTP protocol detected - Use SFTP or FTPS for secure transfer'
    },
    'telnet_protocol': {
        'pattern': r'telnet://[^\s\'"<>]+',
        'severity': 'HIGH',
        'description': 'Telnet protocol detected - Use SSH for secure remote access'
    },
    'ldap_protocol': {
        'pattern': r'ldap://[^\s\'"<>]+',
        'severity': 'MEDIUM',
        'description': 'LDAP protocol detected - Use LDAPS for secure directory access'
    },
    
    # Network security configurations
    'allow_untrusted_root': {
        'pattern': r'(?i)(AllowUntrustedRoot|AcceptUntrustedCertificates)',
        'severity': 'HIGH',
        'description': 'Untrusted root certificates allowed - Security risk'
    },
    'disable_hostname_verification': {
        'pattern': r'(?i)(HostnameVerifier\s*=\s*null|DisableHostnameVerification)',
        'severity': 'HIGH',
        'description': 'Hostname verification disabled - Man-in-the-middle vulnerability'
    }
}

# Legitimate HTTP usage patterns that should NOT trigger alerts
LEGITIMATE_HTTP_PATTERNS = [
    # Local development
    r'http://localhost[:/]',
    r'http://127\.0\.0\.1[:/]',
    r'http://0\.0\.0\.0[:/]',
    r'http://\[::1\][:/]',  # IPv6 localhost
    
    # Internal networks (RFC 1918)
    r'http://10\.\d+\.\d+\.\d+[:/]',
    r'http://172\.(1[6-9]|2\d|3[01])\.\d+\.\d+[:/]',
    r'http://192\.168\.\d+\.\d+[:/]',
    
    # Link-local addresses
    r'http://169\.254\.\d+\.\d+[:/]',
    
    # Internal domain patterns
    r'http://[^./]+\.local[:/]',
    r'http://[^./]+\.internal[:/]',
    r'http://[^./]+\.corp[:/]',
    r'http://[^./]+\.company[:/]',
    r'http://intranet[^./]*[:/]',
    
    # Common non-sensitive services
    r'http://[^./]*weather[^./]*\.',
    r'http://[^./]*news[^./]*\.',
    r'http://[^./]*rss[^./]*\.',
    r'http://[^./]*feed[^./]*\.',
    r'http://[^./]*public[^./]*\.',
    
    # Health check and monitoring endpoints
    r'http://[^./]*/health[^/]*$',
    r'http://[^./]*/status[^/]*$',
    r'http://[^./]*/ping[^/]*$',
    r'http://[^./]*/version[^/]*$',
    r'http://[^./]*/info[^/]*$',
    
    # Development and testing
    r'http://[^./]*test[^./]*\.',
    r'http://[^./]*dev[^./]*\.',
    r'http://[^./]*staging[^./]*\.',
    r'http://[^./]*demo[^./]*\.',
    r'http://[^./]*sandbox[^./]*\.',
    
    # Common non-sensitive APIs
    r'http://api\.openweathermap\.org',
    r'http://[^./]*\.github\.io',
    r'http://httpbin\.org',
    r'http://jsonplaceholder\.typicode\.com',
    r'http://reqres\.in',
    
    # Schema and reference sites (commonly HTTP)
    r'http://schemas?\.microsoft\.com',
    r'http://schemas?\.xmlsoap\.org',
    r'http://www\.w3\.org',
    r'http://schemas?\.google\.com',
    r'http://tempuri\.org',
    r'http://xmlns\.oracle\.com',
    r'http://schemas?\.oasis-open\.org',
    r'http://www\.omg\.org',
    
    # Legacy/example domains (exact matches only)
    r'http://example\.com(/.*)?$',
    r'http://example\.org(/.*)?$',
    r'http://test\.com(/.*)?$',
    r'http://sample\.com(/.*)?$',
    
    # Documentation and learning resources
    r'http://[^./]*documentation[^./]*\.',
    r'http://[^./]*tutorial[^./]*\.',
    r'http://[^./]*guide[^./]*\.',
    
    # Common redirect patterns (often legitimately HTTP)
    r'http://[^./]*/callback[^/]*$',
    r'http://[^./]*/redirect[^/]*$',
    r'http://[^./]*/return[^/]*$',
]

# Network attributes that commonly contain URLs or network configurations
NETWORK_ATTRIBUTES = [
    'Url', 'Uri', 'Address', 'Endpoint', 'BaseUrl', 'ServiceUrl', 'ApiUrl',
    'ServerUrl', 'HostUrl', 'RequestUrl', 'ResponseUrl', 'CallbackUrl',
    'RedirectUrl', 'WebServiceUrl', 'SoapUrl', 'RestUrl', 'HttpUrl',
    'ConnectionString', 'Server', 'Host', 'Domain', 'Value', 'Text',
    'Location', 'Path', 'Source', 'Target', 'Destination',
    'IgnoreSSL', 'IgnoreCert', 'VerifySSL', 'VerifyCert', 'SecurityProtocol',
    'TrustAllCertificates', 'AcceptAllCertificates', 'IgnoreInvalidCertificate'
]

def is_legitimate_http_usage(url: str) -> bool:
    """
    Check if HTTP URL usage is legitimate and should not trigger an alert.
    
    Args:
        url: The URL to check
        
    Returns:
        bool: True if the HTTP usage appears legitimate
    """
    url_lower = url.lower().strip()
    
    # Check against legitimate patterns
    for pattern in LEGITIMATE_HTTP_PATTERNS:
        if re.search(pattern, url_lower, re.IGNORECASE):
            return True
    
    # Additional checks for common non-sensitive patterns
    non_sensitive_keywords = [
        'public', 'open', 'free', 'demo', 'tutorial', 'documentation', 
        'guide', 'help', 'support', 'health', 'status', 'ping', 
        'version', 'info', 'metrics'
    ]
    
    # Check if URL contains non-sensitive keywords (but not if it also contains sensitive ones)
    sensitive_keywords = ['login', 'auth', 'password', 'payment', 'token', 'secret', 'key']
    has_sensitive = any(keyword in url_lower for keyword in sensitive_keywords)
    
    if not has_sensitive:
        for keyword in non_sensitive_keywords:
            if keyword in url_lower:
                return True
    
    return False

def assess_http_risk_level(url: str, context: str) -> str:
    """
    Assess the risk level of HTTP URL usage based on URL content and context.
    
    Args:
        url: The HTTP URL
        context: The context/line where the URL appears
        
    Returns:
        str: Risk level (HIGH, MEDIUM, LOW, or SKIP)
    """
    url_lower = url.lower()
    context_lower = context.lower()
    
    # If it's legitimate usage, skip
    if is_legitimate_http_usage(url):
        return 'SKIP'
    
    # High risk indicators in URL
    high_risk_url_keywords = [
        'login', 'auth', 'signin', 'logon', 'password', 'credential',
        'payment', 'pay', 'billing', 'credit', 'card', 'bank',
        'token', 'secret', 'key', 'oauth'
    ]
    
    # Medium risk indicators in URL
    medium_risk_url_keywords = [
        'personal', 'profile', 'user', 'customer', 'patient', 'medical',
        'data', 'service', 'api', 'submit', 'upload', 'download'
    ]
    
    # Check URL for risk indicators
    for keyword in high_risk_url_keywords:
        if keyword in url_lower:
            return 'HIGH'
    
    for keyword in medium_risk_url_keywords:
        if keyword in url_lower:
            return 'MEDIUM'
    
    # Check context for risk indicators
    high_risk_context_keywords = [
        'password', 'credential', 'authentication', 'login', 'token',
        'secret', 'key', 'payment', 'financial', 'sensitive'
    ]
    
    medium_risk_context_keywords = [
        'personal', 'user', 'customer', 'data', 'information',
        'profile', 'account', 'service'
    ]
    
    for keyword in high_risk_context_keywords:
        if keyword in context_lower:
            return 'HIGH'
    
    for keyword in medium_risk_context_keywords:
        if keyword in context_lower:
            return 'MEDIUM'
    
    # Default to LOW for external HTTP URLs
    if not any(local in url_lower for local in ['localhost', '127.0.0.1', '192.168.', '10.', '172.']):
        return 'LOW'
    
    return 'SKIP'

def scan_insecure_network(file_path, content, root_package=None):
    """
    Scan for insecure network configurations in UIPath .xaml file content.
    
    Args:
        file_path: Path to the file being scanned
        content: Content of the file
        root_package: Root package path for config resolution
        
    Returns:
        List of network security issues found
    """
    results = []
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        # Skip comment lines
        if line.strip().startswith('<!--'):
            continue
        
        # First, check for security patterns in the entire line (for SSL/TLS bypasses)
        for pattern_name, pattern_info in NETWORK_SECURITY_PATTERNS.items():
            if pattern_name in ['ssl_ignore', 'tls_ignore', 'cert_validation_bypass', 
                              'trust_all_certs', 'weak_tls_version', 'allow_untrusted_root',
                              'disable_hostname_verification']:
                pattern_regex = pattern_info['pattern']
                severity = pattern_info['severity']
                description = pattern_info['description']
                
                if re.search(pattern_regex, line, re.IGNORECASE):
                    # Create highlighted content
                    highlighted_value = highlight_match(line.strip(), line.strip())
                    
                    results.append({
                        'line': line_num,
                        'content': highlighted_value,
                        'severity': severity,
                        'description': description,
                        'module': 'insecure_network_detection',
                        'pattern_type': pattern_name,
                        'network_value': line.strip()
                    })
                    
                    # Break after first match to avoid duplicates
                    break
        
        # Look for network-related attributes
        for attr_name in NETWORK_ATTRIBUTES:
            # Pattern to match attribute="value" or attribute='{value}'
            attr_patterns = [
                rf'{attr_name}\s*=\s*"([^"]*)"',
                rf"{attr_name}\s*=\s*'([^']*)'",
                rf'{attr_name}\s*=\s*\{{([^}}]*)\}}',
                rf'{attr_name}>\s*([^<]*)\s*</',  # For element content
            ]
            
            for pattern in attr_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    attr_value = match.group(1).strip()
                    
                    # Skip empty values or very short values
                    if len(attr_value) < 4:
                        continue
                    
                    # Skip null values and simple variables
                    if attr_value.lower() in ['{x:null}', 'nothing', 'null', '', 'true', 'false']:
                        continue
                    
                    # Resolve config values if present
                    resolved_value = resolve_in_config_value(attr_value, root_package) if root_package else None
                    
                    # Check both original and resolved values
                    values_to_check = [(attr_value, "original")]
                    if resolved_value and resolved_value != attr_value:
                        values_to_check.append((resolved_value, "resolved"))
                    
                    for check_value, value_type in values_to_check:
                        # Check against all network security patterns
                        for pattern_name, pattern_info in NETWORK_SECURITY_PATTERNS.items():
                            pattern_regex = pattern_info['pattern']
                            severity = pattern_info['severity']
                            description = pattern_info['description']
                            
                            if re.search(pattern_regex, check_value, re.IGNORECASE):
                                # Special handling for HTTP URLs
                                if pattern_name == 'http_url':
                                    risk_level = assess_http_risk_level(check_value, line)
                                    if risk_level == 'SKIP':
                                        continue
                                    severity = risk_level
                                    if risk_level == 'HIGH':
                                        description = 'HTTP URL for sensitive data detected - Use HTTPS'
                                    elif risk_level == 'MEDIUM':
                                        description = 'HTTP URL detected - Consider using HTTPS'
                                    else:
                                        description = 'External HTTP URL detected - Verify if HTTPS is needed'
                                
                                # Create highlighted content
                                matched_text = match.group(0)
                                
                                if value_type == "resolved":
                                    # Show resolved value with highlighting
                                    highlighted_value = highlight_match(f'{matched_text} -> {resolved_value}', check_value)
                                    description = f'{description} (resolved from Config.xlsx)'
                                    content_line = highlighted_value
                                else:
                                    # Highlight the network config in the original text
                                    highlighted_value = highlight_match(matched_text, check_value)
                                    content_line = highlighted_value
                                
                                results.append({
                                    'line': line_num,
                                    'content': content_line,
                                    'severity': severity,
                                    'description': description,
                                    'module': 'insecure_network_detection',
                                    'pattern_type': pattern_name,
                                    'network_value': check_value
                                })
                                
                                # Break after first match to avoid duplicates
                                break
    
    return results

def scan_package(package_path: str, root_package_name: str = None, scanned_files: set = None) -> List[Dict[str, Any]]:
    """
    Scan a UIPath package for insecure network configurations.
    
    Args:
        package_path: Path to the package directory
        root_package_name: Name of the root package directory
        scanned_files: Set of files that have already been scanned
        
    Returns:
        List of issues found
    """
    issues = []
    package = Path(package_path)
    
    # Initialize scanned_files if not provided
    if scanned_files is None:
        scanned_files = set()
    
    try:
        # Scan all .xaml files recursively in the package
        for file_path in package.rglob('*.xaml'):
            if file_path.is_file():
                # Skip if file has already been scanned
                if str(file_path) in scanned_files:
                    continue
                
                # Add file to scanned set
                scanned_files.add(str(file_path))
                
                file_issues = scan_xaml_file(file_path, package, root_package_name)
                if file_issues:
                    issues.extend(file_issues)
    except Exception as e:
        logger.error(f"Error scanning package {package_path}: {str(e)}")
        issues.append({
            'type': 'insecure_network_detection',
            'severity': 'ERROR',
            'description': f'Error scanning package: {str(e)}',
            'file': str(package_path),
            'line': 0,
            'line_content': '',
            'module': 'insecure_network_detection'
        })
    
    return issues

def scan_xaml_file(file_path: Path, root_package: Path, root_package_name: str = None) -> List[Dict[str, Any]]:
    """
    Scan a single .xaml file for insecure network configurations.
    
    Args:
        file_path: Path to the .xaml file to scan
        root_package: Root package directory for reporting
        root_package_name: Name of the root package directory
        
    Returns:
        List of issues found in the file
    """
    issues = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Use the existing scan_insecure_network function
        network_issues = scan_insecure_network(file_path, content, root_package)
        
        # Convert to the expected format
        lines = content.split('\n')
        package_name = root_package_name if root_package_name else root_package.name
        
        for issue in network_issues:
            line_num = issue['line']
            full_line = lines[line_num - 1] if line_num > 0 and line_num <= len(lines) else ""
            
            issues.append({
                'type': 'insecure_network_detection',
                'severity': issue['severity'],
                'description': issue['description'],
                'file': str(file_path),
                'line': line_num,
                'line_content': issue['content'],
                'full_line': full_line,
                'matched_text': issue['content'],
                'package_name': package_name,
                'module': 'insecure_network_detection',
                'pattern_type': issue.get('pattern_type', 'unknown'),
                'network_value': issue.get('network_value', '')
            })
            
    except Exception as e:
        logger.error(f"Error scanning file {file_path}: {str(e)}")
        issues.append({
            'type': 'insecure_network_detection',
            'severity': 'ERROR',
            'description': f'Error scanning file: {str(e)}',
            'file': str(file_path),
            'line': 0,
            'line_content': '',
            'module': 'insecure_network_detection'
        })
    
    return issues

def find_line_number(content: str, search_text: str) -> int:
    """
    Find the line number of a specific text in content.
    
    Args:
        content: The text content to search in
        search_text: The text to search for
        
    Returns:
        Line number (1-based) where the text is found, or 0 if not found
    """
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        if search_text in line:
            return i
    return 0 