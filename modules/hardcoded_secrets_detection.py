#!/usr/bin/env python3
"""
Hardcoded Secrets Detection Module for UIPath Security Audit Tool
Detects hardcoded secrets and sensitive credentials in UIPath .xaml files

This module identifies patterns for various types of secrets including API keys,
private keys, tokens, connection strings, and other sensitive credentials.
"""

import re
import sys
import logging
import base64
from pathlib import Path
from typing import List, Dict, Any, Tuple

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
MODULE_DESCRIPTION = "Detects hardcoded secrets including API keys, private keys, JWT tokens, database connection strings, and other sensitive credentials. Flags high-confidence secrets as HIGH risk."

# Secret patterns with confidence levels
SECRET_PATTERNS = {
    # AWS Keys
    'aws_access_key': {
        'pattern': r'AKIA[0-9A-Z]{16}',
        'confidence': 'HIGH',
        'description': 'AWS Access Key detected'
    },
    'aws_secret_key': {
        'pattern': r'[A-Za-z0-9/+=]{40}',
        'confidence': 'MEDIUM',
        'description': 'Possible AWS Secret Key detected',
        'context_required': ['aws', 'secret', 'key']
    },
    'aws_session_token': {
        'pattern': r'AQoEXAMPLE[A-Za-z0-9/+=]+',
        'confidence': 'HIGH', 
        'description': 'AWS Session Token detected'
    },
    
    # Azure Keys
    'azure_storage_key': {
        'pattern': r'[A-Za-z0-9+/]{88}==',
        'confidence': 'MEDIUM',
        'description': 'Possible Azure Storage Key detected',
        'context_required': ['azure', 'storage', 'account']
    },
    'azure_client_secret': {
        'pattern': r'[A-Za-z0-9_~.-]{34,40}',
        'confidence': 'MEDIUM',
        'description': 'Possible Azure Client Secret detected',
        'context_required': ['azure', 'client', 'secret']
    },
    
    # Google Cloud
    'google_api_key': {
        'pattern': r'AIza[0-9A-Za-z_-]{35}',
        'confidence': 'HIGH',
        'description': 'Google API Key detected'
    },
    'google_oauth2': {
        'pattern': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        'confidence': 'HIGH',
        'description': 'Google OAuth2 Client ID detected'
    },
    
    # GitHub
    'github_token': {
        'pattern': r'ghp_[A-Za-z0-9]{36}',
        'confidence': 'HIGH',
        'description': 'GitHub Personal Access Token detected'
    },
    'github_app_token': {
        'pattern': r'gho_[A-Za-z0-9]{36}',
        'confidence': 'HIGH',
        'description': 'GitHub App Token detected'
    },
    'github_refresh_token': {
        'pattern': r'ghr_[A-Za-z0-9]{76}',
        'confidence': 'HIGH',
        'description': 'GitHub Refresh Token detected'
    },
    
    # JWT Tokens
    'jwt_token': {
        'pattern': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        'confidence': 'HIGH',
        'description': 'JWT Token detected'
    },
    
    # Private Keys
    'rsa_private_key': {
        'pattern': r'-----BEGIN (RSA )?PRIVATE KEY-----',
        'confidence': 'HIGH',
        'description': 'RSA Private Key detected'
    },
    'ssh_private_key': {
        'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',
        'confidence': 'HIGH',
        'description': 'SSH Private Key detected'
    },
    'ec_private_key': {
        'pattern': r'-----BEGIN EC PRIVATE KEY-----',
        'confidence': 'HIGH',
        'description': 'EC Private Key detected'
    },
    'pkcs8_private_key': {
        'pattern': r'-----BEGIN ENCRYPTED PRIVATE KEY-----',
        'confidence': 'HIGH',
        'description': 'PKCS#8 Private Key detected'
    },
    
    # Database Connection Strings
    'sql_server_connection': {
        'pattern': r'Server\s*=\s*[^;]+;\s*Database\s*=\s*[^;]+;\s*User\s+Id\s*=\s*[^;]+;\s*Password\s*=\s*[^;]+',
        'confidence': 'HIGH',
        'description': 'SQL Server connection string with password detected'
    },
    'mysql_connection': {
        'pattern': r'server\s*=\s*[^;]+;\s*database\s*=\s*[^;]+;\s*uid\s*=\s*[^;]+;\s*pwd\s*=\s*[^;]+',
        'confidence': 'HIGH',
        'description': 'MySQL connection string with password detected'
    },
    'postgres_connection': {
        'pattern': r'postgresql://[^:]+:[^@]+@[^/]+/\w+',
        'confidence': 'HIGH',
        'description': 'PostgreSQL connection string with password detected'
    },
    'mongodb_connection': {
        'pattern': r'mongodb://[^:]+:[^@]+@[^/]+',
        'confidence': 'HIGH',
        'description': 'MongoDB connection string with password detected'
    },
    
    # API Keys (Service-specific)
    'slack_token': {
        'pattern': r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}',
        'confidence': 'HIGH',
        'description': 'Slack Token detected'
    },
    'slack_webhook': {
        'pattern': r'https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[A-Za-z0-9]{24}',
        'confidence': 'HIGH',
        'description': 'Slack Webhook URL detected'
    },
    'stripe_key': {
        'pattern': r'sk_live_[0-9a-zA-Z]{24}',
        'confidence': 'HIGH',
        'description': 'Stripe Live Secret Key detected'
    },
    'stripe_test_key': {
        'pattern': r'sk_test_[0-9a-zA-Z]{24}',
        'confidence': 'MEDIUM',
        'description': 'Stripe Test Secret Key detected'
    },
    'paypal_client_id': {
        'pattern': r'A[A-Za-z0-9_-]{79}',
        'confidence': 'MEDIUM',
        'description': 'Possible PayPal Client ID detected',
        'context_required': ['paypal', 'client']
    },
    'twilio_sid': {
        'pattern': r'AC[a-z0-9]{32}',
        'confidence': 'HIGH',
        'description': 'Twilio Account SID detected'
    },
    'twilio_token': {
        'pattern': r'SK[a-z0-9]{32}',
        'confidence': 'HIGH',
        'description': 'Twilio Auth Token detected'
    },
    'mailgun_key': {
        'pattern': r'key-[a-z0-9]{32}',
        'confidence': 'HIGH',
        'description': 'Mailgun API Key detected'
    },
    'sendgrid_key': {
        'pattern': r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
        'confidence': 'HIGH',
        'description': 'SendGrid API Key detected'
    },
    
    # Firebase
    'firebase_key': {
        'pattern': r'AIza[0-9A-Za-z_-]{35}',
        'confidence': 'MEDIUM',
        'description': 'Possible Firebase API Key detected',
        'context_required': ['firebase']
    },
    
    # Generic patterns (lower confidence)
    'generic_api_key': {
        'pattern': r'["\']?[a-zA-Z0-9]{32,}["\']?',
        'confidence': 'LOW',
        'description': 'Possible API key pattern detected',
        'context_required': ['api', 'key', 'token', 'secret'],
        'min_length': 32
    },
    'hex_encoded_secret': {
        'pattern': r'[a-fA-F0-9]{64,}',
        'confidence': 'LOW',
        'description': 'Possible hex-encoded secret detected',
        'context_required': ['key', 'secret', 'hash'],
        'min_length': 64
    },
    'base64_secret': {
        'pattern': r'[A-Za-z0-9+/]{40,}={0,2}',
        'confidence': 'LOW',
        'description': 'Possible base64-encoded secret detected',
        'context_required': ['key', 'secret', 'token'],
        'min_length': 40
    }
}

def check_context_requirements(value: str, line: str, context_required: List[str]) -> bool:
    """
    Check if the required context keywords are present in the value or line.
    
    Args:
        value: The matched value
        line: The full line containing the value
        context_required: List of required context keywords
        
    Returns:
        bool: True if context requirements are met
    """
    combined_text = (value + " " + line).lower()
    return any(keyword.lower() in combined_text for keyword in context_required)

def is_likely_false_positive(value: str, pattern_name: str) -> bool:
    """
    Check if a detected secret is likely a false positive.
    
    Args:
        value: The detected value
        pattern_name: Name of the pattern that matched
        
    Returns:
        bool: True if likely false positive
    """
    value_lower = value.lower()
    
    # Common false positive patterns
    false_positives = [
        'example', 'sample', 'test', 'demo', 'placeholder', 'dummy',
        'fake', 'mock', 'template', 'default', 'null', 'none', 
        'todo', 'fixme', 'changeme', 'replace', 'your_key_here',
        'abcdef', '123456', '000000', 'ffffff', 'aaaaaa',
        'xxxxxxx', 'yyyyyyy', 'zzzzzzz'
    ]
    
    # Check for obvious false positives
    for fp in false_positives:
        if fp in value_lower:
            return True
    
    # Check for repeated characters (likely placeholder)
    if len(set(value)) < 4 and len(value) > 10:
        return True
    
    # Check for sequential patterns
    if re.search(r'(abc|123|xyz){3,}', value_lower):
        return True
    
    return False

def extract_and_decode_secrets(value: str) -> List[Tuple[str, str]]:
    """
    Extract and decode potential secrets from various encodings.
    
    Args:
        value: The value to analyze
        
    Returns:
        List of tuples (decoded_value, encoding_type)
    """
    results = [("", "plain")]
    
    # Try base64 decoding
    try:
        if len(value) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]*={0,2}$', value):
            decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
            if decoded and len(decoded) > 10:
                results.append((decoded, "base64"))
    except:
        pass
    
    # Try hex decoding
    try:
        if len(value) % 2 == 0 and re.match(r'^[a-fA-F0-9]+$', value):
            decoded = bytes.fromhex(value).decode('utf-8', errors='ignore')
            if decoded and len(decoded) > 10:
                results.append((decoded, "hex"))
    except:
        pass
    
    return results

def scan_hardcoded_secrets(file_path, content, root_package=None):
    """
    Scan for hardcoded secrets in UIPath .xaml file content.
    
    Args:
        file_path: Path to the file being scanned
        content: Content of the file
        root_package: Root package path for config resolution
        
    Returns:
        List of secrets found
    """
    results = []
    
    # Attributes that commonly contain secrets
    secret_attributes = [
        'Value', 'Text', 'Password', 'Key', 'Secret', 'Token', 'ApiKey',
        'ConnectionString', 'ClientSecret', 'AccessToken', 'RefreshToken',
        'PrivateKey', 'Certificate', 'Credential', 'Authorization', 'Auth',
        'ClientId', 'TenantId', 'SubscriptionId', 'SecretKey', 'AccessKey'
    ]
    
    # Create pattern for secret-related attributes
    secret_pattern = '|'.join([rf'{attr}=' for attr in secret_attributes])
    
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        # Skip if line doesn't contain secret-related attributes
        if not re.search(secret_pattern, line, re.IGNORECASE):
            continue
            
        # Look for attribute patterns
        for attr_name in secret_attributes:
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
                    if len(attr_value) < 8:
                        continue
                    
                    # Skip null values and simple variables
                    if attr_value.lower() in ['{x:null}', 'nothing', 'null', '', 'true', 'false']:
                        continue
                    
                    # Skip simple variable references without potential secrets
                    if re.match(r'^\[[\w_]+\]$', attr_value):
                        continue
                    
                    # Resolve config values if present  
                    resolved_value = resolve_in_config_value(attr_value, root_package) if root_package else None
                    
                    # Check both original and resolved values
                    values_to_check = [(attr_value, "original")]
                    if resolved_value and resolved_value != attr_value:
                        values_to_check.append((resolved_value, "resolved"))
                    
                    for check_value, value_type in values_to_check:
                        # Extract and decode potential secrets
                        decoded_secrets = extract_and_decode_secrets(check_value)
                        
                        for secret_value, encoding in decoded_secrets:
                            if not secret_value:
                                secret_value = check_value
                            
                            # Check against all secret patterns
                            for pattern_name, pattern_info in SECRET_PATTERNS.items():
                                pattern_regex = pattern_info['pattern']
                                confidence = pattern_info['confidence']
                                description = pattern_info['description']
                                
                                if re.search(pattern_regex, secret_value, re.IGNORECASE):
                                    # Check context requirements if specified
                                    if 'context_required' in pattern_info:
                                        if not check_context_requirements(secret_value, line, pattern_info['context_required']):
                                            continue
                                    
                                    # Check minimum length if specified
                                    if 'min_length' in pattern_info:
                                        if len(secret_value) < pattern_info['min_length']:
                                            continue
                                    
                                    # Check for false positives
                                    if is_likely_false_positive(secret_value, pattern_name):
                                        continue
                                    
                                    # Determine severity based on confidence
                                    if confidence == 'HIGH':
                                        severity = 'HIGH'
                                    elif confidence == 'MEDIUM':
                                        severity = 'MEDIUM'
                                    else:
                                        severity = 'LOW'
                                    
                                    # Create highlighted content
                                    matched_text = match.group(0)
                                    
                                    if value_type == "resolved":
                                        # Show resolved value with highlighting
                                        if encoding != "plain":
                                            highlighted_value = highlight_match(f'{matched_text} -> {resolved_value} ({encoding} decoded: {secret_value})', secret_value)
                                            description = f'{description} (resolved from Config.xlsx, {encoding} decoded)'
                                        else:
                                            highlighted_value = highlight_match(f'{matched_text} -> {resolved_value}', secret_value)
                                            description = f'{description} (resolved from Config.xlsx)'
                                        content_line = highlighted_value
                                    else:
                                        # Highlight the secret in the original text
                                        if encoding != "plain":
                                            highlighted_value = highlight_match(f'{matched_text} ({encoding} decoded: {secret_value})', secret_value)
                                            description = f'{description} ({encoding} decoded)'
                                        else:
                                            highlighted_value = highlight_match(matched_text, secret_value)
                                        content_line = highlighted_value
                                    
                                    results.append({
                                        'line': line_num,
                                        'content': content_line,
                                        'severity': severity,
                                        'description': description,
                                        'module': 'hardcoded_secrets_detection',
                                        'secret_type': pattern_name,
                                        'confidence': confidence
                                    })
                                    
                                    # Break after first match to avoid duplicates
                                    break
    
    return results

def scan_package(package_path: str, root_package_name: str = None, scanned_files: set = None) -> List[Dict[str, Any]]:
    """
    Scan a UIPath package for hardcoded secrets.
    
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
            'type': 'hardcoded_secrets_detection',
            'severity': 'ERROR',
            'description': f'Error scanning package: {str(e)}',
            'file': str(package_path),
            'line': 0,
            'line_content': '',
            'module': 'hardcoded_secrets_detection'
        })
    
    return issues

def scan_xaml_file(file_path: Path, root_package: Path, root_package_name: str = None) -> List[Dict[str, Any]]:
    """
    Scan a single .xaml file for hardcoded secrets.
    
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
        
        # Use the existing scan_hardcoded_secrets function
        secrets = scan_hardcoded_secrets(file_path, content, root_package)
        
        # Convert to the expected format
        lines = content.split('\n')
        package_name = root_package_name if root_package_name else root_package.name
        
        for secret in secrets:
            line_num = secret['line']
            full_line = lines[line_num - 1] if line_num > 0 and line_num <= len(lines) else ""
            
            issues.append({
                'type': 'hardcoded_secrets_detection',
                'severity': secret['severity'],
                'description': secret['description'],
                'file': str(file_path),
                'line': line_num,
                'line_content': secret['content'],
                'full_line': full_line,
                'matched_text': secret['content'],
                'package_name': package_name,
                'module': 'hardcoded_secrets_detection',
                'secret_type': secret.get('secret_type', 'unknown'),
                'confidence': secret.get('confidence', 'UNKNOWN')
            })
            
    except Exception as e:
        logger.error(f"Error scanning file {file_path}: {str(e)}")
        issues.append({
            'type': 'hardcoded_secrets_detection',
            'severity': 'ERROR',
            'description': f'Error scanning file: {str(e)}',
            'file': str(file_path),
            'line': 0,
            'line_content': '',
            'module': 'hardcoded_secrets_detection'
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