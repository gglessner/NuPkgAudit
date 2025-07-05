#!/usr/bin/env python3
"""
SecureText Detection Module
Scans for hardcoded SecureText attributes in UIPath automation.

Author: Garland Glessner <gglessner@gmail.com>
License: GNU General Public License v3.0
Copyright (C) 2024 Garland Glessner

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import re
import logging
import sys
from pathlib import Path
from typing import List, Dict, Any

# Add the libraries directory to the path
sys.path.append(str(Path(__file__).parent.parent / 'libraries'))

from config_helper import resolve_in_config_value
from highlight_helper import highlight_match

logger = logging.getLogger(__name__)

# Regex pattern to match SecureText attributes
SECURE_TEXT_ATTR_PATTERN = re.compile(
    r'\bSecureText\s*=\s*"([^"]+)"',
    re.IGNORECASE | re.MULTILINE
)

MODULE_DESCRIPTION = "Detects hardcoded SecureText attributes in .xaml files. Flags as HIGH risk if not a variable or {x:Null}."

def scan_package(package_path: str, root_package_name: str = None, scanned_files: set = None) -> List[Dict[str, Any]]:
    """
    Scan a UIPath package for hardcoded secure text.
    
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
            'type': 'secure_text_detection',
            'severity': 'HIGH',
            'description': f'Error scanning package: {str(e)}',
            'file': str(package_path),
            'line': 0,
            'line_content': '',
            'module': 'secure_text_detection'
        })
    
    return issues

def scan_xaml_file(file_path: Path, root_package: Path, root_package_name: str = None) -> List[Dict[str, Any]]:
    """
    Scan a single .xaml file for hardcoded secure text.
    
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
        lines = content.split('\n')
        
        # Use regex to find all matches, even if attribute is split across lines
        for match in SECURE_TEXT_ATTR_PATTERN.finditer(content):
            attr_value = match.group(1)
            matched_text = match.group(0)
            
            # Extract attribute name from the matched text
            attr_name_match = re.search(r'\b(\w*SecureText)\s*=', matched_text, re.IGNORECASE)
            attr_name = attr_name_match.group(1) if attr_name_match else 'SecureText'
            
            resolved_value = resolve_in_config_value(attr_value, root_package)
            
            if resolved_value:
                check_value = resolved_value
                original_value = attr_value
                logger.debug(f"Resolved in_config '{attr_value}' to value from {resolve_in_config_value.__module__}")
            else:
                check_value = attr_value
                original_value = attr_value
                logger.debug(f"Extracted secure text attribute value: {attr_value}")
            
            # Check for NetworkCredential patterns with hardcoded values
            extracted_password = None
            if 'NetworkCredential' in attr_value:
                logger.debug(f"NetworkCredential attribute value: {attr_value}")
                
                # Look for password parameter in NetworkCredential constructor
                network_cred_patterns = [
                    r'NetworkCredential\s*\([^,]*,\s*&quot;([^&]+)&quot;',
                    r'NetworkCredential\s*\([^,]*,\s*"([^"]+)"'
                ]
                
                for pattern in network_cred_patterns:
                    password_match = re.search(pattern, attr_value, re.IGNORECASE)
                    if password_match:
                        extracted_password = password_match.group(1)
                        break
            
            # Only report if not in [variable] format and not {x:Null}
            if not is_variable_format(check_value):
                line_num = find_line_number(content, matched_text)
                package_name = root_package_name if root_package_name else root_package.name
                full_line = lines[line_num - 1] if line_num > 0 and line_num <= len(lines) else ""
                
                # Check if this is an in_AuthenticationData pattern
                is_auth_data_pattern = is_authentication_data_pattern(attr_value)
                
                # Check if this is a Config_data pattern
                is_config_data_pattern_detected = is_config_data_pattern(attr_value)
                
                # Check if this is a DirectCast Config pattern
                is_directcast_config_pattern_detected = is_directcast_config_pattern(attr_value)
                
                # Check if this is an io_Credentials pattern
                is_io_credentials_pattern_detected = is_io_credentials_pattern(attr_value)
                
                # Check if this is a NetworkCredential pattern with dynamic retrieval
                is_networkcredential_dynamic_pattern_detected = is_networkcredential_with_dynamic_pattern(attr_value)
                
                # Check if this is a CType io_Config pattern
                is_ctype_io_config_pattern_detected = is_ctype_io_config_pattern(attr_value)
                
                # Check if this is a DirectCast in_ConfigDetails pattern
                is_directcast_configdetails_pattern_detected = is_directcast_configdetails_pattern(attr_value)
                
                # Check if this is a TryCast Config_Data pattern
                is_trycast_config_data_pattern_detected = is_trycast_config_data_pattern(attr_value)
                
                # Check if this is a TryCast in_config pattern
                is_trycast_in_config_pattern_detected = is_trycast_in_config_pattern(attr_value)
                
                # Check if this is a DirectCast in_Config pattern
                is_directcast_in_config_pattern_detected = is_directcast_in_config_pattern(attr_value)
                
                # Determine if this is an In_Config/in_config pattern
                is_in_config = False
                if ('in_config' in attr_value.lower() or 'inconfig' in attr_value.lower()) and '[' in attr_value and ']' in attr_value:
                    is_in_config = True
                
                if is_networkcredential_dynamic_pattern_detected:
                    severity, description = determine_networkcredential_dynamic_severity_and_description(attr_value)
                    content_line = matched_text.strip()
                elif extracted_password:
                    description = f'Hard-coded {attr_name} detected (NetworkCredential)'
                    content_line = f'{matched_text.strip()} -> {extracted_password}'
                    severity = 'HIGH'
                elif resolved_value:
                    description = f'Hard-coded {attr_name} detected'
                    # Highlight the resolved value in yellow
                    highlighted_value = highlight_match(f'{matched_text.strip()} -> {resolved_value}', str(resolved_value))
                    content_line = highlighted_value
                    severity = 'HIGH'
                elif is_in_config:
                    description = f'Hard-coded {attr_name} detected'
                    highlighted_missing = highlight_match(f'{matched_text.strip()} -> Value not in Config.xlsx', 'Value not in Config.xlsx')
                    content_line = highlighted_missing
                    severity = 'FALSE-POSITIVE'
                elif is_auth_data_pattern:
                    severity, description = determine_authentication_data_severity_and_description(attr_value)
                    content_line = matched_text.strip()
                elif is_config_data_pattern_detected:
                    severity, description = determine_config_data_severity_and_description(attr_value)
                    content_line = matched_text.strip()
                elif is_directcast_config_pattern_detected:
                    severity, description = determine_directcast_config_severity_and_description(attr_value)
                    content_line = matched_text.strip()
                elif is_io_credentials_pattern_detected:
                    severity, description = determine_io_credentials_severity_and_description(attr_value)
                    content_line = matched_text.strip()
                elif is_ctype_io_config_pattern_detected:
                    severity, description = determine_ctype_io_config_severity_and_description(attr_value)
                    content_line = matched_text.strip()
                elif is_directcast_configdetails_pattern_detected:
                    severity, description = determine_directcast_configdetails_severity_and_description(attr_value)
                    content_line = matched_text.strip()
                elif is_trycast_config_data_pattern_detected:
                    severity, description = determine_trycast_config_data_severity_and_description(attr_value)
                    content_line = matched_text.strip()
                elif is_trycast_in_config_pattern_detected:
                    # Check if this was an unresolved in_config pattern
                    if resolved_value is None and is_in_config:
                        description = f'Hard-coded {attr_name} detected'
                        highlighted_missing = highlight_match(f'{matched_text.strip()} -> Value not in Config.xlsx', 'Value not in Config.xlsx')
                        content_line = highlighted_missing
                        severity = 'FALSE-POSITIVE'
                    else:
                        severity, description = determine_trycast_in_config_severity_and_description(attr_value)
                        content_line = matched_text.strip()
                elif is_directcast_in_config_pattern_detected:
                    # Check if this was an unresolved in_config pattern
                    if resolved_value is None and is_in_config:
                        description = f'Hard-coded {attr_name} detected'
                        highlighted_missing = highlight_match(f'{matched_text.strip()} -> Value not in Config.xlsx', 'Value not in Config.xlsx')
                        content_line = highlighted_missing
                        severity = 'FALSE-POSITIVE'
                    else:
                        severity, description = determine_directcast_in_config_severity_and_description(attr_value)
                        content_line = matched_text.strip()
                else:
                    description = f'Hard-coded {attr_name} detected'
                    content_line = matched_text.strip()
                    severity = 'HIGH'
                
                issues.append({
                    'type': 'secure_text_detection',
                    'severity': severity,
                    'description': description,
                    'file': str(file_path),
                    'line': line_num,
                    'line_content': content_line,
                    'full_line': full_line,
                    'matched_text': matched_text,
                    'package_name': package_name,
                    'module': 'secure_text_detection'
                })
    except Exception as e:
        logger.warning(f"Error reading file {file_path}: {str(e)}")
    
    return issues

def is_variable_format(value: str) -> bool:
    """
    Check if a value is in variable format [variable_name] or {x:Null}.
    Returns True if it's a safe variable reference, False if it contains hardcoded values.
    """
    stripped_value = value.strip()
    
    # {x:Null} is always safe
    if stripped_value == '{x:Null}':
        return True
    
    # Check if it's in square brackets
    if stripped_value.startswith('[') and stripped_value.endswith(']'):
        inner_content = stripped_value[1:-1].strip()
        
        # In_Config patterns should always be resolved and checked
        if 'in_config' in stripped_value.lower():
            return False
        
        # Check for in_AuthenticationData patterns (different handling)
        if is_authentication_data_pattern(inner_content):
            return False  # We want to flag these, but with different severity
        
        # Check for Config_data patterns (different handling)
        if is_config_data_pattern(inner_content):
            return False  # We want to flag these, but with different severity
        
        # Check for DirectCast Config patterns (different handling)
        if is_directcast_config_pattern(inner_content):
            return False  # We want to flag these, but with different severity
        
        # Check for io_Credentials patterns (different handling)
        if is_io_credentials_pattern(inner_content):
            return False  # We want to flag these, but with different severity
        
        # Check for NetworkCredential patterns with dynamic retrieval (different handling)
        if is_networkcredential_with_dynamic_pattern(inner_content):
            return False  # We want to flag these, but with different severity
        
        # Check for CType io_Config patterns (different handling)
        if is_ctype_io_config_pattern(inner_content):
            return False  # We want to flag these, but with different severity
        
        # Check for DirectCast in_ConfigDetails patterns (different handling)
        if is_directcast_configdetails_pattern(inner_content):
            return False  # We want to flag these, but with different severity
        
        # Check for TryCast Config_Data patterns (different handling)
        if is_trycast_config_data_pattern(inner_content):
            return False  # We want to flag these, but with different severity
        
        # Check for TryCast in_config patterns (different handling)
        if is_trycast_in_config_pattern(inner_content):
            return False  # We want to flag these, but with different severity
        
        # Check for DirectCast in_Config patterns (different handling)
        if is_directcast_in_config_pattern(inner_content):
            return False  # We want to flag these, but with different severity
        
        # Check for non-empty quoted strings - indicates hardcoded values
        # Empty strings (&quot;&quot;) are often just placeholders, ignore them
        quoted_patterns = re.findall(r'&quot;([^&]*)&quot;|"([^"]*)"', inner_content)
        has_hardcoded_values = any(match[0] or match[1] for match in quoted_patterns if (match[0] or match[1]).strip())
        
        if has_hardcoded_values:
            return False
        
        # Check for .NET expressions that might contain variables (unquoted references)
        if any(pattern in inner_content for pattern in [
            'NetworkCredential', 'DirectCast', 'SecureString', 'Convert.',
            'System.', 'new ', 'New ', '(', ')', '.'
        ]):
            # This might be a complex expression - check for hardcoded values more carefully
            quoted_strings = re.findall(r'&quot;([^&]+)&quot;|"([^"]+)"', inner_content)
            non_empty_strings = [match[0] or match[1] for match in quoted_strings if (match[0] or match[1]).strip()]
            return len(non_empty_strings) == 0
        
        # If no quoted strings found and it's in brackets, treat as variable
        return True
    
    # Not in brackets - check if it's a simple identifier (variable)
    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', stripped_value):
        return True
    
    return False

def is_authentication_data_pattern(content: str) -> bool:
    """
    Check if the content represents an in_AuthenticationData pattern.
    Examples:
    - in_AuthenticationData(&quot;mypassword&quot;).ToString
    - in_AuthenticationData(&quot;pwd&quot;).ToString
    """
    import re
    
    # Pattern to match in_AuthenticationData and similar authentication access patterns
    auth_patterns = [
        r'in_AuthenticationData\s*\(\s*&quot;[^&]+&quot;\s*\)',    # in_AuthenticationData(&quot;key&quot;)
        r'in_AuthenticationData\s*\(\s*"[^"]+"\s*\)',              # in_AuthenticationData("key")
        r'in_Authentication\s*\(\s*&quot;[^&]+&quot;\s*\)',        # in_Authentication(&quot;key&quot;)
        r'in_Authentication\s*\(\s*"[^"]+"\s*\)',                  # in_Authentication("key")
    ]
    
    for pattern in auth_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    
    return False

def is_config_data_pattern(content: str) -> bool:
    """
    Check if the content represents a Config_data pattern.
    Examples:
    - Config_data(&quot;AccessCode&quot;).ToString
    - config_data(&quot;secret_key&quot;).ToString
    """
    import re
    
    # Pattern to match Config_data and similar config access patterns
    config_patterns = [
        r'Config_data\s*\(\s*&quot;[^&]+&quot;\s*\)',    # Config_data(&quot;key&quot;)
        r'Config_data\s*\(\s*"[^"]+"\s*\)',              # Config_data("key")
        r'config_data\s*\(\s*&quot;[^&]+&quot;\s*\)',    # config_data(&quot;key&quot;) - lowercase variant
        r'config_data\s*\(\s*"[^"]+"\s*\)',              # config_data("key") - lowercase variant
    ]
    
    for pattern in config_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    
    return False

def is_directcast_config_pattern(content: str) -> bool:
    """
    Check if the content represents a DirectCast Config pattern.
    Examples:
    - DirectCast(Config(&quot;My_password&quot;),SecureString)
    - DirectCast(config(&quot;api_password&quot;),SecureString)
    - DirectCast(Config(&quot;secret_key&quot;), String)
    """
    import re
    
    # Pattern to match DirectCast Config and similar config access patterns
    directcast_config_patterns = [
        r'DirectCast\s*\(\s*Config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*SecureString\s*\)',    # DirectCast(Config(&quot;key&quot;),SecureString)
        r'DirectCast\s*\(\s*Config\s*\(\s*"[^"]+"\s*\)\s*,\s*SecureString\s*\)',              # DirectCast(Config("key"),SecureString)
        r'DirectCast\s*\(\s*config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*SecureString\s*\)',    # DirectCast(config(&quot;key&quot;),SecureString) - lowercase
        r'DirectCast\s*\(\s*config\s*\(\s*"[^"]+"\s*\)\s*,\s*SecureString\s*\)',              # DirectCast(config("key"),SecureString) - lowercase
        r'DirectCast\s*\(\s*Config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*String\s*\)',         # DirectCast(Config(&quot;key&quot;), String)
        r'DirectCast\s*\(\s*Config\s*\(\s*"[^"]+"\s*\)\s*,\s*String\s*\)',                   # DirectCast(Config("key"), String)
    ]
    
    for pattern in directcast_config_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    
    return False

def determine_authentication_data_severity_and_description(attr_value: str) -> tuple:
    """
    Determine appropriate severity and description for in_AuthenticationData patterns.
    Returns (severity, description)
    """
    # Check for specific authentication data patterns
    if 'in_AuthenticationData' in attr_value or 'in_authenticationdata' in attr_value:
        return 'MEDIUM', 'SecureText retrieved from AuthenticationData - Review authentication source security'
    elif 'in_Authentication' in attr_value or 'in_authentication' in attr_value:
        return 'MEDIUM', 'SecureText retrieved from Authentication - Review authentication source security'
    else:
        return 'INFO', 'SecureText retrieved from authentication source - Review if source is secure'

def determine_config_data_severity_and_description(attr_value: str) -> tuple:
    """
    Determine appropriate severity and description for Config_data patterns.
    Returns (severity, description)
    """
    # Check for specific config data patterns
    if 'Config_data' in attr_value or 'config_data' in attr_value:
        return 'MEDIUM', 'SecureText retrieved from Config_data - Review configuration source security'
    else:
        return 'INFO', 'SecureText retrieved from configuration data source - Review if source is secure'

def determine_directcast_config_severity_and_description(attr_value: str) -> tuple:
    """
    Determine appropriate severity and description for DirectCast Config patterns.
    Returns (severity, description)
    """
    # Check for specific DirectCast Config patterns
    if 'DirectCast' in attr_value and 'Config' in attr_value:
        if 'SecureString' in attr_value:
            return 'MEDIUM', 'SecureText retrieved from DirectCast Config SecureString - Review configuration source security'
        elif 'String' in attr_value:
            return 'MEDIUM', 'SecureText retrieved from DirectCast Config String - Review configuration source security'
        else:
            return 'MEDIUM', 'SecureText retrieved from DirectCast Config - Review configuration source security'
    else:
        return 'INFO', 'SecureText retrieved from DirectCast configuration source - Review if source is secure'

def is_io_credentials_pattern(content: str) -> bool:
    """
    Check if the content represents an io_Credentials pattern.
    Examples:
    - io_Credentials(&quot;domain&quot;).SecurePassword
    - IO_Credentials(&quot;api_creds&quot;).SecurePassword
    """
    import re
    
    # Pattern to match io_Credentials and similar credential access patterns
    io_credentials_patterns = [
        r'io_Credentials\s*\(\s*&quot;[^&]+&quot;\s*\)\.SecurePassword',    # io_Credentials(&quot;key&quot;).SecurePassword
        r'io_Credentials\s*\(\s*"[^"]+"\s*\)\.SecurePassword',              # io_Credentials("key").SecurePassword
        r'IO_Credentials\s*\(\s*&quot;[^&]+&quot;\s*\)\.SecurePassword',    # IO_Credentials(&quot;key&quot;).SecurePassword - uppercase
        r'IO_Credentials\s*\(\s*"[^"]+"\s*\)\.SecurePassword',              # IO_Credentials("key").SecurePassword - uppercase
    ]
    
    for pattern in io_credentials_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    
    return False

def determine_io_credentials_severity_and_description(attr_value: str) -> tuple:
    """
    Determine appropriate severity and description for io_Credentials patterns.
    Returns (severity, description)
    """
    # Check for specific io_Credentials patterns
    if 'io_Credentials' in attr_value or 'IO_Credentials' in attr_value:
        return 'MEDIUM', 'SecureText retrieved from io_Credentials - Review credentials source security'
    else:
        return 'INFO', 'SecureText retrieved from credentials source - Review if source is secure'

def is_networkcredential_with_dynamic_pattern(content: str) -> bool:
    """
    Check if the content represents a NetworkCredential pattern with dynamic password retrieval.
    Examples:
    - (new System.Net.Network.NetworkCredential(&quot;&quot;, in_JsonObject(&quot;password&quot;).ToString))
    - (new System.Net.NetworkCredential(&quot;&quot;, jsonData(&quot;pass&quot;).ToString))
    """
    import re
    
    # Check if it's a NetworkCredential pattern first
    if 'NetworkCredential' not in content:
        return False
    
    # Pattern to match NetworkCredential with dynamic password retrieval
    dynamic_patterns = [
        r'NetworkCredential\s*\([^,]*,\s*[^)]*(?:in_JsonObject|jsonData|jsonConfig|io_JsonObject)',  # JSON object patterns
        r'NetworkCredential\s*\([^,]*,\s*[^)]*(?:in_AuthenticationData|in_Authentication)',         # Auth data patterns
        r'NetworkCredential\s*\([^,]*,\s*[^)]*(?:Config_data|config_data)',                         # Config data patterns
        r'NetworkCredential\s*\([^,]*,\s*[^)]*(?:io_Config|IO_Config)',                             # io_Config patterns
    ]
    
    for pattern in dynamic_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    
    return False

def determine_networkcredential_dynamic_severity_and_description(attr_value: str) -> tuple:
    """
    Determine appropriate severity and description for NetworkCredential patterns with dynamic retrieval.
    Returns (severity, description)
    """
    # Check for specific dynamic patterns in NetworkCredential
    if 'in_JsonObject' in attr_value or 'jsonData' in attr_value or 'jsonConfig' in attr_value or 'io_JsonObject' in attr_value:
        return 'MEDIUM', 'SecureText retrieved from NetworkCredential with JSON object - Review data source security'
    elif 'in_AuthenticationData' in attr_value or 'in_Authentication' in attr_value:
        return 'MEDIUM', 'SecureText retrieved from NetworkCredential with AuthenticationData - Review authentication source security'
    elif 'Config_data' in attr_value or 'config_data' in attr_value:
        return 'MEDIUM', 'SecureText retrieved from NetworkCredential with Config_data - Review configuration source security'
    elif 'io_Config' in attr_value or 'IO_Config' in attr_value:
        return 'MEDIUM', 'SecureText retrieved from NetworkCredential with io_Config - Review configuration source security'
    else:
        return 'MEDIUM', 'SecureText retrieved from NetworkCredential with dynamic source - Review data source security'

def is_ctype_io_config_pattern(content: str) -> bool:
    """
    Check if the content represents a CType io_Config pattern.
    Examples:
    - ctype(io_Config(&quot;Password&quot;),system.security.SecureString)
    - CType(IO_Config(&quot;ApiKey&quot;), System.Security.SecureString)
    - ctype(ioConfig(&quot;secret&quot;), SecureString)
    """
    import re
    
    # Check if it's a CType pattern first
    if not re.search(r'ctype\s*\(', content, re.IGNORECASE):
        return False
    
    # Pattern to match CType with io_Config patterns
    ctype_io_config_patterns = [
        r'ctype\s*\(\s*io_Config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,',           # ctype(io_Config(&quot;key&quot;),
        r'ctype\s*\(\s*io_Config\s*\(\s*"[^"]+"\s*\)\s*,',                     # ctype(io_Config("key"),
        r'ctype\s*\(\s*IO_Config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,',           # ctype(IO_Config(&quot;key&quot;),
        r'ctype\s*\(\s*IO_Config\s*\(\s*"[^"]+"\s*\)\s*,',                     # ctype(IO_Config("key"),
        r'ctype\s*\(\s*ioConfig\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,',            # ctype(ioConfig(&quot;key&quot;),
        r'ctype\s*\(\s*ioConfig\s*\(\s*"[^"]+"\s*\)\s*,',                      # ctype(ioConfig("key"),
    ]
    
    for pattern in ctype_io_config_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    
    return False

def determine_ctype_io_config_severity_and_description(attr_value: str) -> tuple:
    """
    Determine appropriate severity and description for CType io_Config patterns.
    Returns (severity, description)
    """
    # Check for specific CType io_Config patterns
    if 'io_Config' in attr_value or 'IO_Config' in attr_value or 'ioConfig' in attr_value:
        return 'MEDIUM', 'SecureText retrieved from CType io_Config - Review configuration source security'
    else:
        return 'INFO', 'SecureText retrieved from CType configuration source - Review if source is secure'

def is_directcast_configdetails_pattern(content: str) -> bool:
    """
    Check if the content represents a DirectCast in_ConfigDetails pattern.
    Examples:
    - DirectCast(in_ConfigDetails(&quot;Password&quot;),SecureString)
    - DirectCast(in_configdetails(&quot;ApiKey&quot;), SecureString)
    - DirectCast(in_ConfigDetails(&quot;secret&quot;), String)
    """
    import re
    
    # Check if it's a DirectCast pattern first
    if 'DirectCast' not in content:
        return False
    
    # Pattern to match DirectCast with in_ConfigDetails patterns
    directcast_configdetails_patterns = [
        r'DirectCast\s*\(\s*in_ConfigDetails\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*SecureString\s*\)',    # DirectCast(in_ConfigDetails(&quot;key&quot;),SecureString)
        r'DirectCast\s*\(\s*in_ConfigDetails\s*\(\s*"[^"]+"\s*\)\s*,\s*SecureString\s*\)',              # DirectCast(in_ConfigDetails("key"),SecureString)
        r'DirectCast\s*\(\s*in_configdetails\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*SecureString\s*\)',    # DirectCast(in_configdetails(&quot;key&quot;),SecureString) - lowercase
        r'DirectCast\s*\(\s*in_configdetails\s*\(\s*"[^"]+"\s*\)\s*,\s*SecureString\s*\)',              # DirectCast(in_configdetails("key"),SecureString) - lowercase
        r'DirectCast\s*\(\s*in_ConfigDetails\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*String\s*\)',         # DirectCast(in_ConfigDetails(&quot;key&quot;), String)
        r'DirectCast\s*\(\s*in_ConfigDetails\s*\(\s*"[^"]+"\s*\)\s*,\s*String\s*\)',                   # DirectCast(in_ConfigDetails("key"), String)
        r'DirectCast\s*\(\s*in_configdetails\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*String\s*\)',         # DirectCast(in_configdetails(&quot;key&quot;), String) - lowercase
        r'DirectCast\s*\(\s*in_configdetails\s*\(\s*"[^"]+"\s*\)\s*,\s*String\s*\)',                   # DirectCast(in_configdetails("key"), String) - lowercase
    ]
    
    for pattern in directcast_configdetails_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    
    return False

def determine_directcast_configdetails_severity_and_description(attr_value: str) -> tuple:
    """
    Determine appropriate severity and description for DirectCast in_ConfigDetails patterns.
    Returns (severity, description)
    """
    # Check for specific DirectCast in_ConfigDetails patterns
    if 'in_ConfigDetails' in attr_value or 'in_configdetails' in attr_value:
        if 'SecureString' in attr_value:
            return 'MEDIUM', 'SecureText retrieved from DirectCast in_ConfigDetails SecureString - Review configuration source security'
        elif 'String' in attr_value:
            return 'MEDIUM', 'SecureText retrieved from DirectCast in_ConfigDetails String - Review configuration source security'
        else:
            return 'MEDIUM', 'SecureText retrieved from DirectCast in_ConfigDetails - Review configuration source security'
    else:
        return 'INFO', 'SecureText retrieved from DirectCast configuration details source - Review if source is secure'

def is_trycast_config_data_pattern(content: str) -> bool:
    """
    Check if the content represents a TryCast Config_Data pattern.
    Examples:
    - TryCast(Config_Data(&quot;Asset_Pass&quot;), System.Security.SecureString)
    - TryCast(config_data(&quot;ApiSecret&quot;), System.Security.SecureString)
    - TryCast(Config_Data(&quot;secret_key&quot;), String)
    """
    import re
    
    # Check if it's a TryCast pattern first
    if 'TryCast' not in content:
        return False
    
    # Pattern to match TryCast with Config_Data patterns
    trycast_config_data_patterns = [
        r'TryCast\s*\(\s*Config_Data\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*System\.Security\.SecureString\s*\)',    # TryCast(Config_Data(&quot;key&quot;), System.Security.SecureString)
        r'TryCast\s*\(\s*Config_Data\s*\(\s*"[^"]+"\s*\)\s*,\s*System\.Security\.SecureString\s*\)',              # TryCast(Config_Data("key"), System.Security.SecureString)
        r'TryCast\s*\(\s*config_data\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*System\.Security\.SecureString\s*\)',    # TryCast(config_data(&quot;key&quot;), System.Security.SecureString) - lowercase
        r'TryCast\s*\(\s*config_data\s*\(\s*"[^"]+"\s*\)\s*,\s*System\.Security\.SecureString\s*\)',              # TryCast(config_data("key"), System.Security.SecureString) - lowercase
        r'TryCast\s*\(\s*Config_Data\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*SecureString\s*\)',                     # TryCast(Config_Data(&quot;key&quot;), SecureString)
        r'TryCast\s*\(\s*Config_Data\s*\(\s*"[^"]+"\s*\)\s*,\s*SecureString\s*\)',                               # TryCast(Config_Data("key"), SecureString)
        r'TryCast\s*\(\s*config_data\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*SecureString\s*\)',                     # TryCast(config_data(&quot;key&quot;), SecureString) - lowercase
        r'TryCast\s*\(\s*config_data\s*\(\s*"[^"]+"\s*\)\s*,\s*SecureString\s*\)',                               # TryCast(config_data("key"), SecureString) - lowercase
        r'TryCast\s*\(\s*Config_Data\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*String\s*\)',                          # TryCast(Config_Data(&quot;key&quot;), String)
        r'TryCast\s*\(\s*Config_Data\s*\(\s*"[^"]+"\s*\)\s*,\s*String\s*\)',                                    # TryCast(Config_Data("key"), String)
        r'TryCast\s*\(\s*config_data\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*String\s*\)',                          # TryCast(config_data(&quot;key&quot;), String) - lowercase
        r'TryCast\s*\(\s*config_data\s*\(\s*"[^"]+"\s*\)\s*,\s*String\s*\)',                                    # TryCast(config_data("key"), String) - lowercase
    ]
    
    for pattern in trycast_config_data_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    
    return False

def determine_trycast_config_data_severity_and_description(attr_value: str) -> tuple:
    """
    Determine appropriate severity and description for TryCast Config_Data patterns.
    Returns (severity, description)
    """
    # Check for specific TryCast Config_Data patterns
    if 'Config_Data' in attr_value or 'config_data' in attr_value:
        if 'SecureString' in attr_value:
            return 'MEDIUM', 'SecureText retrieved from TryCast Config_Data SecureString - Review configuration source security'
        elif 'String' in attr_value:
            return 'MEDIUM', 'SecureText retrieved from TryCast Config_Data String - Review configuration source security'
        else:
            return 'MEDIUM', 'SecureText retrieved from TryCast Config_Data - Review configuration source security'
    else:
        return 'INFO', 'SecureText retrieved from TryCast configuration data source - Review if source is secure'

def is_trycast_in_config_pattern(content: str) -> bool:
    """
    Check if the content represents a TryCast in_config pattern.
    Examples:
    - TryCast(in_config(&quot;My_Pass&quot;), System.Security.SecureString)
    - TryCast(In_Config(&quot;ApiPassword&quot;), System.Security.SecureString)
    - TryCast(in_config(&quot;secret_token&quot;), String)
    """
    import re
    
    # Check if it's a TryCast pattern first
    if 'TryCast' not in content:
        return False
    
    # Pattern to match TryCast with in_config patterns
    trycast_in_config_patterns = [
        r'TryCast\s*\(\s*in_config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*System\.Security\.SecureString\s*\)',    # TryCast(in_config(&quot;key&quot;), System.Security.SecureString)
        r'TryCast\s*\(\s*in_config\s*\(\s*"[^"]+"\s*\)\s*,\s*System\.Security\.SecureString\s*\)',              # TryCast(in_config("key"), System.Security.SecureString)
        r'TryCast\s*\(\s*In_Config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*System\.Security\.SecureString\s*\)',    # TryCast(In_Config(&quot;key&quot;), System.Security.SecureString) - capitalized
        r'TryCast\s*\(\s*In_Config\s*\(\s*"[^"]+"\s*\)\s*,\s*System\.Security\.SecureString\s*\)',              # TryCast(In_Config("key"), System.Security.SecureString) - capitalized
        r'TryCast\s*\(\s*in_config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*SecureString\s*\)',                     # TryCast(in_config(&quot;key&quot;), SecureString)
        r'TryCast\s*\(\s*in_config\s*\(\s*"[^"]+"\s*\)\s*,\s*SecureString\s*\)',                               # TryCast(in_config("key"), SecureString)
        r'TryCast\s*\(\s*In_Config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*SecureString\s*\)',                     # TryCast(In_Config(&quot;key&quot;), SecureString) - capitalized
        r'TryCast\s*\(\s*In_Config\s*\(\s*"[^"]+"\s*\)\s*,\s*SecureString\s*\)',                               # TryCast(In_Config("key"), SecureString) - capitalized
        r'TryCast\s*\(\s*in_config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*String\s*\)',                          # TryCast(in_config(&quot;key&quot;), String)
        r'TryCast\s*\(\s*in_config\s*\(\s*"[^"]+"\s*\)\s*,\s*String\s*\)',                                    # TryCast(in_config("key"), String)
        r'TryCast\s*\(\s*In_Config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*String\s*\)',                          # TryCast(In_Config(&quot;key&quot;), String) - capitalized
        r'TryCast\s*\(\s*In_Config\s*\(\s*"[^"]+"\s*\)\s*,\s*String\s*\)',                                    # TryCast(In_Config("key"), String) - capitalized
    ]
    
    for pattern in trycast_in_config_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    
    return False

def determine_trycast_in_config_severity_and_description(attr_value: str) -> tuple:
    """
    Determine appropriate severity and description for TryCast in_config patterns.
    Returns (severity, description)
    """
    # Check for specific TryCast in_config patterns
    if 'in_config' in attr_value or 'In_Config' in attr_value:
        if 'SecureString' in attr_value:
            return 'MEDIUM', 'SecureText retrieved from TryCast in_config SecureString - Review configuration source security'
        elif 'String' in attr_value:
            return 'MEDIUM', 'SecureText retrieved from TryCast in_config String - Review configuration source security'
        else:
            return 'MEDIUM', 'SecureText retrieved from TryCast in_config - Review configuration source security'
    else:
        return 'INFO', 'SecureText retrieved from TryCast in_config source - Review if source is secure'

def is_directcast_in_config_pattern(content: str) -> bool:
    """
    Check if the content represents a DirectCast in_Config pattern.
    Examples:
    - DirectCast(in_Config(&quot;my_pass&quot;),SecureString)
    - DirectCast(In_Config(&quot;ApiSecretKey&quot;), SecureString)
    - DirectCast(in_config(&quot;token_value&quot;), String)
    """
    import re
    
    # Check if it's a DirectCast pattern first
    if 'DirectCast' not in content:
        return False
    
    # Pattern to match DirectCast with in_Config patterns
    directcast_in_config_patterns = [
        r'DirectCast\s*\(\s*in_Config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*SecureString\s*\)',    # DirectCast(in_Config(&quot;key&quot;),SecureString)
        r'DirectCast\s*\(\s*in_Config\s*\(\s*"[^"]+"\s*\)\s*,\s*SecureString\s*\)',              # DirectCast(in_Config("key"),SecureString)
        r'DirectCast\s*\(\s*In_Config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*SecureString\s*\)',    # DirectCast(In_Config(&quot;key&quot;), SecureString) - capitalized
        r'DirectCast\s*\(\s*In_Config\s*\(\s*"[^"]+"\s*\)\s*,\s*SecureString\s*\)',              # DirectCast(In_Config("key"), SecureString) - capitalized
        r'DirectCast\s*\(\s*in_config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*SecureString\s*\)',    # DirectCast(in_config(&quot;key&quot;), SecureString) - lowercase
        r'DirectCast\s*\(\s*in_config\s*\(\s*"[^"]+"\s*\)\s*,\s*SecureString\s*\)',              # DirectCast(in_config("key"), SecureString) - lowercase
        r'DirectCast\s*\(\s*in_Config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*String\s*\)',         # DirectCast(in_Config(&quot;key&quot;), String)
        r'DirectCast\s*\(\s*in_Config\s*\(\s*"[^"]+"\s*\)\s*,\s*String\s*\)',                   # DirectCast(in_Config("key"), String)
        r'DirectCast\s*\(\s*In_Config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*String\s*\)',         # DirectCast(In_Config(&quot;key&quot;), String) - capitalized
        r'DirectCast\s*\(\s*In_Config\s*\(\s*"[^"]+"\s*\)\s*,\s*String\s*\)',                   # DirectCast(In_Config("key"), String) - capitalized
        r'DirectCast\s*\(\s*in_config\s*\(\s*&quot;[^&]+&quot;\s*\)\s*,\s*String\s*\)',         # DirectCast(in_config(&quot;key&quot;), String) - lowercase
        r'DirectCast\s*\(\s*in_config\s*\(\s*"[^"]+"\s*\)\s*,\s*String\s*\)',                   # DirectCast(in_config("key"), String) - lowercase
    ]
    
    for pattern in directcast_in_config_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    
    return False

def determine_directcast_in_config_severity_and_description(attr_value: str) -> tuple:
    """
    Determine appropriate severity and description for DirectCast in_Config patterns.
    Returns (severity, description)
    """
    # Check for specific DirectCast in_Config patterns
    if 'in_Config' in attr_value or 'In_Config' in attr_value or 'in_config' in attr_value:
        if 'SecureString' in attr_value:
            return 'MEDIUM', 'SecureText retrieved from DirectCast in_Config SecureString - Review configuration source security'
        elif 'String' in attr_value:
            return 'MEDIUM', 'SecureText retrieved from DirectCast in_Config String - Review configuration source security'
        else:
            return 'MEDIUM', 'SecureText retrieved from DirectCast in_Config - Review configuration source security'
    else:
        return 'INFO', 'SecureText retrieved from DirectCast in_Config source - Review if source is secure'

def find_line_number(content: str, search_text: str) -> int:
    """
    Find the line number where the search text occurs in the content.
    
    Args:
        content: The file content to search in
        search_text: The text to search for
        
    Returns:
        The line number (1-indexed) where the text was found, or 0 if not found
    """
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        if search_text in line:
            return i
    return 0 