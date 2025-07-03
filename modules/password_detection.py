#!/usr/bin/env python3
"""
Password Detection Module
Scans for hardcoded password attributes in UIPath automation.

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

# Regex pattern to match Password attributes
# This will match even if the attribute is split across lines
# Uses word boundaries to avoid matching ClientCertificatePassword
# Also matches in_Password and out_Password
PASSWORD_ATTR_PATTERN = re.compile(
    r'\b(?:in_|out_)?Password\s*=\s*"([^"]+)"',
    re.IGNORECASE | re.MULTILINE
)

# Regex to match NetworkCredential pattern inside brackets
NETWORK_CREDENTIAL_PATTERN = re.compile(
    r'\[\s*(?:new|New)\s+System\.[Nn][Ee][Tt]\.NetworkCredential\(\s*(?:string\.Empty|&quot;&quot;)\s*,\s*&quot;([^&]+)&quot;\s*\)\.SecurePassword\s*\]',
    re.IGNORECASE
)

MODULE_DESCRIPTION = "Detects hardcoded Password, in_Password, and out_Password attributes in .xaml files. Flags as HIGH risk if not a variable or {x:Null}."

def scan_package(package_path: str, root_package_name: str = None, scanned_files: set = None) -> List[Dict[str, Any]]:
    """
    Scan a UIPath package for hardcoded passwords.
    
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
            'type': 'password_detection',
            'severity': 'HIGH',
            'description': f'Error scanning package: {str(e)}',
            'file': str(package_path),
            'line': 0,
            'line_content': '',
            'module': 'password_detection'
        })
    
    return issues

def scan_xaml_file(file_path: Path, root_package: Path, root_package_name: str = None) -> List[Dict[str, Any]]:
    """
    Scan a single .xaml file for hardcoded passwords.
    
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
        for match in PASSWORD_ATTR_PATTERN.finditer(content):
            attr_value = match.group(1)
            matched_text = match.group(0)
            
            # Use the improved helper to resolve any in_config inside brackets
            resolved_value = resolve_in_config_value(attr_value, root_package)
            # Check for NetworkCredential pattern
            network_cred_match = NETWORK_CREDENTIAL_PATTERN.search(attr_value.strip())
            if network_cred_match:
                extracted_password = network_cred_match.group(1)
            else:
                extracted_password = None
            if resolved_value:
                check_value = resolved_value
                original_value = attr_value
            else:
                check_value = attr_value
                original_value = attr_value
            
            # Only report if not in [variable] format and not {x:Null}
            if not is_variable_format(check_value):
                line_num = find_line_number(content, matched_text)
                package_name = root_package_name if root_package_name else root_package.name
                
                # Get the full line content
                full_line = lines[line_num - 1] if line_num > 0 and line_num <= len(lines) else ""
                
                # Determine if this is an In_Config/in_config pattern
                is_in_config = False
                if 'in_config' in attr_value.lower() or 'inconfig' in attr_value.lower():
                    is_in_config = True
                
                if extracted_password:
                    description = f'Hard-coded Password detected (NetworkCredential)'
                    content_line = f'{matched_text.strip()} -> {extracted_password}'
                elif resolved_value:
                    description = f'Hard-coded Password detected'
                    # Highlight the resolved value in yellow
                    highlighted_value = highlight_match(f'{matched_text.strip()} -> {resolved_value}', str(resolved_value))
                    content_line = highlighted_value
                elif is_in_config:
                    description = f'Hard-coded Password detected'
                    highlighted_missing = highlight_match(f'{matched_text.strip()} -> Value not in Config.xlsx', 'Value not in Config.xlsx')
                    content_line = highlighted_missing
                    severity = 'FALSE-POSITIVE'
                else:
                    description = f'Hard-coded Password detected'
                    content_line = matched_text.strip()
                    severity = 'HIGH'
                issues.append({
                    'type': 'password_detection',
                    'severity': severity if 'severity' in locals() else 'HIGH',
                    'description': description,
                    'file': str(file_path),
                    'line': line_num,
                    'line_content': content_line,
                    'full_line': full_line,
                    'matched_text': matched_text,
                    'package_name': package_name,
                    'module': 'password_detection'
                })
    except Exception as e:
        logger.warning(f"Error reading file {file_path}: {str(e)}")
    return issues

def is_variable_format(value: str) -> bool:
    """
    Check if a value is in variable format [variable_name] or {x:Null}.
    Note: In_Config patterns are NOT considered safe - they should be resolved and checked.
    """
    stripped_value = value.strip()
    # Only consider simple variable format [variable_name] as safe, not In_Config patterns
    if stripped_value.startswith('[') and stripped_value.endswith(']'):
        # Check if it's an In_Config pattern - if so, it's NOT safe
        if 'In_Config' in stripped_value:
            return False
        return True
    return stripped_value == '{x:Null}'

def find_line_number(content: str, search_text: str) -> int:
    """
    Find the line number for a specific text in the content.
    """
    lines = content.split('\n')
    for line_num, line in enumerate(lines, 1):
        if search_text in line:
            return line_num
    return 0 