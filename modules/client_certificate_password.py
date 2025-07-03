#!/usr/bin/env python3
"""
Client Certificate Password Detection Module
Scans for hardcoded client certificate passwords in UIPath automation.

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
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Regex pattern to match both ClientCertificatePassword and SecureClientCertificatePassword attributes
# This will match even if the attribute is split across lines
PASSWORD_ATTR_PATTERN = re.compile(
    r'(ClientCertificatePassword|SecureClientCertificatePassword)\s*=\s*"([^"]+)"',
    re.IGNORECASE | re.MULTILINE
)

MODULE_DESCRIPTION = "Detects hardcoded ClientCertificatePassword and SecureClientCertificatePassword attributes in .xaml files. Flags as HIGH risk if not a variable or {x:Null}."

def scan_package(package_path: str, root_package_name: str = None, scanned_files: set = None) -> List[Dict[str, Any]]:
    """
    Scan a UIPath package for hardcoded client certificate passwords.
    
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
            'type': 'client_certificate_password',
            'severity': 'HIGH',
            'description': f'Error scanning package: {str(e)}',
            'file': str(package_path),
            'line': 0,
            'line_content': '',
            'module': 'client_certificate_password'
        })
    
    return issues

def scan_xaml_file(file_path: Path, root_package: Path, root_package_name: str = None) -> List[Dict[str, Any]]:
    """
    Scan a single .xaml file for hardcoded client certificate passwords.
    
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
        # Use regex to find all matches, even if attribute is split across lines
        for match in PASSWORD_ATTR_PATTERN.finditer(content):
            attr_name = match.group(1)
            attr_value = match.group(2)
            # Only report if not in [variable] format
            if not is_variable_format(attr_value):
                line_num = find_line_number(content, match.group(0))
                # Use root package name if provided, otherwise use current package name
                package_name = root_package_name if root_package_name else root_package.name
                issues.append({
                    'type': 'client_certificate_password',
                    'severity': 'HIGH',
                    'description': f'Hard-coded {attr_name} detected',
                    'file': str(file_path),
                    'line': line_num,
                    'line_content': match.group(0).strip(),
                    'package_name': package_name,
                    'module': 'client_certificate_password'
                })
    except Exception as e:
        logger.warning(f"Error reading file {file_path}: {str(e)}")
    return issues

def is_variable_format(value: str) -> bool:
    """
    Check if a value is in variable format [variable_name] or {x:Null}.
    
    Args:
        value: The value to check
        
    Returns:
        True if it's in variable format, False otherwise
    """
    stripped_value = value.strip()
    return (stripped_value.startswith('[') and stripped_value.endswith(']')) or stripped_value == '{x:Null}'

def find_line_number(content: str, search_text: str) -> int:
    """
    Find the line number for a specific text in the content.
    
    Args:
        content: The file content
        search_text: The text to search for
        
    Returns:
        Line number (1-indexed)
    """
    lines = content.split('\n')
    for line_num, line in enumerate(lines, 1):
        if search_text in line:
            return line_num
    return 0 