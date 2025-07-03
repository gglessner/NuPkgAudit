#!/usr/bin/env python3
"""
SecureString Casting Module
Scans for dangerous .SecureString casting patterns in UIPath automation.

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

def scan_package(package_path: str) -> List[Dict[str, Any]]:
    """
    Scan a UIPath package for .SecureString casting patterns.
    
    Args:
        package_path: Path to the package directory
        
    Returns:
        List of issues found
    """
    issues = []
    package = Path(package_path)
    
    # File extensions to scan
    scan_extensions = {'.xaml', '.vb', '.cs', '.txt', '.json', '.xml', '.config', '.ini'}
    
    try:
        for file_path in package.iterdir():
            if file_path.is_file() and file_path.suffix.lower() in scan_extensions:
                file_issues = scan_file(file_path)
                if file_issues:
                    issues.extend(file_issues)
                    
    except Exception as e:
        logger.error(f"Error scanning package {package_path}: {str(e)}")
        issues.append({
            'type': 'securestring_casting',
            'severity': 'ERROR',
            'description': f'Error scanning package: {str(e)}',
            'file': str(package_path),
            'line': 0,
            'line_content': '',
            'module': 'securestring_casting'
        })
    
    return issues

def scan_file(file_path: Path) -> List[Dict[str, Any]]:
    """
    Scan a single file for .SecureString casting patterns.
    
    Args:
        file_path: Path to the file to scan
        
    Returns:
        List of issues found in the file
    """
    issues = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                line_issues = analyze_line_for_securestring(line, str(file_path), line_num)
                if line_issues:
                    issues.extend(line_issues)
                    
    except Exception as e:
        logger.warning(f"Error reading file {file_path}: {str(e)}")
    
    return issues

def analyze_line_for_securestring(line: str, file_path: str, line_num: int) -> List[Dict[str, Any]]:
    """
    Analyze a single line for .SecureString casting patterns.
    
    Args:
        line: The line content to analyze
        file_path: Path to the file
        line_num: Line number
        
    Returns:
        List of issues found in the line
    """
    issues = []
    
    # Pattern 1: InArgument with SecureString casting (most specific first)
    # Example: <InArgument x:TypeArguments="ss:SecureString">"password".ToSecureString()</InArgument>
    pattern1 = r'<InArgument[^>]*>["\'][^"\']+["\']\.ToSecureString\(\)[^<]*</InArgument>'
    matches1 = re.finditer(pattern1, line, re.IGNORECASE)
    
    for match in matches1:
        matched_content = match.group(0)
        
        # Skip if this is a false positive
        if is_false_positive(matched_content, line):
            continue
            
        issues.append({
            'type': 'securestring_casting',
            'severity': 'HIGH',
            'description': 'Potential InArgument with String cast to SecureString',
            'file': file_path,
            'line': line_num,
            'line_content': line.strip(),
            'matched_content': matched_content,
            'module': 'securestring_casting'
        })
    
    # Pattern 2: InArgument with SecurePassword casting
    # Example: <InArgument x:TypeArguments="ss:SecureString">"password".SecurePassword</InArgument>
    pattern2 = r'<InArgument[^>]*>["\'][^"\']+["\']\.SecurePassword[^<]*</InArgument>'
    matches2 = re.finditer(pattern2, line, re.IGNORECASE)
    
    for match in matches2:
        matched_content = match.group(0)
        
        # Skip if this is a false positive
        if is_false_positive(matched_content, line):
            continue
            
        issues.append({
            'type': 'securestring_casting',
            'severity': 'HIGH',
            'description': 'Potential InArgument with String cast to SecurePassword',
            'file': file_path,
            'line': line_num,
            'line_content': line.strip(),
            'matched_content': matched_content,
            'module': 'securestring_casting'
        })
    
    # Pattern 3: String literal cast to SecureString (standalone)
    # Example: "password123".ToSecureString()
    pattern3 = r'["\'][^"\']+["\']\.ToSecureString\(\)'
    matches3 = re.finditer(pattern3, line, re.IGNORECASE)
    
    for match in matches3:
        matched_content = match.group(0)
        
        # Skip if this is a false positive
        if is_false_positive(matched_content, line):
            continue
            
        # Skip if already matched by InArgument pattern
        if '<InArgument' in line and '</InArgument>' in line:
            continue
            
        issues.append({
            'type': 'securestring_casting',
            'severity': 'HIGH',
            'description': 'Potential String literal cast to SecureString',
            'file': file_path,
            'line': line_num,
            'line_content': line.strip(),
            'matched_content': matched_content,
            'module': 'securestring_casting'
        })
    
    # Pattern 4: String literal cast to SecurePassword (standalone)
    # Example: "password123".SecurePassword
    pattern4 = r'["\'][^"\']+["\']\.SecurePassword'
    matches4 = re.finditer(pattern4, line, re.IGNORECASE)
    
    for match in matches4:
        matched_content = match.group(0)
        
        # Skip if this is a false positive
        if is_false_positive(matched_content, line):
            continue
            
        # Skip if already matched by InArgument pattern
        if '<InArgument' in line and '</InArgument>' in line:
            continue
            
        issues.append({
            'type': 'securestring_casting',
            'severity': 'HIGH',
            'description': 'Potential String literal cast to SecurePassword',
            'file': file_path,
            'line': line_num,
            'line_content': line.strip(),
            'matched_content': matched_content,
            'module': 'securestring_casting'
        })
    
    return issues

def is_false_positive(value: str, full_line: str = None) -> bool:
    """
    Check if a matched value is a false positive.
    
    Args:
        value: The matched value
        full_line: The full line content for context
        
    Returns:
        True if this is a false positive, False otherwise
    """
    v = value.strip().lower()
    
    # Check for null/empty values
    if v in ('{x:null}', 'null', '""', "''"):
        return True
    
    # Check for boolean literals
    if value.strip() in {'True', 'False', 'TRUE', 'FALSE', 'true', 'false'}:
        return True
    
    # Check for integer or float values
    try:
        if isinstance(value, str) and value.strip():
            int(value.strip())
            return True
    except ValueError:
        try:
            float(value.strip())
            return True
        except ValueError:
            pass
    
    # Check for UIPath configuration patterns
    if full_line:
        uipath_config_patterns = [
            r'UiPath\.[A-Za-z]+\.[A-Za-z]+\.[A-Za-z]+\.[A-Za-z]+',
            r'UiPath\.[A-Za-z]+\.[A-Za-z]+\.[A-Za-z]+',
            r'UiPath\.[A-Za-z]+\.[A-Za-z]+',
            r'UiPath\.[A-Za-z]+',
        ]
        
        for pattern in uipath_config_patterns:
            if re.search(pattern, full_line, re.IGNORECASE):
                return True
    
    # Check for UIPath activity configuration values
    uipath_config_values = {
        'true', 'false', 'yes', 'no', '0', '1', '2', '3', '4', '5',
        '100', '200', '300', '500', '1000', '2000', '3000', '5000',
        'left', 'right', 'center', 'top', 'bottom', 'middle',
        'click', 'doubleclick', 'rightclick', 'hover',
        'visible', 'hidden', 'enabled', 'disabled',
        'text', 'value', 'innertext', 'outertext',
        'id', 'name', 'class', 'tag', 'xpath', 'css',
        'screenshot', 'image', 'file', 'folder', 'directory',
        'excel', 'csv', 'json', 'xml', 'txt', 'pdf',
        'chrome', 'firefox', 'edge', 'ie', 'safari',
        'windows', 'desktop', 'application', 'process',
        'wait', 'delay', 'timeout', 'interval', 'duration',
        'retry', 'continue', 'break', 'stop', 'pause',
        'start', 'end', 'begin', 'finish', 'complete',
        'success', 'error', 'warning', 'info', 'debug',
        'log', 'trace', 'verbose', 'quiet', 'silent',
        'default', 'automatic', 'manual', 'enabled', 'disabled',
        'visible', 'hidden', 'true', 'false', 'yes', 'no',
        'on', 'off', 'active', 'inactive', 'running', 'stopped',
        'open', 'closed', 'read', 'write', 'append', 'overwrite',
        'first', 'last', 'all', 'none', 'any', 'every',
        'before', 'after', 'during', 'while', 'until', 'since',
        'ascending', 'descending', 'alphabetical', 'numerical',
        'date', 'time', 'datetime', 'timestamp', 'utc', 'local',
        'utf-8', 'ascii', 'unicode', 'binary', 'hex', 'base64'
    }
    
    if v in uipath_config_values:
        return True
    
    # Check for numeric values
    if v.isdigit() and len(v) <= 5:
        return True
    
    # Check for UIPath variable references
    if re.match(r'^\[[A-Za-z_][A-Za-z0-9_]*\]$', value):
        return True
    
    return False 