#!/usr/bin/env python3
"""
SQL Injection Detection Module
Scans for SQL injection vulnerabilities in UIPath automation.

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

# Configure logging
logger = logging.getLogger(__name__)

MODULE_DESCRIPTION = "Detects SQL injection vulnerabilities in database queries, connection strings, and stored procedure calls. Flags string concatenation, unparameterized queries, and dynamic SQL construction."

def is_string_concatenation_sql_pattern(stripped_value):
    """
    Detect SQL queries using string concatenation which could lead to SQL injection
    """
    # Patterns for string concatenation in SQL
    concatenation_patterns = [
        r'SELECT\s+.*?\+.*?FROM',  # SELECT with + concatenation
        r'INSERT\s+.*?\+.*?VALUES',  # INSERT with + concatenation
        r'UPDATE\s+.*?\+.*?SET',  # UPDATE with + concatenation
        r'DELETE\s+.*?\+.*?WHERE',  # DELETE with + concatenation
        r'WHERE\s+.*?\+.*?[=<>]',  # WHERE clause with concatenation
        r'["\'].*?\+.*?["\'].*?WHERE',  # String concatenation in WHERE
        r'["\'].*?\+\s*\w+\s*\+.*?["\']',  # Variable concatenation pattern
        r'Query.*?=.*?["\'].*?\+.*?["\']',  # Query property with concatenation
        r'CommandText.*?=.*?["\'].*?\+.*?["\']',  # CommandText with concatenation
    ]
    
    for pattern in concatenation_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE | re.DOTALL):
            return True
    return False

def is_unparameterized_query_pattern(stripped_value):
    """
    Detect unparameterized database queries that may be vulnerable to SQL injection
    """
    # Look for SQL keywords with potential variable insertion
    unparameterized_patterns = [
        r'SELECT\s+.*?WHERE\s+.*?["\'].*?\[.*?\].*?["\']',  # Variables in WHERE clause
        r'INSERT\s+INTO\s+.*?VALUES\s*\(.*?\[.*?\].*?\)',  # Variables in INSERT VALUES
        r'UPDATE\s+.*?SET\s+.*?=\s*["\'].*?\[.*?\].*?["\']',  # Variables in UPDATE SET
        r'DELETE\s+FROM\s+.*?WHERE\s+.*?["\'].*?\[.*?\].*?["\']',  # Variables in DELETE WHERE
        r'EXEC\s+.*?\[.*?\]',  # Execute with variables
        r'sp_executesql.*?\[.*?\]',  # sp_executesql with variables
    ]
    
    for pattern in unparameterized_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE | re.DOTALL):
            return True
    return False

def is_dynamic_query_construction_pattern(stripped_value):
    """
    Detect dynamic SQL query construction patterns
    """
    dynamic_patterns = [
        r'["\']SELECT\s+.*?["\'].*?\+.*?["\'].*?["\']',  # Dynamic SELECT construction
        r'String\.Format\s*\(\s*["\'].*?SELECT.*?\{.*?\}.*?["\']',  # String.Format with SQL
        r'String\.Concat\s*\(.*?SELECT.*?\)',  # String.Concat with SQL
        r'\$["\']SELECT.*?\{.*?\}.*?["\']',  # String interpolation with SQL
        r'StringBuilder.*?Append.*?SELECT',  # StringBuilder with SQL
        r'["\'].*?WHERE.*?\{.*?\}.*?["\']',  # String interpolation in WHERE
    ]
    
    for pattern in dynamic_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE | re.DOTALL):
            return True
    return False

def is_database_connection_injection_pattern(stripped_value):
    """
    Detect potential SQL injection in database connection strings
    """
    connection_patterns = [
        r'Data\s+Source\s*=.*?\+.*?;',  # Data Source with concatenation
        r'Server\s*=.*?\+.*?;',  # Server with concatenation
        r'Database\s*=.*?\+.*?;',  # Database with concatenation
        r'ConnectionString.*?=.*?["\'].*?\+.*?["\']',  # ConnectionString with concatenation
        r'Initial\s+Catalog\s*=.*?\[.*?\]',  # Initial Catalog with variables
    ]
    
    for pattern in connection_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE | re.DOTALL):
            return True
    return False

def is_stored_procedure_injection_pattern(stripped_value):
    """
    Detect potential SQL injection in stored procedure calls
    """
    sp_patterns = [
        r'EXEC\s+.*?\+.*?;',  # EXEC with concatenation
        r'EXECUTE\s+.*?\+.*?;',  # EXECUTE with concatenation
        r'sp_.*?\+.*?;',  # Stored procedure with concatenation
        r'CALL\s+.*?\+.*?\(',  # CALL with concatenation
    ]
    
    for pattern in sp_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE | re.DOTALL):
            return True
    return False

def is_sql_comment_injection_pattern(stripped_value):
    """
    Detect SQL comment-based injection patterns
    """
    comment_patterns = [
        r'--.*?\+.*?',  # SQL line comment with concatenation
        r'/\*.*?\+.*?\*/',  # SQL block comment with concatenation
        r'["\'].*?--.*?["\']',  # String containing SQL comments
        r'["\'].*?/\*.*?\*/.*?["\']',  # String containing block comments
    ]
    
    for pattern in comment_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE | re.DOTALL):
            return True
    return False

def is_union_based_injection_pattern(stripped_value):
    """
    Detect UNION-based SQL injection patterns
    """
    union_patterns = [
        r'UNION\s+SELECT.*?\+.*?',  # UNION SELECT with concatenation
        r'["\'].*?UNION.*?["\'].*?\+',  # UNION in concatenated strings
        r'ORDER\s+BY.*?\+.*?',  # ORDER BY with concatenation (for column enumeration)
    ]
    
    for pattern in union_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE | re.DOTALL):
            return True
    return False

def determine_sql_injection_severity_and_description(attr_value):
    """
    Determine the severity and description for SQL injection vulnerabilities
    """
    stripped_value = attr_value.strip().strip('"').strip("'")
    
    # Critical patterns (HIGH severity)
    if (is_string_concatenation_sql_pattern(stripped_value) or 
        is_unparameterized_query_pattern(stripped_value)):
        return 'HIGH', 'SQL injection vulnerability detected - Unparameterized query with string concatenation'
    
    # High-risk patterns (HIGH severity)
    if (is_union_based_injection_pattern(stripped_value) or 
        is_sql_comment_injection_pattern(stripped_value)):
        return 'HIGH', 'SQL injection vulnerability detected - Advanced injection patterns found'
    
    # Medium-risk patterns (MEDIUM severity)
    if (is_dynamic_query_construction_pattern(stripped_value) or 
        is_database_connection_injection_pattern(stripped_value) or 
        is_stored_procedure_injection_pattern(stripped_value)):
        return 'MEDIUM', 'Potential SQL injection vulnerability - Dynamic SQL construction detected'
    
    return 'LOW', 'Potential SQL injection risk - Review query construction'

def scan_sql_injection_vulnerabilities(file_path, content, root_package=None):
    """
    Scan for SQL injection vulnerabilities in UIPath XAML files
    """
    results = []
    
    # SQL-related attributes to check
    sql_attributes = [
        'Query', 'CommandText', 'ConnectionString', 'SqlQuery', 'Statement',
        'Command', 'QueryString', 'DatabaseQuery', 'SqlStatement',
        'Value', 'Expression', 'Arguments', 'Parameters'
    ]
    
    # Create pattern for SQL-related attributes
    sql_pattern = '|'.join([rf'{attr}=' for attr in sql_attributes])
    
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        # Skip if line doesn't contain SQL-related attributes
        if not re.search(sql_pattern, line, re.IGNORECASE):
            continue
            
        # Look for attribute patterns
        for attr_name in sql_attributes:
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
                    if len(attr_value) < 10:
                        continue
                    
                    # Check if this looks like SQL content
                    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 
                                  'ALTER', 'EXEC', 'EXECUTE', 'CALL', 'sp_', 'FROM', 'WHERE']
                    
                    has_sql_keyword = any(keyword.lower() in attr_value.lower() for keyword in sql_keywords)
                    if not has_sql_keyword:
                        continue
                    
                    # Resolve config values if present  
                    resolved_value = resolve_in_config_value(attr_value, root_package) if root_package else None
                    
                    # Check various SQL injection patterns
                    is_vulnerable = (
                        is_string_concatenation_sql_pattern(attr_value) or
                        is_unparameterized_query_pattern(attr_value) or
                        is_dynamic_query_construction_pattern(attr_value) or
                        is_database_connection_injection_pattern(attr_value) or
                        is_stored_procedure_injection_pattern(attr_value) or
                        is_sql_comment_injection_pattern(attr_value) or
                        is_union_based_injection_pattern(attr_value)
                    )
                    
                    if is_vulnerable:
                        severity, description = determine_sql_injection_severity_and_description(attr_value)
                        
                        # Create highlighted content
                        matched_text = match.group(0)
                        
                        if resolved_value and resolved_value != attr_value:
                            # Show resolved value with highlighting
                            highlighted_value = highlight_match(f'{matched_text} -> {resolved_value}', str(resolved_value))
                            content_line = highlighted_value
                            description = f'{description} (resolved from Config.xlsx)'
                        else:
                            # Highlight the vulnerable pattern
                            content_line = highlight_match(matched_text, attr_value)
                        
                        results.append({
                            'line': line_num,
                            'content': content_line,
                            'severity': severity,
                            'description': description,
                            'module': 'sql_injection_detection'
                        })
    
    return results

def scan_package(package_path: str, root_package_name: str = None, scanned_files: set = None) -> List[Dict[str, Any]]:
    """
    Scan a UIPath package for SQL injection vulnerabilities.
    
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
            'type': 'sql_injection_detection',
            'severity': 'ERROR',
            'description': f'Error scanning package: {str(e)}',
            'file': str(package_path),
            'line': 0,
            'line_content': '',
            'module': 'sql_injection_detection'
        })
    
    return issues

def scan_xaml_file(file_path: Path, root_package: Path, root_package_name: str = None) -> List[Dict[str, Any]]:
    """
    Scan a single .xaml file for SQL injection vulnerabilities.
    
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
        
        # Use the existing scan_sql_injection_vulnerabilities function
        vulnerabilities = scan_sql_injection_vulnerabilities(file_path, content, root_package)
        
        # Convert to the expected format
        lines = content.split('\n')
        package_name = root_package_name if root_package_name else root_package.name
        
        for vuln in vulnerabilities:
            line_num = vuln['line']
            full_line = lines[line_num - 1] if line_num > 0 and line_num <= len(lines) else ""
            
            issues.append({
                'type': 'sql_injection_detection',
                'severity': vuln['severity'],
                'description': vuln['description'],
                'file': str(file_path),
                'line': line_num,
                'line_content': vuln['content'],
                'full_line': full_line,
                'matched_text': vuln['content'],
                'package_name': package_name,
                'module': 'sql_injection_detection'
            })
            
    except Exception as e:
        logger.error(f"Error scanning file {file_path}: {str(e)}")
        issues.append({
            'type': 'sql_injection_detection',
            'severity': 'ERROR',
            'description': f'Error scanning file: {str(e)}',
            'file': str(file_path),
            'line': 0,
            'line_content': '',
            'module': 'sql_injection_detection'
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