#!/usr/bin/env python3
"""
Database Security Detection Module
Scans for database-specific security vulnerabilities in UIPath automation.

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
import sys
import logging
from pathlib import Path
from typing import List, Dict, Any

# Add the libraries directory to the path
sys.path.append(str(Path(__file__).parent.parent / 'libraries'))

from config_helper import resolve_in_config_value
from highlight_helper import highlight_match

# Configure logging
logger = logging.getLogger(__name__)

MODULE_DESCRIPTION = "Detects database-specific security vulnerabilities including connection strings with embedded credentials, dynamic SQL construction, missing parameterized queries, and database admin credential exposure."

# Database security patterns
DATABASE_SECURITY_PATTERNS = {
    # Connection String Security Issues
    'sql_server_connection_with_password': {
        'pattern': r'(?:Server|Data Source)\s*=\s*[^;]+;\s*(?:Database|Initial Catalog)\s*=\s*[^;]+;[^;]*(?:Password|Pwd)\s*=\s*[^;]+',
        'severity': 'HIGH',
        'description': 'SQL Server connection string with embedded password'
    },
    'mysql_connection_with_password': {
        'pattern': r'(?:server|host)\s*=\s*[^;]+;[^;]*(?:password|pwd)\s*=\s*[^;]+',
        'severity': 'HIGH',
        'description': 'MySQL connection string with embedded password'
    },
    'postgresql_connection_with_password': {
        'pattern': r'(?:Host|Server)\s*=\s*[^;]+;[^;]*Password\s*=\s*[^;]+',
        'severity': 'HIGH',
        'description': 'PostgreSQL connection string with embedded password'
    },
    'oracle_connection_with_password': {
        'pattern': r'(?:Data Source|Server)\s*=\s*[^;]+;[^;]*Password\s*=\s*[^;]+',
        'severity': 'HIGH',
        'description': 'Oracle connection string with embedded password'
    },
    'mongodb_connection_with_password': {
        'pattern': r'mongodb://[^:]+:[^@]+@[^/]+',
        'severity': 'HIGH',
        'description': 'MongoDB connection string with embedded credentials'
    },
    
    # Admin/Privileged Account Usage
    'database_admin_credentials': {
        'pattern': r'(?:User(?:\s+Id)?|Username|Uid)\s*=\s*(?:sa|root|admin|administrator|dba|postgres|mysql)',
        'severity': 'HIGH',
        'description': 'Database admin/root account usage detected'
    },
    'sql_server_sa_account': {
        'pattern': r'(?:User(?:\s+Id)?|Username|Uid)\s*=\s*sa\b',
        'severity': 'HIGH',
        'description': 'SQL Server SA (system administrator) account usage'
    },
    'mysql_root_account': {
        'pattern': r'(?:User(?:\s+Id)?|Username|Uid)\s*=\s*root\b',
        'severity': 'HIGH',
        'description': 'MySQL root account usage detected'
    },
    
    # Dynamic SQL Construction Patterns
    'string_concatenation_sql': {
        'pattern': r'(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\s+[^"\']*\+\s*["\'][^"\']*["\']',
        'severity': 'HIGH',
        'description': 'Dynamic SQL construction using string concatenation'
    },
    'sql_injection_vulnerable_pattern': {
        'pattern': r'(?:SELECT|INSERT|UPDATE|DELETE)\s+[^"\']*\+\s*(?:in_|out_|io_)\w+',
        'severity': 'HIGH',
        'description': 'SQL query construction with user input - potential SQL injection'
    },
    'format_string_sql': {
        'pattern': r'(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)[^"\']*String\.Format\s*\(',
        'severity': 'MEDIUM',
        'description': 'SQL query using String.Format - potential injection risk'
    },
    
    # Missing Parameterized Query Indicators
    'hardcoded_where_clause': {
        'pattern': r'WHERE\s+\w+\s*=\s*["\'][^"\']+["\']',
        'severity': 'MEDIUM',
        'description': 'Hardcoded WHERE clause values - consider parameterized queries'
    },
    'hardcoded_insert_values': {
        'pattern': r'INSERT\s+INTO\s+\w+[^(]*\([^)]*\)\s+VALUES\s*\([^)]*["\'][^"\']*["\'][^)]*\)',
        'severity': 'MEDIUM',
        'description': 'Hardcoded INSERT values - consider parameterized queries'
    },
    
    # Database Command Execution Patterns
    'execute_sql_command': {
        'pattern': r'(?:ExecuteNonQuery|ExecuteScalar|ExecuteReader)\s*\(\s*["\'][^"\']*\+',
        'severity': 'HIGH',
        'description': 'SQL command execution with concatenated strings'
    },
    'sql_command_with_variables': {
        'pattern': r'(?:CommandText|Query)\s*=\s*[^"\']*\+\s*(?:in_|out_|io_)\w+',
        'severity': 'HIGH',
        'description': 'SQL command text built with variables - injection risk'
    },
    
    # Database Schema Manipulation
    'drop_table_command': {
        'pattern': r'DROP\s+TABLE\s+\w+',
        'severity': 'MEDIUM',
        'description': 'DROP TABLE command detected - potential data loss risk'
    },
    'truncate_table_command': {
        'pattern': r'TRUNCATE\s+TABLE\s+\w+',
        'severity': 'MEDIUM',
        'description': 'TRUNCATE TABLE command detected - data deletion risk'
    },
    'alter_table_command': {
        'pattern': r'ALTER\s+TABLE\s+\w+',
        'severity': 'LOW',
        'description': 'ALTER TABLE command detected - schema modification'
    },
    
    # Unsafe Database Configurations
    'integrated_security_false': {
        'pattern': r'Integrated\s+Security\s*=\s*(?:false|no|0)\b',
        'severity': 'MEDIUM',
        'description': 'Integrated Security disabled - using SQL authentication'
    },
    'trust_server_certificate': {
        'pattern': r'TrustServerCertificate\s*=\s*(?:true|yes|1)\b',
        'severity': 'MEDIUM',
        'description': 'TrustServerCertificate enabled - SSL certificate validation bypassed'
    },
    'encrypt_false': {
        'pattern': r'Encrypt\s*=\s*(?:false|no|0)\b',
        'severity': 'MEDIUM',
        'description': 'Database encryption disabled - data transmitted in plain text'
    },
    
    # Database Backup/Restore Operations
    'backup_to_disk': {
        'pattern': r'BACKUP\s+DATABASE\s+\w+\s+TO\s+DISK',
        'severity': 'LOW',
        'description': 'Database backup operation detected'
    },
    'restore_from_disk': {
        'pattern': r'RESTORE\s+DATABASE\s+\w+\s+FROM\s+DISK',
        'severity': 'MEDIUM',
        'description': 'Database restore operation detected - potential security risk'
    },
    
    # Stored Procedure Security
    'execute_stored_procedure': {
        'pattern': r'(?:EXEC|EXECUTE)\s+\w+\s+[^,]*\+',
        'severity': 'MEDIUM',
        'description': 'Stored procedure execution with concatenated parameters'
    },
    'dynamic_stored_procedure': {
        'pattern': r'(?:EXEC|EXECUTE)\s*\(\s*["\'][^"\']*\+',
        'severity': 'HIGH',
        'description': 'Dynamic stored procedure execution - injection risk'
    }
}

# Database-related attribute patterns
DATABASE_ATTRIBUTES = [
    'ConnectionString', 'SqlConnection', 'CommandText', 'Query', 'Sql',
    'Database', 'DataSource', 'Server', 'Host', 'Port', 'Schema',
    'Username', 'Password', 'UserId', 'Uid', 'Pwd', 'Auth',
    'Provider', 'Driver', 'Catalog', 'InitialCatalog'
]

def is_database_related_attribute(attr_name: str) -> bool:
    """Check if an attribute is database-related."""
    attr_lower = attr_name.lower()
    return any(db_attr.lower() in attr_lower for db_attr in DATABASE_ATTRIBUTES)

def analyze_sql_query_security(query: str) -> List[Dict[str, Any]]:
    """
    Analyze a SQL query for security issues.
    
    Args:
        query: SQL query string to analyze
        
    Returns:
        List of security issues found
    """
    issues = []
    query_upper = query.upper()
    
    # Check for common SQL injection patterns
    injection_patterns = [
        (r"'\s*OR\s+'", "SQL injection pattern: OR condition"),
        (r"'\s*AND\s+'", "SQL injection pattern: AND condition"),
        (r"--", "SQL comment detected - potential injection"),
        (r"/\*.*\*/", "SQL block comment detected"),
        (r";\s*(?:DROP|DELETE|UPDATE|INSERT)", "Multiple statements - potential injection"),
        (r"UNION\s+SELECT", "UNION SELECT detected - potential injection"),
        (r"1\s*=\s*1", "Always true condition - potential injection"),
        (r"'\s*=\s*'", "String comparison - potential injection")
    ]
    
    for pattern, description in injection_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            issues.append({
                'pattern': 'sql_injection_indicator',
                'severity': 'HIGH',
                'description': description,
                'matched_text': query
            })
    
    return issues

def scan_database_security(file_path, content, root_package=None):
    """
    Scan for database security issues in UIPath .xaml file content.
    
    Args:
        file_path: Path to the file being scanned
        content: Content of the file
        root_package: Root package path for config resolution
        
    Returns:
        List of database security issues found
    """
    results = []
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        # Skip empty lines and comments
        if not line.strip() or line.strip().startswith('<!--'):
            continue
            
        # Look for database-related attributes
        for attr_name in DATABASE_ATTRIBUTES:
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
                    if len(attr_value) < 3:
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
                        # Check against all database security patterns
                        for pattern_name, pattern_info in DATABASE_SECURITY_PATTERNS.items():
                            pattern_regex = pattern_info['pattern']
                            severity = pattern_info['severity']
                            description = pattern_info['description']
                            
                            if re.search(pattern_regex, check_value, re.IGNORECASE):
                                # Create highlighted content
                                matched_text = match.group(0)
                                
                                if value_type == "resolved":
                                    # Show resolved value with highlighting
                                    highlighted_value = highlight_match(f'{matched_text} -> {resolved_value}', check_value)
                                    description = f'{description} (resolved from Config.xlsx)'
                                    content_line = highlighted_value
                                else:
                                    # Highlight the issue in the original text
                                    highlighted_value = highlight_match(matched_text, check_value)
                                    content_line = highlighted_value
                                
                                results.append({
                                    'line': line_num,
                                    'line_content': content_line,
                                    'severity': severity,
                                    'description': description,
                                    'full_line': line.strip(),
                                    'matched_text': check_value,
                                    'pattern': pattern_name
                                })
                        
                        # Analyze SQL queries for additional security issues
                        if any(sql_keyword in attr_name.lower() for sql_keyword in ['sql', 'query', 'command']):
                            sql_issues = analyze_sql_query_security(check_value)
                            for issue in sql_issues:
                                matched_text = match.group(0)
                                
                                if value_type == "resolved":
                                    highlighted_value = highlight_match(f'{matched_text} -> {resolved_value}', check_value)
                                    description = f"{issue['description']} (resolved from Config.xlsx)"
                                else:
                                    highlighted_value = highlight_match(matched_text, check_value)
                                    description = issue['description']
                                
                                results.append({
                                    'line': line_num,
                                    'line_content': highlighted_value,
                                    'severity': issue['severity'],
                                    'description': description,
                                    'full_line': line.strip(),
                                    'matched_text': check_value,
                                    'pattern': issue['pattern']
                                })
    
    return results

def scan_package(package_path: str, root_package_name: str = None, scanned_files: set = None) -> List[Dict[str, Any]]:
    """
    Scan a UIPath package for database security issues.
    
    Args:
        package_path: Path to the package directory
        root_package_name: Name of the root package (for nested packages)
        scanned_files: Set of already scanned files (to avoid duplicates)
        
    Returns:
        List of database security issues found
    """
    if scanned_files is None:
        scanned_files = set()
    
    issues = []
    package_path = Path(package_path)
    
    # Determine the actual root package name
    if root_package_name is None:
        root_package_name = package_path.name
    
    try:
        # Scan .xaml files in the package
        for xaml_file in package_path.rglob('*.xaml'):
            if str(xaml_file) in scanned_files:
                continue
            scanned_files.add(str(xaml_file))
            
            file_issues = scan_xaml_file(xaml_file, package_path, root_package_name)
            issues.extend(file_issues)
        
        # Also scan other relevant files
        for ext in ['*.config', '*.xml', '*.json']:
            for config_file in package_path.rglob(ext):
                if str(config_file) in scanned_files:
                    continue
                scanned_files.add(str(config_file))
                
                try:
                    with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    file_issues = scan_database_security(config_file, content, package_path)
                    for issue in file_issues:
                        issue['file'] = str(config_file.relative_to(package_path.parent))
                        issue['package_name'] = root_package_name
                        issue['type'] = 'database_security'
                        issue['module'] = 'database_security_detection'
                    issues.extend(file_issues)
                    
                except Exception as e:
                    logger.warning(f"Error reading file {config_file}: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error scanning package {package_path}: {str(e)}")
    
    return issues

def scan_xaml_file(file_path: Path, root_package: Path, root_package_name: str = None) -> List[Dict[str, Any]]:
    """
    Scan a single .xaml file for database security issues.
    
    Args:
        file_path: Path to the .xaml file
        root_package: Root package path
        root_package_name: Name of the root package
        
    Returns:
        List of database security issues found
    """
    issues = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        file_issues = scan_database_security(file_path, content, root_package)
        
        for issue in file_issues:
            issue['file'] = str(file_path.relative_to(root_package.parent))
            issue['package_name'] = root_package_name or root_package.name
            issue['type'] = 'database_security'
            issue['module'] = 'database_security_detection'
        
        issues.extend(file_issues)
        
    except Exception as e:
        logger.warning(f"Error reading file {file_path}: {str(e)}")
    
    return issues

def find_line_number(content: str, search_text: str) -> int:
    """
    Find the line number where the search text appears.
    
    Args:
        content: Content to search in
        search_text: Text to search for
        
    Returns:
        Line number (1-indexed) or 1 if not found
    """
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        if search_text in line:
            return i
    return 1 