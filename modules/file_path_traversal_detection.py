#!/usr/bin/env python3
"""
File Path Traversal Detection Module for UIPath Security Audit Tool
Detects path traversal vulnerabilities in UIPath .xaml files

This module identifies patterns where file paths can be manipulated to access
unauthorized files or directories, leading to path traversal attacks.
"""

import re
import sys
import logging
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
MODULE_DESCRIPTION = "Detects file path traversal vulnerabilities including directory traversal, absolute path injection, environment variable abuse, and unsafe file operations."

# Path traversal patterns with severity levels
PATH_TRAVERSAL_PATTERNS = {
    # Directory traversal patterns
    'classic_traversal': {
        'pattern': r'\.\.[\\/]',
        'severity': 'HIGH',
        'description': 'Directory traversal attack detected - Classic ../ or ..\\ pattern'
    },
    'encoded_traversal': {
        'pattern': r'%2e%2e[\\/]|%2e%2e%2f|%2e%2e%5c',
        'severity': 'HIGH',
        'description': 'Directory traversal attack detected - URL encoded ../ pattern'
    },
    'double_encoded_traversal': {
        'pattern': r'%252e%252e[\\/]|%252e%252e%252f|%252e%252e%255c',
        'severity': 'HIGH',
        'description': 'Directory traversal attack detected - Double URL encoded ../ pattern'
    },
    'unicode_traversal': {
        'pattern': r'\.\.[\u002f\u005c\uff0f\uff3c]',
        'severity': 'HIGH',
        'description': 'Directory traversal attack detected - Unicode path separator'
    },
    'mixed_traversal': {
        'pattern': r'\.\.[\\/][\\/]+|\.\.[\\/]\.\.[\\/]',
        'severity': 'HIGH',
        'description': 'Directory traversal attack detected - Mixed or multiple separators'
    },
    
    # Absolute path injection
    'windows_absolute_path': {
        'pattern': r'[a-zA-Z]:\\|\\\\[^\\]+\\',
        'severity': 'MEDIUM',
        'description': 'Absolute path injection detected - Windows path'
    },
    'unix_absolute_path': {
        'pattern': r'^/[^/]',
        'severity': 'MEDIUM',
        'description': 'Absolute path injection detected - Unix path'
    },
    'unc_path': {
        'pattern': r'\\\\[^\\]+\\[^\\]+',
        'severity': 'HIGH',
        'description': 'UNC path injection detected - Network path access'
    },
    
    # Environment variable abuse
    'windows_env_vars': {
        'pattern': r'%[A-Z_][A-Z0-9_]*%',
        'severity': 'MEDIUM',
        'description': 'Environment variable in path - Potential path manipulation'
    },
    'powershell_env_vars': {
        'pattern': r'\$env:[A-Z_][A-Z0-9_]*',
        'severity': 'MEDIUM',
        'description': 'PowerShell environment variable in path - Potential manipulation'
    },
    'cmd_env_vars': {
        'pattern': r'%[A-Z_][A-Z0-9_]*%',
        'severity': 'MEDIUM',
        'description': 'Command prompt environment variable in path'
    },
    
    # Dangerous system paths
    'windows_system_paths': {
        'pattern': r'(?i)(C:\\Windows\\System32|C:\\Windows\\SysWOW64|C:\\Program Files)',
        'severity': 'HIGH',
        'description': 'System directory access detected - Potential privilege escalation'
    },
    'unix_system_paths': {
        'pattern': r'(?i)(/etc/|/bin/|/sbin/|/usr/bin/|/usr/sbin/|/root/)',
        'severity': 'HIGH',
        'description': 'System directory access detected - Potential privilege escalation'
    },
    'config_files': {
        'pattern': r'(?i)(\.config|\.ini|\.conf|web\.config|app\.config)',
        'severity': 'MEDIUM',
        'description': 'Configuration file access detected - Potential information disclosure'
    },
    
    # Archive extraction (Zip Slip)
    'zip_slip': {
        'pattern': r'(\.zip|\.tar|\.gz|\.7z|\.rar).*\.\.[/\\]',
        'severity': 'HIGH',
        'description': 'Zip Slip vulnerability detected - Archive extraction path traversal'
    },
    
    # Null byte injection
    'null_byte_injection': {
        'pattern': r'%00|\x00',
        'severity': 'HIGH',
        'description': 'Null byte injection detected - File extension bypass'
    },
    
    # File inclusion patterns
    'file_inclusion': {
        'pattern': r'file://|file:///|file:\\\\',
        'severity': 'MEDIUM',
        'description': 'File URI scheme detected - Potential local file inclusion'
    },
    
    # Backup and temporary files
    'backup_files': {
        'pattern': r'\.bak|\.backup|\.old|\.tmp|\.temp|~$',
        'severity': 'LOW',
        'description': 'Backup or temporary file access - Potential information disclosure'
    }
}

# File operation attributes that commonly contain file paths
FILE_PATH_ATTRIBUTES = [
    'FileName', 'FilePath', 'Path', 'FullPath', 'Source', 'Target', 'Destination',
    'InputPath', 'OutputPath', 'Directory', 'Folder', 'Location', 'Uri', 'Url',
    'From', 'To', 'File', 'ArchivePath', 'ExtractPath', 'WorkingDirectory',
    'BasePath', 'RootPath', 'RelativePath', 'AbsolutePath', 'Value', 'Text'
]

def is_safe_path_pattern(value: str) -> bool:
    """
    Check if a path pattern is considered safe (likely not a traversal attack).
    
    Args:
        value: The path value to check
        
    Returns:
        bool: True if the path appears safe
    """
    value_lower = value.lower()
    
    # Safe patterns that are unlikely to be attacks
    safe_patterns = [
        r'^[a-zA-Z0-9_\-\.]+$',  # Simple filename
        r'^[a-zA-Z0-9_\-\.\\\/]+$',  # Simple relative path
        r'^\w+\.(txt|csv|xlsx|pdf|doc|docx|xml|json)$',  # Common file extensions
        r'^output[\\/][\w\-\.]+$',  # Output directory
        r'^temp[\\/][\w\-\.]+$',  # Temp directory
        r'^data[\\/][\w\-\.]+$',  # Data directory
    ]
    
    # Check if it matches any safe pattern
    for pattern in safe_patterns:
        if re.match(pattern, value, re.IGNORECASE):
            return True
    
    # Check for obvious placeholders
    placeholders = [
        'example', 'sample', 'test', 'demo', 'placeholder', 'dummy',
        'template', 'default', 'your_file', 'file_name', 'path_here'
    ]
    
    for placeholder in placeholders:
        if placeholder in value_lower:
            return True
    
    return False

def check_context_for_safety(line: str, value: str) -> bool:
    """
    Check if the context suggests this is a safe operation.
    
    Args:
        line: The full line containing the path
        value: The path value
        
    Returns:
        bool: True if context suggests safety
    """
    line_lower = line.lower()
    
    # Safe context indicators
    safe_contexts = [
        'displayname', 'comment', 'description', 'example', 'sample',
        'test', 'demo', 'placeholder', 'template'
    ]
    
    return any(context in line_lower for context in safe_contexts)

def scan_file_path_traversal(file_path, content, root_package=None):
    """
    Scan for file path traversal vulnerabilities in UIPath .xaml file content.
    
    Args:
        file_path: Path to the file being scanned
        content: Content of the file
        root_package: Root package path for config resolution
        
    Returns:
        List of path traversal vulnerabilities found
    """
    results = []
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        # Skip comment lines
        if line.strip().startswith('<!--'):
            continue
        
        # Look for file path attributes
        for attr_name in FILE_PATH_ATTRIBUTES:
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
                    if len(attr_value) < 2:
                        continue
                    
                    # Skip null values and simple variables
                    if attr_value.lower() in ['{x:null}', 'nothing', 'null', '', 'true', 'false']:
                        continue
                    
                    # Check if it's a safe path pattern
                    if is_safe_path_pattern(attr_value):
                        continue
                    
                    # Check if context suggests safety
                    if check_context_for_safety(line, attr_value):
                        continue
                    
                    # Resolve config values if present
                    resolved_value = resolve_in_config_value(attr_value, root_package) if root_package else None
                    
                    # Check both original and resolved values
                    values_to_check = [(attr_value, "original")]
                    if resolved_value and resolved_value != attr_value:
                        values_to_check.append((resolved_value, "resolved"))
                    
                    for check_value, value_type in values_to_check:
                        # Check against all path traversal patterns
                        for pattern_name, pattern_info in PATH_TRAVERSAL_PATTERNS.items():
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
                                    # Highlight the path in the original text
                                    highlighted_value = highlight_match(matched_text, check_value)
                                    content_line = highlighted_value
                                
                                results.append({
                                    'line': line_num,
                                    'content': content_line,
                                    'severity': severity,
                                    'description': description,
                                    'module': 'file_path_traversal_detection',
                                    'pattern_type': pattern_name,
                                    'path_value': check_value
                                })
                                
                                # Break after first match to avoid duplicates
                                break
    
    return results

def scan_package(package_path: str, root_package_name: str = None, scanned_files: set = None) -> List[Dict[str, Any]]:
    """
    Scan a UIPath package for file path traversal vulnerabilities.
    
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
            'type': 'file_path_traversal_detection',
            'severity': 'ERROR',
            'description': f'Error scanning package: {str(e)}',
            'file': str(package_path),
            'line': 0,
            'line_content': '',
            'module': 'file_path_traversal_detection'
        })
    
    return issues

def scan_xaml_file(file_path: Path, root_package: Path, root_package_name: str = None) -> List[Dict[str, Any]]:
    """
    Scan a single .xaml file for file path traversal vulnerabilities.
    
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
        
        # Use the existing scan_file_path_traversal function
        traversal_issues = scan_file_path_traversal(file_path, content, root_package)
        
        # Convert to the expected format
        lines = content.split('\n')
        package_name = root_package_name if root_package_name else root_package.name
        
        for issue in traversal_issues:
            line_num = issue['line']
            full_line = lines[line_num - 1] if line_num > 0 and line_num <= len(lines) else ""
            
            issues.append({
                'type': 'file_path_traversal_detection',
                'severity': issue['severity'],
                'description': issue['description'],
                'file': str(file_path),
                'line': line_num,
                'line_content': issue['content'],
                'full_line': full_line,
                'matched_text': issue['content'],
                'package_name': package_name,
                'module': 'file_path_traversal_detection',
                'pattern_type': issue.get('pattern_type', 'unknown'),
                'path_value': issue.get('path_value', '')
            })
            
    except Exception as e:
        logger.error(f"Error scanning file {file_path}: {str(e)}")
        issues.append({
            'type': 'file_path_traversal_detection',
            'severity': 'ERROR',
            'description': f'Error scanning file: {str(e)}',
            'file': str(file_path),
            'line': 0,
            'line_content': '',
            'module': 'file_path_traversal_detection'
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