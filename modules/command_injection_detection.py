#!/usr/bin/env python3
"""
Command Injection Detection Module for UIPath Security Audit Tool
Detects command injection vulnerabilities in UIPath .xaml files

This module identifies patterns where user input or dynamic content is used
to construct system commands, which can lead to command injection attacks.
"""

import re
import sys
import logging
from pathlib import Path
from typing import List, Dict, Any

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
MODULE_DESCRIPTION = "Detects command injection vulnerabilities in system commands, PowerShell scripts, and file operations. Flags string concatenation, dynamic command construction, and unsafe user input usage."

def is_string_concatenation_command_pattern(stripped_value):
    """
    Detect command injection via string concatenation patterns.
    
    Args:
        stripped_value: The attribute value to check
        
    Returns:
        bool: True if string concatenation command pattern detected
    """
    # Common string concatenation patterns with system commands
    concatenation_patterns = [
        r'[\"\'].*[\"\']\s*\+\s*.*',  # "cmd" + variable
        r'.*\+\s*[\"\'].*[\"\']',     # variable + "cmd"
        r'[\"\'].*[\"\']\s*&\s*.*',   # "cmd" & variable (VB.NET)
        r'.*&\s*[\"\'].*[\"\']',      # variable & "cmd" (VB.NET)
    ]
    
    # Check for concatenation patterns
    for pattern in concatenation_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE):
            return True
    
    return False

def is_dynamic_command_construction_pattern(stripped_value):
    """
    Detect dynamic command construction patterns.
    
    Args:
        stripped_value: The attribute value to check
        
    Returns:
        bool: True if dynamic command construction detected
    """
    # Dynamic construction patterns
    construction_patterns = [
        r'String\.Format\s*\(',
        r'String\.Concat\s*\(',
        r'StringBuilder\.',
        r'\$[\"\'].*\{.*\}.*[\"\']',  # PowerShell string interpolation
        r'[\"\'].*\{.*\}.*[\"\']',    # String formatting
        r'Environment\.GetCommandLineArgs',
        r'Environment\.GetEnvironmentVariable',
        r'Process\.GetCommandLine',
    ]
    
    for pattern in construction_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE):
            return True
    
    return False

def is_shell_metacharacter_pattern(stripped_value):
    """
    Detect shell metacharacters that could indicate command injection.
    
    Args:
        stripped_value: The attribute value to check
        
    Returns:
        bool: True if shell metacharacters detected
    """
    # Dangerous shell metacharacters
    metacharacters = [
        r';\s*\w+',          # Command separation
        r'\|\s*\w+',         # Pipe to command
        r'&&\s*\w+',         # AND operator
        r'\|\|\s*\w+',       # OR operator
        r'`[^`]*`',          # Command substitution
        r'\$\([^)]*\)',      # Command substitution
        r'>\s*\w+',          # Output redirection
        r'<\s*\w+',          # Input redirection
        r'&\s*\w+',          # Background execution
    ]
    
    for pattern in metacharacters:
        if re.search(pattern, stripped_value, re.IGNORECASE):
            return True
    
    return False

def is_powershell_injection_pattern(stripped_value):
    """
    Detect PowerShell injection patterns.
    
    Args:
        stripped_value: The attribute value to check
        
    Returns:
        bool: True if PowerShell injection pattern detected
    """
    # PowerShell injection patterns
    powershell_patterns = [
        r'Invoke-Expression\s*\(',
        r'iex\s*\(',
        r'Invoke-Command\s*\(',
        r'icm\s*\(',
        r'Start-Process\s*.*-ArgumentList',
        r'cmd\s*/c\s*',
        r'powershell\s*-c\s*',
        r'powershell\s*-Command\s*',
        r'powershell\s*-EncodedCommand\s*',
        r'[&.]\s*\$\w+',     # Variable execution
    ]
    
    for pattern in powershell_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE):
            return True
    
    return False

def is_file_path_injection_pattern(stripped_value):
    """
    Detect file path injection patterns.
    
    Args:
        stripped_value: The attribute value to check
        
    Returns:
        bool: True if file path injection pattern detected
    """
    # File path injection patterns
    path_patterns = [
        r'\.\.[\\/]',        # Directory traversal
        r'[\\/]\.\.[\\/]',   # Directory traversal in path
        r'%\w+%',            # Environment variable expansion
        r'\$env:\w+',        # PowerShell environment variables
        r'[\"\'].*[\"\']\s*\+\s*.*[\\/]',  # Path concatenation
        r'System\.IO\.Path\.Combine\s*\(',  # Dynamic path combination
    ]
    
    for pattern in path_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE):
            return True
    
    return False

def is_registry_injection_pattern(stripped_value):
    """
    Detect registry injection patterns.
    
    Args:
        stripped_value: The attribute value to check
        
    Returns:
        bool: True if registry injection pattern detected
    """
    # Registry injection patterns
    registry_patterns = [
        r'HKEY_[A-Z_]+\\.*\+',  # Registry key concatenation
        r'Registry\.\w+\s*\(',
        r'RegistryKey\.\w+\s*\(',
        r'reg\s+add\s+',
        r'reg\s+delete\s+',
        r'reg\s+query\s+',
    ]
    
    for pattern in registry_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE):
            return True
    
    return False

def determine_command_injection_severity_and_description(attr_value):
    """
    Determine the severity and description of a command injection vulnerability.
    
    Args:
        attr_value: The attribute value to analyze
        
    Returns:
        tuple: (severity, description)
    """
    # Check for different types of command injection
    if is_string_concatenation_command_pattern(attr_value):
        return 'HIGH', 'Command injection vulnerability detected - String concatenation with system commands'
    
    if is_shell_metacharacter_pattern(attr_value):
        return 'HIGH', 'Command injection vulnerability detected - Shell metacharacters found'
    
    if is_powershell_injection_pattern(attr_value):
        return 'HIGH', 'Command injection vulnerability detected - PowerShell injection patterns found'
    
    if is_dynamic_command_construction_pattern(attr_value):
        return 'MEDIUM', 'Potential command injection vulnerability - Dynamic command construction detected'
    
    if is_file_path_injection_pattern(attr_value):
        return 'MEDIUM', 'Potential command injection vulnerability - File path injection patterns found'
    
    if is_registry_injection_pattern(attr_value):
        return 'MEDIUM', 'Potential command injection vulnerability - Registry injection patterns found'
    
    return 'LOW', 'Potential command injection risk - Review command construction'

def scan_command_injection_vulnerabilities(file_path, content, root_package=None):
    """
    Scan for command injection vulnerabilities in UIPath .xaml file content.
    
    Args:
        file_path: Path to the file being scanned
        content: Content of the file
        root_package: Root package path for config resolution
        
    Returns:
        List of vulnerabilities found
    """
    results = []
    
    # Command injection related attributes
    command_attributes = [
        'CommandLine', 'FileName', 'Arguments', 'WorkingDirectory', 'Script',
        'PowerShellScript', 'Command', 'ProcessName', 'Path', 'Key', 'Value',
        'ArgumentList', 'ScriptBlock', 'FilePath', 'FullName', 'ExecutablePath',
        'ShellExecute', 'UseShellExecute', 'Verb', 'WindowStyle', 'CreateNoWindow',
        'RedirectStandardOutput', 'RedirectStandardError', 'RedirectStandardInput',
        'StandardOutputEncoding', 'StandardErrorEncoding', 'StandardInputEncoding'
    ]
    
    # Create pattern for command-related attributes
    command_pattern = '|'.join([rf'{attr}=' for attr in command_attributes])
    
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        # Skip if line doesn't contain command-related attributes
        if not re.search(command_pattern, line, re.IGNORECASE):
            continue
            
        # Look for attribute patterns
        for attr_name in command_attributes:
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
                    if len(attr_value) < 5:
                        continue
                    
                    # Skip null values and simple variables
                    if attr_value.lower() in ['{x:null}', 'nothing', 'null', '']:
                        continue
                    
                    # Check if this looks like a command or script
                    command_keywords = ['cmd', 'powershell', 'bash', 'sh', 'exe', 'bat', 'ps1', 
                                      'python', 'java', 'node', 'perl', 'ruby', 'php']
                    
                    has_command_keyword = any(keyword.lower() in attr_value.lower() for keyword in command_keywords)
                    has_path_chars = any(char in attr_value for char in ['\\', '/', '.', ':', '|', '&', ';', '>', '<'])
                    
                    if not (has_command_keyword or has_path_chars):
                        continue
                    
                    # Resolve config values if present  
                    resolved_value = resolve_in_config_value(attr_value, root_package) if root_package else None
                    
                    # Check various command injection patterns
                    is_vulnerable = (
                        is_string_concatenation_command_pattern(attr_value) or
                        is_dynamic_command_construction_pattern(attr_value) or
                        is_shell_metacharacter_pattern(attr_value) or
                        is_powershell_injection_pattern(attr_value) or
                        is_file_path_injection_pattern(attr_value) or
                        is_registry_injection_pattern(attr_value)
                    )
                    
                    if is_vulnerable:
                        severity, description = determine_command_injection_severity_and_description(attr_value)
                        
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
                            'module': 'command_injection_detection'
                        })
    
    return results

def scan_package(package_path: str, root_package_name: str = None, scanned_files: set = None) -> List[Dict[str, Any]]:
    """
    Scan a UIPath package for command injection vulnerabilities.
    
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
            'type': 'command_injection_detection',
            'severity': 'ERROR',
            'description': f'Error scanning package: {str(e)}',
            'file': str(package_path),
            'line': 0,
            'line_content': '',
            'module': 'command_injection_detection'
        })
    
    return issues

def scan_xaml_file(file_path: Path, root_package: Path, root_package_name: str = None) -> List[Dict[str, Any]]:
    """
    Scan a single .xaml file for command injection vulnerabilities.
    
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
        
        # Use the existing scan_command_injection_vulnerabilities function
        vulnerabilities = scan_command_injection_vulnerabilities(file_path, content, root_package)
        
        # Convert to the expected format
        lines = content.split('\n')
        package_name = root_package_name if root_package_name else root_package.name
        
        for vuln in vulnerabilities:
            line_num = vuln['line']
            full_line = lines[line_num - 1] if line_num > 0 and line_num <= len(lines) else ""
            
            issues.append({
                'type': 'command_injection_detection',
                'severity': vuln['severity'],
                'description': vuln['description'],
                'file': str(file_path),
                'line': line_num,
                'line_content': vuln['content'],
                'full_line': full_line,
                'matched_text': vuln['content'],
                'package_name': package_name,
                'module': 'command_injection_detection'
            })
            
    except Exception as e:
        logger.error(f"Error scanning file {file_path}: {str(e)}")
        issues.append({
            'type': 'command_injection_detection',
            'severity': 'ERROR',
            'description': f'Error scanning file: {str(e)}',
            'file': str(file_path),
            'line': 0,
            'line_content': '',
            'module': 'command_injection_detection'
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