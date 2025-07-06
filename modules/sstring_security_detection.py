#!/usr/bin/env python3
"""
SString (SecureString) Security Detection Module
Tracks sensitive variable declarations and monitors their usage patterns to detect insecure handling.

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
from typing import List, Dict, Any, Set, Tuple
from dataclasses import dataclass

# Add the libraries directory to the path
sys.path.append(str(Path(__file__).parent.parent / 'libraries'))

from config_helper import resolve_in_config_value
from highlight_helper import highlight_match

# Configure logging
logger = logging.getLogger(__name__)

MODULE_DESCRIPTION = "Tracks sensitive variable declarations (SecureString, SString, etc.) and monitors their usage patterns to detect insecure assignments, logging, string conversions, or exposure throughout workflows."

@dataclass
class SensitiveVariable:
    """Represents a sensitive variable and its properties."""
    name: str
    var_type: str
    declared_line: int
    declared_file: str
    scope: str = "workflow"
    is_secure: bool = True

class SStringSecurityAnalyzer:
    """Analyzes SString and SecureString usage patterns in XAML content."""
    
    def __init__(self):
        self.sensitive_variables: Dict[str, SensitiveVariable] = {}
        self.current_file = ""
        
        # Sensitive variable type patterns
        self.sensitive_types = {
            'SecureString': r'(?:System\.Security\.)?SecureString',
            'SString': r'SString',
            'SecurePassword': r'SecurePassword',
            'NetworkCredential': r'(?:System\.Net\.)?NetworkCredential',
            'PSCredential': r'(?:System\.Management\.Automation\.)?PSCredential',
            'X509Certificate2': r'(?:System\.Security\.Cryptography\.X509Certificates\.)?X509Certificate2'
        }
        
        # Insecure usage patterns
        self.insecure_patterns = {
            'string_conversion': {
                'pattern': r'\.ToString\(\)',
                'severity': 'HIGH',
                'description': 'SecureString converted to plain string - exposes sensitive data'
            },
            'string_format': {
                'pattern': r'String\.Format\([^)]*{var_name}',
                'severity': 'HIGH', 
                'description': 'Sensitive variable used in String.Format - potential exposure'
            },
            'string_concatenation': {
                'pattern': r'["\'][^"\']*\+\s*{var_name}|\+\s*{var_name}\s*\+',
                'severity': 'HIGH',
                'description': 'Sensitive variable used in string concatenation - exposes data'
            },
            'log_message': {
                'pattern': r'(?:Log\s+Message|WriteLog|Console\.Write)',
                'severity': 'HIGH',
                'description': 'Sensitive variable potentially logged - data exposure risk'
            },
            'write_text_file': {
                'pattern': r'Write\s+Text\s+File',
                'severity': 'HIGH',
                'description': 'Sensitive variable written to file - persistent exposure risk'
            },
            'message_box': {
                'pattern': r'Message\s+Box',
                'severity': 'MEDIUM',
                'description': 'Sensitive variable displayed in message box - UI exposure'
            },
            'assign_to_string': {
                'pattern': r'(?:String|Text)\s*=\s*{var_name}',
                'severity': 'HIGH',
                'description': 'SecureString assigned to plain string variable - data exposure'
            },
            'http_request_body': {
                'pattern': r'(?:Body|Content)\s*=.*{var_name}',
                'severity': 'HIGH',
                'description': 'Sensitive variable used in HTTP request body - network exposure'
            },
            'sql_query': {
                'pattern': r'(?:Query|CommandText)\s*=.*{var_name}',
                'severity': 'HIGH',
                'description': 'Sensitive variable used in SQL query - database exposure'
            },
            'json_serialize': {
                'pattern': r'(?:JsonConvert\.SerializeObject|Serialize).*{var_name}',
                'severity': 'MEDIUM',
                'description': 'Sensitive variable serialized to JSON - potential exposure'
            },
            'xml_serialize': {
                'pattern': r'(?:XmlSerializer|Serialize).*{var_name}',
                'severity': 'MEDIUM',
                'description': 'Sensitive variable serialized to XML - potential exposure'
            }
        }
    
    def find_sensitive_variable_declarations(self, content: str, file_path: str) -> List[SensitiveVariable]:
        """Find all sensitive variable declarations in the content."""
        sensitive_vars = []
        lines = content.split('\n')
        
        # Patterns for variable declarations
        declaration_patterns = [
            # Variable declarations with type
            r'<Variable\s+x:TypeArguments="([^"]*(?:SecureString|SString|SecurePassword|NetworkCredential|PSCredential|X509Certificate2)[^"]*)"\s+Name="([^"]*)"',
            # Property declarations
            r'<Property\s+Name="([^"]*)"\s+Type="[^"]*(?:SecureString|SString|SecurePassword|NetworkCredential|PSCredential|X509Certificate2)[^"]*"',
            # InArgument/OutArgument declarations
            r'<(?:InArgument|OutArgument|InOutArgument)\s+x:TypeArguments="([^"]*(?:SecureString|SString|SecurePassword|NetworkCredential|PSCredential|X509Certificate2)[^"]*)"\s+x:Key="([^"]*)"'
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in declaration_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    if len(match.groups()) >= 2:
                        var_type = match.group(1)
                        var_name = match.group(2)
                    else:
                        var_type = "SecureString"
                        var_name = match.group(1)
                    
                    # Determine if it's truly secure
                    is_secure = any(secure_type in var_type for secure_type in self.sensitive_types.values())
                    
                    sensitive_var = SensitiveVariable(
                        name=var_name,
                        var_type=var_type,
                        declared_line=line_num,
                        declared_file=file_path,
                        is_secure=is_secure
                    )
                    sensitive_vars.append(sensitive_var)
                    self.sensitive_variables[var_name] = sensitive_var
        
        return sensitive_vars
    
    def find_variable_usage_violations(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find insecure usage patterns of tracked sensitive variables."""
        violations = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for var_name, var_info in self.sensitive_variables.items():
                # Skip if variable not used in this line
                if var_name not in line:
                    continue
                
                # Check each insecure pattern
                for pattern_name, pattern_info in self.insecure_patterns.items():
                    pattern = pattern_info['pattern'].replace('{var_name}', re.escape(var_name))
                    
                    if re.search(pattern, line, re.IGNORECASE):
                        # Additional context checks
                        context_safe = self.check_safe_context(line, var_name, pattern_name)
                        
                        if not context_safe:
                            highlighted_line = highlight_match(line, var_name)
                            
                            violations.append({
                                'line': line_num,
                                'line_content': highlighted_line,
                                'severity': pattern_info['severity'],
                                'description': f"{pattern_info['description']} (variable: {var_name}, type: {var_info.var_type})",
                                'full_line': line.strip(),
                                'matched_text': var_name,
                                'pattern': f'sstring_{pattern_name}',
                                'variable_info': var_info
                            })
        
        return violations
    
    def check_safe_context(self, line: str, var_name: str, pattern_name: str) -> bool:
        """Check if the usage is in a safe context."""
        line_lower = line.lower()
        
        # Safe contexts for certain patterns
        safe_contexts = {
            'string_conversion': [
                # Safe if it's being assigned back to a secure type
                'securestring', 'sstring', 'securepassword'
            ],
            'log_message': [
                # Safe if it's just logging the variable name, not value
                'variable name', 'var name', 'parameter name'
            ]
        }
        
        if pattern_name in safe_contexts:
            return any(safe_ctx in line_lower for safe_ctx in safe_contexts[pattern_name])
        
        # Check for null/empty checks (generally safe)
        null_check_patterns = [
            rf'{re.escape(var_name)}\s+is\s+nothing',
            rf'string\.isnullorempty\({re.escape(var_name)}\)',
            rf'{re.escape(var_name)}\s*==\s*null',
            rf'{re.escape(var_name)}\.length\s*[<>=]'
        ]
        
        return any(re.search(pattern, line, re.IGNORECASE) for pattern in null_check_patterns)
    
    def find_insecure_assignments(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find insecure assignments to sensitive variables."""
        violations = []
        lines = content.split('\n')
        
        # Patterns for insecure assignments (looking for attribute assignments)
        insecure_assignment_patterns = [
            # Attribute assignments with sensitive types - Fixed to allow exact matches
            r'(\w*(?:SecureString|SString|SecurePassword|SecureText|NetworkCredential|PSCredential|X509Certificate2)\w*)\s*=\s*"([^"]*)"',
            r'(\w*(?:SecureString|SString|SecurePassword|SecureText|NetworkCredential|PSCredential|X509Certificate2)\w*)\s*=\s*\'([^\']*)\'',
            r'(\w*(?:SecureString|SString|SecurePassword|SecureText|NetworkCredential|PSCredential|X509Certificate2)\w*)\s*=\s*([^"\'\s>]+)',
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in insecure_assignment_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    attr_name = match.group(1)
                    if len(match.groups()) >= 2:
                        attr_value = match.group(2)
                    else:
                        attr_value = match.group(1)
                    
                    # Skip if it's a safe variable format (including {x:Null})
                    if is_variable_format(attr_value):
                        continue
                    
                    # Skip if it's a secure assignment method
                    if self.is_secure_assignment(line):
                        continue
                    
                    highlighted_line = highlight_match(line, attr_name)
                    
                    violations.append({
                        'line': line_num,
                        'line_content': highlighted_line,
                        'severity': 'HIGH',
                        'description': f'Insecure assignment to sensitive attribute (attribute: {attr_name}, value: {attr_value})',
                        'full_line': line.strip(),
                        'matched_text': attr_name,
                        'pattern': 'sstring_insecure_assignment'
                    })
        
        return violations
    
    def is_secure_assignment(self, line: str) -> bool:
        """Check if the assignment uses secure methods."""
        secure_assignment_patterns = [
            r'SecureStringToBSTR',
            r'SecureStringToGlobalAllocAnsi',
            r'SecureStringToGlobalAllocUnicode',
            r'ConvertTo-SecureString',
            r'NetworkCredential\([^)]*\)\.SecurePassword',
            r'DirectCast\([^)]*,\s*SecureString\)',
            r'CType\([^)]*,\s*SecureString\)',
            r'TryCast\([^)]*,\s*SecureString\)',
            r'New\s+SecureString\(',
            r'\.SecurePassword\b'
        ]
        
        return any(re.search(pattern, line, re.IGNORECASE) for pattern in secure_assignment_patterns)

def scan_sstring_security(file_path, content, root_package=None):
    """
    Scan for SString/SecureString security issues in UIPath .xaml file content.
    
    Args:
        file_path: Path to the file being scanned
        content: Content of the file
        root_package: Root package path for config resolution
        
    Returns:
        List of SString security issues found
    """
    analyzer = SStringSecurityAnalyzer()
    analyzer.current_file = str(file_path)
    results = []
    
    # Step 1: Find all sensitive variable declarations
    sensitive_vars = analyzer.find_sensitive_variable_declarations(content, str(file_path))
    
    # Step 2: Find usage violations
    usage_violations = analyzer.find_variable_usage_violations(content, str(file_path))
    results.extend(usage_violations)
    
    # Step 3: Find insecure assignments
    assignment_violations = analyzer.find_insecure_assignments(content, str(file_path))
    results.extend(assignment_violations)
    
    # Step 4: Check for hardcoded SecureString creations
    hardcoded_violations = find_hardcoded_securestring_creations(content)
    results.extend(hardcoded_violations)
    
    return results

def find_hardcoded_securestring_creations(content: str) -> List[Dict[str, Any]]:
    """Find hardcoded SecureString creations."""
    violations = []
    lines = content.split('\n')
    
    hardcoded_patterns = [
        # New SecureString with hardcoded string
        r'New\s+(?:System\.Security\.)?SecureString\(["\'][^"\']*["\']',
        # DirectCast with hardcoded string to SecureString
        r'DirectCast\(["\'][^"\']*["\'],\s*(?:System\.Security\.)?SecureString\)',
        # ConvertTo-SecureString with hardcoded string
        r'ConvertTo-SecureString\s+["\'][^"\']*["\']',
        # SecureString.AppendChar with hardcoded characters
        r'\.AppendChar\(["\'][^"\']*["\']'
    ]
    
    for line_num, line in enumerate(lines, 1):
        for pattern in hardcoded_patterns:
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                matched_text = match.group(0)
                highlighted_line = highlight_match(line, matched_text)
                
                violations.append({
                    'line': line_num,
                    'line_content': highlighted_line,
                    'severity': 'HIGH',
                    'description': 'Hardcoded SecureString creation - defeats purpose of secure storage',
                    'full_line': line.strip(),
                    'matched_text': matched_text,
                    'pattern': 'sstring_hardcoded_creation'
                })
    
    return violations

def scan_package(package_path: str, root_package_name: str = None, scanned_files: set = None) -> List[Dict[str, Any]]:
    """
    Scan a UIPath package for SString security issues.
    
    Args:
        package_path: Path to the package directory
        root_package_name: Name of the root package (for nested packages)
        scanned_files: Set of already scanned files (to avoid duplicates)
        
    Returns:
        List of SString security issues found
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
        
    except Exception as e:
        logger.error(f"Error scanning package {package_path}: {str(e)}")
    
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
        
        # Check for non-empty quoted strings - indicates hardcoded values
        # Empty strings (&quot;&quot;) are often just placeholders, ignore them
        import re
        quoted_patterns = re.findall(r'&quot;([^&]*)&quot;|"([^"]*)"', inner_content)
        has_hardcoded_values = any(match[0] or match[1] for match in quoted_patterns if (match[0] or match[1]).strip())
        
        if has_hardcoded_values:
            return False
        
        # Check for .NET expressions that might contain variables (unquoted references)
        if any(pattern in inner_content for pattern in [
            'NetworkCredential', 'DirectCast', 'SecureString', 'Convert.',
            'System.', 'new ', 'New ', '(', ')', '.'
        ]):
            # This is a .NET expression, but if it doesn't contain quoted strings,
            # it's likely using variables and should be considered safe
            return True
        
        # Simple variable reference like [variableName] - safe
        return True
    
    # Plain text values are not safe
    return False

def scan_xaml_file(file_path: Path, root_package: Path, root_package_name: str = None) -> List[Dict[str, Any]]:
    """
    Scan a single .xaml file for SString security issues.
    
    Args:
        file_path: Path to the .xaml file
        root_package: Root package path
        root_package_name: Name of the root package
        
    Returns:
        List of SString security issues found
    """
    issues = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        file_issues = scan_sstring_security(file_path, content, root_package)
        
        for issue in file_issues:
            issue['file'] = str(file_path.relative_to(root_package.parent))
            issue['package_name'] = root_package_name or root_package.name
            issue['type'] = 'sstring_security'
            issue['module'] = 'sstring_security_detection'
        
        issues.extend(file_issues)
        
    except Exception as e:
        logger.warning(f"Error reading file {file_path}: {str(e)}")
    
    return issues 