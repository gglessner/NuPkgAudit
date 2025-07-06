#!/usr/bin/env python3
"""
XML External Entity (XXE) Detection Module
Scans for XXE vulnerabilities in XML processing within UIPath automation.

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

MODULE_DESCRIPTION = "Detects XML External Entity (XXE) vulnerabilities in XML processing including DOCTYPE declarations with ENTITY definitions, external entity references, SYSTEM and PUBLIC entity declarations, and unsafe XML parser configurations."

# XXE vulnerability patterns
XXE_PATTERNS = {
    # DOCTYPE with ENTITY declarations
    'doctype_with_entity': {
        'pattern': r'<!DOCTYPE\s+\w+\s*\[.*?<!ENTITY\s+\w+\s+(?:SYSTEM|PUBLIC)',
        'severity': 'HIGH',
        'description': 'DOCTYPE declaration with ENTITY definition - potential XXE vulnerability'
    },
    'doctype_system_entity': {
        'pattern': r'<!DOCTYPE\s+\w+\s+SYSTEM\s+["\'][^"\']*["\']',
        'severity': 'HIGH',
        'description': 'DOCTYPE with SYSTEM entity - XXE vulnerability'
    },
    'doctype_public_entity': {
        'pattern': r'<!DOCTYPE\s+\w+\s+PUBLIC\s+["\'][^"\']*["\']\s+["\'][^"\']*["\']',
        'severity': 'HIGH',
        'description': 'DOCTYPE with PUBLIC entity - XXE vulnerability'
    },
    
    # ENTITY declarations
    'entity_system_declaration': {
        'pattern': r'<!ENTITY\s+\w+\s+SYSTEM\s+["\'][^"\']*["\']',
        'severity': 'HIGH',
        'description': 'ENTITY with SYSTEM declaration - XXE vulnerability'
    },
    'entity_public_declaration': {
        'pattern': r'<!ENTITY\s+\w+\s+PUBLIC\s+["\'][^"\']*["\']\s+["\'][^"\']*["\']',
        'severity': 'HIGH',
        'description': 'ENTITY with PUBLIC declaration - XXE vulnerability'
    },
    'parameter_entity_declaration': {
        'pattern': r'<!ENTITY\s+%\s*\w+\s+SYSTEM\s+["\'][^"\']*["\']',
        'severity': 'HIGH',
        'description': 'Parameter entity with SYSTEM - XXE vulnerability'
    },
    
    # External entity references (excluding common HTML entities)
    'external_entity_reference': {
        'pattern': r'&(?!(?:amp|lt|gt|quot|apos|nbsp|copy|reg|trade|hellip|mdash|ndash|lsquo|rsquo|ldquo|rdquo|bull|middot|deg|plusmn|times|divide|frac12|frac14|frac34|sup1|sup2|sup3|#\d+|#x[0-9a-fA-F]+);)[a-zA-Z][a-zA-Z0-9]*;',
        'severity': 'MEDIUM',
        'description': 'External entity reference - potential XXE if entity is externally defined'
    },
    'parameter_entity_reference': {
        'pattern': r'%[a-zA-Z][a-zA-Z0-9]*;',
        'severity': 'MEDIUM',
        'description': 'Parameter entity reference - potential XXE vulnerability'
    },
    
    # Common XXE payloads
    'file_protocol_entity': {
        'pattern': r'<!ENTITY\s+\w+\s+SYSTEM\s+["\']file://[^"\']*["\']',
        'severity': 'HIGH',
        'description': 'ENTITY with file:// protocol - file disclosure XXE attack'
    },
    'http_protocol_entity': {
        'pattern': r'<!ENTITY\s+\w+\s+SYSTEM\s+["\']https?://[^"\']*["\']',
        'severity': 'HIGH',
        'description': 'ENTITY with HTTP protocol - SSRF/XXE vulnerability'
    },
    'ftp_protocol_entity': {
        'pattern': r'<!ENTITY\s+\w+\s+SYSTEM\s+["\']ftp://[^"\']*["\']',
        'severity': 'HIGH',
        'description': 'ENTITY with FTP protocol - XXE vulnerability'
    },
    
    # Unsafe XML parser configurations
    'xmldocument_load_xml': {
        'pattern': r'XmlDocument\s*\(\s*\)\.LoadXml\s*\(',
        'severity': 'MEDIUM',
        'description': 'XmlDocument.LoadXml() without DTD processing disabled - potential XXE'
    },
    'xmlreader_create': {
        'pattern': r'XmlReader\.Create\s*\([^)]*\)',
        'severity': 'LOW',
        'description': 'XmlReader.Create() - verify DTD processing is disabled'
    },
    'xmltextreader_usage': {
        'pattern': r'XmlTextReader\s*\(',
        'severity': 'MEDIUM',
        'description': 'XmlTextReader usage - DTD processing enabled by default, potential XXE'
    },
    
    # XML parsing with user input
    'xml_load_with_variable': {
        'pattern': r'LoadXml\s*\(\s*(?:in_|out_|io_)\w+',
        'severity': 'HIGH',
        'description': 'XML loading with user input - XXE vulnerability if DTD processing enabled'
    },
    'xml_parse_with_variable': {
        'pattern': r'(?:Parse|Load)Xml\s*\(\s*[^"\']*(?:in_|out_|io_)\w+',
        'severity': 'HIGH',
        'description': 'XML parsing with user input - potential XXE vulnerability'
    },
    
    # Specific XXE attack patterns
    'xxe_file_read_pattern': {
        'pattern': r'<!ENTITY\s+\w+\s+SYSTEM\s+["\']file:///(?:etc/passwd|windows/system32|c:\\)',
        'severity': 'HIGH',
        'description': 'XXE file read attack pattern detected'
    },
    'xxe_billion_laughs': {
        'pattern': r'<!ENTITY\s+\w+\s+["\'](?:&\w+;){2,}["\']',
        'severity': 'HIGH',
        'description': 'Billion Laughs XXE attack pattern - DoS vulnerability'
    },
    'xxe_recursive_entity': {
        'pattern': r'<!ENTITY\s+(\w+)\s+["\'][^"\']*&\1;[^"\']*["\']',
        'severity': 'HIGH',
        'description': 'Recursive entity definition - XXE DoS vulnerability'
    },
    
    # XML Schema and DTD references
    'external_dtd_reference': {
        'pattern': r'<!DOCTYPE\s+\w+\s+SYSTEM\s+["\']https?://[^"\']*\.dtd["\']',
        'severity': 'HIGH',
        'description': 'External DTD reference - XXE vulnerability'
    },
    'xml_schema_location': {
        'pattern': r'xsi:schemaLocation\s*=\s*["\'][^"\']*https?://[^"\']*["\']',
        'severity': 'MEDIUM',
        'description': 'External XML schema location - potential XXE/SSRF'
    },
    'xml_namespace_uri': {
        'pattern': r'xmlns(?::\w+)?\s*=\s*["\']https?://[^"\']*["\']',
        'severity': 'LOW',
        'description': 'External namespace URI - verify if schema is fetched'
    },
    
    # Unsafe XML processing methods
    'deserialize_xml_with_input': {
        'pattern': r'XmlSerializer\s*\([^)]*\)\.Deserialize\s*\(\s*(?:in_|out_|io_)\w+',
        'severity': 'HIGH',
        'description': 'XML deserialization with user input - XXE vulnerability'
    },
    'xpath_with_user_input': {
        'pattern': r'SelectNodes\s*\(\s*[^"\']*(?:in_|out_|io_)\w+',
        'severity': 'MEDIUM',
        'description': 'XPath query with user input - potential XXE/XPath injection'
    }
}

# XML-related attribute patterns
XML_ATTRIBUTES = [
    'XmlContent', 'XmlData', 'XmlString', 'XmlText', 'XmlDocument',
    'XmlFile', 'XmlPath', 'XmlInput', 'XmlOutput', 'XmlSource',
    'DtdProcessing', 'XmlResolver', 'XmlReaderSettings', 'XmlParserContext',
    'DocumentType', 'SystemId', 'PublicId', 'InternalSubset'
]

def is_xml_related_attribute(attr_name: str) -> bool:
    """Check if an attribute is XML-related."""
    attr_lower = attr_name.lower()
    return any(xml_attr.lower() in attr_lower for xml_attr in XML_ATTRIBUTES)

def analyze_xml_content_security(xml_content: str) -> List[Dict[str, Any]]:
    """
    Analyze XML content for XXE vulnerabilities.
    
    Args:
        xml_content: XML content string to analyze
        
    Returns:
        List of XXE vulnerabilities found
    """
    issues = []
    
    # Check for DOCTYPE with internal subset
    if '<!DOCTYPE' in xml_content and '[' in xml_content:
        # Extract the internal subset
        doctype_match = re.search(r'<!DOCTYPE[^>]*\[(.*?)\]', xml_content, re.DOTALL)
        if doctype_match:
            internal_subset = doctype_match.group(1)
            
            # Check for entity declarations in internal subset
            entity_declarations = re.findall(r'<!ENTITY[^>]*>', internal_subset)
            for entity_decl in entity_declarations:
                if 'SYSTEM' in entity_decl or 'PUBLIC' in entity_decl:
                    issues.append({
                        'pattern': 'internal_subset_external_entity',
                        'severity': 'HIGH',
                        'description': 'External entity in DOCTYPE internal subset - XXE vulnerability',
                        'matched_text': entity_decl
                    })
    
    # Check for common XXE indicators
    xxe_indicators = [
        (r'&\w+;', 'Entity reference found - verify entities are not externally defined'),
        (r'%\w+;', 'Parameter entity reference - potential XXE vulnerability'),
        (r'file://', 'File protocol usage - potential file disclosure'),
        (r'SYSTEM\s+["\']', 'SYSTEM entity declaration - XXE vulnerability'),
        (r'PUBLIC\s+["\']', 'PUBLIC entity declaration - XXE vulnerability')
    ]
    
    for pattern, description in xxe_indicators:
        if re.search(pattern, xml_content, re.IGNORECASE):
            issues.append({
                'pattern': 'xxe_indicator',
                'severity': 'MEDIUM',
                'description': description,
                'matched_text': xml_content
            })
    
    return issues

def scan_xxe_vulnerabilities(file_path, content, root_package=None):
    """
    Scan for XXE vulnerabilities in UIPath .xaml file content.
    
    Args:
        file_path: Path to the file being scanned
        content: Content of the file
        root_package: Root package path for config resolution
        
    Returns:
        List of XXE vulnerabilities found
    """
    results = []
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        # Skip empty lines and comments
        if not line.strip() or line.strip().startswith('<!--'):
            continue
            
        # Look for XML-related attributes
        for attr_name in XML_ATTRIBUTES:
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
                        # Check against all XXE patterns
                        for pattern_name, pattern_info in XXE_PATTERNS.items():
                            pattern_regex = pattern_info['pattern']
                            severity = pattern_info['severity']
                            description = pattern_info['description']
                            
                            if re.search(pattern_regex, check_value, re.IGNORECASE | re.DOTALL):
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
                        
                        # Analyze XML content for additional XXE issues
                        if any(xml_keyword in attr_name.lower() for xml_keyword in ['xml', 'dtd', 'entity']):
                            xml_issues = analyze_xml_content_security(check_value)
                            for issue in xml_issues:
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
        
        # Also check the entire line for XXE patterns (not just attributes)
        for pattern_name, pattern_info in XXE_PATTERNS.items():
            pattern_regex = pattern_info['pattern']
            severity = pattern_info['severity']
            description = pattern_info['description']
            
            matches = re.finditer(pattern_regex, line, re.IGNORECASE | re.DOTALL)
            for match in matches:
                matched_text = match.group(0)
                highlighted_line = highlight_match(line, matched_text)
                
                results.append({
                    'line': line_num,
                    'line_content': highlighted_line,
                    'severity': severity,
                    'description': description,
                    'full_line': line.strip(),
                    'matched_text': matched_text,
                    'pattern': pattern_name
                })
    
    return results

def scan_package(package_path: str, root_package_name: str = None, scanned_files: set = None) -> List[Dict[str, Any]]:
    """
    Scan a UIPath package for XXE vulnerabilities.
    
    Args:
        package_path: Path to the package directory
        root_package_name: Name of the root package (for nested packages)
        scanned_files: Set of already scanned files (to avoid duplicates)
        
    Returns:
        List of XXE vulnerabilities found
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
        
        # Also scan XML and config files
        for ext in ['*.xml', '*.config', '*.xsd', '*.dtd']:
            for xml_file in package_path.rglob(ext):
                if str(xml_file) in scanned_files:
                    continue
                scanned_files.add(str(xml_file))
                
                try:
                    with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    file_issues = scan_xxe_vulnerabilities(xml_file, content, package_path)
                    for issue in file_issues:
                        issue['file'] = str(xml_file.relative_to(package_path.parent))
                        issue['package_name'] = root_package_name
                        issue['type'] = 'xxe_vulnerability'
                        issue['module'] = 'xxe_detection'
                    issues.extend(file_issues)
                    
                except Exception as e:
                    logger.warning(f"Error reading file {xml_file}: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error scanning package {package_path}: {str(e)}")
    
    return issues

def scan_xaml_file(file_path: Path, root_package: Path, root_package_name: str = None) -> List[Dict[str, Any]]:
    """
    Scan a single .xaml file for XXE vulnerabilities.
    
    Args:
        file_path: Path to the .xaml file
        root_package: Root package path
        root_package_name: Name of the root package
        
    Returns:
        List of XXE vulnerabilities found
    """
    issues = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        file_issues = scan_xxe_vulnerabilities(file_path, content, root_package)
        
        for issue in file_issues:
            issue['file'] = str(file_path.relative_to(root_package.parent))
            issue['package_name'] = root_package_name or root_package.name
            issue['type'] = 'xxe_vulnerability'
            issue['module'] = 'xxe_detection'
        
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