#!/usr/bin/env python3
"""
UIPath Automation Security Auditor v3.0 - Modular Framework
Scans subdirectories and executes modules from the modules directory.

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

import argparse
import json
import logging
import os
import sys
import importlib.util
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Import colorama for cross-platform color support
try:
    from colorama import init, Fore, Back, Style
    init()  # Initialize colorama for cross-platform support
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Fallback color codes (may not work on all Windows terminals)
    class Fore:
        RED = '\033[91m'
        YELLOW = '\033[93m'
        CYAN = '\033[96m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        WHITE = '\033[97m'
    class Style:
        RESET_ALL = '\033[0m'

from libraries.highlight_helper import highlight_match

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class UIPathSecurityAuditorV3:
    """Modular security auditor for UIPath automation packages."""
    
    def __init__(self, scan_directory: str, modules_directory: str = "modules", inline_mode: bool = False, severity_filter: set = None):
        self.scan_directory = Path(scan_directory)
        self.modules_directory = Path(modules_directory)
        self.inline_mode = inline_mode
        self.severity_filter = severity_filter or {'ERROR', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
        self.results = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_packages': 0,
            'packages_with_issues': 0,
            'total_issues': 0,
            'packages': {}
        }
        
        # Track scanned files to avoid duplicates
        self.scanned_files = set()
        
        # Load all modules
        self.modules = self.load_modules()
        
    def load_modules(self) -> List[Any]:
        """Load all modules from the modules directory."""
        modules = []
        
        if not self.modules_directory.exists():
            logger.warning(f"Modules directory not found: {self.modules_directory}")
            return modules
        
        # Find all Python files in modules directory and sort them alphabetically
        module_files = sorted(list(self.modules_directory.glob("*.py")))
        
        for module_file in module_files:
            if module_file.name.startswith("__"):
                continue  # Skip __init__.py and similar files
                
            try:
                # Load the module using importlib
                spec = importlib.util.spec_from_file_location(
                    module_file.stem, 
                    module_file
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Check if module has required interface
                if hasattr(module, 'scan_package'):
                    modules.append(module)
                    logger.info(f"Loaded module: {module_file.name}")
                else:
                    logger.warning(f"Module {module_file.name} missing 'scan_package' function")
                    
            except Exception as e:
                logger.error(f"Error loading module {module_file.name}: {str(e)}")
        
        logger.info(f"Loaded {len(modules)} modules in alphabetical order")
        return modules
    
    def print_inline_issues(self, package_name: str, issues: List[Dict[str, Any]]) -> None:
        """Print issues immediately for inline reporting mode."""
        if not self.inline_mode or not issues:
            return
        
        # Filter issues by severity
        filtered_issues = [issue for issue in issues if issue['severity'] in self.severity_filter]
        if not filtered_issues:
            return
        
        # Print package header
        print(f"\n{Fore.YELLOW}[PACKAGE] {package_name}{Style.RESET_ALL}")
        print(f"   Found {len(filtered_issues)} issue(s)")
        print("-" * 60)
        
        # Print each issue
        for issue in filtered_issues:
            severity = issue['severity']
            color = self.get_severity_color(severity)
            
            reset = self.get_reset_code()
            print(f"  {color}[{severity}]{reset} {issue['description']}")
            print(f"    File: {issue['file']}")
            
            if issue.get('cell_address'):
                print(f"    Cell: {issue['cell_address']}")
            if issue.get('line', 0) > 0:
                print(f"    Line: {issue['line']}")
            
            print(f"    Content: {issue['line_content']}")
            
            if issue.get('full_line') and issue.get('matched_text'):
                highlighted_context = highlight_match(issue['full_line'], issue['matched_text'])
                print(f"    Context: {highlighted_context}")
            
            if issue.get('module'):
                print(f"    Module: {issue['module']}")
            
            print()  # Empty line between issues
    
    def get_severity_color(self, severity: str) -> str:
        """Get the color code for a severity level."""
        if COLORAMA_AVAILABLE:
            if severity == 'HIGH':
                return Fore.RED
            elif severity == 'MEDIUM':
                return Fore.YELLOW
            elif severity == 'LOW':
                return Fore.CYAN
            elif severity == 'INFO':
                return Fore.BLUE
            elif severity == 'ERROR':
                return Fore.MAGENTA
            else:
                return Fore.WHITE
        else:
            return ""
    
    def get_reset_code(self) -> str:
        """Get the reset code for color formatting."""
        return Style.RESET_ALL if COLORAMA_AVAILABLE else ""
    
    def scan_package(self, package_path: Path, print_info: bool = True, root_package_name: str = None) -> Dict[str, Any]:
        """Scan a single UIPath package using all loaded modules."""
        package_name = package_path.name
        if print_info:
            logger.info(f"Scanning package: {package_name}")
        
        # Use root package name if provided, otherwise use current package name
        display_package_name = root_package_name if root_package_name else package_name
        
        package_results = {
            'package_name': display_package_name,
            'package_path': str(package_path),
            'issues': [],
            'file_count': 0,
            'issue_count': 0,
            'modules_executed': []
        }
        
        try:
            # Count files in package
            for file_path in package_path.rglob('*'):
                if file_path.is_file():
                    package_results['file_count'] += 1
            
            # Execute each module
            for module in self.modules:
                try:
                    logger.debug(f"Executing module {module.__name__} on package {package_name}")
                    
                    # Each module gets its own scanned_files set to avoid duplicates within the module
                    # but allow different modules to scan the same files
                    module_scanned_files = set()
                    
                    # Call the module's scan_package function with root package name and scanned files
                    module_issues = module.scan_package(str(package_path), root_package_name=root_package_name, scanned_files=module_scanned_files)
                    
                    if module_issues:
                        package_results['issues'].extend(module_issues)
                        package_results['issue_count'] += len(module_issues)
                    
                    package_results['modules_executed'].append(module.__name__)
                    
                except Exception as e:
                    logger.error(f"Error executing module {module.__name__} on package {package_name}: {str(e)}")
                    package_results['issues'].append({
                        'type': 'module_error',
                        'severity': 'ERROR',
                        'description': f'Error executing module {module.__name__}: {str(e)}',
                        'file': str(package_path),
                        'line': 0,
                        'module': module.__name__
                    })
            
        except Exception as e:
            logger.error(f"Error scanning package {package_name}: {str(e)}")
            package_results['issues'].append({
                'type': 'scan_error',
                'severity': 'ERROR',
                'description': f'Error scanning package: {str(e)}',
                'file': str(package_path),
                'line': 0
            })
        
        # Print issues inline if enabled
        self.print_inline_issues(display_package_name, package_results['issues'])
        
        return package_results
    
    def scan_all_packages(self) -> Dict[str, Any]:
        """Scan all packages in the directory."""
        logger.info(f"Starting security audit of packages in: {self.scan_directory}")
        
        if not self.scan_directory.exists():
            raise FileNotFoundError(f"Directory not found: {self.scan_directory}")
        
        # Only include immediate subdirectories (top-level packages)
        top_level_directories = [d for d in self.scan_directory.iterdir() if d.is_dir()]
        top_level_directories.sort()
        logger.info(f"Found {len(top_level_directories)} top-level package directories to scan in alphabetical order")
        logger.info(f"Using {len(self.modules)} modules")
        
        # Print inline mode header if enabled
        if self.inline_mode:
            cyan_color = self.get_severity_color('LOW')  # Use cyan for headers
            reset = self.get_reset_code()
            print(f"\n{cyan_color}>>> INLINE MODE ENABLED - Real-time feedback{reset}")
            print(f">>> Scanning {len(top_level_directories)} packages with {len(self.modules)} modules")
            print(f">>> Showing severities: {', '.join(sorted(self.severity_filter))}")
            print("=" * 80)
        
        for dir_path in top_level_directories:
            print_info = True
            root_package_name = dir_path.name
            package_results = self.scan_package(dir_path, print_info=print_info, root_package_name=root_package_name)
            if root_package_name not in self.results['packages']:
                self.results['packages'][root_package_name] = package_results
                self.results['total_packages'] += 1
            else:
                # Merge issues from subdirectories into the existing package, avoiding duplicates
                existing_issues = self.results['packages'][root_package_name]['issues']
                existing_keys = set()
                for issue in existing_issues:
                    key = (issue.get('file', ''), issue.get('line', 0), issue.get('module', ''), issue.get('description', ''))
                    existing_keys.add(key)
                new_issues = []
                for issue in package_results['issues']:
                    key = (issue.get('file', ''), issue.get('line', 0), issue.get('module', ''), issue.get('description', ''))
                    if key not in existing_keys:
                        new_issues.append(issue)
                        existing_keys.add(key)
                self.results['packages'][root_package_name]['issues'].extend(new_issues)
                self.results['packages'][root_package_name]['issue_count'] = len(self.results['packages'][root_package_name]['issues'])
            if package_results['issue_count'] > 0:
                if root_package_name not in [p['package_name'] for p in self.results['packages'].values() if p['issue_count'] > 0]:
                    self.results['packages_with_issues'] += 1
                self.results['total_issues'] += package_results['issue_count']
        
        # Print inline mode completion message
        if self.inline_mode:
            cyan_color = self.get_severity_color('LOW')  # Use cyan for headers
            yellow_color = self.get_severity_color('MEDIUM')  # Use yellow for report notice
            reset = self.get_reset_code()
            print(f"\n{cyan_color}>>> INLINE SCANNING COMPLETE{reset}")
            print(f">>> Total packages scanned: {self.results['total_packages']}")
            print(f">>> Packages with issues: {self.results['packages_with_issues']}")
            print(f">>> Total issues found: {self.results['total_issues']}")
            print("=" * 80)
            print(f"{yellow_color}>>> Full detailed report follows below...{reset}\n")
        
        return self.results
    
    def generate_report(self, output_file: str = None, severity_filter: set = None) -> str:
        """Generate a comprehensive security report."""
        report_lines = []
        
        # Apply severity filter if specified
        filtered_results = self.results.copy()
        if severity_filter:
            for package in filtered_results['packages'].values():
                package['issues'] = [i for i in package['issues'] if i['severity'] in severity_filter]
                package['issue_count'] = len(package['issues'])
            
            # Recalculate totals
            filtered_results['total_issues'] = sum(p['issue_count'] for p in filtered_results['packages'].values())
            filtered_results['packages_with_issues'] = sum(1 for p in filtered_results['packages'].values() if p['issue_count'] > 0)
        
        # Header
        report_lines.append("=" * 80)
        report_lines.append("UIPath Automation Security Audit Report v3.0 - Modular Framework")
        report_lines.append("=" * 80)
        report_lines.append(f"Scan Date: {filtered_results['scan_timestamp']}")
        report_lines.append(f"Total Packages Scanned: {filtered_results['total_packages']}")
        report_lines.append(f"Packages with Issues: {filtered_results['packages_with_issues']}")
        report_lines.append(f"Total Issues Found: {filtered_results['total_issues']}")
        # Print each module's name and description
        report_lines.append("Modules Loaded:")
        for module in self.modules:
            desc = getattr(module, 'MODULE_DESCRIPTION', '(No description provided)')
            report_lines.append(f"  - {module.__name__}: {desc}")
        if severity_filter:
            report_lines.append(f"Filtered by Severity: {', '.join(sorted(severity_filter))}")
        report_lines.append("")
        
        # Issues by Severity
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0, 'ERROR': 0, 'FALSE-POSITIVE': 0}
        for package in filtered_results['packages'].values():
            for issue in package['issues']:
                severity_counts[issue['severity']] += 1
        
        report_lines.append("Issues by Severity:")
        for severity, count in severity_counts.items():
            if count > 0:
                report_lines.append(f"  {severity}: {count}")
        report_lines.append("")
        
        # Detailed Findings
        report_lines.append("Detailed Findings:")
        report_lines.append("-" * 80)
        report_lines.append("")
        
        for package_name, package in filtered_results['packages'].items():
            if package['issue_count'] > 0:
                report_lines.append(f"Package: {package_name}")
                report_lines.append(f"Issues Found: {package['issue_count']}")
                
                for issue in package['issues']:
                    report_lines.append(f"  [{issue['severity']}] {issue['description']}")
                    report_lines.append(f"    File: {issue['file']}")
                    if issue.get('cell_address'):
                        report_lines.append(f"    Cell: {issue['cell_address']}")
                    if issue.get('line', 0) > 0:
                        report_lines.append(f"    Line: {issue['line']}")
                    report_lines.append(f"    Content: {issue['line_content']}")
                    if issue.get('full_line') and issue.get('matched_text'):
                        highlighted_context = highlight_match(issue['full_line'], issue['matched_text'])
                        report_lines.append(f"    Context: {highlighted_context}")
                    if issue.get('module'):
                        report_lines.append(f"    Module: {issue['module']}")
                    report_lines.append("")
        
        report = "\n".join(report_lines)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"Report saved to: {output_file}")
        
        return report
    
    def generate_colored_report(self, severity_filter: set = None) -> str:
        """Generate a comprehensive security report with color coding for console output."""
        report_lines = []
        
        # Apply severity filter if specified
        filtered_results = self.results.copy()
        if severity_filter:
            for package in filtered_results['packages'].values():
                package['issues'] = [i for i in package['issues'] if i['severity'] in severity_filter]
                package['issue_count'] = len(package['issues'])
            
            # Recalculate totals
            filtered_results['total_issues'] = sum(p['issue_count'] for p in filtered_results['packages'].values())
            filtered_results['packages_with_issues'] = sum(1 for p in filtered_results['packages'].values() if p['issue_count'] > 0)
        
        # Header
        report_lines.append("=" * 80)
        report_lines.append("UIPath Automation Security Audit Report v3.0 - Modular Framework")
        report_lines.append("=" * 80)
        report_lines.append(f"Scan Date: {filtered_results['scan_timestamp']}")
        report_lines.append(f"Total Packages Scanned: {filtered_results['total_packages']}")
        report_lines.append(f"Packages with Issues: {filtered_results['packages_with_issues']}")
        report_lines.append(f"Total Issues Found: {filtered_results['total_issues']}")
        # Print each module's name and description
        report_lines.append("Modules Loaded:")
        for module in self.modules:
            desc = getattr(module, 'MODULE_DESCRIPTION', '(No description provided)')
            report_lines.append(f"  - {module.__name__}: {desc}")
        if severity_filter:
            report_lines.append(f"Filtered by Severity: {', '.join(sorted(severity_filter))}")
        report_lines.append("")
        
        # Issues by Severity (with colors)
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0, 'ERROR': 0, 'FALSE-POSITIVE': 0}
        for package in filtered_results['packages'].values():
            for issue in package['issues']:
                severity_counts[issue['severity']] += 1
        
        report_lines.append("Issues by Severity:")
        for severity, count in severity_counts.items():
            if count > 0:
                color = self.get_severity_color(severity)
                reset = self.get_reset_code()
                report_lines.append(f"  {color}{severity}{reset}: {count}")
        report_lines.append("")
        
        # Detailed Findings (with colors)
        report_lines.append("Detailed Findings:")
        report_lines.append("-" * 80)
        report_lines.append("")
        
        for package_name, package in filtered_results['packages'].items():
            if package['issue_count'] > 0:
                package_color = self.get_severity_color('INFO')  # Use blue for package names
                reset = self.get_reset_code()
                report_lines.append(f"{package_color}Package: {package_name}{reset}")
                report_lines.append(f"Issues Found: {package['issue_count']}")
                
                for issue in package['issues']:
                    severity = issue['severity']
                    color = self.get_severity_color(severity)
                    report_lines.append(f"  {color}[{severity}]{reset} {issue['description']}")
                    report_lines.append(f"    File: {issue['file']}")
                    if issue.get('cell_address'):
                        report_lines.append(f"    Cell: {issue['cell_address']}")
                    if issue.get('line', 0) > 0:
                        report_lines.append(f"    Line: {issue['line']}")
                    report_lines.append(f"    Content: {issue['line_content']}")
                    if issue.get('full_line') and issue.get('matched_text'):
                        highlighted_context = highlight_match(issue['full_line'], issue['matched_text'])
                        report_lines.append(f"    Context: {highlighted_context}")
                    if issue.get('module'):
                        report_lines.append(f"    Module: {issue['module']}")
                    report_lines.append("")
        
        return "\n".join(report_lines)
    
    def export_json(self, output_file: str, severity_filter: set = None) -> None:
        """Export results to JSON format."""
        # Apply severity filter if specified
        filtered_results = self.results.copy()
        if severity_filter:
            for package in filtered_results['packages'].values():
                package['issues'] = [i for i in package['issues'] if i['severity'] in severity_filter]
                package['issue_count'] = len(package['issues'])
            
            # Recalculate totals
            filtered_results['total_issues'] = sum(p['issue_count'] for p in filtered_results['packages'].values())
            filtered_results['packages_with_issues'] = sum(1 for p in filtered_results['packages'].values() if p['issue_count'] > 0)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(filtered_results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON results saved to: {output_file}")

def main():
    """Main function to run the security audit."""
    parser = argparse.ArgumentParser(
        description='UIPath Automation Security Auditor v3.0 - Modular Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python NuPkgAudit_v3.py /path/to/packages
  python NuPkgAudit_v3.py /path/to/packages --modules /path/to/modules
  python NuPkgAudit_v3.py /path/to/packages --sev-high --output report.txt
  python NuPkgAudit_v3.py /path/to/packages --output report.txt --json results.json
  python NuPkgAudit_v3.py /path/to/packages --warn --verbose
  python NuPkgAudit_v3.py /path/to/packages --inline --sev-high
        """
    )
    
    parser.add_argument('directory', help='Directory containing UIPath packages')
    parser.add_argument('--modules', '-m', default='modules', help='Directory containing scan modules (default: modules)')
    parser.add_argument('--output', '-o', help='Output file for text report (optional)')
    parser.add_argument('--json', '-j', help='Output file for JSON results (optional)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--warn', '-w', action='store_true', help='Show warning messages (hidden by default)')
    parser.add_argument('--inline', '-i', action='store_true', help='Show issues immediately as each package is scanned (real-time feedback)')
    
    # Severity filtering
    parser.add_argument('--sev-high', action='store_true', help='Only show HIGH severity findings')
    parser.add_argument('--sev-medium', action='store_true', help='Only show MEDIUM severity findings')
    parser.add_argument('--sev-low', action='store_true', help='Only show LOW severity findings')
    parser.add_argument('--sev-info', action='store_true', help='Only show INFO severity findings')
    parser.add_argument('--sev-fp', action='store_true', help='Include FALSE-POSITIVE findings')
    
    args = parser.parse_args()
    
    # Configure logging with timestamps
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    elif args.warn:
        # Show warnings when --warn flag is used
        logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
    else:
        # Show INFO for package scanning progress but hide warnings
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        # Create a filter to suppress WARNING messages but allow INFO, ERROR, and CRITICAL
        class NoWarningFilter(logging.Filter):
            def filter(self, record):
                return record.levelno != logging.WARNING
        
        # Apply the filter to the root logger and all existing loggers
        root_logger = logging.getLogger()
        root_logger.addFilter(NoWarningFilter())
        
        # Also apply to all handlers to ensure warnings are suppressed everywhere
        for handler in root_logger.handlers:
            handler.addFilter(NoWarningFilter())
    
    try:
        # Determine which severities to include
        selected_severities = set()
        if args.sev_high:
            selected_severities.add('HIGH')
        if args.sev_medium:
            selected_severities.add('MEDIUM')
        if args.sev_low:
            selected_severities.add('LOW')
        if args.sev_info:
            selected_severities.add('INFO')
        if args.sev_fp:
            selected_severities.add('FALSE-POSITIVE')
        # If no filter is set, include all
        if not selected_severities:
            selected_severities = {'ERROR', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
        
        # Create auditor and scan packages
        auditor = UIPathSecurityAuditorV3(args.directory, args.modules, inline_mode=args.inline, severity_filter=selected_severities)
        results = auditor.scan_all_packages()
        
        # Generate colored report for console output
        colored_report = auditor.generate_colored_report(severity_filter=selected_severities)
        
        # Always print colored report to console
        print(colored_report)
        
        # Save to file only if explicitly requested
        if args.output:
            auditor.generate_report(args.output, severity_filter=selected_severities)
        
        # Export JSON only if explicitly requested
        if args.json:
            auditor.export_json(args.json, severity_filter=selected_severities)
        
        # Exit with appropriate code
        if results['total_issues'] > 0:
            sys.exit(1)  # Exit with error if issues found
        else:
            sys.exit(0)  # Exit successfully if no issues
            
    except UnicodeDecodeError as ude:
        logger.error(f"UnicodeDecodeError: {ude}. Problematic string: {ude.object[ude.start:ude.end]}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Audit failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main() 