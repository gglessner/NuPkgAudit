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
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class UIPathSecurityAuditorV3:
    """Modular security auditor for UIPath automation packages."""
    
    def __init__(self, scan_directory: str, modules_directory: str = "modules"):
        self.scan_directory = Path(scan_directory)
        self.modules_directory = Path(modules_directory)
        self.results = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_packages': 0,
            'packages_with_issues': 0,
            'total_issues': 0,
            'packages': {}
        }
        
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
                    
                    # Call the module's scan_package function with root package name
                    module_issues = module.scan_package(str(package_path), root_package_name=root_package_name)
                    
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
        
        return package_results
    
    def scan_all_packages(self) -> Dict[str, Any]:
        """Scan all packages in the directory."""
        logger.info(f"Starting security audit of packages in: {self.scan_directory}")
        
        if not self.scan_directory.exists():
            raise FileNotFoundError(f"Directory not found: {self.scan_directory}")
        
        # Recursively find all subdirectories (at any depth)
        all_directories = [d for d in self.scan_directory.rglob('*') if d.is_dir()]
        # Also include the immediate subdirectories (top-level)
        top_level_directories = [d for d in self.scan_directory.iterdir() if d.is_dir()]
        
        # Sort directories alphabetically
        all_directories.sort()
        top_level_directories.sort()
        
        logger.info(f"Found {len(all_directories)} directories to scan in alphabetical order")
        logger.info(f"Using {len(self.modules)} modules")
        
        for dir_path in all_directories:
            # Only print INFO for top-level subdirectories
            print_info = dir_path in top_level_directories
            
            # Determine the root package name (the top-level directory name)
            root_package_name = None
            if dir_path in top_level_directories:
                root_package_name = dir_path.name
            else:
                # Find the top-level directory that contains this subdirectory
                for top_dir in top_level_directories:
                    if dir_path.is_relative_to(top_dir):
                        root_package_name = top_dir.name
                        break
            
            package_results = self.scan_package(dir_path, print_info=print_info, root_package_name=root_package_name)
            self.results['packages'][dir_path.name] = package_results
            self.results['total_packages'] += 1
            
            if package_results['issue_count'] > 0:
                self.results['packages_with_issues'] += 1
                self.results['total_issues'] += package_results['issue_count']
        
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
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0, 'ERROR': 0}
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
                    if issue.get('module'):
                        report_lines.append(f"    Module: {issue['module']}")
                    report_lines.append("")
        
        report = "\n".join(report_lines)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"Report saved to: {output_file}")
        
        return report
    
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
        """
    )
    
    parser.add_argument('directory', help='Directory containing UIPath packages')
    parser.add_argument('--modules', '-m', default='modules', help='Directory containing scan modules (default: modules)')
    parser.add_argument('--output', '-o', help='Output file for text report (optional)')
    parser.add_argument('--json', '-j', help='Output file for JSON results (optional)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    # Severity filtering
    parser.add_argument('--sev-high', action='store_true', help='Only show HIGH severity findings')
    parser.add_argument('--sev-medium', action='store_true', help='Only show MEDIUM severity findings')
    parser.add_argument('--sev-low', action='store_true', help='Only show LOW severity findings')
    parser.add_argument('--sev-info', action='store_true', help='Only show INFO severity findings')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
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
        # If no filter is set, include all
        if not selected_severities:
            selected_severities = {'HIGH', 'MEDIUM', 'LOW', 'INFO', 'ERROR'}
        
        # Create auditor and scan packages
        auditor = UIPathSecurityAuditorV3(args.directory, args.modules)
        results = auditor.scan_all_packages()
        
        # Generate report (stdout only by default)
        report = auditor.generate_report(severity_filter=selected_severities)
        
        # Always print report to console
        print(report)
        
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
            
    except Exception as e:
        logger.error(f"Audit failed: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 