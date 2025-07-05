# NuPkgAudit - UIPath Automation Security Auditor v3.0

A comprehensive modular security auditing framework for UIPath automation packages that scans for security vulnerabilities, hardcoded credentials, and configuration issues with advanced pattern detection, real-time feedback, and color-coded reporting.

## Overview

NuPkgAudit is a sophisticated security auditing tool designed specifically for UIPath automation projects. It provides an extensible modular framework that scans UIPath packages for various security issues including hardcoded credentials, insecure network configurations, SQL injection vulnerabilities, file path traversal, and authentication data exposure. The tool features advanced pattern detection, intelligent Config.xlsx resolution, real-time scanning feedback, and color-coded output for enhanced usability.

## Key Features

- **Modular Architecture**: Extensible framework with 7 specialized security modules + beta modules
- **Comprehensive Scanning**: Scans multiple file types (.xaml, .vb, .cs, .txt, .json, .xml, .config, .ini, .xlsx)
- **Advanced Security Detection**: Identifies hardcoded credentials, network vulnerabilities, SQL injection, and more
- **Real-Time Feedback**: `--inline` mode shows issues immediately as packages are scanned
- **Color-Coded Output**: RED for HIGH severity, YELLOW for MEDIUM, CYAN for LOW, with timestamps
- **Sophisticated Pattern Detection**: Detects complex dynamic retrieval patterns including:
  - `in_AuthenticationData` patterns
  - `Config_data` patterns  
  - `DirectCast` and `TryCast` configurations
  - `NetworkCredential` patterns
  - `io_Config` and `io_Credentials` patterns
  - Case-insensitive `in_config` patterns in any context
- **Config.xlsx Resolution**: Automatically resolves configuration values from package Config.xlsx files
- **Intelligent Classification**: Distinguishes between hardcoded values (HIGH) and dynamic patterns (MEDIUM/FALSE-POSITIVE)
- **Enhanced Highlighting**: Yellow highlighting with "→" format for resolved values and missing config keys
- **Flexible Severity Levels**: HIGH, MEDIUM, LOW, INFO, ERROR, FALSE-POSITIVE classifications
- **Multiple Output Formats**: Text reports, JSON, and Excel export capabilities
- **Configurable Logging**: `--warn` flag to control warning visibility, timestamps for package scanning
- **Clean Output**: DEBUG-level logging for verbose attribute extraction details
- **Beta Module Support**: Separate `modules-beta/` directory for experimental or high-false-positive modules

## Installation

### Prerequisites

- Python 3.6 or higher
- Required dependencies listed in requirements.txt

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd NuPkgAudit3
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Scan a directory containing UIPath packages:

```bash
python NuPkgAudit.py packages
```

### Advanced Usage

```bash
# Real-time feedback with inline mode
python NuPkgAudit.py packages --inline --sev-high

# Show warnings (hidden by default)
python NuPkgAudit.py packages --warn

# Include FALSE-POSITIVE findings in report
python NuPkgAudit.py packages --sev-fp

# Generate text report with color output
python NuPkgAudit.py packages --output report.txt

# Generate JSON results
python NuPkgAudit.py packages --json results.json

# Filter by specific severity levels
python NuPkgAudit.py packages --sev-high
python NuPkgAudit.py packages --sev-medium --sev-low

# Multiple severity filters with real-time feedback
python NuPkgAudit.py packages --sev-high --sev-medium --inline --output critical_issues.txt

# Verbose output with detailed logging (shows DEBUG messages)
python NuPkgAudit.py packages --verbose

# Use beta modules (experimental)
python NuPkgAudit.py packages --modules modules-beta
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `directory` | Directory containing UIPath packages (required) |
| `--modules, -m` | Directory containing scan modules (default: modules) |
| `--output, -o` | Output file for text report |
| `--json, -j` | Output file for JSON results |
| `--verbose, -v` | Enable verbose output with detailed logging (shows DEBUG messages) |
| `--warn, -w` | Show warning messages (hidden by default) |
| `--inline, -i` | Show issues immediately as each package is scanned (real-time feedback) |
| `--sev-high` | Include HIGH severity findings |
| `--sev-medium` | Include MEDIUM severity findings |
| `--sev-low` | Include LOW severity findings |
| `--sev-info` | Include INFO severity findings |
| `--sev-error` | Include ERROR severity findings |
| `--sev-fp` | Include FALSE-POSITIVE findings |

## Security Modules

### Active Modules (`modules/`)

#### 1. Password Detection Module (`password_detection.py`)
**Detects hardcoded Password, in_Password, and out_Password attributes in .xaml files.**

**Pattern Detection:**
- Basic hardcoded passwords → **HIGH**
- `in_AuthenticationData` patterns → **MEDIUM**
- `Config_data` retrieval patterns → **MEDIUM** 
- `DirectCast` configuration patterns → **MEDIUM**
- `NetworkCredential` with hardcoded values → **HIGH**
- `in_config` patterns with Config.xlsx resolution

#### 2. Secure Text Detection Module (`secure_text_detection.py`)
**Detects hardcoded SecureText attributes with comprehensive pattern analysis.**

**Advanced Pattern Detection:**
- `io_Credentials` patterns → **MEDIUM**
- `NetworkCredential` with JSON object retrieval → **MEDIUM**
- `CType io_Config` patterns → **MEDIUM**
- `DirectCast in_ConfigDetails` patterns → **MEDIUM**
- `TryCast Config_Data` patterns → **MEDIUM**

#### 3. Token Detection Module (`token_detection.py`)
**Scans for hardcoded Token, in_Token, and out_Token attributes.**

#### 4. Username Detection Module (`username_detection.py`)
**Detects hardcoded Username, in_Username, and out_Username attributes.**

#### 5. Client Certificate Password Detection Module (`client_certificate_password.py`)
**Scans for ClientCertificatePassword and SecureClientCertificatePassword attributes.**

#### 6. Hardcoded Secrets Detection Module (`hardcoded_secrets_detection.py`)
**Detects hardcoded secrets including API keys, private keys, and connection strings.**

**Features:**
- API keys and tokens → **HIGH**
- Private keys and certificates → **HIGH**
- Database connection strings → **HIGH**
- JWT tokens → **MEDIUM**

#### 7. Insecure Network Detection Module (`insecure_network_detection.py`)
**Detects insecure network configurations and HTTP usage for sensitive data.**

**Features:**
- HTTP usage for sensitive data → **HIGH**
- Certificate validation bypasses → **HIGH**
- Weak TLS settings → **MEDIUM**
- Legitimate schema usage → **FALSE-POSITIVE**

### Beta Modules (`modules-beta/`)

#### 1. SQL Injection Detection Module (`sql_injection_detection.py`)
**Detects SQL injection vulnerabilities in database queries and connection strings.**

**Features:**
- String concatenation in SQL queries → **HIGH**
- Unparameterized queries → **HIGH**
- Dynamic SQL construction → **MEDIUM**
- Stored procedure calls → **LOW**
- Moved to beta due to potential false positives

#### 2. File Path Traversal Detection Module (`file_path_traversal_detection.py`)
**Detects file path traversal vulnerabilities and unsafe file operations.**

**Features:**
- Directory traversal patterns (`../`, `..\\`) → **HIGH**
- Absolute path injection → **MEDIUM**
- Environment variable abuse → **MEDIUM**
- Unsafe file operations → **LOW**
- Moved to beta due to potential false positives

#### 3. XLSX Secrets Detection Module (`xlsx_secrets_detection.py`)
**Scans Excel files for sensitive data in configuration sheets.**

**Features:**
- Scans Config.xlsx files for dangerous keys
- Detects passwords, API keys, tokens in spreadsheets
- May have false positives with common terms

#### 4. Command Injection Detection Module (`command_injection_detection.py`)
**Detects command injection vulnerabilities in system calls.**

**Features:**
- Shell command injection → **HIGH**
- Process execution with user input → **HIGH**
- PowerShell command construction → **MEDIUM**
- Moved to beta due to potential false positives

## Real-Time Scanning with --inline Mode

The `--inline` flag provides immediate feedback as packages are scanned:

```bash
python NuPkgAudit.py packages --inline --sev-high
```

**Features:**
- **Real-time issue display**: Shows issues immediately as found
- **Color-coded severity**: RED for HIGH, YELLOW for MEDIUM, CYAN for LOW
- **Progress indicators**: Shows scanning progress and completion status
- **Timestamped package scanning**: Shows when each package starts processing
- **Completion summary**: Total packages, issues found, and processing time

**Example Output:**
```
>>> INLINE MODE ENABLED - Real-time feedback
>>> Scanning 9 packages with 7 modules
>>> Showing severities: HIGH, MEDIUM
================================================================================

2025-07-05 02:19:23,479 - INFO - Scanning package: package1
2025-07-05 02:19:23,528 - INFO - Scanning package: package2

[PACKAGE] package2
  [HIGH] Hard-coded Password detected
    File: packages\package2\TestPassword.xaml
    Line: 15
    Content: Password="HardcodedPass"

>>> INLINE SCANNING COMPLETE
>>> Total packages scanned: 9
>>> Packages with issues: 3
>>> Total issues found: 12
================================================================================
>>> Full detailed report follows below...
```

## Color-Coded Output

The tool uses color coding throughout for enhanced readability:

| Color | Severity | Usage |
|-------|----------|-------|
| **RED** | HIGH | Critical security issues |
| **YELLOW** | MEDIUM | Potential security concerns |
| **CYAN** | LOW | Best practice violations |
| **BLUE** | INFO | Informational findings |
| **MAGENTA** | ERROR | Scan errors or exceptions |

Colors are applied to:
- Severity levels in summary sections
- `[SEVERITY]` tags in detailed findings
- Package names in reports
- Inline mode headers and messages

## Config.xlsx Resolution

The tool automatically searches for and resolves configuration values from `Config.xlsx` files within each package:

**Search Locations:**
- `{package}/lib/net45/Data/Config.xlsx`
- `{package}/Data/Config.xlsx`
- `{package}/Config.xlsx`

**Resolution Logic:**
1. **Key Found + Has Value** → **HIGH** severity with resolved value highlighting
2. **Key Found + Empty Value** → **HIGH** severity (empty values are flagged)
3. **Key Not Found** → **FALSE-POSITIVE** with "Value not in Config.xlsx" message

**Example Output:**
```
[HIGH] Hard-coded Password detected
  Content: Password="[In_Config(&quot;Password&quot;).ToString] → mySecretPassword123"
  
[FALSE-POSITIVE] Hard-coded SecureText detected  
  Content: SecureText="[In_Config(&quot;MissingKey&quot;).ToString] → Value not in Config.xlsx"
```

## Severity Classifications

| Severity | Description | Examples |
|----------|-------------|----------|
| **HIGH** | Definite security risks | Hardcoded passwords, SQL injection, path traversal |
| **MEDIUM** | Potential security concerns | Dynamic patterns, weak configurations |
| **LOW** | Best practice violations | Minor configuration issues |
| **INFO** | Informational findings | Documentation or context information |
| **ERROR** | Scan errors or exceptions | File read errors, parsing failures |
| **FALSE-POSITIVE** | Likely safe patterns | Unresolved config references, legitimate schemas |

## Logging and Warning Control

The tool provides flexible logging control:

**Default Behavior:**
- Shows timestamped package scanning progress
- Hides warning messages for cleaner output
- Hides verbose attribute extraction details (DEBUG level)
- Shows errors and critical information

**With `--warn` flag:**
- Shows warning messages (config keys not found, etc.)
- Useful for debugging configuration issues

**With `--verbose` flag:**
- Shows all logging levels including debug information
- Detailed module execution information
- Verbose attribute extraction details

## Output Formats

### Text Report
Comprehensive text-based report with:
- Executive summary with issue counts by severity
- Color-coded severity levels
- Package-by-package breakdown
- Detailed findings with context
- Yellow highlighting for matches
- Module execution statistics

### JSON Output
Structured JSON containing:
- Scan metadata and timestamps
- Complete issue catalog with detailed attributes
- File and line references
- Module performance data

### Console Output
Real-time scanning progress with:
- Timestamped package processing status
- Color-coded severity indicators
- Config.xlsx resolution messages
- Final summary statistics

## Project Structure

```
NuPkgAudit3/
├── NuPkgAudit.py                      # Main auditor script
├── modules/                           # Active security modules
│   ├── client_certificate_password.py # Certificate password detection
│   ├── hardcoded_secrets_detection.py # API keys, tokens, secrets
│   ├── insecure_network_detection.py  # HTTP usage, cert bypasses
│   ├── password_detection.py          # Password pattern detection
│   ├── secure_text_detection.py       # SecureText pattern detection
│   ├── token_detection.py             # Token pattern detection
│   └── username_detection.py          # Username pattern detection
├── modules-beta/                      # Beta/experimental modules
│   ├── command_injection_detection.py # Command injection (high FP rate)
│   ├── file_path_traversal_detection.py # Path traversal (potential FPs)
│   ├── sql_injection_detection.py     # SQL injection (potential FPs)
│   └── xlsx_secrets_detection.py      # Excel file scanning (slow)
├── libraries/                         # Helper libraries
│   ├── config_helper.py               # Config.xlsx resolution utilities
│   └── highlight_helper.py            # Text highlighting functions
├── packages/                          # Test packages (for development)
├── requirements.txt                   # Python dependencies
├── create_config_xlsx.py             # Config.xlsx creation utility
├── test_results.xlsx                 # Test results output
├── LICENSE                           # GNU GPL v3 license
└── README.md                         # This comprehensive guide
```

## Creating Custom Modules

To create a custom security module:

1. Create a Python file in the `modules/` directory (or `modules-beta/` for experimental modules)
2. Add the standard GPL header with author and license information
3. Implement the required functions:

```python
#!/usr/bin/env python3
"""
Custom Security Module
Description of what this module detects.

Author: Your Name <your.email@example.com>
License: GNU General Public License v3.0
Copyright (C) 2024 Your Name

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

def scan_package(package_path: str, root_package_name: str = None, scanned_files: set = None) -> List[Dict[str, Any]]:
    """
    Scan a package for security issues.
    
    Args:
        package_path: Path to the package directory
        root_package_name: Name of the root package (for nested packages)
        scanned_files: Set of already scanned files (to avoid duplicates)
    
    Returns:
        List of issue dictionaries
    """
    issues = []
    # Implementation here
    return issues
```

3. Return issue dictionaries with this structure:

```python
{
    'type': 'module_name',
    'severity': 'HIGH|MEDIUM|LOW|INFO|ERROR|FALSE-POSITIVE',
    'description': 'Detailed issue description',
    'file': 'relative/path/to/file.xaml',
    'line': line_number,
    'line_content': 'highlighted content with matches',
    'full_line': 'complete line from file',
    'matched_text': 'the specific matched pattern',
    'package_name': 'package_name',
    'module': 'module_name'
}
```

## Example Usage Scenarios

### Security Audit Workflow
```bash
# 1. Quick security scan with real-time feedback
python NuPkgAudit.py packages --inline

# 2. Critical issues only with colors
python NuPkgAudit.py packages --sev-high --inline

# 3. Comprehensive audit including potential false positives  
python NuPkgAudit.py packages --sev-fp --output full_audit.txt

# 4. Development workflow - all findings with verbose logging
python NuPkgAudit.py packages --sev-high --sev-medium --sev-fp --verbose --warn

# 5. Test beta modules (includes SQL injection, file path traversal detection)
python NuPkgAudit.py packages --modules modules-beta --sev-high
```

### Typical Output Summary
```
Issues by Severity:
  HIGH: 21        # Hardcoded credentials, network issues, secrets
  MEDIUM: 47      # Dynamic patterns, weak configurations
  LOW: 8          # Best practice violations
  FALSE-POSITIVE: 11  # Unresolved config references, legitimate schemas
  
Modules loaded: 7 (client_certificate_password, hardcoded_secrets_detection, insecure_network_detection, password_detection, secure_text_detection, token_detection, username_detection)
```

## Security Considerations

- **Read-Only Operation**: Tool only reads files, never modifies automation packages
- **Config.xlsx Security**: Resolved values may contain sensitive data - handle reports securely
- **False Positive Analysis**: Review FALSE-POSITIVE findings to ensure config keys exist where expected
- **Context Review**: Always manually review findings considering business context
- **Sensitive Environment**: Use in controlled environments when scanning production automation code
- **Beta Module Caution**: Modules in `modules-beta/` may have higher false positive rates

## Performance & Scalability

- **Parallel Processing**: Modules execute independently for optimal performance
- **Memory Efficient**: Processes files individually to minimize memory usage
- **Large Package Support**: Handles enterprise-scale UIPath automation projects
- **Incremental Scanning**: Tracks scanned files to avoid duplicate processing in nested packages
- **Real-time Feedback**: Inline mode provides immediate results without waiting for completion
- **Clean Output**: Verbose logging controlled by flags for better performance

## Troubleshooting

### Common Issues

**Config.xlsx Not Found:**
- Ensure Config.xlsx exists in package Data directory
- Check file permissions and accessibility  
- Verify package structure follows UIPath conventions

**Missing Dependencies:**
```bash
pip install -r requirements.txt
```

**Color Output Issues:**
- Install colorama: `pip install colorama`
- Ensure terminal supports ANSI color codes
- Colors automatically disabled on unsupported terminals

**High False Positive Rate:**
- Move problematic modules to `modules-beta/`
- Use severity filters to focus on critical issues
- Review FALSE-POSITIVE findings for legitimate patterns

**Verbose Output:**
- Use `--verbose` flag only when debugging
- Default mode hides DEBUG-level attribute extraction details
- Use `--warn` flag to see configuration warnings

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-security-module`)
3. Add your security module following the established patterns
4. Include proper GPL header with author information
5. Test thoroughly with various UIPath automation patterns
6. Update README.md with new module documentation
7. Submit a pull request with detailed description

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Support & Feedback

For issues, feature requests, or questions about UIPath security best practices, please create an issue in the repository with detailed information about your automation environment and security requirements. 