# NuPkgAudit - UIPath Automation Security Auditor v3.0

A modular security auditing framework for UIPath automation packages that scans for security vulnerabilities and best practice violations.

## Overview

NuPkgAudit is a comprehensive security auditing tool designed specifically for UIPath automation projects. It provides a modular framework that can scan UIPath packages for various security issues including hardcoded credentials, insecure string handling, and other security vulnerabilities.

## Features

- **Modular Architecture**: Extensible framework with pluggable security modules
- **Comprehensive Scanning**: Scans multiple file types (.xaml, .vb, .cs, .txt, .json, .xml, .config, .ini)
- **Security Detection**: Identifies hardcoded credentials and insecure SecureString casting patterns
- **Flexible Reporting**: Generate reports in text and JSON formats
- **Severity Filtering**: Filter results by severity level (HIGH, MEDIUM, LOW, INFO, ERROR)
- **Alphabetical Processing**: Processes packages in alphabetical order for consistent results

## Installation

### Prerequisites

- Python 3.6 or higher
- Required dependencies (see requirements.txt)

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd NuPkgAudit
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Scan a directory containing UIPath packages:

```bash
python NuPkgAudit.py /path/to/packages
```

### Advanced Usage

```bash
# Scan with custom modules directory
python NuPkgAudit.py /path/to/packages --modules /path/to/modules

# Generate text report
python NuPkgAudit.py /path/to/packages --output report.txt

# Generate JSON results
python NuPkgAudit.py /path/to/packages --json results.json

# Filter by severity
python NuPkgAudit.py /path/to/packages --sev-high --output high_issues.txt

# Verbose output
python NuPkgAudit.py /path/to/packages --verbose
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `directory` | Directory containing UIPath packages (required) |
| `--modules, -m` | Directory containing scan modules (default: modules) |
| `--output, -o` | Output file for text report |
| `--json, -j` | Output file for JSON results |
| `--verbose, -v` | Enable verbose output |
| `--sev-high` | Only show HIGH severity findings |
| `--sev-medium` | Only show MEDIUM severity findings |
| `--sev-low` | Only show LOW severity findings |
| `--sev-info` | Only show INFO severity findings |

## Security Modules

### Credential Detection Module (`credential_detection.py`)

Scans for hardcoded passwords and credentials in UIPath automation files.

**Detects:**
- Hardcoded password assignments (`password = "value"`)
- Various credential patterns in configuration files

**False Positive Filtering:**
- UIPath configuration patterns
- Boolean literals and numeric values
- UIPath variable references
- Common configuration values

### SecureString Casting Module (`securestring_casting.py`)

Identifies dangerous SecureString casting patterns that can expose sensitive data.

**Detects:**
- String literals cast to SecureString using `.ToSecureString()`
- String literals cast to SecurePassword using `.SecurePassword`
- InArgument elements with SecureString casting
- Various SecureString casting patterns in XAML files

**False Positive Filtering:**
- UIPath configuration patterns
- Boolean literals and numeric values
- UIPath variable references
- Common configuration values

## Output Formats

### Text Report

The text report includes:
- Scan summary with statistics
- Issues grouped by severity
- Detailed findings with file locations and line numbers
- Module execution information

### JSON Output

The JSON output contains structured data including:
- Scan metadata (timestamp, package counts)
- Detailed issue information
- File and line references
- Module execution details

## Exit Codes

- `0`: No security issues found
- `1`: Security issues detected or error occurred

## Creating Custom Modules

To create a custom security module:

1. Create a Python file in the `modules/` directory
2. Implement a `scan_package(package_path: str)` function
3. Return a list of issue dictionaries with the following structure:

```python
{
    'type': 'module_name',
    'severity': 'HIGH|MEDIUM|LOW|INFO|ERROR',
    'description': 'Issue description',
    'file': 'file_path',
    'line': line_number,
    'line_content': 'content of the line',
    'module': 'module_name'
}
```

### Example Module Structure

```python
#!/usr/bin/env python3
"""
Custom Security Module
Description of what this module detects.
"""

import re
import logging
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def scan_package(package_path: str) -> List[Dict[str, Any]]:
    """
    Scan a UIPath package for security issues.
    
    Args:
        package_path: Path to the package directory
        
    Returns:
        List of issues found
    """
    issues = []
    # Your scanning logic here
    return issues
```

## Project Structure

```
NuPkgAudit/
├── NuPkgAudit.py              # Main auditor script
├── modules/                   # Security modules directory
│   ├── credential_detection.py
│   └── securestring_casting.py
├── requirements.txt           # Python dependencies
├── LICENSE                    # GNU GPL v3 license
└── README.md                 # This file
```

## Security Considerations

- The tool scans for security issues but does not modify files
- Always review findings manually before taking action
- Consider the context of detected issues (false positives may occur)
- Use in a controlled environment when scanning sensitive code

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your security module or improvements
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Author

Garland Glessner <gglessner@gmail.com>

## Version History

- **v3.0**: Modular framework with extensible security modules
- Enhanced false positive filtering
- Improved reporting capabilities
- Alphabetical package processing

## Support

For issues, questions, or contributions, please:
1. Check existing issues in the repository
2. Create a new issue with detailed information
3. Include sample code or files that demonstrate the problem

## Disclaimer

This tool is provided for educational and security auditing purposes. Users are responsible for ensuring compliance with applicable laws and regulations when using this tool. The authors are not liable for any misuse or damage resulting from the use of this software. 