# NuPkgAudit - UIPath Automation Security Auditor v3.0

A comprehensive modular security auditing framework for UIPath automation packages that scans for security vulnerabilities, hardcoded credentials, and configuration issues with advanced pattern detection and Config.xlsx resolution.

## Overview

NuPkgAudit is a sophisticated security auditing tool designed specifically for UIPath automation projects. It provides an extensible modular framework that scans UIPath packages for various security issues including hardcoded credentials, insecure string handling, configuration vulnerabilities, and authentication data exposure. The tool features advanced pattern detection for dynamic configuration retrieval patterns and intelligent Config.xlsx resolution.

## Key Features

- **🔧 Modular Architecture**: Extensible framework with 5 specialized security modules
- **🔍 Comprehensive Scanning**: Scans multiple file types (.xaml, .vb, .cs, .txt, .json, .xml, .config, .ini)
- **🛡️ Advanced Security Detection**: Identifies hardcoded credentials, tokens, usernames, and secure text patterns
- **⚙️ Sophisticated Pattern Detection**: Detects complex dynamic retrieval patterns including:
  - `in_AuthenticationData` patterns
  - `Config_data` patterns  
  - `DirectCast` and `TryCast` configurations
  - `NetworkCredential` patterns
  - `io_Config` and `io_Credentials` patterns
  - Case-insensitive `in_config` patterns in any context
- **📊 Config.xlsx Resolution**: Automatically resolves configuration values from package Config.xlsx files
- **🎯 Intelligent Classification**: Distinguishes between hardcoded values (HIGH) and dynamic patterns (MEDIUM/FALSE-POSITIVE)
- **🔆 Enhanced Highlighting**: Yellow highlighting with "→" format for resolved values and missing config keys
- **📈 Flexible Severity Levels**: HIGH, MEDIUM, LOW, INFO, ERROR, FALSE-POSITIVE classifications
- **📄 Multiple Output Formats**: Text reports, JSON, and Excel export capabilities
- **🎨 Cross-Platform Color Support**: Uses colorama for consistent colored output

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
# Include FALSE-POSITIVE findings in report
python NuPkgAudit.py packages --sev-fp

# Generate text report
python NuPkgAudit.py packages --output report.txt

# Generate JSON results
python NuPkgAudit.py packages --json results.json

# Filter by specific severity levels
python NuPkgAudit.py packages --sev-high
python NuPkgAudit.py packages --sev-medium --sev-low

# Multiple severity filters
python NuPkgAudit.py packages --sev-high --sev-medium --output critical_issues.txt

# Verbose output with detailed logging
python NuPkgAudit.py packages --verbose
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `directory` | Directory containing UIPath packages (required) |
| `--modules, -m` | Directory containing scan modules (default: modules) |
| `--output, -o` | Output file for text report |
| `--json, -j` | Output file for JSON results |
| `--verbose, -v` | Enable verbose output with detailed logging |
| `--sev-high` | Include HIGH severity findings |
| `--sev-medium` | Include MEDIUM severity findings |
| `--sev-low` | Include LOW severity findings |
| `--sev-info` | Include INFO severity findings |
| `--sev-error` | Include ERROR severity findings |
| `--sev-fp` | Include FALSE-POSITIVE findings |

## Security Modules

### 1. Password Detection Module (`password_detection.py`)
**Detects hardcoded Password, in_Password, and out_Password attributes in .xaml files.**

**Pattern Detection:**
- Basic hardcoded passwords → **HIGH**
- `in_AuthenticationData` patterns → **MEDIUM**
- `Config_data` retrieval patterns → **MEDIUM** 
- `DirectCast` configuration patterns → **MEDIUM**
- `NetworkCredential` with hardcoded values → **HIGH**
- `in_config` patterns with Config.xlsx resolution:
  - Found in Config.xlsx → **HIGH** (with resolved value)
  - Not found in Config.xlsx → **FALSE-POSITIVE** (with highlighting)

**Example Detections:**
```xml
<!-- HIGH: Hardcoded password -->
<Assign Password="hardcoded123" />

<!-- MEDIUM: Dynamic authentication data -->
<Assign Password="[in_AuthenticationData(&quot;api_password&quot;).ToString]" />

<!-- FALSE-POSITIVE: Config key not found -->
<Assign Password="[In_Config(&quot;MissingKey&quot;).ToString] → Value not in Config.xlsx" />
```

### 2. Secure Text Detection Module (`secure_text_detection.py`)
**Detects hardcoded SecureText attributes with comprehensive pattern analysis.**

**Advanced Pattern Detection:**
- `io_Credentials` patterns → **MEDIUM**
- `NetworkCredential` with JSON object retrieval → **MEDIUM**
- `CType io_Config` patterns → **MEDIUM**
- `DirectCast in_ConfigDetails` patterns → **MEDIUM**
- `TryCast Config_Data` patterns → **MEDIUM**
- `TryCast in_config` patterns → **MEDIUM**
- `DirectCast in_Config` patterns → **MEDIUM**
- All with case-insensitive detection and Config.xlsx resolution

**Example Detections:**
```xml
<!-- MEDIUM: Dynamic credentials retrieval -->
<Assign SecureText="[io_Credentials(&quot;domain&quot;).SecurePassword]" />

<!-- MEDIUM: NetworkCredential with JSON -->
<Assign SecureText="[(new System.Net.Network.NetworkCredential(&quot;&quot;, in_JsonObject(&quot;password&quot;).ToString)).SecurePassword]" />

<!-- FALSE-POSITIVE: Unresolved config -->
<Assign SecureText="[TryCast(in_config(&quot;My_Pass&quot;), SecureString)] → Value not in Config.xlsx" />
```

### 3. Token Detection Module (`token_detection.py`)
**Scans for hardcoded Token, in_Token, and out_Token attributes.**

**Features:**
- Hardcoded token detection → **HIGH**
- Variable format validation
- Config.xlsx resolution for `in_config` patterns
- FALSE-POSITIVE classification for missing config keys

### 4. Username Detection Module (`username_detection.py`)
**Detects hardcoded Username, in_Username, and out_Username attributes.**

**Features:**
- Hardcoded username detection → **HIGH**
- Advanced `in_config` pattern detection
- Config.xlsx value resolution
- Case-insensitive pattern matching

### 5. Client Certificate Password Detection Module (`client_certificate_password.py`)
**Scans for ClientCertificatePassword and SecureClientCertificatePassword attributes.**

**Features:**
- Hardcoded certificate password detection → **HIGH**
- `in_config` pattern resolution
- FALSE-POSITIVE classification for unresolved configurations

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
| **HIGH** | Definite security risks | Hardcoded passwords, resolved config values |
| **MEDIUM** | Potential security concerns | Dynamic authentication patterns, configuration retrieval |
| **LOW** | Best practice violations | Minor configuration issues |
| **INFO** | Informational findings | Documentation or context information |
| **ERROR** | Scan errors or exceptions | File read errors, parsing failures |
| **FALSE-POSITIVE** | Likely safe patterns | Unresolved config references, template patterns |

## Output Formats

### Text Report
Comprehensive text-based report with:
- Executive summary with issue counts by severity
- Package-by-package breakdown
- Detailed findings with context
- Color-coded highlighting (yellow for matches)
- Module execution statistics

### JSON Output
Structured JSON containing:
- Scan metadata and timestamps
- Complete issue catalog with detailed attributes
- File and line references
- Module performance data

### Console Output
Real-time scanning progress with:
- Package processing status
- Config.xlsx resolution messages
- Warning notifications for missing keys
- Final summary statistics

## Advanced Pattern Detection

The tool recognizes sophisticated UIPath patterns including:

### Authentication Data Patterns
```xml
<Assign Password="[in_AuthenticationData(&quot;mypassword&quot;).ToString]" />
<Assign Password="[in_Authentication(&quot;pwd&quot;).ToString]" />
```

### Configuration Data Patterns  
```xml
<Assign Password="[Config_data(&quot;AccessCode&quot;).ToString]" />
<Assign Password="[config_data(&quot;secret_key&quot;).ToString]" />
```

### DirectCast/TryCast Patterns
```xml
<Assign SecureText="[DirectCast(Config(&quot;My_password&quot;),SecureString)]" />
<Assign SecureText="[TryCast(Config_Data(&quot;Asset_Pass&quot;), System.Security.SecureString)]" />
```

### NetworkCredential Patterns
```xml
<Assign Password="[new System.net.NetworkCredential(&quot;&quot;,&quot;pass1234&quot;).SecurePassword]" />
<Assign SecureText="[(new System.Net.Network.NetworkCredential(&quot;&quot;, in_JsonObject(&quot;password&quot;).ToString)).SecurePassword]" />
```

### io_Config and io_Credentials Patterns
```xml
<Assign SecureText="[ctype(io_Config(&quot;Password&quot;),system.security.SecureString)]" />
<Assign SecureText="[io_Credentials(&quot;domain&quot;).SecurePassword]" />
```

## Creating Custom Modules

To create a custom security module:

1. Create a Python file in the `modules/` directory
2. Implement the required functions:

```python
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

def scan_xaml_file(file_path: Path, root_package: Path, root_package_name: str = None) -> List[Dict[str, Any]]:
    """Scan individual XAML files"""
    # Implementation here
    pass
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

## Project Structure

```
NuPkgAudit3/
├── NuPkgAudit.py                      # Main auditor script
├── modules/                           # Security modules directory
│   ├── client_certificate_password.py # Certificate password detection
│   ├── password_detection.py          # Password pattern detection
│   ├── secure_text_detection.py       # SecureText pattern detection  
│   ├── token_detection.py             # Token pattern detection
│   └── username_detection.py          # Username pattern detection
├── libraries/                         # Helper libraries
│   ├── config_helper.py               # Config.xlsx resolution utilities
│   └── highlight_helper.py            # Text highlighting functions
├── packages/                          # Test packages (for development)
├── requirements.txt                   # Python dependencies
├── create_config_xlsx.py             # Config.xlsx creation utility
├── LICENSE                           # GNU GPL v3 license
└── README.md                         # This comprehensive guide
```

## Example Usage Scenarios

### Security Audit Workflow
```bash
# 1. Quick security scan
python NuPkgAudit.py packages

# 2. Comprehensive audit including potential false positives  
python NuPkgAudit.py packages --sev-fp --output full_audit.txt

# 3. Critical issues only
python NuPkgAudit.py packages --sev-high --sev-error --json critical.json

# 4. Development workflow - all findings with verbose logging
python NuPkgAudit.py packages --sev-high --sev-medium --sev-fp --verbose
```

### Typical Output Summary
```
Issues by Severity:
  HIGH: 21        # Hardcoded credentials, resolved config values
  MEDIUM: 47      # Dynamic patterns, authentication data access
  FALSE-POSITIVE: 11  # Unresolved config references
  
Modules loaded: 5 (client_certificate_password, password_detection, secure_text_detection, token_detection, username_detection)
```

## Security Considerations

- **Read-Only Operation**: Tool only reads files, never modifies automation packages
- **Config.xlsx Security**: Resolved values may contain sensitive data - handle reports securely
- **False Positive Analysis**: Review FALSE-POSITIVE findings to ensure config keys exist where expected
- **Context Review**: Always manually review findings considering business context
- **Sensitive Environment**: Use in controlled environments when scanning production automation code

## Performance & Scalability

- **Parallel Processing**: Modules execute independently for optimal performance
- **Memory Efficient**: Processes files individually to minimize memory usage
- **Large Package Support**: Handles enterprise-scale UIPath automation projects
- **Incremental Scanning**: Tracks scanned files to avoid duplicate processing in nested packages

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

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-security-module`)
3. Add your security module following the established patterns
4. Test thoroughly with various UIPath automation patterns
5. Update README.md with new module documentation
6. Submit a pull request with detailed description

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Support & Feedback

For issues, feature requests, or questions about UIPath security best practices, please create an issue in the repository with detailed information about your automation environment and security requirements. 