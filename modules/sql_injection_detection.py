import re
import logging
from libraries.config_helper import resolve_config_value
from libraries.highlight_helper import highlight_match

# Configure logging
logger = logging.getLogger(__name__)

def is_string_concatenation_sql_pattern(stripped_value):
    """
    Detect SQL queries using string concatenation which could lead to SQL injection
    """
    # Patterns for string concatenation in SQL
    concatenation_patterns = [
        r'SELECT\s+.*?\+.*?FROM',  # SELECT with + concatenation
        r'INSERT\s+.*?\+.*?VALUES',  # INSERT with + concatenation
        r'UPDATE\s+.*?\+.*?SET',  # UPDATE with + concatenation
        r'DELETE\s+.*?\+.*?WHERE',  # DELETE with + concatenation
        r'WHERE\s+.*?\+.*?[=<>]',  # WHERE clause with concatenation
        r'["\'].*?\+.*?["\'].*?WHERE',  # String concatenation in WHERE
        r'["\'].*?\+\s*\w+\s*\+.*?["\']',  # Variable concatenation pattern
        r'Query.*?=.*?["\'].*?\+.*?["\']',  # Query property with concatenation
        r'CommandText.*?=.*?["\'].*?\+.*?["\']',  # CommandText with concatenation
    ]
    
    for pattern in concatenation_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE | re.DOTALL):
            return True
    return False

def is_unparameterized_query_pattern(stripped_value):
    """
    Detect unparameterized database queries that may be vulnerable to SQL injection
    """
    # Look for SQL keywords with potential variable insertion
    unparameterized_patterns = [
        r'SELECT\s+.*?WHERE\s+.*?["\'].*?\[.*?\].*?["\']',  # Variables in WHERE clause
        r'INSERT\s+INTO\s+.*?VALUES\s*\(.*?\[.*?\].*?\)',  # Variables in INSERT VALUES
        r'UPDATE\s+.*?SET\s+.*?=\s*["\'].*?\[.*?\].*?["\']',  # Variables in UPDATE SET
        r'DELETE\s+FROM\s+.*?WHERE\s+.*?["\'].*?\[.*?\].*?["\']',  # Variables in DELETE WHERE
        r'EXEC\s+.*?\[.*?\]',  # Execute with variables
        r'sp_executesql.*?\[.*?\]',  # sp_executesql with variables
    ]
    
    for pattern in unparameterized_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE | re.DOTALL):
            return True
    return False

def is_dynamic_query_construction_pattern(stripped_value):
    """
    Detect dynamic SQL query construction patterns
    """
    dynamic_patterns = [
        r'["\']SELECT\s+.*?["\'].*?\+.*?["\'].*?["\']',  # Dynamic SELECT construction
        r'String\.Format\s*\(\s*["\'].*?SELECT.*?\{.*?\}.*?["\']',  # String.Format with SQL
        r'String\.Concat\s*\(.*?SELECT.*?\)',  # String.Concat with SQL
        r'\$["\']SELECT.*?\{.*?\}.*?["\']',  # String interpolation with SQL
        r'StringBuilder.*?Append.*?SELECT',  # StringBuilder with SQL
        r'["\'].*?WHERE.*?\{.*?\}.*?["\']',  # String interpolation in WHERE
    ]
    
    for pattern in dynamic_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE | re.DOTALL):
            return True
    return False

def is_database_connection_injection_pattern(stripped_value):
    """
    Detect potential SQL injection in database connection strings
    """
    connection_patterns = [
        r'Data\s+Source\s*=.*?\+.*?;',  # Data Source with concatenation
        r'Server\s*=.*?\+.*?;',  # Server with concatenation
        r'Database\s*=.*?\+.*?;',  # Database with concatenation
        r'ConnectionString.*?=.*?["\'].*?\+.*?["\']',  # ConnectionString with concatenation
        r'Initial\s+Catalog\s*=.*?\[.*?\]',  # Initial Catalog with variables
    ]
    
    for pattern in connection_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE | re.DOTALL):
            return True
    return False

def is_stored_procedure_injection_pattern(stripped_value):
    """
    Detect potential SQL injection in stored procedure calls
    """
    sp_patterns = [
        r'EXEC\s+.*?\+.*?;',  # EXEC with concatenation
        r'EXECUTE\s+.*?\+.*?;',  # EXECUTE with concatenation
        r'sp_.*?\+.*?;',  # Stored procedure with concatenation
        r'CALL\s+.*?\+.*?\(',  # CALL with concatenation
    ]
    
    for pattern in sp_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE | re.DOTALL):
            return True
    return False

def is_sql_comment_injection_pattern(stripped_value):
    """
    Detect SQL comment-based injection patterns
    """
    comment_patterns = [
        r'--.*?\+.*?',  # SQL line comment with concatenation
        r'/\*.*?\+.*?\*/',  # SQL block comment with concatenation
        r'["\'].*?--.*?["\']',  # String containing SQL comments
        r'["\'].*?/\*.*?\*/.*?["\']',  # String containing block comments
    ]
    
    for pattern in comment_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE | re.DOTALL):
            return True
    return False

def is_union_based_injection_pattern(stripped_value):
    """
    Detect UNION-based SQL injection patterns
    """
    union_patterns = [
        r'UNION\s+SELECT.*?\+.*?',  # UNION SELECT with concatenation
        r'["\'].*?UNION.*?["\'].*?\+',  # UNION in concatenated strings
        r'ORDER\s+BY.*?\+.*?',  # ORDER BY with concatenation (for column enumeration)
    ]
    
    for pattern in union_patterns:
        if re.search(pattern, stripped_value, re.IGNORECASE | re.DOTALL):
            return True
    return False

def determine_sql_injection_severity_and_description(attr_value):
    """
    Determine the severity and description for SQL injection vulnerabilities
    """
    stripped_value = attr_value.strip().strip('"').strip("'")
    
    # Critical patterns (HIGH severity)
    if (is_string_concatenation_sql_pattern(stripped_value) or 
        is_unparameterized_query_pattern(stripped_value)):
        return 'HIGH', 'SQL injection vulnerability detected - Unparameterized query with string concatenation'
    
    # High-risk patterns (HIGH severity)
    if (is_union_based_injection_pattern(stripped_value) or 
        is_sql_comment_injection_pattern(stripped_value)):
        return 'HIGH', 'SQL injection vulnerability detected - Advanced injection patterns found'
    
    # Medium-risk patterns (MEDIUM severity)
    if (is_dynamic_query_construction_pattern(stripped_value) or 
        is_database_connection_injection_pattern(stripped_value) or 
        is_stored_procedure_injection_pattern(stripped_value)):
        return 'MEDIUM', 'Potential SQL injection vulnerability - Dynamic SQL construction detected'
    
    return 'LOW', 'Potential SQL injection risk - Review query construction'

def scan_sql_injection_vulnerabilities(file_path, content):
    """
    Scan for SQL injection vulnerabilities in UIPath XAML files
    """
    results = []
    
    # SQL-related attributes to check
    sql_attributes = [
        'Query', 'CommandText', 'ConnectionString', 'SqlQuery', 'Statement',
        'Command', 'QueryString', 'DatabaseQuery', 'SqlStatement', 'Text',
        'Value', 'Expression', 'Arguments', 'Parameters'
    ]
    
    # Create pattern for SQL-related attributes
    sql_pattern = '|'.join([rf'{attr}=' for attr in sql_attributes])
    
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        # Skip if line doesn't contain SQL-related attributes
        if not re.search(sql_pattern, line, re.IGNORECASE):
            continue
            
        # Look for attribute patterns
        for attr_name in sql_attributes:
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
                    if len(attr_value) < 10:
                        continue
                    
                    # Check if this looks like SQL content
                    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 
                                  'ALTER', 'EXEC', 'EXECUTE', 'CALL', 'sp_', 'FROM', 'WHERE']
                    
                    has_sql_keyword = any(keyword.lower() in attr_value.lower() for keyword in sql_keywords)
                    if not has_sql_keyword:
                        continue
                    
                    # Resolve config values if present
                    resolved_value = resolve_config_value(attr_value, file_path)
                    
                    # Check various SQL injection patterns
                    is_vulnerable = (
                        is_string_concatenation_sql_pattern(attr_value) or
                        is_unparameterized_query_pattern(attr_value) or
                        is_dynamic_query_construction_pattern(attr_value) or
                        is_database_connection_injection_pattern(attr_value) or
                        is_stored_procedure_injection_pattern(attr_value) or
                        is_sql_comment_injection_pattern(attr_value) or
                        is_union_based_injection_pattern(attr_value)
                    )
                    
                    if is_vulnerable:
                        severity, description = determine_sql_injection_severity_and_description(attr_value)
                        
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
                            'module': 'sql_injection_detection'
                        })
    
    return results 