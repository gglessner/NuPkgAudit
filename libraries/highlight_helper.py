import re

try:
    from colorama import Fore, Style
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    class Fore:
        YELLOW = '\033[93m'
    class Style:
        RESET_ALL = '\033[0m'

def highlight_match(full_line: str, matched_text: str) -> str:
    """
    Highlight the matched text in yellow within the full line.
    Uses colorama for cross-platform compatibility.
    """
    if not full_line or not matched_text:
        return full_line
    escaped_match = re.escape(matched_text.strip())
    if COLORAMA_AVAILABLE:
        yellow_start = Fore.YELLOW
        yellow_end = Style.RESET_ALL
    else:
        yellow_start = '\033[93m'
        yellow_end = '\033[0m'
    def highlight_repl(match):
        return f'{yellow_start}{match.group(0)}{yellow_end}'
    highlighted_line = re.sub(
        escaped_match,
        highlight_repl,
        full_line,
        flags=re.IGNORECASE
    )
    return highlighted_line 