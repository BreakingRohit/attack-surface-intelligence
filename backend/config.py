"""
Configuration module for Attack Surface Intelligence System
Production-grade settings with enhanced payloads and detection patterns
"""

import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent
MODULES_DIR = BASE_DIR / "modules"
WORDLISTS_DIR = BASE_DIR / "wordlists"
OUTPUT_DIR = BASE_DIR / "output"
REPORTS_DIR = OUTPUT_DIR / "reports"

# Ensure directories exist
WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# FIX #11: Performance settings - Optimized for speed
DEFAULT_THREADS = 25  # Increased for faster prioritized scanning
DEFAULT_TIMEOUT = 4  # Reduced from 5 for faster timeout detection
MAX_CRAWL_DEPTH = 2
MAX_REQUESTS_PER_DOMAIN = 100
MAX_RETRIES = 1  # Reduced from 2 for faster failure detection
RETRY_DELAY = 0.5  # Reduced from 1 for faster retries

# FIX #11: Caching and optimization
# - Baseline responses cached during vulnerability testing
# - JS analysis results cached per domain
# - Endpoint deduplication reduces duplicate testing
# - Early stopping on high confidence findings (>0.85)
# - Parallel module execution for independent stages
# Expected performance improvement: 40-60% faster overall

# Crawler settings
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
FOLLOW_REDIRECTS = True
VERIFY_SSL = False

# Alive endpoint filtering - accept these status codes as "alive"
ALIVE_STATUS_CODES = range(200, 400)  # 200-399 are alive

# Subdomain discovery
DEFAULT_SUB_WORDLIST = WORDLISTS_DIR / "subdomains.txt"
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "cpanel", "whois", "admin", "api", "dev", "test", "staging", "qa",
    "cdn", "static", "images", "assets", "media", "download", "blog",
    "shop", "store", "app", "mobile", "api2", "v1", "v2", "old", "new",
    "portal", "secure", "vpn", "remote", "ftp", "sftp", "backup", "db",
    "database", "mysql", "postgres", "redis", "elastic", "kibana", "grafana"
]

# Directory discovery
DEFAULT_DIR_WORDLIST = WORDLISTS_DIR / "directories.txt"
COMMON_DIRECTORIES = [
    "admin", "api", "app", "assets", "backup", "blog", "cdn", "config",
    "data", "dev", "download", "files", "images", "js", "login", "mail",
    "media", "old", "public", "secure", "static", "test", "tmp", "upload",
    "uploads", "user", "users", "var", "view", "views", "web", "www",
    "dashboard", "panel", "administrator", "manage", "portal", "console",
    "auth", "account", "profile", "settings", "docs", "documentation"
]

# FIX #6: HIGH-RISK ENDPOINT KEYWORDS - Expanded for better detection
# Mark endpoint HIGH if it contains any of these keywords
HIGH_RISK_ENDPOINT_KEYWORDS = [
    # Authentication & Authorization
    "admin", "login", "logout", "signin", "signup", "register", "auth",
    "oauth", "sso", "password", "reset", "forgot", "verify", "confirm",
    
    # User & Account Management
    "user", "users", "account", "profile", "settings", "preferences",
    "dashboard", "panel", "portal", "console", "manage", "management",
    
    # API & Data Access
    "api", "graphql", "rest", "v1", "v2", "v3", "endpoint", "service",
    
    # Sensitive Operations
    "upload", "download", "file", "files", "document", "export", "import",
    "backup", "restore", "delete", "remove", "update", "edit", "modify",
    
    # Internal/Debug
    "debug", "test", "dev", "staging", "internal", "private", "secure",
    "config", "configuration", "setup", "install", "phpinfo", "info",
    
    # Financial & Transactions
    "payment", "checkout", "cart", "order", "invoice", "billing", "subscription",
    
    # Database & Admin
    "database", "db", "sql", "query", "phpmyadmin", "adminer", "phpMyAdmin"
]


def is_high_risk_endpoint(endpoint: str) -> bool:
    """
    FIX #6: Helper function to check if an endpoint is high-risk
    Returns True if endpoint contains any high-risk keyword
    """
    endpoint_lower = endpoint.lower()
    return any(keyword in endpoint_lower for keyword in HIGH_RISK_ENDPOINT_KEYWORDS)

# ============================================================================
# VULNERABILITY DETECTION PAYLOADS (Layered: Basic -> Advanced)
# Maximum 5-6 payloads per vulnerability type for efficiency
# ============================================================================

# SQL Injection Payloads
SQLi_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "'--",
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND SLEEP(3)--",
]

# XSS Payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
]

# LFI Payloads
LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "/etc/passwd%00",
]

# SSRF Payloads
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254",  # AWS metadata
    "http://[::1]",
    "http://0.0.0.0",
]

# Open Redirect Payloads
OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "////evil.com",
]

# Command Injection Payloads (Light - safe for detection)
COMMAND_INJECTION_PAYLOADS = [
    ";id",
    "| id",
    "&& whoami",
    "|| whoami",
    "`id`",
]

# IDOR test values
IDOR_TEST_VALUES = [1, 2, 3, 10, 100, 999, "admin", "test", "0"]

# ============================================================================
# PARAMETER CLASSIFICATION MAPPINGS
# ============================================================================

# Parameter -> Vulnerability Type Mapping
PARAM_VULN_MAPPING = {
    # SQLi / IDOR prone parameters
    "id": ["SQLi", "IDOR"],
    "user_id": ["SQLi", "IDOR"],
    "userid": ["SQLi", "IDOR"],
    "account_id": ["SQLi", "IDOR"],
    "product_id": ["SQLi", "IDOR"],
    "order_id": ["SQLi", "IDOR"],
    "item_id": ["SQLi", "IDOR"],
    "post_id": ["SQLi", "IDOR"],
    "comment_id": ["SQLi", "IDOR"],
    "doc_id": ["SQLi", "IDOR"],
    
    # XSS prone parameters
    "q": ["XSS"],
    "query": ["XSS"],
    "search": ["XSS"],
    "keyword": ["XSS"],
    "term": ["XSS"],
    "s": ["XSS"],
    "name": ["XSS"],
    "message": ["XSS"],
    "comment": ["XSS"],
    "body": ["XSS"],
    "content": ["XSS"],
    "title": ["XSS"],
    "description": ["XSS"],
    
    # LFI prone parameters
    "file": ["LFI"],
    "filename": ["LFI"],
    "path": ["LFI"],
    "filepath": ["LFI"],
    "template": ["LFI"],
    "page": ["LFI", "SQLi"],
    "include": ["LFI"],
    "doc": ["LFI"],
    "document": ["LFI"],
    "folder": ["LFI"],
    "root": ["LFI"],
    "dir": ["LFI"],
    
    # SSRF / Open Redirect prone parameters
    "url": ["SSRF", "Open Redirect"],
    "redirect": ["Open Redirect"],
    "redirect_url": ["Open Redirect"],
    "return": ["Open Redirect"],
    "return_url": ["Open Redirect"],
    "next": ["Open Redirect"],
    "next_url": ["Open Redirect"],
    "dest": ["SSRF", "Open Redirect"],
    "destination": ["SSRF", "Open Redirect"],
    "uri": ["SSRF", "Open Redirect"],
    "link": ["SSRF", "Open Redirect"],
    "target": ["SSRF"],
    "host": ["SSRF"],
    "domain": ["SSRF"],
    
    # Command Injection prone parameters
    "cmd": ["Command Injection"],
    "exec": ["Command Injection"],
    "command": ["Command Injection"],
    "execute": ["Command Injection"],
    "ping": ["Command Injection"],
    "ip": ["Command Injection"],
    "host": ["Command Injection", "SSRF"],
    
    # HIGH-RISK authentication parameters
    "auth": ["Credential Exposure"],
    "token": ["Credential Exposure"],
    "api_key": ["Credential Exposure"],
    "apikey": ["Credential Exposure"],
    "key": ["Credential Exposure"],
    "secret": ["Credential Exposure"],
    "password": ["Credential Exposure"],
    "passwd": ["Credential Exposure"],
    "pwd": ["Credential Exposure"],
    "session": ["Credential Exposure"],
    "jwt": ["Credential Exposure"],
    "bearer": ["Credential Exposure"],
}

# Risk levels for parameter types
HIGH_RISK_PARAMS = [
    "id", "user_id", "userid", "account_id", "product_id", "order_id",
    "auth", "token", "api_key", "apikey", "key", "secret", "password",
    "admin", "file", "path", "cmd", "exec", "url", "redirect"
]

MEDIUM_RISK_PARAMS = [
    "search", "q", "query", "keyword", "category", "type", "page",
    "name", "email", "message", "comment", "title"
]

# SQL Error Keywords for detection
SQL_ERROR_KEYWORDS = [
    "SQL", "mysql", "postgres", "syntax", "error", "exception",
    "Warning", "ODBC", "Oracle", "SQLite", "MariaDB", "Microsoft SQL",
    "invalid query", "sql error", "database error", "query failed",
    "ORA-", "PG::", "unclosed quotation"
]

# LFI Success Indicators
LFI_INDICATORS = [
    "root:x:", "daemon:x:", "bin:x:",  # /etc/passwd
    "[extensions]", "[fonts]",  # win.ini
    "<?php", "<%", "#!/",  # source disclosure
]

# API keywords for endpoint classification
API_KEYWORDS = [
    "api", "endpoint", "rest", "graphql", "v1", "v2", "v3",
    "service", "method", "function", "webhook", "callback"
]

# Output settings
OUTPUT_FORMATS = ["text", "json"]
DEFAULT_OUTPUT_FORMAT = "text"

# CLI Colors (ANSI escape codes)
COLORS = {
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "MAGENTA": "\033[95m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "GREY": "\033[90m",
}

# Severity colors
SEVERITY_COLORS = {
    "CRITICAL": COLORS["RED"],
    "HIGH": COLORS["MAGENTA"],
    "MEDIUM": COLORS["YELLOW"],
    "LOW": COLORS["CYAN"],
    "INFO": COLORS["GREY"],
}
