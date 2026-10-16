
ATTACK_SIGNATURES = [
    {
        "name": "SQL Injection - UNION SELECT",
        "category": "SQL_INJECTION",
        "pattern": r"\bunion\s+(?:all\s+)?select\b",
        "severity": "HIGH",
    },
    {
        "name": "SQL Injection - Boolean Condition",
        "category": "SQL_INJECTION",
        "pattern": r"""(?i)\b(?:or|and)\b\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?""",
        "severity": "HIGH",
    },
    {
        "name": "SQL Injection - SELECT FROM",
        "category": "SQL_INJECTION",
        "pattern": r"\bselect\b.{1,200}\bfrom\b",
        "severity": "HIGH",
    },
    {
        "name": "SQL Injection - SQL Comment",
        "category": "SQL_INJECTION",
        "pattern": r"(?:--|#)\s*$",
        "severity": "MEDIUM",
    },
    {
        "name": "Cross-Site Scripting - Script Tag",
        "category": "XSS",
        "pattern": r"<\s*script\b",
        "severity": "HIGH",
    },
    {
        "name": "Cross-Site Scripting - JavaScript URI",
        "category": "XSS",
        "pattern": r"javascript\s*:",
        "severity": "HIGH",
    },
    {
        "name": "Cross-Site Scripting - Event Handler",
        "category": "XSS",
        "pattern": r"\bon(?:error|load|click)\s*=",
        "severity": "HIGH",
    },
    {
        "name": "Path Traversal - Relative Path",
        "category": "PATH_TRAVERSAL",
        "pattern": r"\.\.[/\\]",
        "severity": "HIGH",
    },
    {
        "name": "Path Traversal - Encoded Path",
        "category": "PATH_TRAVERSAL",
        "pattern": r"%2e%2e(?:%2f|%5c)",
        "severity": "HIGH",
    },
    {
        "name": "Path Traversal - Sensitive File",
        "category": "PATH_TRAVERSAL",
        "pattern": r"/etc/passwd\b",
        "severity": "HIGH",
    },
    {
        "name": "Command Injection - Shell Separator",
        "category": "COMMAND_INJECTION",
        "pattern": r"(?:;|&&|\|\|)\s*(?:cat|whoami|id|uname)\b",
        "severity": "HIGH",
    },
    {
        "name": "Command Injection - Pipe",
        "category": "COMMAND_INJECTION",
        "pattern": r"\|\s*(?:cat|whoami|id|uname)\b",
        "severity": "HIGH",
    },
    {
        "name": "Command Injection - Backticks",
        "category": "COMMAND_INJECTION",
        "pattern": r"`[^`\r\n]{1,150}`",
        "severity": "HIGH",
    },
    {
        "name": "Command Injection - Command Substitution",
        "category": "COMMAND_INJECTION",
        "pattern": r"\$\([^()\r\n]{1,150}\)",
        "severity": "HIGH",
    },
]
