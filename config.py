# Configuration file for Web Security Scanner

# Scanner settings
TIMEOUT = 10  # Request timeout in seconds
MAX_THREADS = 5  # Maximum concurrent threads
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# SQL Injection settings
SQLI_DETECTION_TIMEOUT = 5  # Time-based SQLi detection delay
SQLI_MAX_PAYLOADS = 50  # Maximum payloads to test per parameter

# XSS settings
XSS_MAX_PAYLOADS = 30  # Maximum XSS payloads to test

# Report settings
REPORT_DIR = "reports"
REPORT_FORMAT = "html"  # html, json, or both

# Logging
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR
LOG_FILE = "scanner.log"
