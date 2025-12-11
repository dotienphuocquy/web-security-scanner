"""
Quick Test Script for Web Security Scanner
Run this to test the scanner against the vulnerable app
"""

import sys
import time
import subprocess
import requests
from colorama import Fore, Style, init

init(autoreset=True)

def check_vulnerable_app():
    """Check if vulnerable app is running"""
    try:
        response = requests.get('http://127.0.0.1:8080', timeout=2)
        return True
    except:
        return False

def test_sql_injection():
    """Test SQL Injection scanner"""
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Testing SQL Injection Scanner{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    from scanners.sql_injection import SQLInjectionScanner
    
    test_urls = [
        "http://127.0.0.1:8080/login",
        "http://127.0.0.1:8080/search?q=test",
        "http://127.0.0.1:8080/profile?id=1"
    ]
    
    total_vulns = 0
    for url in test_urls:
        print(f"\n{Fore.YELLOW}[*] Testing: {url}{Style.RESET_ALL}")
        scanner = SQLInjectionScanner(url)
        results = scanner.scan()
        total_vulns += len(results)
    
    return total_vulns

def test_xss():
    """Test XSS scanner"""
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Testing XSS Scanner{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    from scanners.xss_scanner import XSSScanner
    
    test_urls = [
        "http://127.0.0.1:8080/search?q=test",
        "http://127.0.0.1:8080/post/1"
    ]
    
    total_vulns = 0
    for url in test_urls:
        print(f"\n{Fore.YELLOW}[*] Testing: {url}{Style.RESET_ALL}")
        scanner = XSSScanner(url)
        results = scanner.scan()
        total_vulns += len(results)
    
    return total_vulns

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Web Security Scanner - Quick Test{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    # Check if vulnerable app is running
    if not check_vulnerable_app():
        print(f"{Fore.RED}[!] Vulnerable app is not running!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Please start it first:{Style.RESET_ALL}")
        print(f"    cd vulnerable_app")
        print(f"    python app.py")
        print(f"\n{Fore.YELLOW}[*] Or run in another terminal, then run this test again.{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}[✓] Vulnerable app is running{Style.RESET_ALL}\n")
    
    # Test SQL Injection
    sqli_vulns = test_sql_injection()
    
    # Test XSS
    xss_vulns = test_xss()
    
    # Summary
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Test Summary{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"SQL Injection vulnerabilities found: {Fore.GREEN}{sqli_vulns}{Style.RESET_ALL}")
    print(f"XSS vulnerabilities found: {Fore.GREEN}{xss_vulns}{Style.RESET_ALL}")
    print(f"Total vulnerabilities found: {Fore.GREEN}{sqli_vulns + xss_vulns}{Style.RESET_ALL}")
    
    if sqli_vulns + xss_vulns > 0:
        print(f"\n{Fore.GREEN}[✓] Scanner is working correctly!{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}[!] No vulnerabilities detected. There might be an issue.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
