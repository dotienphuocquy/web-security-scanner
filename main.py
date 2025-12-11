#!/usr/bin/env python3
"""
Web Security Scanner - SQL Injection & XSS Detection Tool
Main entry point for the application
"""

import sys
import argparse
from colorama import init, Fore, Style

# Initialize colorama for Windows
init(autoreset=True)

def print_banner():
    """Display application banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║      {Fore.RED}WEB SECURITY SCANNER{Fore.CYAN}                               ║
║      {Fore.YELLOW}SQL Injection & XSS Detection Tool{Fore.CYAN}                ║
║                                                           ║
║      Version: 1.0                                         ║
║      Author: Security Testing Tool                       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def main():
    """Main application entry point"""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='Web Security Scanner for SQL Injection and XSS vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-u', '--url', 
                        help='Target URL to scan',
                        required=False)
    
    parser.add_argument('-t', '--type',
                        choices=['sqli', 'xss', 'all'],
                        default='all',
                        help='Type of scan: sqli, xss, or all (default: all)')
    
    parser.add_argument('-o', '--output',
                        help='Output file for report',
                        default='report')
    
    parser.add_argument('--gui',
                        action='store_true',
                        help='Launch web-based GUI interface')
    
    args = parser.parse_args()
    
    if args.gui:
        print(f"{Fore.GREEN}[*] Starting Web GUI interface...{Style.RESET_ALL}")
        from gui.app import start_gui
        start_gui()
    elif args.url:
        print(f"{Fore.GREEN}[*] Target URL: {args.url}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[*] Scan Type: {args.type.upper()}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Starting scan...{Style.RESET_ALL}\n")
        
        # Import scanners
        from scanners.sql_injection import SQLInjectionScanner
        from scanners.xss_scanner import XSSScanner
        from utils.report_generator import ReportGenerator
        
        results = []
        
        if args.type in ['sqli', 'all']:
            print(f"{Fore.CYAN}[*] Running SQL Injection scan...{Style.RESET_ALL}")
            sqli_scanner = SQLInjectionScanner(args.url)
            sqli_results = sqli_scanner.scan()
            results.extend(sqli_results)
        
        if args.type in ['xss', 'all']:
            print(f"{Fore.CYAN}[*] Running XSS scan...{Style.RESET_ALL}")
            xss_scanner = XSSScanner(args.url)
            xss_results = xss_scanner.scan()
            results.extend(xss_results)
        
        # Generate report
        print(f"\n{Fore.GREEN}[*] Generating report...{Style.RESET_ALL}")
        report_gen = ReportGenerator()
        report_gen.generate(results, args.output)
        
        print(f"{Fore.GREEN}[✓] Scan completed! Report saved to: {args.output}.html{Style.RESET_ALL}")
    else:
        parser.print_help()
        print(f"\n{Fore.YELLOW}Examples:{Style.RESET_ALL}")
        print(f"  python main.py -u http://example.com -t all")
        print(f"  python main.py -u http://example.com -t sqli -o sqli_report")
        print(f"  python main.py --gui")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
