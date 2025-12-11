"""
SQL Injection Scanner Module
Automatically detects SQL injection vulnerabilities in web applications
"""

import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from colorama import Fore, Style

from utils.http_client import HTTPClient
from utils.crawler import WebCrawler
from payloads.sql_payloads import SQLPayloads
from config import SQLI_DETECTION_TIMEOUT, SQLI_MAX_PAYLOADS


class SQLInjectionScanner:
    """SQL Injection vulnerability scanner"""
    
    def __init__(self, url):
        self.url = url
        self.client = HTTPClient()
        self.vulnerabilities = []
        self.tested_params = set()
    
    def scan(self):
        """Main scan function"""
        print(f"{Fore.CYAN}[*] Starting SQL Injection scan on: {self.url}{Style.RESET_ALL}")
        
        # Check if URL is base URL (no specific page)
        parsed = urlparse(self.url)
        is_base_url = parsed.path in ['', '/']
        
        urls_to_scan = [self.url]
        
        # If base URL, crawl to find pages
        if is_base_url:
            print(f"{Fore.CYAN}[*] Base URL detected, crawling website...{Style.RESET_ALL}")
            crawler = WebCrawler(self.url, max_depth=2, max_pages=15)
            discovered_urls = crawler.crawl()
            
            if discovered_urls:
                important_urls = crawler.get_important_endpoints()
                urls_to_scan = important_urls[:10]  # Limit to 10 most important
                print(f"{Fore.GREEN}[✓] Will scan {len(urls_to_scan)} discovered page(s){Style.RESET_ALL}")
        
        # Scan each URL
        for scan_url in urls_to_scan:
            self.url = scan_url
            self._scan_single_url()
        
        # Print summary
        self._print_summary()
        
        return self.vulnerabilities
    
    def _scan_single_url(self):
        """Scan a single URL"""
        if len(self.vulnerabilities) > 0:
            print(f"\n{Fore.CYAN}[*] Scanning: {self.url}{Style.RESET_ALL}")
        
        # Get parameters from URL
        params = self._get_url_parameters()
        
        # Scan GET parameters
        if params:
            print(f"{Fore.YELLOW}[*] Testing GET parameters: {list(params.keys())}{Style.RESET_ALL}")
            self._scan_get_parameters(params)
        
        # Scan POST forms
        forms = self._get_forms()
        if forms:
            print(f"{Fore.YELLOW}[*] Found {len(forms)} form(s), testing POST parameters...{Style.RESET_ALL}")
            for form in forms:
                self._scan_post_form(form)
    
    def _get_url_parameters(self):
        """Extract parameters from URL"""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        # Convert lists to single values
        result = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        # Also set base URL without parameters
        self.base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return result
    
    def _get_forms(self):
        """Extract forms from the webpage"""
        try:
            response = self.client.get(self.url)
            if not response:
                return []
            
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            form_details = []
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = []
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_type = input_tag.get('type', 'text')
                    input_name = input_tag.get('name')
                    if input_name:
                        inputs.append({
                            'type': input_type,
                            'name': input_name
                        })
                
                if inputs:
                    form_details.append({
                        'action': action,
                        'method': method,
                        'inputs': inputs
                    })
            
            return form_details
        except Exception as e:
            print(f"{Fore.RED}[!] Error parsing forms: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _scan_get_parameters(self, params):
        """Scan GET parameters for SQL injection"""
        for param_name, param_value in params.items():
            if param_name in self.tested_params:
                continue
            
            self.tested_params.add(param_name)
            print(f"{Fore.CYAN}  [*] Testing parameter: {param_name}{Style.RESET_ALL}")
            
            # Test error-based SQL injection
            if self._test_error_based(param_name, param_value, params):
                continue
            
            # Test union-based SQL injection
            if self._test_union_based(param_name, param_value, params):
                continue
            
            # Test boolean-based SQL injection
            if self._test_boolean_based(param_name, param_value, params):
                continue
            
            # Test time-based SQL injection
            if self._test_time_based(param_name, param_value, params):
                continue
    
    def _scan_post_form(self, form):
        """Scan POST form for SQL injection"""
        action = form['action']
        method = form['method']
        inputs = form['inputs']
        
        # Build form URL
        parsed = urlparse(self.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        if action.startswith('http'):
            form_url = action
        elif action.startswith('/'):
            form_url = base + action
        elif action:
            # Relative URL
            path = parsed.path.rsplit('/', 1)[0] if '/' in parsed.path else ''
            form_url = base + path + '/' + action
        else:
            # Empty action means current page
            form_url = self.url.split('?')[0]
        
        print(f"{Fore.CYAN}  [*] Testing form at: {form_url}{Style.RESET_ALL}")
        
        # Test each input field
        for input_field in inputs:
            if input_field['type'] in ['submit', 'button', 'hidden']:
                continue
            
            param_name = input_field['name']
            if param_name in self.tested_params:
                continue
            
            self.tested_params.add(param_name)
            print(f"{Fore.CYAN}    [*] Testing field: {param_name}{Style.RESET_ALL}")
            
            # Build form data
            form_data = {}
            for inp in inputs:
                form_data[inp['name']] = 'test'
            
            # Test error-based
            if self._test_error_based_post(form_url, param_name, form_data):
                continue
            
            # Test time-based
            self._test_time_based_post(form_url, param_name, form_data)
    
    def _test_error_based(self, param_name, param_value, params):
        """Test for error-based SQL injection"""
        for payload in SQLPayloads.ERROR_BASED[:20]:  # Test first 20 payloads
            test_params = params.copy()
            test_params[param_name] = payload
            
            response = self._send_request(test_params)
            if response and self._check_sql_errors(response.text):
                self._add_vulnerability(
                    vuln_type="Error-based SQL Injection",
                    param=param_name,
                    payload=payload,
                    method="GET",
                    evidence="SQL error detected in response"
                )
                print(f"{Fore.GREEN}    [✓] Vulnerable to Error-based SQLi!{Style.RESET_ALL}")
                return True
        
        # Also test numeric injection for id parameters
        if param_name.lower() in ['id', 'user_id', 'post_id', 'product_id']:
            numeric_payloads = ["1'", "1\"", "1 AND 1=1", "1 AND 1=2", "1 OR 1=1"]
            for payload in numeric_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                response = self._send_request(test_params)
                if response and self._check_sql_errors(response.text):
                    self._add_vulnerability(
                        vuln_type="Error-based SQL Injection",
                        param=param_name,
                        payload=payload,
                        method="GET",
                        evidence="SQL error detected in numeric parameter"
                    )
                    print(f"{Fore.GREEN}    [✓] Vulnerable to Error-based SQLi (numeric)!{Style.RESET_ALL}")
                    return True
        
        return False
    
    def _test_union_based(self, param_name, param_value, params):
        """Test for union-based SQL injection"""
        # Test numeric UNION for id parameters
        if param_name.lower() in ['id', 'user_id', 'post_id', 'product_id']:
            numeric_union_payloads = [
                "1 UNION SELECT NULL--",
                "1 UNION SELECT NULL,NULL--",
                "1 UNION SELECT NULL,NULL,NULL--",
                "1 UNION SELECT NULL,NULL,NULL,NULL--",
                "1 UNION SELECT NULL,NULL,NULL,NULL,NULL--",
                "1 UNION SELECT 1,2,3,4,5--",
            ]
            for payload in numeric_union_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                response = self._send_request(test_params)
                if response and self._check_union_success(response.text):
                    self._add_vulnerability(
                        vuln_type="Union-based SQL Injection",
                        param=param_name,
                        payload=payload,
                        method="GET",
                        evidence="Union query successful with numeric injection"
                    )
                    print(f"{Fore.GREEN}    [✓] Vulnerable to Union-based SQLi!{Style.RESET_ALL}")
                    return True
        
        for payload in SQLPayloads.UNION_BASED[:10]:  # Test first 10 payloads
            test_params = params.copy()
            test_params[param_name] = payload
            
            response = self._send_request(test_params)
            if response:
                # Check for successful UNION injection indicators
                if self._check_union_success(response.text):
                    self._add_vulnerability(
                        vuln_type="Union-based SQL Injection",
                        param=param_name,
                        payload=payload,
                        method="GET",
                        evidence="Union query successful"
                    )
                    print(f"{Fore.GREEN}    [✓] Vulnerable to Union-based SQLi!{Style.RESET_ALL}")
                    return True
        
        return False
    
    def _test_boolean_based(self, param_name, param_value, params):
        """Test for boolean-based blind SQL injection"""
        # Get baseline response
        baseline_response = self._send_request(params)
        if not baseline_response:
            return False
        
        baseline_length = len(baseline_response.text)
        
        # Test with true condition
        true_params = params.copy()
        true_params[param_name] = param_value + SQLPayloads.BOOLEAN_BASED[0]  # AND '1'='1
        true_response = self._send_request(true_params)
        
        # Test with false condition
        false_params = params.copy()
        false_params[param_name] = param_value + SQLPayloads.BOOLEAN_BASED[1]  # AND '1'='2
        false_response = self._send_request(false_params)
        
        if true_response and false_response:
            true_length = len(true_response.text)
            false_length = len(false_response.text)
            
            # Check if responses differ significantly
            if abs(true_length - baseline_length) < 100 and abs(true_length - false_length) > 100:
                self._add_vulnerability(
                    vuln_type="Boolean-based Blind SQL Injection",
                    param=param_name,
                    payload=SQLPayloads.BOOLEAN_BASED[0],
                    method="GET",
                    evidence=f"Response length differs: True={true_length}, False={false_length}"
                )
                print(f"{Fore.GREEN}    [✓] Vulnerable to Boolean-based Blind SQLi!{Style.RESET_ALL}")
                return True
        
        return False
    
    def _test_time_based(self, param_name, param_value, params):
        """Test for time-based blind SQL injection"""
        for payload in SQLPayloads.TIME_BASED[:5]:  # Test first 5 payloads
            test_params = params.copy()
            test_params[param_name] = payload
            
            start_time = time.time()
            response = self._send_request(test_params)
            elapsed_time = time.time() - start_time
            
            # Check if response was delayed (indicating successful time-based injection)
            if elapsed_time >= SQLI_DETECTION_TIMEOUT - 1:  # Allow 1 second tolerance
                self._add_vulnerability(
                    vuln_type="Time-based Blind SQL Injection",
                    param=param_name,
                    payload=payload,
                    method="GET",
                    evidence=f"Response delayed by {elapsed_time:.2f} seconds"
                )
                print(f"{Fore.GREEN}    [✓] Vulnerable to Time-based Blind SQLi!{Style.RESET_ALL}")
                return True
        
        return False
    
    def _test_error_based_post(self, url, param_name, form_data):
        """Test POST form for error-based SQL injection"""
        for payload in SQLPayloads.ERROR_BASED[:10]:
            test_data = form_data.copy()
            test_data[param_name] = payload
            
            response = self.client.post(url, data=test_data)
            if response and self._check_sql_errors(response.text):
                self._add_vulnerability(
                    vuln_type="Error-based SQL Injection",
                    param=param_name,
                    payload=payload,
                    method="POST",
                    url=url,
                    evidence="SQL error detected in response"
                )
                print(f"{Fore.GREEN}      [✓] Vulnerable to Error-based SQLi (POST)!{Style.RESET_ALL}")
                return True
        
        return False
    
    def _test_time_based_post(self, url, param_name, form_data):
        """Test POST form for time-based SQL injection"""
        for payload in SQLPayloads.TIME_BASED[:3]:
            test_data = form_data.copy()
            test_data[param_name] = payload
            
            start_time = time.time()
            response = self.client.post(url, data=test_data)
            elapsed_time = time.time() - start_time
            
            if elapsed_time >= SQLI_DETECTION_TIMEOUT - 1:
                self._add_vulnerability(
                    vuln_type="Time-based Blind SQL Injection",
                    param=param_name,
                    payload=payload,
                    method="POST",
                    url=url,
                    evidence=f"Response delayed by {elapsed_time:.2f} seconds"
                )
                print(f"{Fore.GREEN}      [✓] Vulnerable to Time-based Blind SQLi (POST)!{Style.RESET_ALL}")
                return True
        
        return False
    
    def _send_request(self, params):
        """Send GET request with parameters"""
        # Use base_url if available, otherwise parse from self.url
        if hasattr(self, 'base_url'):
            base = self.base_url
        else:
            parsed = urlparse(self.url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        query_string = urlencode(params)
        test_url = base + '?' + query_string if query_string else base
        
        return self.client.get(test_url)
    
    def _check_sql_errors(self, response_text):
        """Check if response contains SQL error messages"""
        for signature in SQLPayloads.ERROR_SIGNATURES:
            if signature.lower() in response_text.lower():
                return True
        return False
    
    def _check_union_success(self, response_text):
        """Check for indicators of successful UNION injection"""
        # Look for typical database information
        indicators = [
            r'\d+\.\d+\.\d+',  # Version numbers
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',  # UUIDs
            'information_schema',
            'mysql',
            'postgres',
            'mssql',
        ]
        
        for indicator in indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                return True
        return False
    
    def _add_vulnerability(self, vuln_type, param, payload, method, evidence="", url=None):
        """Add vulnerability to results"""
        vuln = {
            'type': vuln_type,
            'category': 'SQL Injection',
            'url': url or self.url,
            'parameter': param,
            'method': method,
            'payload': payload,
            'evidence': evidence,
            'severity': 'High',
            'recommendation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs.'
        }
        self.vulnerabilities.append(vuln)
    
    def _print_summary(self):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SQL Injection Scan Summary{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        if self.vulnerabilities:
            print(f"{Fore.RED}[!] Found {len(self.vulnerabilities)} SQL Injection vulnerability(ies):{Style.RESET_ALL}\n")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{Fore.YELLOW}[{i}] {vuln['type']}{Style.RESET_ALL}")
                print(f"    Parameter: {vuln['parameter']}")
                print(f"    Method: {vuln['method']}")
                print(f"    Payload: {vuln['payload']}")
                print(f"    Evidence: {vuln['evidence']}\n")
        else:
            print(f"{Fore.GREEN}[✓] No SQL Injection vulnerabilities found{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
