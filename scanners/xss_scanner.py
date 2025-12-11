"""
XSS (Cross-Site Scripting) Scanner Module
Automatically detects XSS vulnerabilities in web applications
"""

import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from colorama import Fore, Style

from utils.http_client import HTTPClient
from utils.crawler import WebCrawler
from payloads.xss_payloads import XSSPayloads
from config import XSS_MAX_PAYLOADS


class XSSScanner:
    """XSS vulnerability scanner"""
    
    def __init__(self, url):
        self.url = url
        self.client = HTTPClient()
        self.vulnerabilities = []
        self.tested_params = set()
        self.stored_xss_payloads = {}  # Track payloads for Stored XSS detection
    
    def scan(self):
        """Main scan function"""
        print(f"{Fore.CYAN}[*] Starting XSS scan on: {self.url}{Style.RESET_ALL}")
        
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
        
        # Check for Stored XSS
        if self.stored_xss_payloads:
            print(f"{Fore.YELLOW}[*] Checking for Stored XSS...{Style.RESET_ALL}")
            self._check_stored_xss()
        
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
            print(f"{Fore.YELLOW}[*] Testing GET parameters for Reflected XSS: {list(params.keys())}{Style.RESET_ALL}")
            self._scan_get_parameters(params)
        
        # Scan POST forms
        forms = self._get_forms()
        if forms:
            print(f"{Fore.YELLOW}[*] Found {len(forms)} form(s), testing for XSS...{Style.RESET_ALL}")
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
        """Scan GET parameters for Reflected XSS"""
        for param_name, param_value in params.items():
            if param_name in self.tested_params:
                continue
            
            self.tested_params.add(param_name)
            print(f"{Fore.CYAN}  [*] Testing parameter: {param_name}{Style.RESET_ALL}")
            
            # Test basic XSS payloads
            self._test_reflected_xss(param_name, param_value, params, "GET")
    
    def _scan_post_form(self, form):
        """Scan POST form for XSS"""
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
            if input_field['type'] in ['submit', 'button']:
                continue
            
            param_name = input_field['name']
            if param_name in self.tested_params:
                continue
            
            self.tested_params.add(param_name)
            print(f"{Fore.CYAN}    [*] Testing field: {param_name}{Style.RESET_ALL}")
            
            # Build form data
            form_data = {}
            for inp in inputs:
                if inp['name'] == param_name:
                    form_data[inp['name']] = 'test'
                else:
                    form_data[inp['name']] = 'normalvalue'
            
            # Test Reflected XSS
            self._test_reflected_xss_post(form_url, param_name, form_data)
            
            # Test Stored XSS by submitting payload
            self._test_stored_xss_post(form_url, param_name, form_data)
    
    def _test_reflected_xss(self, param_name, param_value, params, method="GET"):
        """Test for Reflected XSS"""
        payloads = XSSPayloads.get_basic_payloads()[:XSS_MAX_PAYLOADS]
        
        for payload in payloads:
            test_params = params.copy()
            test_params[param_name] = payload
            
            response = self._send_get_request(test_params)
            
            if response and self._check_xss_in_response(payload, response.text):
                self._add_vulnerability(
                    vuln_type="Reflected XSS",
                    param=param_name,
                    payload=payload,
                    method=method,
                    evidence="Payload reflected in response without sanitization"
                )
                print(f"{Fore.GREEN}    [✓] Vulnerable to Reflected XSS!{Style.RESET_ALL}")
                return True
        
        return False
    
    def _test_reflected_xss_post(self, url, param_name, form_data):
        """Test POST form for Reflected XSS"""
        payloads = XSSPayloads.get_basic_payloads()[:15]
        
        for payload in payloads:
            test_data = form_data.copy()
            test_data[param_name] = payload
            
            response = self.client.post(url, data=test_data)
            
            if response and self._check_xss_in_response(payload, response.text):
                self._add_vulnerability(
                    vuln_type="Reflected XSS",
                    param=param_name,
                    payload=payload,
                    method="POST",
                    url=url,
                    evidence="Payload reflected in response without sanitization"
                )
                print(f"{Fore.GREEN}      [✓] Vulnerable to Reflected XSS (POST)!{Style.RESET_ALL}")
                return True
        
        return False
    
    def _test_stored_xss_post(self, url, param_name, form_data):
        """Test POST form for Stored XSS by submitting payload"""
        # Generate unique payload
        payload, unique_id = XSSPayloads.generate_unique_payload("basic")
        
        test_data = form_data.copy()
        test_data[param_name] = payload
        
        # Submit the payload
        response = self.client.post(url, data=test_data)
        
        if response:
            # Store payload info for later verification
            self.stored_xss_payloads[unique_id] = {
                'url': url,
                'param': param_name,
                'payload': payload,
                'form_data': form_data
            }
            
            # Immediately check if payload is stored in response
            if self._check_xss_in_response(payload, response.text):
                self._add_vulnerability(
                    vuln_type="Stored XSS",
                    param=param_name,
                    payload=payload,
                    method="POST",
                    url=url,
                    evidence=f"Payload stored and reflected (ID: {unique_id})"
                )
                print(f"{Fore.GREEN}      [✓] Vulnerable to Stored XSS!{Style.RESET_ALL}")
                return True
        
        return False
    
    def _check_stored_xss(self):
        """Check if any submitted payloads are stored and reflected"""
        print(f"{Fore.CYAN}  [*] Verifying {len(self.stored_xss_payloads)} stored payload(s)...{Style.RESET_ALL}")
        
        # Wait a bit for the data to be stored
        time.sleep(1)
        
        for unique_id, payload_info in self.stored_xss_payloads.items():
            # Re-fetch the page to check if payload is stored
            response = self.client.get(payload_info['url'])
            
            if response and unique_id in response.text:
                # Check if it's actually executable XSS
                if self._check_xss_in_response(payload_info['payload'], response.text):
                    self._add_vulnerability(
                        vuln_type="Stored XSS",
                        param=payload_info['param'],
                        payload=payload_info['payload'],
                        method="POST",
                        url=payload_info['url'],
                        evidence=f"Payload persistently stored and reflected (ID: {unique_id})"
                    )
                    print(f"{Fore.GREEN}    [✓] Confirmed Stored XSS (ID: {unique_id})!{Style.RESET_ALL}")
    
    def _check_xss_in_response(self, payload, response_text):
        """Check if XSS payload is reflected in response without proper encoding"""
        # Remove HTML encoding to check raw payload
        import html
        decoded_response = html.unescape(response_text)
        
        # Check if payload appears unencoded
        if payload in decoded_response:
            # Verify it's not just in comments or script strings
            # Check if it's in dangerous contexts
            dangerous_contexts = [
                f">{payload}<",  # Between tags
                f">{payload}",   # After opening tag
                f"{payload}<",   # Before closing tag
                f'"{payload}"',  # In attribute value
                f"'{payload}'",  # In attribute value
            ]
            
            for context in dangerous_contexts:
                if context in decoded_response:
                    return True
            
            # Also check with regex patterns
            for pattern in XSSPayloads.XSS_DETECTION_PATTERNS:
                if re.search(pattern, decoded_response, re.IGNORECASE):
                    return True
        
        return False
    
    def _send_get_request(self, params):
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
    
    def _add_vulnerability(self, vuln_type, param, payload, method, evidence="", url=None):
        """Add vulnerability to results"""
        vuln = {
            'type': vuln_type,
            'category': 'Cross-Site Scripting (XSS)',
            'url': url or self.url,
            'parameter': param,
            'method': method,
            'payload': payload,
            'evidence': evidence,
            'severity': 'High' if vuln_type == 'Stored XSS' else 'Medium',
            'recommendation': 'Encode all user inputs before rendering. Use Content Security Policy (CSP). Validate and sanitize all user inputs.'
        }
        self.vulnerabilities.append(vuln)
    
    def _print_summary(self):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}XSS Scan Summary{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        if self.vulnerabilities:
            print(f"{Fore.RED}[!] Found {len(self.vulnerabilities)} XSS vulnerability(ies):{Style.RESET_ALL}\n")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                severity_color = Fore.RED if vuln['severity'] == 'High' else Fore.YELLOW
                print(f"{severity_color}[{i}] {vuln['type']} ({vuln['severity']}){Style.RESET_ALL}")
                print(f"    Parameter: {vuln['parameter']}")
                print(f"    Method: {vuln['method']}")
                print(f"    Payload: {vuln['payload']}")
                print(f"    Evidence: {vuln['evidence']}\n")
        else:
            print(f"{Fore.GREEN}[✓] No XSS vulnerabilities found{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
