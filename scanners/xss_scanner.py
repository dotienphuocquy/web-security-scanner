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
from scanners.xss_context_detector import XSSContextDetector
from config import XSS_MAX_PAYLOADS


class XSSScanner:
    """XSS vulnerability scanner"""

    def __init__(self, url, enable_context_detection=False):
        self.url = url
        self.client = HTTPClient()
        self.vulnerabilities = []
        self.tested_params = set()
        self.stored_xss_payloads = {}  # Track payloads for Stored XSS detection
        self.enable_context_detection = enable_context_detection
        self.context_detector = XSSContextDetector() if enable_context_detection else None
        self.context_analysis = []  # Store context detection results

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
        # Step 1: Context Detection (if enabled)
        if self.enable_context_detection:
            return self._test_with_context_detection(param_name, params, method)

        # Step 2: Standard testing (original behavior)
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
        # Step 1: Context Detection (if enabled)
        if self.enable_context_detection:
            return self._test_post_with_context_detection(url, param_name, form_data)

        # Step 2: Standard testing (original behavior)
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

    def _test_with_context_detection(self, param_name, params, method="GET"):
        """Test XSS with context detection"""
        print(f"{Fore.CYAN}      [*] Running Context Detection...{Style.RESET_ALL}")

        # Step 1: Inject unique marker to detect reflection contexts
        unique_marker = f"XSS_MARKER_{int(time.time()*1000)}"
        test_params = params.copy()
        test_params[param_name] = unique_marker

        response = self._send_get_request(test_params)
        if not response:
            return False

        # Step 2: Detect contexts where marker appears
        contexts = self.context_detector.detect_contexts(unique_marker, response.text)

        if not contexts:
            print(f"{Fore.YELLOW}      [!] Marker not reflected in response{Style.RESET_ALL}")
            return False

        print(f"{Fore.GREEN}      [✓] Found {len(contexts)} reflection context(s){Style.RESET_ALL}")

        # Print brief context info
        for ctx in contexts:
            risk_color = {
                'Critical': Fore.RED,
                'High': Fore.YELLOW,
                'Medium': Fore.BLUE,
                'Low': Fore.GREEN
            }.get(ctx['details'].get('risk', 'Unknown'), Fore.WHITE)
            print(f"          {risk_color}→ {ctx['type']} context (Risk: {ctx['details'].get('risk')}){Style.RESET_ALL}")
        # Step 3: Generate context-specific payloads
        context_payloads = self.context_detector.generate_context_payloads(contexts)

        # Step 4: Test with optimized payloads for each context
        vulnerabilities_found = []
        for ctx_type, payloads in context_payloads.items():
            print(f"{Fore.CYAN}      [*] Testing {ctx_type} context with {len(payloads)} payload(s)...{Style.RESET_ALL}")

            context_exploited = False
            for payload in payloads[:5]:  # Limit to 5 payloads per context
                test_params = params.copy()
                test_params[param_name] = payload

                response = self._send_get_request(test_params)

                if response and self._check_xss_in_response(payload, response.text):
                    # Find which context was exploited
                    exploited_context = next((c for c in contexts if c['type'] == ctx_type), None)
                    risk_level = exploited_context['details'].get('risk', 'Medium') if exploited_context else 'Medium'

                    # Extract snippet showing the reflection
                    snippet = exploited_context['snippet'] if exploited_context else ''

                    self._add_vulnerability(
                        vuln_type="Reflected XSS",
                        param=param_name,
                        payload=payload,
                        method=method,
                        evidence=f"Context-aware exploitation: {ctx_type} context (Risk: {risk_level})",
                        context_info={
                            'context_type': ctx_type,
                            'risk': risk_level,
                            'details': exploited_context['details'] if exploited_context else {},
                            'successful_payload': payload,
                            'snippet': snippet
                        }
                    )
                    print(f"{Fore.GREEN}      [✓] Vulnerable to Reflected XSS in {ctx_type} context!{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}          Payload: {payload[:80]}...{Style.RESET_ALL}" if len(payload) > 80 else f"{Fore.CYAN}          Payload: {payload}{Style.RESET_ALL}")
                    vulnerabilities_found.append(ctx_type)
                    context_exploited = True
                    break  # One successful payload per context is enough

            # Don't stop - continue testing other contexts even if one succeeded
            if context_exploited:
                print(f"{Fore.YELLOW}      [*] Continuing to test other contexts...{Style.RESET_ALL}")

        # Print context analysis (shows ALL detected contexts)
        if contexts:
            self.context_detector.detected_contexts = contexts
            self.context_detector.print_context_analysis()

        # Print summary of exploited contexts
        if vulnerabilities_found:
            print(f"\n{Fore.GREEN}[✓] Successfully exploited {len(vulnerabilities_found)} context(s): {', '.join(vulnerabilities_found)}{Style.RESET_ALL}")

        return len(vulnerabilities_found) > 0

    def _test_post_with_context_detection(self, url, param_name, form_data):
        """Test POST form with context detection"""
        print(f"{Fore.CYAN}        [*] Running Context Detection (POST)...{Style.RESET_ALL}")

        # Step 1: Inject unique marker
        unique_marker = f"XSS_MARKER_{int(time.time()*1000)}"
        test_data = form_data.copy()
        test_data[param_name] = unique_marker

        response = self.client.post(url, data=test_data)
        if not response:
            return False

        # Step 2: Detect contexts
        contexts = self.context_detector.detect_contexts(unique_marker, response.text)

        if not contexts:
            print(f"{Fore.YELLOW}        [!] Marker not reflected in response{Style.RESET_ALL}")
            return False

        print(f"{Fore.GREEN}        [✓] Found {len(contexts)} reflection context(s){Style.RESET_ALL}")

        # Print brief context info
        for ctx in contexts:
            risk_color = {
                'Critical': Fore.RED,
                'High': Fore.YELLOW,
                'Medium': Fore.BLUE,
                'Low': Fore.GREEN
            }.get(ctx['details'].get('risk', 'Unknown'), Fore.WHITE)
            print(f"            {risk_color}→ {ctx['type']} context (Risk: {ctx['details'].get('risk')}){Style.RESET_ALL}")

        # Store context analysis
        self.context_analysis.append({
            'parameter': param_name,
            'method': 'POST',
            'url': url,
            'contexts': contexts
        })

        # Step 3: Generate and test context-specific payloads
        context_payloads = self.context_detector.generate_context_payloads(contexts)

        vulnerabilities_found = []
        for ctx_type, payloads in context_payloads.items():
            print(f"{Fore.CYAN}        [*] Testing {ctx_type} context with {len(payloads)} payload(s)...{Style.RESET_ALL}")

            context_exploited = False
            for payload in payloads[:5]:
                test_data = form_data.copy()
                test_data[param_name] = payload

                response = self.client.post(url, data=test_data)

                if response and self._check_xss_in_response(payload, response.text):
                    exploited_context = next((c for c in contexts if c['type'] == ctx_type), None)
                    risk_level = exploited_context['details'].get('risk', 'Medium') if exploited_context else 'Medium'

                    # Extract snippet showing the reflection
                    snippet = exploited_context['snippet'] if exploited_context else ''

                    self._add_vulnerability(
                        vuln_type="Reflected XSS",
                        param=param_name,
                        payload=payload,
                        method="POST",
                        url=url,
                        evidence=f"Context-aware exploitation: {ctx_type} context (Risk: {risk_level})",
                        context_info={
                            'context_type': ctx_type,
                            'risk': risk_level,
                            'details': exploited_context['details'] if exploited_context else {},
                            'successful_payload': payload,
                            'snippet': snippet
                        }
                    )
                    print(f"{Fore.GREEN}        [✓] Vulnerable to Reflected XSS in {ctx_type} context!{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}            Payload: {payload[:80]}...{Style.RESET_ALL}" if len(payload) > 80 else f"{Fore.CYAN}            Payload: {payload}{Style.RESET_ALL}")
                    vulnerabilities_found.append(ctx_type)
                    context_exploited = True
                    break

            # Continue testing other contexts
            if context_exploited:
                print(f"{Fore.YELLOW}        [*] Continuing to test other contexts...{Style.RESET_ALL}")

        # Print context analysis (shows ALL detected contexts)
        if contexts:
            self.context_detector.detected_contexts = contexts
            self.context_detector.print_context_analysis()

        # Print summary
        if vulnerabilities_found:
            print(f"\n{Fore.GREEN}[✓] Successfully exploited {len(vulnerabilities_found)} context(s): {', '.join(vulnerabilities_found)}{Style.RESET_ALL}")

        return len(vulnerabilities_found) > 0

    def _add_vulnerability(self, vuln_type, param, payload, method, evidence="", url=None, context_info=None):
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

        # Add context information if available
        if context_info:
            vuln['context'] = context_info
            # Upgrade severity based on context risk
            if context_info.get('risk') == 'Critical':
                vuln['severity'] = 'Critical'

        self.vulnerabilities.append(vuln)

    def _print_summary(self):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}XSS Scan Summary{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        if self.vulnerabilities:
            print(f"{Fore.RED}[!] Found {len(self.vulnerabilities)} XSS vulnerability(ies):{Style.RESET_ALL}\n")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                severity_color = {
                    'Critical': Fore.RED,
                    'High': Fore.RED,
                    'Medium': Fore.YELLOW,
                    'Low': Fore.GREEN
                }.get(vuln['severity'], Fore.YELLOW)

                print(f"{severity_color}[{i}] {vuln['type']} ({vuln['severity']}){Style.RESET_ALL}")
                print(f"    Parameter: {vuln['parameter']}")
                print(f"    Method: {vuln['method']}")
                print(f"    Payload: {vuln['payload']}")
                print(f"    Evidence: {vuln['evidence']}")

                # Print context information if available
                if 'context' in vuln:
                    ctx = vuln['context']
                    print(f"    Context Type: {ctx.get('context_type', 'Unknown')}")
                    print(f"    Context Risk: {ctx.get('risk', 'Unknown')}")
                    if 'details' in ctx:
                        details = ctx['details']
                        if 'attribute' in details:
                            print(f"    Attribute: {details['attribute']}")
                        if 'tag' in details:
                            print(f"    Tag: <{details['tag']}>")
                        if 'parent_tag' in details:
                            print(f"    Parent Tag: <{details['parent_tag']}>")
                        if 'exact_location' in details:
                            print(f"    Location: {details['exact_location']}")

                    # Show successful payload
                    if 'successful_payload' in ctx:
                        payload = ctx['successful_payload']
                        if len(payload) > 80:
                            print(f"    Successful Payload: {payload[:77]}...")
                        else:
                            print(f"    Successful Payload: {payload}")

                    # Show snippet (evidence)
                    if 'snippet' in ctx:
                        snippet = ctx['snippet']
                        if len(snippet) > 100:
                            snippet = snippet[:97] + '...'
                        print(f"    Code Snippet: {snippet}")

                print()
        else:
            print(f"{Fore.GREEN}[✓] No XSS vulnerabilities found{Style.RESET_ALL}")

        # Print context analysis summary if context detection was enabled
        if self.enable_context_detection and self.context_analysis:
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Context Detection Summary{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[✓] Analyzed {len(self.context_analysis)} parameter(s) with context detection{Style.RESET_ALL}")

            total_contexts = sum(len(analysis['contexts']) for analysis in self.context_analysis)
            print(f"{Fore.GREEN}[✓] Total reflection contexts found: {total_contexts}{Style.RESET_ALL}")

            # Count contexts by type
            context_types = {}
            for analysis in self.context_analysis:
                for ctx in analysis['contexts']:
                    ctx_type = ctx['type']
                    context_types[ctx_type] = context_types.get(ctx_type, 0) + 1

            if context_types:
                print(f"\n{Fore.CYAN}Context Type Distribution:{Style.RESET_ALL}")
                for ctx_type, count in sorted(context_types.items(), key=lambda x: x[1], reverse=True):
                    print(f"  - {ctx_type}: {count}")

        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
