"""
Web Crawler Module
Automatically discover pages and endpoints to scan
"""

import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style

from utils.http_client import HTTPClient


class WebCrawler:
    """Simple web crawler to discover pages"""
    
    def __init__(self, base_url, max_depth=2, max_pages=20):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.client = HTTPClient()
        self.visited = set()
        self.discovered_urls = set()
        
        # Parse base domain
        parsed = urlparse(base_url)
        self.base_domain = f"{parsed.scheme}://{parsed.netloc}"
    
    def crawl(self):
        """Crawl website and discover URLs"""
        print(f"{Fore.CYAN}[*] Crawling website to discover pages...{Style.RESET_ALL}")
        
        self._crawl_url(self.base_url, depth=0)
        
        # Always add common paths
        common_paths = [
            '/login', '/admin', '/search', '/profile', 
            '/user', '/dashboard', '/register', '/contact',
            '/post', '/comment', '/api'
        ]
        
        for path in common_paths:
            test_url = self.base_domain + path
            if self._url_exists(test_url):
                self.discovered_urls.add(test_url)
        
        print(f"{Fore.GREEN}[✓] Discovered {len(self.discovered_urls)} page(s){Style.RESET_ALL}")
        
        return list(self.discovered_urls)
    
    def _crawl_url(self, url, depth):
        """Recursively crawl URL"""
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return
        
        if url in self.visited:
            return
        
        # Only crawl URLs from same domain
        if not url.startswith(self.base_domain):
            return
        
        self.visited.add(url)
        
        try:
            response = self.client.get(url)
            if not response or response.status_code != 200:
                return
            
            # Add current URL
            self.discovered_urls.add(url)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                
                # Build absolute URL
                absolute_url = urljoin(url, href)
                
                # Remove fragment
                absolute_url = absolute_url.split('#')[0]
                
                # Crawl link
                if absolute_url not in self.visited:
                    self._crawl_url(absolute_url, depth + 1)
            
            # Find forms - these are important for scanning
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action:
                    form_url = urljoin(url, action)
                    self.discovered_urls.add(form_url)
        
        except Exception as e:
            pass
    
    def _url_exists(self, url):
        """Check if URL exists"""
        try:
            response = self.client.get(url)
            return response and response.status_code in [200, 301, 302]
        except:
            return False
    
    def get_important_endpoints(self):
        """Get most important endpoints for security testing"""
        important = []
        keywords = ['login', 'admin', 'search', 'profile', 'user', 'post', 'comment']
        
        for url in self.discovered_urls:
            url_lower = url.lower()
            if any(keyword in url_lower for keyword in keywords):
                important.append(url)
        
        # If no important endpoints found, return all
        return important if important else list(self.discovered_urls)
