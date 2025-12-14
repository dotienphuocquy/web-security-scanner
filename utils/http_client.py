"""
HTTP Client utility for making web requests
"""

import requests
import urllib3
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from config import TIMEOUT, USER_AGENT

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HTTPClient:
    """HTTP client wrapper with custom headers and error handling"""

    def __init__(self, timeout=TIMEOUT):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

    def get(self, url, params=None, allow_redirects=True):
        """Send GET request"""
        try:
            response = self.session.get(
                url,
                params=params,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=False
            )
            return response
        except requests.RequestException as e:
            return None

    def post(self, url, data=None, allow_redirects=True):
        """Send POST request"""
        try:
            response = self.session.post(
                url,
                data=data,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=False
            )
            return response
        except requests.RequestException as e:
            return None

    @staticmethod
    def parse_url(url):
        """Parse URL and return components"""
        return urlparse(url)

    @staticmethod
    def get_params_from_url(url):
        """Extract parameters from URL"""
        parsed = urlparse(url)
        return parse_qs(parsed.query)

    @staticmethod
    def build_url(base_url, params):
        """Build URL with parameters"""
        parsed = urlparse(base_url)
        query_string = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            query_string,
            parsed.fragment
        ))
