"""
Utils модуль для сканеров CyberScope

Содержит:
- xss_payloads: XSS payload-ы
- sql_payloads: SQL injection payload-ы
- css_payloads: CSS injection payload-ы
- xxe_payloads: XXE payload-ы
- technology_patterns: Паттерны для определения технологий
"""

from .xss_payloads import (
    get_xss_payloads,
    get_xss_payloads_count
)

from .sql_payloads import (
    get_sql_payloads,
    get_sql_payloads_count
)

from .css_payloads import (
    get_css_payloads,
    get_css_payloads_count
)

from .xxe_payloads import (
    get_xxe_payloads,
    get_xxe_payloads_count
)

__all__ = [
    'get_xss_payloads',
    'get_xss_payloads_count',
    'get_sql_payloads',
    'get_sql_payloads_count',
    'get_css_payloads',
    'get_css_payloads_count',
    'get_xxe_payloads',
    'get_xxe_payloads_count'
]
