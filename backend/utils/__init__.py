"""
Utils модуль для сканеров CyberScope

Содержит:
- xss_payloads: XSS и SQL injection payload-ы
- technology_patterns: Паттерны для определения технологий
"""

from .xss_payloads import (
    get_xss_payloads,
    get_sql_payloads,
    get_xss_payloads_count,
    get_sql_payloads_count
)

__all__ = [
    'get_xss_payloads',
    'get_sql_payloads',
    'get_xss_payloads_count',
    'get_sql_payloads_count'
]
