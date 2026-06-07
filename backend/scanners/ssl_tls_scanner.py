#!/usr/bin/env python3
"""
Детальный анализатор SSL/TLS конфигурации веб-сайтов
Проверяет протоколы, шифры, сертификаты и уязвимости
"""

import argparse
import socket
import ssl
import sys
import os
from pathlib import Path
from urllib.parse import urlparse
from colorama import Fore, Style, init
import json
import datetime
import re
from core.report_utils import ReportBase
import concurrent.futures

# Инициализация цветного вывода
init(autoreset=True)


class SSLTLSScanner(ReportBase):
    """Детальный анализатор SSL/TLS конфигурации"""
    
    def __init__(self, target_url, output_base=None, reports_dir=None):
        super().__init__('ssl-tls', target_url, Path(reports_dir) if reports_dir else None)
        
        self.target_url = target_url.rstrip('/')
        self.hostname = urlparse(target_url).hostname or "unknown_host"
        self.port = 443
        self.scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Результаты сканирования
        self.ssl_version = None
        self.tls_versions = {}
        self.cipher_suites = []
        self.certificate_info = {}
        self.vulnerabilities = []
        self.recommendations = []
        self.overall_score = 0
        
        if output_base:
            self.filename_base = output_base
        else:
            self.filename_base = f"ssl_tls_{self.hostname}_{self.scan_id}"

    def check_ssl_tls_support(self):
        """Проверка поддержки различных версий SSL/TLS"""
        print(f"{Fore.CYAN}[*] Проверка поддержки SSL/TLS версий...")
        
        versions = {
            'SSLv2': ssl.PROTOCOL_SSLv2 if hasattr(ssl, 'PROTOCOL_SSLv2') else None,
            'SSLv3': ssl.PROTOCOL_SSLv3 if hasattr(ssl, 'PROTOCOL_SSLv3') else None,
            'TLSv1.0': ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
            'TLSv1.3': ssl.PROTOCOL_TLS if hasattr(ssl, 'PROTOCOL_TLS') else None,
        }
        
        for version_name, protocol in versions.items():
            if protocol is None:
                continue
                
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                    ssock = context.wrap_socket(sock, server_hostname=self.hostname)
                    try:
                        cipher = ssock.cipher()
                        self.tls_versions[version_name] = {
                            'supported': True,
                            'cipher': cipher[0] if cipher else 'Unknown'
                        }
                        
                        # Определяем уровень угрозы
                        if version_name in ['SSLv2', 'SSLv3']:
                            self.vulnerabilities.append({
                                'type': f'{version_name} Detection',
                                'severity': 'Critical',
                                'description': f'{version_name} является устаревшим и содержит известные уязвимости',
                                'recommendation': f'Отключите {version_name}'
                            })
                        elif version_name in ['TLSv1.0', 'TLSv1.1']:
                            self.vulnerabilities.append({
                                'type': f'{version_name} Detection',
                                'severity': 'High',
                                'description': f'{version_name} содержит уязвимости и не рекомендуется',
                                'recommendation': f'Отключите {version_name} или обновите до TLSv1.2+'
                            })
                        
                        print(f"{Fore.GREEN}[+] {version_name}: Поддерживается ({cipher[0] if cipher else 'Unknown'})")
                    finally:
                        ssock.close()
                
            except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as e:
                self.tls_versions[version_name] = {'supported': False}
                print(f"{Fore.YELLOW}[-] {version_name}: Не поддерживается")

    def analyze_certificate(self):
        """Анализ деталей SSL сертификата"""
        print(f"{Fore.CYAN}[*] Анализ SSL сертификата...")
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                ssock = context.wrap_socket(sock, server_hostname=self.hostname)
                try:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
                    
                    if cert:
                        # Основная информация
                        self.certificate_info = {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'version': cert.get('version'),
                            'serialNumber': str(cert.get('serialNumber', 'N/A')),
                            'notBefore': cert.get('notBefore', 'N/A'),
                            'notAfter': cert.get('notAfter', 'N/A'),
                            'subjectAltName': cert.get('subjectAltName', []),
                            'extensions': self._extract_extensions(cert_der)
                        }
                        
                        # Проверка срока действия
                        self._check_certificate_expiration(cert.get('notAfter'))
                        
                        # Проверка SAN
                        self._check_san(cert.get('subjectAltName', []))
                        
                        print(f"{Fore.GREEN}[+] Сертификат успешно получен")
                        print(f"    Издатель: {self.certificate_info['issuer'].get('organizationName', 'N/A')}")
                        print(f"    Срок действия: {self.certificate_info['notBefore']} - {self.certificate_info['notAfter']}")
                    else:
                        print(f"{Fore.YELLOW}[!] Не удалось получить информацию о сертификате")
                finally:
                    ssock.close()
                    
        except Exception as e:
            print(f"{Fore.RED}[!] Ошибка при анализе сертификата: {e}")

    def _extract_extensions(self, cert_der):
        """Извлечение расширений сертификата"""
        extensions = {}
        try:
            # Простой парсинг расширений из DER
            if b'2.5.29.17' in cert_der:  # OID для SAN
                extensions['SAN'] = 'Present'
            if b'2.5.29.19' in cert_der:  # OID для Basic Constraints
                extensions['BasicConstraints'] = 'Present'
            if b'2.5.29.15' in cert_der:  # OID для Key Usage
                extensions['KeyUsage'] = 'Present'
            if b'2.5.29.37' in cert_der:  # OID для Extended Key Usage
                extensions['ExtendedKeyUsage'] = 'Present'
            if b'2.5.29.32' in cert_der:  # OID для Certificate Policies
                extensions['CertificatePolicies'] = 'Present'
        except:
            pass
        
        return extensions if extensions else {'status': 'Could not parse extensions'}

    def _check_certificate_expiration(self, not_after_str):
        """Проверка срока действия сертификата"""
        try:
            # Парсинг даты
            expire_date = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
            days_to_expire = (expire_date - datetime.datetime.now()).days
            
            if days_to_expire < 0:
                self.vulnerabilities.append({
                    'type': 'Expired Certificate',
                    'severity': 'Critical',
                    'description': 'SSL сертификат истек',
                    'recommendation': 'Немедленно обновите SSL сертификат'
                })
                print(f"{Fore.RED}[!] Сертификат истек {abs(days_to_expire)} дней назад")
            elif days_to_expire < 30:
                self.vulnerabilities.append({
                    'type': 'Certificate Expiring Soon',
                    'severity': 'High',
                    'description': f'SSL сертификат истекает через {days_to_expire} дней',
                    'recommendation': 'Обновите SSL сертификат в ближайшее время'
                })
                print(f"{Fore.YELLOW}[!] Сертификат истекает через {days_to_expire} дней")
            else:
                print(f"{Fore.GREEN}[+] Сертификат действителен ещё {days_to_expire} дней")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Не удалось определить срок действия: {e}")

    def _check_san(self, san_list):
        """Проверка Subject Alternative Name"""
        if not san_list:
            self.vulnerabilities.append({
                'type': 'Missing SAN',
                'severity': 'Medium',
                'description': 'Сертификат не содержит Subject Alternative Names',
                'recommendation': 'Используйте сертификат с правильными SAN'
            })
        else:
            san_hosts = [name[1] for name in san_list if name[0] == 'DNS']
            print(f"{Fore.GREEN}[+] SAN: {', '.join(san_hosts)}")

    def check_cipher_strength(self):
        """Проверка стойкости шифров"""
        print(f"{Fore.CYAN}[*] Анализ стойкости шифров...")
        
        # Слабые шифры
        weak_ciphers = [
            'NULL', 'EXPORT', 'DES', 'RC4', 'MD5', 'PSK',
            'anon', 'ADH', 'AECDH', 'MD4', 'MD2'
        ]
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                ssock = context.wrap_socket(sock, server_hostname=self.hostname)
                try:
                    cipher = ssock.cipher()
                    
                    if cipher:
                        cipher_name = cipher[0]
                        self.cipher_suites.append({
                            'name': cipher_name,
                            'protocol': cipher[1],
                            'bits': cipher[2]
                        })
                        
                        # Проверка на слабые шифры
                        is_weak = any(weak in cipher_name.upper() for weak in weak_ciphers)
                        
                        if is_weak:
                            self.vulnerabilities.append({
                                'type': 'Weak Cipher Suite',
                                'severity': 'High',
                                'description': f'Обнаружен слабый шифр: {cipher_name}',
                                'recommendation': 'Используйте только сильные шифры (AES-GCM, ChaCha20)'
                            })
                            print(f"{Fore.RED}[!] Слабый шифр: {cipher_name}")
                        else:
                            print(f"{Fore.GREEN}[+] Шифр: {cipher_name} ({cipher[2]} bits)")
                        
                        # Оценка битов
                        if cipher[2] < 128:
                            self.vulnerabilities.append({
                                'type': 'Insufficient Cipher Key Length',
                                'severity': 'High',
                                'description': f'Шифр использует только {cipher[2]} бит',
                                'recommendation': 'Используйте шифры с ключом минимум 256 бит'
                            })
                        elif cipher[2] >= 256:
                            print(f"{Fore.GREEN}[+] Длина ключа: {cipher[2]} бит (Хорошо)")
                finally:
                    ssock.close()
        
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Ошибка при проверке шифров: {e}")

    def check_vulnerabilities(self):
        """Проверка известных SSL/TLS уязвимостей"""
        print(f"{Fore.CYAN}[*] Проверка известных уязвимостей...")
        
        # POODLE (SSLv3)
        if self.tls_versions.get('SSLv3', {}).get('supported'):
            self.vulnerabilities.append({
                'type': 'POODLE Attack (CVE-2014-3566)',
                'severity': 'Critical',
                'description': 'Сервер поддерживает SSLv3, уязвимый для атаки POODLE',
                'recommendation': 'Отключите SSLv3'
            })
        
        # Heartbleed (OpenSSL)
        if self.tls_versions.get('TLSv1.0', {}).get('supported') or \
           self.tls_versions.get('TLSv1.1', {}).get('supported'):
            self.vulnerabilities.append({
                'type': 'Potential Heartbleed Vulnerability',
                'severity': 'Critical',
                'description': 'Старые версии TLS могут быть уязвимы для Heartbleed',
                'recommendation': 'Обновите OpenSSL и TLS версии'
            })
        
        # Forward Secrecy
        has_fs = any('ECDHE' in cs['name'] or 'DHE' in cs['name'] for cs in self.cipher_suites)
        if not has_fs:
            self.vulnerabilities.append({
                'type': 'Lack of Perfect Forward Secrecy',
                'severity': 'Medium',
                'description': 'Конфигурация не использует Forward Secrecy',
                'recommendation': 'Включите цифровые подписи на основе ECDHE или DHE'
            })
        else:
            print(f"{Fore.GREEN}[+] Perfect Forward Secrecy: Поддерживается")

    def generate_score(self):
        """Генерация общей оценки безопасности"""
        base_score = 100
        critical_count = len([v for v in self.vulnerabilities if v['severity'] == 'Critical'])
        high_count = len([v for v in self.vulnerabilities if v['severity'] == 'High'])
        medium_count = len([v for v in self.vulnerabilities if v['severity'] == 'Medium'])
        low_count = len([v for v in self.vulnerabilities if v['severity'] == 'Low'])
        
        base_score -= critical_count * 15
        base_score -= high_count * 8
        base_score -= medium_count * 3
        base_score -= low_count * 1
        
        # Добавляем бонусы за положительное
        if self.tls_versions.get('TLSv1.3', {}).get('supported'):
            base_score += 10
        
        has_fs = any('ECDHE' in cs['name'] or 'DHE' in cs['name'] for cs in self.cipher_suites)
        if has_fs:
            base_score += 5
        
        self.overall_score = max(0, min(100, base_score))
        print(f"{Fore.CYAN}[*] Общая оценка безопасности: {self.overall_score}/100")

    def generate_recommendations(self):
        """Генерация рекомендаций"""
        if not self.tls_versions.get('TLSv1.3', {}).get('supported'):
            self.recommendations.append('Включите поддержку TLSv1.3')
        
        if self.tls_versions.get('SSLv2', {}).get('supported') or \
           self.tls_versions.get('SSLv3', {}).get('supported'):
            self.recommendations.append('Отключите SSLv2 и SSLv3')
        
        if self.tls_versions.get('TLSv1.0', {}).get('supported') or \
           self.tls_versions.get('TLSv1.1', {}).get('supported'):
            self.recommendations.append('Отключите TLSv1.0 и TLSv1.1')
        
        has_weak = any('RC4' in cs['name'] or 'NULL' in cs['name'] for cs in self.cipher_suites)
        if has_weak:
            self.recommendations.append('Удалите слабые шифры (RC4, NULL)')
        
        self.recommendations.append('Используйте сертификаты с 256-битными ключами')
        self.recommendations.append('Регулярно обновляйте OpenSSL')
        self.recommendations.append('Включите HSTS заголовок')
        self.recommendations.append('Используйте OCSP Stapling')

    def run_scan(self):
        """Запуск полного сканирования"""
        print(f"{Fore.GREEN}[*] Начинаем SSL/TLS сканирование: {self.target_url}")
        print(f"{Fore.GREEN}[*] Хост: {self.hostname}")
        print(f"{Fore.GREEN}[*] ID сканирования: {self.scan_id}")
        print(f"{Fore.CYAN}{'='*60}")
        
        # Запуск проверок
        checks = [
            self.check_ssl_tls_support,
            self.analyze_certificate,
            self.check_cipher_strength,
            self.check_vulnerabilities
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                print(f"{Fore.RED}[!] Ошибка в {check.__name__}: {e}")
        
        # Генерация оценки и рекомендаций
        self.generate_recommendations()
        self.generate_score()
        
        return True

    def get_json_report(self):
        """Получить отчет в формате JSON"""
        return {
            'scan_info': {
                'target_url': self.target_url,
                'hostname': self.hostname,
                'port': self.port,
                'scan_id': self.scan_id,
                'scan_datetime': datetime.datetime.now().isoformat(),
                'scanner': 'SSL/TLS Configuration Analyzer'
            },
            'summary': {
                'overall_score': self.overall_score,
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'Critical']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'High']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'Medium']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'Low'])
            },
            'ssl_tls_versions': self.tls_versions,
            'cipher_suites': self.cipher_suites,
            'certificate_info': {
                'subject': str(self.certificate_info.get('subject', {})),
                'issuer': str(self.certificate_info.get('issuer', {})),
                'notBefore': self.certificate_info.get('notBefore'),
                'notAfter': self.certificate_info.get('notAfter'),
                'subjectAltName': str(self.certificate_info.get('subjectAltName', [])),
                'extensions': self.certificate_info.get('extensions', {})
            },
            'vulnerabilities': self.vulnerabilities,
            'recommendations': self.recommendations
        }

    def _generate_txt_report(self):
        """Генерировать содержимое TXT отчета"""
        lines = []
        
        # Заголовок
        lines.append("=" * 80)
        lines.append("SSL/TLS КОНФИГУРАЦИЯ - ДЕТАЛЬНЫЙ АНАЛИЗ")
        lines.append("=" * 80)
        lines.append("")
        
        # Информация о сканировании
        lines.append("📋 ИНФОРМАЦИЯ О СКАНИРОВАНИИ")
        lines.append("─" * 80)
        lines.append(f"  Целевой URL:          {self.target_url}")
        lines.append(f"  Хост:                 {self.hostname}")
        lines.append(f"  Порт:                 {self.port}")
        lines.append(f"  ID сканирования:      {self.scan_id}")
        lines.append(f"  Дата сканирования:    {datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
        lines.append("")
        
        # Общая оценка
        lines.append("🔐 ОБЩАЯ ОЦЕНКА БЕЗОПАСНОСТИ")
        lines.append("─" * 80)
        score_bar = "█" * (self.overall_score // 10) + "░" * (10 - self.overall_score // 10)
        lines.append(f"  Оценка: {self.overall_score}/100 [{score_bar}]")
        lines.append("")
        
        # Версии SSL/TLS
        lines.append("🔗 ПОДДЕРЖИВАЕМЫЕ ВЕРСИИ SSL/TLS")
        lines.append("─" * 80)
        for version, info in self.tls_versions.items():
            status = "✓ Поддерживается" if info.get('supported') else "✗ Не поддерживается"
            cipher = info.get('cipher', 'N/A')
            severity = ""
            
            if info.get('supported'):
                if version in ['SSLv2', 'SSLv3']:
                    severity = " [КРИТИЧНО: Отключите]"
                elif version in ['TLSv1.0', 'TLSv1.1']:
                    severity = " [ОПАСНО: Обновите]"
                elif version == 'TLSv1.3':
                    severity = " [ХОРОШО]"
            
            lines.append(f"  {version:12} {status:25} {cipher}{severity}")
        lines.append("")
        
        # Информация о сертификате
        lines.append("📜 ИНФОРМАЦИЯ О СЕРТИФИКАТЕ")
        lines.append("─" * 80)
        cert_info = self.certificate_info
        if cert_info:
            subject = cert_info.get('subject', {})
            issuer = cert_info.get('issuer', {})
            
            lines.append(f"  CN (Subject):         {subject.get('commonName', 'N/A')}")
            lines.append(f"  Организация:          {subject.get('organizationName', 'N/A')}")
            lines.append(f"  Издатель:             {issuer.get('organizationName', 'N/A')}")
            lines.append(f"  Издатель CN:          {issuer.get('commonName', 'N/A')}")
            lines.append(f"  Не ранее:             {cert_info.get('notBefore', 'N/A')}")
            lines.append(f"  Не позже:             {cert_info.get('notAfter', 'N/A')}")
            
            san = cert_info.get('subjectAltName', [])
            if san:
                san_hosts = [name[1] for name in san if name[0] == 'DNS']
                lines.append(f"  SAN:                  {', '.join(san_hosts[:5])}")
                if len(san_hosts) > 5:
                    lines.append(f"                        ... и ещё {len(san_hosts) - 5}")
        lines.append("")
        
        # Шифры
        lines.append("🔑 ШИФРЫ (CIPHER SUITES)")
        lines.append("─" * 80)
        if self.cipher_suites:
            for i, cipher in enumerate(self.cipher_suites, 1):
                strength = "Strong" if cipher['bits'] >= 256 else "Medium" if cipher['bits'] >= 128 else "Weak"
                lines.append(f"  [{i}] {cipher['name']}")
                lines.append(f"      Версия: {cipher['protocol']}, Ключ: {cipher['bits']} бит ({strength})")
        else:
            lines.append("  Информация о шифрах недоступна")
        lines.append("")
        
        # Уязвимости
        lines.append("⚠️ ОБНАРУЖЕННЫЕ УЯЗВИМОСТИ")
        lines.append("─" * 80)
        critical = len([v for v in self.vulnerabilities if v['severity'] == 'Critical'])
        high = len([v for v in self.vulnerabilities if v['severity'] == 'High'])
        medium = len([v for v in self.vulnerabilities if v['severity'] == 'Medium'])
        low = len([v for v in self.vulnerabilities if v['severity'] == 'Low'])
        
        lines.append(f"  🔴 Критичные:    {critical}")
        lines.append(f"  🟠 Высокие:      {high}")
        lines.append(f"  🟡 Средние:      {medium}")
        lines.append(f"  🟢 Низкие:       {low}")
        lines.append(f"  Всего:           {len(self.vulnerabilities)}")
        lines.append("")
        
        if self.vulnerabilities:
            lines.append("📌 СПИСОК УЯЗВИМОСТЕЙ:")
            lines.append("─" * 80)
            for i, vuln in enumerate(self.vulnerabilities, 1):
                severity_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(vuln['severity'], "⚪")
                lines.append(f"\n  [{i}] {severity_icon} {vuln['type']}")
                lines.append(f"      Тяжесть:       {vuln['severity']}")
                lines.append(f"      Описание:      {vuln['description']}")
                lines.append(f"      Рекомендация:  {vuln['recommendation']}")
        lines.append("")
        
        # Рекомендации
        lines.append("💡 РЕКОМЕНДАЦИИ ПО УЛУЧШЕНИЮ")
        lines.append("─" * 80)
        for i, rec in enumerate(self.recommendations, 1):
            lines.append(f"  {i}. {rec}")
        lines.append("")
        
        # Завершение
        lines.append("═" * 80)
        lines.append(f"Дата создания отчета: {datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
        lines.append(f"ID сканирования:      {self.scan_id}")
        lines.append("═" * 80)
        
        return "\n".join(lines)

    def save_reports(self):
        """Сохранение отчетов JSON и TXT"""
        try:
            # JSON отчет
            json_report = self.get_json_report()
            super().save_json_report(json_report)
            print(f"{Fore.GREEN}[+] JSON отчет сохранен")
            
            # TXT отчет
            txt_content = self._generate_txt_report()
            super().save_txt_report(txt_content)
            print(f"{Fore.GREEN}[+] TXT отчет сохранен")
            
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Ошибка при сохранении отчетов: {e}")
            return False

    def print_summary(self):
        """Вывод краткого резюме"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}SSL/TLS АНАЛИЗ - РЕЗЮМЕ")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}Целевой URL: {self.target_url}")
        print(f"{Fore.WHITE}Оценка: {self.overall_score}/100")
        print(f"{Fore.WHITE}Уязвимостей найдено: {len(self.vulnerabilities)}")
        print(f"{Fore.CYAN}{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Детальный анализатор SSL/TLS конфигурации',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python ssl_tls_scanner.py -u https://example.com
  python ssl_tls_scanner.py -u https://example.com -o my_ssl_scan
  python ssl_tls_scanner.py -u https://example.com:8443
  
Структура отчетов:
  reports/ssl-tls/
    json/    - JSON отчеты
    txt/     - TXT отчеты
        """
    )
    parser.add_argument('-u', '--url', required=True, help='Целевой URL')
    parser.add_argument('-o', '--output', help='Базовое имя файла отчета')
    
    args = parser.parse_args()
    
    # Создание сканера
    scanner = SSLTLSScanner(args.url, args.output)
    
    # Запуск сканирования
    if scanner.run_scan():
        scanner.print_summary()
        
        # Сохранение отчетов
        scanner.save_reports()
        
        print(f"{Fore.GREEN}[+] Отчеты сохранены в:")
        print(f"    JSON: {scanner.json_dir}")
        print(f"    TXT:  {scanner.txt_dir}")
    else:
        print(f"{Fore.RED}[!] Сканирование не удалось завершить")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Сканирование прервано пользователем")
    except Exception as e:
        print(f"{Fore.RED}[!] Критическая ошибка: {e}")
