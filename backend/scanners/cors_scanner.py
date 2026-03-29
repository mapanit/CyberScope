#!/usr/bin/env python3
"""
CORS (Cross-Origin Resource Sharing) уязвимости сканер
Проверяет неправильную конфигурацию CORS политики
Используется только в образовательных целях на собственных ресурсах
"""

import requests
import json
import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, init
from core.report_utils import ReportBase

# Инициализация цветного вывода
init(autoreset=True)


class CORSScanner(ReportBase):
    """Сканер для выявления уязвимостей CORS"""

    def __init__(self, target_url: str, output_base=None, reports_dir=None):
        super().__init__('cors', target_url, Path(reports_dir) if reports_dir else None)
        
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.found_vulnerabilities = []
        self.scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.hostname = urlparse(target_url).hostname or "unknown_host"
        
        # Совместимость с существующим кодом
        self.output_format = "all"
        self.base_dir = Path.cwd()
        
        # Базовое имя для файлов
        if output_base:
            self.filename_base = output_base
        else:
            self.filename_base = f"cors_{self.hostname}_{self.scan_id}"

    def get_json_report(self) -> dict:
        """Возвращает отчет в формате JSON"""
        report = {
            'scan_info': {
                'target_url': self.target_url,
                'hostname': self.hostname,
                'scan_id': self.scan_id,
                'scan_datetime': datetime.datetime.now().isoformat(),
                'tool': 'cors'
            },
            'summary': {
                'total_vulnerabilities': len(self.found_vulnerabilities),
                'critical': len([v for v in self.found_vulnerabilities if v['severity'] == 'Critical']),
                'high': len([v for v in self.found_vulnerabilities if v['severity'] == 'High']),
                'medium': len([v for v in self.found_vulnerabilities if v['severity'] == 'Medium']),
                'low': len([v for v in self.found_vulnerabilities if v['severity'] == 'Low'])
            },
            'vulnerabilities': self.found_vulnerabilities,
            'recommendations': [
                'Избегайте использования Access-Control-Allow-Origin: *',
                'Никогда не используйте Access-Control-Allow-Credentials: true с wildcard',
                'Явно указывайте разрешенные домены',
                'Ограничивайте Access-Control-Allow-Methods только необходимыми методами',
                'Проверяйте Origin заголовок перед обработкой запроса',
                'Используйте preflight запросы (OPTIONS) для проверки разрешений',
                'Регулярно проверяйте и обновляйте CORS политику'
            ]
        }
        return report

    def check_connection(self) -> bool:
        """Проверка доступности сайта"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            print(f"{Fore.GREEN}[+] Соединение установлено: {response.status_code}")
            return response.status_code in [200, 301, 302, 303, 307, 308]
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Ошибка подключения: {e}")
            return False

    def check_cors_headers(self):
        """Проверка CORS заголовков"""
        print(f"{Fore.CYAN}[*] Проверка CORS заголовков...")
        
        try:
            # Делаем OPTIONS запрос
            response = self.session.options(self.target_url, timeout=10, verify=False)
            
            cors_headers = {
                'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
                'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods'),
                'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers'),
                'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
                'Access-Control-Max-Age': response.headers.get('Access-Control-Max-Age'),
                'Access-Control-Expose-Headers': response.headers.get('Access-Control-Expose-Headers')
            }
            
            # Проверяем наличие CORS заголовков
            has_cors = any(v is not None for v in cors_headers.values())
            
            if not has_cors:
                print(f"{Fore.YELLOW}[!] CORS заголовки не найдены")
                return
            
            print(f"{Fore.GREEN}[+] CORS заголовки найдены:")
            for header, value in cors_headers.items():
                if value:
                    print(f"    {header}: {value}")
            
            # Анализируем уязвимости
            self._analyze_cors_headers(cors_headers)
            
        except Exception as e:
            print(f"{Fore.RED}[!] Ошибка при проверке CORS: {e}")

    def _analyze_cors_headers(self, cors_headers: dict):
        """Анализ CORS заголовков на уязвимости"""
        allow_origin = cors_headers.get('Access-Control-Allow-Origin')
        allow_credentials = cors_headers.get('Access-Control-Allow-Credentials')
        allow_methods = cors_headers.get('Access-Control-Allow-Methods')
        
        # Уязвимость 1: Wildcard Origin
        if allow_origin == '*':
            self.found_vulnerabilities.append({
                'type': 'Wildcard Origin (*)',
                'severity': 'High',
                'details': 'Access-Control-Allow-Origin установлен на * (все домены)',
                'recommendation': 'Явно указывайте разрешенные домены вместо использования *',
                'affected_url': self.target_url,
                'impact': 'Любой домен может делать cross-origin запросы',
                'timestamp': datetime.datetime.now().isoformat()
            })
            print(f"{Fore.RED}[!] Найдена уязвимость: Wildcard Origin (*)")
        
        # Уязвимость 2: Wildcard Origin + Credentials
        if allow_origin == '*' and allow_credentials == 'true':
            self.found_vulnerabilities.append({
                'type': 'Wildcard Origin with Credentials',
                'severity': 'Critical',
                'details': 'Access-Control-Allow-Origin: * используется с Access-Control-Allow-Credentials: true',
                'recommendation': 'Удалите Access-Control-Allow-Credentials или замените * на конкретный домен',
                'affected_url': self.target_url,
                'impact': 'Critical - Может привести к краже учетных данных и сессий',
                'timestamp': datetime.datetime.now().isoformat()
            })
            print(f"{Fore.RED}[!] CRITICAL: Wildcard Origin с Credentials!")
        
        # Уязвимость 3: Null Origin
        if allow_origin == 'null' or allow_origin == 'null ':
            self.found_vulnerabilities.append({
                'type': 'Null Origin',
                'severity': 'Medium',
                'details': 'Access-Control-Allow-Origin установлен на null',
                'recommendation': 'Не используйте null как разрешенный origin',
                'affected_url': self.target_url,
                'impact': 'Локальные файлы и sandbox могут делать запросы',
                'timestamp': datetime.datetime.now().isoformat()
            })
            print(f"{Fore.YELLOW}[!] Найдена уязвимость: Null Origin")
        
        # Уязвимость 4: Слишком много методов
        if allow_methods:
            methods = [m.strip().upper() for m in allow_methods.split(',')]
            dangerous_methods = ['DELETE', 'PUT', 'PATCH']
            found_dangerous = [m for m in methods if m in dangerous_methods]
            
            if found_dangerous:
                self.found_vulnerabilities.append({
                    'type': 'Dangerous HTTP Methods',
                    'severity': 'Medium',
                    'details': f'Разрешены опасные методы: {", ".join(found_dangerous)}',
                    'recommendation': 'Ограничьте разрешенные методы только необходимыми (GET, POST)',
                    'affected_url': self.target_url,
                    'impact': 'Удаление или изменение данных из других источников',
                    'timestamp': datetime.datetime.now().isoformat()
                })
                print(f"{Fore.YELLOW}[!] Найдены опасные методы: {found_dangerous}")

    def test_cors_with_origin(self, test_origin: str):
        """Тестирование CORS с конкретным Origin"""
        print(f"{Fore.CYAN}[*] Тестирование CORS с Origin: {test_origin}...")
        
        try:
            headers = {'Origin': test_origin}
            response = self.session.get(self.target_url, headers=headers, timeout=10, verify=False)
            
            allow_origin = response.headers.get('Access-Control-Allow-Origin')
            allow_credentials = response.headers.get('Access-Control-Allow-Credentials')
            
            if allow_origin == test_origin or allow_origin == '*':
                # Тестируем с credentials
                headers['Origin'] = test_origin
                response = self.session.get(
                    self.target_url,
                    headers=headers,
                    timeout=10,
                    verify=False
                )
                
                if allow_credentials == 'true' and allow_origin:
                    self.found_vulnerabilities.append({
                        'type': 'Credentials Exposed to Origin',
                        'severity': 'High',
                        'details': f'Origin {test_origin} может быть использован для получения учетных данных',
                        'recommendation': 'Проверьте whitelist доменов в CORS политике',
                        'affected_url': self.target_url,
                        'impact': 'Утечка аутентификационной информации',
                        'timestamp': datetime.datetime.now().isoformat()
                    })
                    print(f"{Fore.RED}[!] Найдена уязвимость: Credentials к {test_origin}")
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Ошибка тестирования Origin: {e}")

    def test_preflight_bypass(self):
        """Тестирование возможности обхода preflight запросов"""
        print(f"{Fore.CYAN}[*] Тестирование preflight запросов...")
        
        try:
            # Тестируем OPTIONS запрос
            response = self.session.options(self.target_url, timeout=10, verify=False)
            
            if response.status_code == 404:
                self.found_vulnerabilities.append({
                    'type': 'Preflight Not Implemented',
                    'severity': 'Low',
                    'details': 'OPTIONS метод не поддерживается (возвращает 404)',
                    'recommendation': 'Реализуйте обработку OPTIONS запросов',
                    'affected_url': self.target_url,
                    'impact': 'Некоректная обработка CORS preflight запросов',
                    'timestamp': datetime.datetime.now().isoformat()
                })
                print(f"{Fore.YELLOW}[!] OPTIONS запросы не обработаны")
            
            elif response.status_code == 200:
                print(f"{Fore.GREEN}[+] OPTIONS запросы обработаны корректно")
        
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Ошибка при тестировании preflight: {e}")

    def run_all_checks(self) -> bool:
        """Запуск всех проверок"""
        print(f"{Fore.GREEN}[*] Начинаем CORS сканирование: {self.target_url}")
        print(f"{Fore.GREEN}[*] ID сканирования: {self.scan_id}")
        
        if not self.check_connection():
            print(f"{Fore.RED}[!] Сайт недоступен!")
            return False
        
        # Основные проверки
        self.check_cors_headers()
        
        # Тестируем с разными origins
        test_origins = [
            'http://evil.com',
            'https://attacker.com',
            'http://localhost:3000',
            'http://127.0.0.1:8000'
        ]
        
        for origin in test_origins:
            self.test_cors_with_origin(origin)
        
        # Тестируем preflight
        self.test_preflight_bypass()
        
        return self.print_report()

    def print_report(self, return_json=False) -> bool:
        """Вывод отчета о сканировании"""
        if return_json:
            return self.get_json_report()
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}ОТЧЕТ CORS СКАНИРОВАНИЯ")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}Цель: {self.target_url}")
        print(f"{Fore.WHITE}ID сканирования: {self.scan_id}")
        print(f"{Fore.WHITE}Найдено уязвимостей: {len(self.found_vulnerabilities)}")
        print(f"{Fore.CYAN}{'-'*60}")

        if not self.found_vulnerabilities:
            print(f"{Fore.GREEN}[+] CORS уязвимостей не найдено!")
        else:
            # Группировка по уровню серьезности
            critical_vulns = [
                v for v in self.found_vulnerabilities if v['severity'] == 'Critical']
            high_vulns = [
                v for v in self.found_vulnerabilities if v['severity'] == 'High']
            medium_vulns = [
                v for v in self.found_vulnerabilities if v['severity'] == 'Medium']
            low_vulns = [
                v for v in self.found_vulnerabilities if v['severity'] == 'Low']

            if critical_vulns:
                print(f"{Fore.RED}[!] Critical: {len(critical_vulns)}")
            print(f"{Fore.RED}[!] Высокий риск: {len(high_vulns)}")
            print(f"{Fore.YELLOW}[!] Средний риск: {len(medium_vulns)}")
            print(f"{Fore.BLUE}[!] Низкий риск: {len(low_vulns)}")
            print()

            for i, vuln in enumerate(self.found_vulnerabilities, 1):
                if vuln['severity'] == 'Critical':
                    color = Fore.RED
                elif vuln['severity'] == 'High':
                    color = Fore.RED
                elif vuln['severity'] == 'Medium':
                    color = Fore.YELLOW
                else:
                    color = Fore.BLUE
                
                print(f"{color}[{i}] {vuln['type']}")
                print(f"    Уровень риска: {vuln['severity']}")
                print(f"    Детали: {vuln['details']}")
                print(f"    Рекомендации: {vuln['recommendation']}")
                print(f"    Влияние: {vuln['impact']}")
                print()
        
        # Сохранять отчеты
        self.save_json_report()
        self.save_txt_report()
        
        return True

    def save_json_report(self) -> str:
        """Сохранение отчета в JSON файл"""
        report = self.get_json_report()
        report['vulnerabilities'] = self.found_vulnerabilities
        
        return super().save_json_report(report)

    def save_txt_report(self) -> str:
        """Сохранение отчета в текстовый файл"""
        try:
            content = self._generate_txt_report()
            return super().save_txt_report(content)
        except Exception as e:
            print(f"{Fore.RED}[!] Ошибка при сохранении TXT отчета: {e}")

    def _generate_txt_report(self) -> str:
        """Генерировать содержимое TXT отчета"""
        lines = []
        
        # Заголовок
        lines.append("=" * 80)
        lines.append("ОТЧЕТ CORS СКАНИРОВАНИЯ")
        lines.append("=" * 80)
        lines.append("")
        
        # Информация о сканировании
        lines.append("📋 ИНФОРМАЦИЯ О СКАНИРОВАНИИ")
        lines.append("─" * 80)
        lines.append(f"  Целевой URL:          {self.target_url}")
        lines.append(f"  Имя хоста:            {self.hostname}")
        lines.append(f"  ID сканирования:      {self.scan_id}")
        lines.append(f"  Дата сканирования:    {datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
        lines.append(f"  Найдено уязвимостей:  {len(self.found_vulnerabilities)}")
        lines.append("")
        
        # Статистика
        critical_count = len([v for v in self.found_vulnerabilities if v['severity'] == 'Critical'])
        high_count = len([v for v in self.found_vulnerabilities if v['severity'] == 'High'])
        medium_count = len([v for v in self.found_vulnerabilities if v['severity'] == 'Medium'])
        low_count = len([v for v in self.found_vulnerabilities if v['severity'] == 'Low'])
        
        lines.append("📊 СТАТИСТИКА РЕЗУЛЬТАТОВ")
        lines.append("─" * 80)
        if critical_count > 0:
            lines.append(f"  🔴 Critical:          {critical_count}")
        lines.append(f"  🔴 Высокий риск:      {high_count}")
        lines.append(f"  🟡 Средний риск:      {medium_count}")
        lines.append(f"  🟢 Низкий риск:       {low_count}")
        lines.append(f"  Всего:                {len(self.found_vulnerabilities)}")
        lines.append("")
        
        # Детали
        if self.found_vulnerabilities:
            lines.append("🔍 ДЕТАЛИ УЯЗВИМОСТЕЙ")
            lines.append("─" * 80)
            
            for i, vuln in enumerate(self.found_vulnerabilities, 1):
                lines.append(f"\n[{i}] {vuln['type']}")
                lines.append(f"  Уровень риска:        {vuln['severity']}")
                lines.append(f"  Затронутый URL:       {vuln.get('affected_url', self.target_url)}")
                lines.append(f"  Описание:              {vuln['details']}")
                lines.append(f"  Влияние:               {vuln['impact']}")
                lines.append(f"  Рекомендации:         {vuln['recommendation']}")
                lines.append(f"  Время обнаружения:    {vuln.get('timestamp', 'N/A')[:19]}")
                lines.append("  " + "─" * 76)
            lines.append("")
        
        # Рекомендации
        lines.append("💼 ОБЩИЕ РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОСТИ CORS")
        lines.append("─" * 80)
        recommendations = [
            "1. Избегайте использования Access-Control-Allow-Origin: *",
            "2. Никогда не комбинируйте * с Access-Control-Allow-Credentials: true",
            "3. Явно указывайте разрешенные домены в whitelist",
            "4. Ограничивайте разрешенные HTTP методы (GET, POST)",
            "5. Ограничивайте разрешенные заголовки только необходимыми",
            "6. Устанавливайте правильное значение Access-Control-Max-Age",
            "7. Регулярно проверяйте и обновляйте CORS политику",
            "8. Логируйте и мониторьте cross-origin запросы",
            "9. Используйте HTTPS для всех cross-origin взаимодействий",
            "10. Применяйте Content Security Policy (CSP) дополнительно"
        ]
        for rec in recommendations:
            lines.append(f"  {rec}")
        lines.append("")
        
        # Завершение
        lines.append("═" * 80)
        lines.append(f"Дата создания отчета: {datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
        lines.append(f"ID сканирования:      {self.scan_id}")
        lines.append("═" * 80)
        
        return "\n".join(lines)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='CORS сканер для выявления уязвимостей',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python cors_scanner.py -u https://example.com
  python cors_scanner.py -u https://example.com -o my_cors_report
  python cors_scanner.py -u https://example.com --json-output
        """
    )
    parser.add_argument('-u', '--url', required=True,
                        help='Целевой URL для сканирования')
    parser.add_argument(
        '-o', '--output', help='Базовое имя для файлов отчета (без расширения)')
    parser.add_argument('--json-output', action='store_true',
                        help='Вывести результат в формате JSON')

    args = parser.parse_args()

    # Запуск сканирования
    scanner = CORSScanner(args.url, args.output)
    success = scanner.run_all_checks()

    if args.json_output:
        report = scanner.print_report(return_json=True)
        print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
