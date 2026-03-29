#!/usr/bin/env python3
"""
Wappalyzer Technology Detection Tool
Определяет технологии, используемые на веб-сайте
Сохраняет отчеты в TXT формате
"""

import requests
from bs4 import BeautifulSoup
import re
from pathlib import Path
from datetime import datetime
import sys
from urllib.parse import urlparse
from colorama import Fore, Style, init
from typing import Dict, List, Optional, Any
from utils.technology_patterns import TECHNOLOGY_PATTERNS

# Инициализация цветного вывода
init(autoreset=True)


class WappalyzerTextReport:
    """Класс для создания текстового отчета Wappalyzer"""
    
    def __init__(self, target_url: str, reports_dir: Path = None):
        """Инициализация текстового отчета"""
        self.target_url = target_url
        self.hostname = urlparse(target_url).hostname or "unknown"
        self.scan_datetime = datetime.now().isoformat()
        self.scan_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Настройка директорий
        if reports_dir is None:
            reports_dir = Path(__file__).parent.parent / "reports"
        else:
            reports_dir = Path(reports_dir)
        
        # Создаем папку wappalyzer и txt подпапку
        self.wappalyzer_dir = reports_dir / "wappalyzer"
        self.txt_dir = self.wappalyzer_dir / "txt"
        self.txt_dir.mkdir(parents=True, exist_ok=True)
        
        self.report_path = self.txt_dir / f"wappalyzer_{self.scan_time}.txt"
        self.content = []
    
    def add_header(self):
        """Добавить заголовок отчета"""
        self.content.append("┌" + "─" * 78 + "┐")
        self.content.append("│" + " " * 15 + "WAPPALYZER - АНАЛИЗ ТЕХНОЛОГИЙ САЙТА" + " " * 26 + "│")
        self.content.append("└" + "─" * 78 + "┘")
        self.content.append("")
        
        self.content.append("📋 ИНФОРМАЦИЯ О СКАНИРОВАНИИ")
        self.content.append("─" * 80)
        self.content.append(f"  URL сайта:          {self.target_url}")
        self.content.append(f"  Хостнейм:           {self.hostname}")
        self.content.append(f"  Дата сканирования:  {datetime.fromisoformat(self.scan_datetime).strftime('%d.%m.%Y')}")
        self.content.append(f"  Время сканирования: {datetime.fromisoformat(self.scan_datetime).strftime('%H:%M:%S')}")
        self.content.append("")
    
    def add_technologies(self, technologies: List[Dict[str, Any]]):
        """Добавить список обнаруженных технологий"""
        self.content.append("🔍 ОБНАРУЖЕННЫЕ ТЕХНОЛОГИИ")
        self.content.append("─" * 80)
        
        if not technologies:
            self.content.append("  ⚠️  Технологии не обнаружены")
            self.content.append("")
            return
        
        self.content.append(f"  📊 Всего обнаружено: {len(technologies)} технолог(ий)")
        self.content.append("")
        
        # Группируем по категориям
        by_category = {}
        for tech in technologies:
            category = tech.get('category', 'Other')
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(tech)
        
        # Выводим по категориям
        for category in sorted(by_category.keys()):
            self.content.append(f"  ▼ {category.upper()}")
            self.content.append("  " + "─" * 76)
            
            for tech in by_category[category]:
                tech_name = tech['technology']
                version = tech.get('version', '-')
                tech_type = tech.get('type', 'Auto-detect')
                
                version_info = f" (v{version})" if version != '-' else ""
                self.content.append(f"     • {tech_name}{version_info}")
                self.content.append(f"       └─ Тип: {tech_type}")
            
            self.content.append("")
    
    def add_summary(self, technologies: List[Dict[str, Any]]):
        """Добавить итоговую сводку"""
        self.content.append("┌" + "─" * 78 + "┐")
        self.content.append("│" + " " * 28 + "ИТОГОВАЯ СВОДКА" + " " * 34 + "│")
        self.content.append("└" + "─" * 78 + "┘")
        self.content.append("")
        
        total = len(technologies)
        self.content.append(f"  ✅ ВСЕГО ТЕХНОЛОГИЙ ОБНАРУЖЕНО: {total}")
        self.content.append("")
        
        # Группировка по категориям для статистики
        by_category = {}
        for tech in technologies:
            category = tech.get('category', 'Other')
            if category not in by_category:
                by_category[category] = 0
            by_category[category] += 1
        
        if by_category:
            self.content.append("  📈 Статистика по категориям:")
            for category in sorted(by_category.keys()):
                count = by_category[category]
                self.content.append(f"     • {category:30s}: {count:3d}")
        
        self.content.append("")
        self.content.append("=" * 80)
        self.content.append(f"Дата создания отчета: {datetime.fromisoformat(self.scan_datetime).strftime('%d.%m.%Y %H:%M:%S')}")
        self.content.append("=" * 80)
    
    def save(self) -> str:
        """Сохранить отчет в файл"""
        with open(self.report_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(self.content))
        
        print(f"[+] TXT отчет сохранен: {self.report_path}")
        return str(self.report_path)


class WappalyzerScanner:
    """Класс для определения технологий на веб-сайте"""
    
    def __init__(self, target_url: str, reports_dir: str = None):
        """
        Инициализация сканера Wappalyzer
        
        Args:
            target_url: URL сайта для сканирования
            reports_dir: Директория для сохранения отчетов
        """
        self.target_url = target_url.rstrip('/')
        if not self.target_url.startswith(('http://', 'https://')):
            self.target_url = f'http://{self.target_url}'
        
        self.hostname = urlparse(self.target_url).hostname or "unknown"
        self.scan_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.detected_technologies = []
        self.response_headers = {}
        
        # Директория для отчетов
        if reports_dir is None:
            self.reports_base = Path(__file__).parent.parent / "reports"
        else:
            self.reports_base = Path(reports_dir)
        
        self.reports_base.mkdir(parents=True, exist_ok=True)
        
        # Загружаем паттерны из отдельного файла
        self.technology_patterns = TECHNOLOGY_PATTERNS
    
    def fetch_page(self) -> Optional[str]:
        """Получить исходный код страницы"""
        try:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Загружаем {self.target_url}...")
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(self.target_url, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Сохраняем заголовки для последующей проверки
            self.response_headers = dict(response.headers)
            
            return response.text
        except requests.RequestException as e:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Ошибка при загрузке: {e}")
            self.response_headers = {}
            return None
    
    def scan(self) -> List[Dict[str, Any]]:
        """Сканировать сайт и определить технологии"""
        html_content = self.fetch_page()
        if not html_content:
            return []
        
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Анализируем технологии...")
        
        for tech_name, tech_config in self.technology_patterns.items():
            patterns = tech_config['patterns']
            version_patterns = tech_config['version_patterns']
            
            for pattern in patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    # Проверяем что технология еще не добавлена
                    if not any(t['technology'] == tech_name for t in self.detected_technologies):
                        # Пытаемся найти версию
                        version = None
                        for version_pattern in version_patterns:
                            version_match = re.search(version_pattern, html_content, re.IGNORECASE)
                            if version_match:
                                version = version_match.group(1)
                                break
                        
                        tech_info = {
                            'technology': tech_name,
                            'detected_at': datetime.now().isoformat(),
                            'pattern': pattern
                        }
                        
                        if version:
                            tech_info['version'] = version
                        
                        self.detected_technologies.append(tech_info)
                        
                        version_str = f" (v{version})" if version else ""
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Обнаружена: {tech_name}{version_str}")
                    break
        
        # Дополнительные проверки через заголовки
        self._check_headers(html_content)
        
        # Проверка специфичных для FastAPI endpoints
        self._check_fastapi_endpoints()
        
        return self.detected_technologies
    
    def _check_headers(self, html_content: str):
        """Проверить заголовки и мета-теги"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Проверка HTTP заголовков сервера
        for header_name, header_value in self.response_headers.items():
            header_lower = header_name.lower()
            value_lower = str(header_value).lower()
            
            # Проверяем различные заголовки
            if 'server' in header_lower:
                print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Server header: {header_value}")
                if 'uvicorn' in value_lower or 'starlette' in value_lower:
                    if not any(t['technology'] == 'FastAPI' for t in self.detected_technologies):
                        self.detected_technologies.append({
                            'technology': 'FastAPI',
                            'type': 'Server Header',
                            'detected_at': datetime.now().isoformat(),
                            'source': f'{header_name}: {header_value}'
                        })
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Обнаружена: FastAPI (по заголовкам сервера)")
            
            if 'x-powered-by' in header_lower:
                if 'fastapi' in value_lower:
                    if not any(t['technology'] == 'FastAPI' for t in self.detected_technologies):
                        self.detected_technologies.append({
                            'technology': 'FastAPI',
                            'type': 'X-Powered-By Header',
                            'detected_at': datetime.now().isoformat(),
                            'source': f'{header_name}: {header_value}'
                        })
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Обнаружена: FastAPI (X-Powered-By)")
        
        # Проверка мета-тегов
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            content = meta.get('content', '').lower()
            name = meta.get('name', '').lower()
            
            if 'generator' in name and content:
                if not any(t['technology'] == content for t in self.detected_technologies):
                    self.detected_technologies.append({
                        'technology': content,
                        'type': 'Meta Generator',
                        'detected_at': datetime.now().isoformat()
                    })
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Обнаружена (мета): {content}")
    
    def _check_fastapi_endpoints(self):
        """Проверить стандартные FastAPI endpoints"""
        fastapi_endpoints = [
            '/docs',              # Swagger UI
            '/redoc',             # ReDoc
            '/openapi.json',      # OpenAPI schema
            '/api/v1/openapi.json',
            '/api/openapi.json'
        ]
        
        for endpoint in fastapi_endpoints:
            try:
                url = f"{self.target_url.rstrip('/')}{endpoint}"
                response = requests.get(url, timeout=5)
                
                # Если найдена документация FastAPI или OpenAPI схема
                if response.status_code == 200:
                    if 'openapi' in response.text.lower() or 'swagger' in response.text.lower() or 'title' in response.text.lower():
                        if not any(t['technology'] == 'FastAPI' for t in self.detected_technologies):
                            self.detected_technologies.append({
                                'technology': 'FastAPI',
                                'type': 'Endpoint Detection',
                                'detected_at': datetime.now().isoformat(),
                                'source': f'Found at {endpoint}'
                            })
                            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Обнаружена: FastAPI (по endpoint {endpoint})")
                            return True
            except requests.RequestException:
                pass
        
        return False
    
    def display_results(self):
        """Вывести результаты в консоль"""
        print(f"\n{Fore.CYAN}{'='*100}")
        print(f"РЕЗУЛЬТАТЫ АНАЛИЗА - Wappalyzer")
        print(f"{'='*100}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}URL:{Style.RESET_ALL} {self.target_url}")
        print(f"{Fore.YELLOW}Время сканирования:{Style.RESET_ALL} {self.scan_time}")
        print(f"{Fore.YELLOW}Обнаружено технологий:{Style.RESET_ALL} {len(self.detected_technologies)}\n")
        
        if self.detected_technologies:
            # Группируем технологии по категориям
            by_category = {}
            for tech in self.detected_technologies:
                category = tech.get('category', 'Other')
                if category not in by_category:
                    by_category[category] = []
                by_category[category].append(tech)
            
            # Выводим каждую категорию
            for category in sorted(by_category.keys()):
                print(f"\n{Fore.YELLOW}▼ {category.upper()}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'Технология':<35} {'Версия':<20} {'Тип':<20}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'-'*100}{Style.RESET_ALL}")
                
                for tech in by_category[category]:
                    tech_name = tech['technology'][:33]
                    version = tech.get('version', '-')[:18]
                    tech_type = tech.get('type', 'Auto-detect')[:18]
                    print(f"{Fore.GREEN}{tech_name:<35} {version:<20} {tech_type:<20}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Технологии не обнаружены{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'='*100}{Style.RESET_ALL}\n")
    
    def save_txt_report(self) -> str:
        """Сохранить TXT отчет"""
        text_report = WappalyzerTextReport(self.target_url, self.reports_base)
        text_report.add_header()
        text_report.add_technologies(self.detected_technologies)
        text_report.add_summary(self.detected_technologies)
        return text_report.save()
    
    def save_json_report(self) -> str:
        """Сохранить JSON отчет"""
        import json
        
        # Создаем директорию если нет
        wappalyzer_dir = self.reports_base / "wappalyzer"
        json_dir = wappalyzer_dir / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        
        # Группируем по категориям для статистики
        by_category = {}
        for tech in self.detected_technologies:
            category = tech.get('category', 'Other')
            if category not in by_category:
                by_category[category] = 0
            by_category[category] += 1
        
        report_data = {
            'scan_info': {
                'target_url': self.target_url,
                'hostname': self.hostname,
                'scan_datetime': datetime.now().isoformat(),
                'scan_time': self.scan_time
            },
            'summary': {
                'total_technologies': len(self.detected_technologies),
                'categories': by_category
            },
            'technologies': self.detected_technologies
        }
        
        # Сохраняем JSON
        json_path = json_dir / f"wappalyzer_{self.scan_time}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"[+] JSON отчет сохранен: {json_path}")
        return str(json_path)


def simple_scan(url: str, reports_dir: str = None) -> Dict[str, Any]:
    """
    Простая функция сканирования для интеграции в другие скрипты
    
    Args:
        url: URL сайта для сканирования
        reports_dir: Директория для сохранения отчетов
    
    Returns:
        Словарь с результатами сканирования и путями к отчетам
    """
    scanner = WappalyzerScanner(url, reports_dir)
    scanner.scan()
    scanner.display_results()
    
    # Сохраняем оба формата
    txt_report = scanner.save_txt_report()
    json_report = scanner.save_json_report()
    
    return {
        'technologies': scanner.detected_technologies,
        'total': len(scanner.detected_technologies),
        'reports': {
            'json': json_report,
            'txt': txt_report
        }
    }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Wappalyzer - Анализ технологий на веб-сайте'
    )
    parser.add_argument('url', help='URL сайта для анализа')
    parser.add_argument(
        '--reports-dir',
        help='Директория для сохранения отчетов',
        default=None
    )
    
    args = parser.parse_args()
    
    try:
        result = simple_scan(args.url, args.reports_dir)
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Ошибка:{Style.RESET_ALL} {e}")
        sys.exit(1)
