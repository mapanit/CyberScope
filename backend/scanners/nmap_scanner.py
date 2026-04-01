#!/usr/bin/env python3
"""
Nmap Port Scanner - Автоматизированное сканирование портов и сервисов
Определяет открытые порты, версии сервисов и выполняет поиск известных CVE
Сохраняет отчеты в JSON и TXT форматах
"""

import nmap
import json
import requests
import re
import sys
import os
from pathlib import Path
from datetime import datetime
from urllib.parse import quote
from typing import Dict, List, Optional, Any, Tuple
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
try:
    import nvdlib
    NVDLIB_AVAILABLE = True
except ImportError:
    NVDLIB_AVAILABLE = False
from core.report_utils import ReportBase

# Инициализация цветного вывода
init(autoreset=True)

# Кеш для CVE поисков (потокобезопасный)
CVE_CACHE = {}
CVE_CACHE_LOCK = threading.Lock()


class CVESearcher:
    """Класс для поиска CVE информации"""
    
    @staticmethod
    def search_cve(product: str, version: str = None) -> List[Dict[str, Any]]:
        """
        Поиск CVE для продукта и версии
        
        Args:
            product: Название продукта (apache, nginx, openssh и т.д.)
            version: Версия продукта (опционально)
            
        Returns:
            Список найденных CVE с информацией о них
        """
        cache_key = f"{product}:{version}" if version else product
        
        # Проверяем кеш потокобезопасным образом
        with CVE_CACHE_LOCK:
            if cache_key in CVE_CACHE:
                return CVE_CACHE[cache_key]
        
        results = []
        
        try:
            # Простой способ - ищем в известных CVE для популярных сервисов
            results = CVESearcher._search_known_cves(product, version)
            
            # Если не найдено локально, пытаемся использовать API (опционально)
            if not results:
                results = CVESearcher._search_via_api(product, version)
        
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Ошибка поиска CVE для {product}: {e}")
        
        # Сохраняем в кеш потокобезопасно
        with CVE_CACHE_LOCK:
            CVE_CACHE[cache_key] = results
        
        return results
    
    @staticmethod
    def _search_known_cves(product: str, version: str = None) -> List[Dict[str, Any]]:
        """Поиск в известной базе CVE для популярных сервисов"""
        
        known_cves = {
            'apache': [
                {
                    'product': 'Apache HTTP Server',
                    'min_version': '2.4.0',
                    'max_version': '2.4.49',
                    'cve_id': 'CVE-2021-44790',
                    'severity': 'High',
                    'description': 'Buffer overflow in mod_lua and mod_jk of Apache HTTP Server'
                },
                {
                    'product': 'Apache HTTP Server',
                    'min_version': '2.4.0',
                    'max_version': '2.4.43',
                    'cve_id': 'CVE-2020-9490',
                    'severity': 'High',
                    'description': 'Improper handling of HTTP requests in Apache HTTP Server'
                }
            ],
            'nginx': [
                {
                    'product': 'Nginx',
                    'min_version': '1.16.0',
                    'max_version': '1.19.6',
                    'cve_id': 'CVE-2021-3618',
                    'severity': 'High',
                    'description': 'Vulnerability in HTTP2 handling in Nginx'
                }
            ],
            'openssh': [
                {
                    'product': 'OpenSSH',
                    'min_version': '1.0',
                    'max_version': '8.2',
                    'cve_id': 'CVE-2020-14145',
                    'severity': 'Medium',
                    'description': 'Information disclosure in OpenSSH'
                },
                {
                    'product': 'OpenSSH',
                    'min_version': '7.4',
                    'max_version': '8.5',
                    'cve_id': 'CVE-2021-28041',
                    'severity': 'High',
                    'description': 'Authentication bypass in OpenSSH'
                }
            ],
            'openssl': [
                {
                    'product': 'OpenSSL',
                    'min_version': '1.0.1',
                    'max_version': '1.0.1i',
                    'cve_id': 'CVE-2014-0160',
                    'severity': 'Critical',
                    'description': 'Heartbleed - Buffer over-read in OpenSSL'
                }
            ],
            'mysql': [
                {
                    'product': 'MySQL',
                    'min_version': '5.6',
                    'max_version': '5.6.30',
                    'cve_id': 'CVE-2015-3156',
                    'severity': 'High',
                    'description': 'Vulnerability in MySQL'
                }
            ],
            'postgresql': [
                {
                    'product': 'PostgreSQL',
                    'min_version': '9.0',
                    'max_version': '12.5',
                    'cve_id': 'CVE-2021-22911',
                    'severity': 'Medium',
                    'description': 'Vulnerability in PostgreSQL'
                }
            ]
        }
        
        results = []
        product_lower = product.lower() if product else ""
        
        for service_name, cves in known_cves.items():
            if service_name in product_lower:
                for cve_info in cves:
                    # Если указана версия, проверяем попадает ли она в диапазон
                    if version:
                        if CVESearcher._is_version_vulnerable(version, cve_info.get('min_version'), cve_info.get('max_version')):
                            results.append(cve_info)
                    else:
                        # Если версия не указана, включаем все CVE для этого сервиса
                        results.append(cve_info)
        
        return results
    
    @staticmethod
    def _is_version_vulnerable(current: str, min_ver: str, max_ver: str) -> bool:
        """Проверка, уязвима ли текущая версия"""
        try:
            curr_parts = [int(x) for x in current.split('.')[:3]]
            min_parts = [int(x) for x in min_ver.split('.')[:3]]
            max_parts = [int(x) for x in max_ver.split('.')[:3]]
            
            # Паддируем до 3 компонентов
            while len(curr_parts) < 3:
                curr_parts.append(0)
            while len(min_parts) < 3:
                min_parts.append(0)
            while len(max_parts) < 3:
                max_parts.append(0)
            
            return min_parts <= curr_parts <= max_parts
        except (ValueError, AttributeError):
            return False
    
    @staticmethod
    def _search_via_api(product: str, version: str = None) -> List[Dict[str, Any]]:
        """Поиск CVE через API (используется nvdlib если доступен)"""
        # Сначала пробуем nvdlib если доступен
        if NVDLIB_AVAILABLE:
            try:
                results = CVESearcher._search_via_nvdlib(product, version)
                if results:
                    return results
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Ошибка поиска CVE через nvdlib: {e}")
        
        # Fallback на CveDetails API
        try:
            if version:
                url = f"https://www.cvedetails.com/json-feed.php?product={quote(product)}&version={quote(version)}"
            else:
                url = f"https://www.cvedetails.com/json-feed.php?product={quote(product)}"
            
            # Устанавливаем timeout чтобы не зависать
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('cveCollection', [])[:5]  # Ограничиваем до 5 результатов
        except Exception as e:
            pass
        
        return []
    
    @staticmethod
    def _search_via_nvdlib(product: str, version: str = None) -> List[Dict[str, Any]]:
        """Поиск CVE через nvdlib API"""
        if not NVDLIB_AVAILABLE:
            return []
        
        try:
            results = []
            # Ищем CVE по продукту
            cves = nvdlib.searchCPE(query=product, limit=10)
            
            for cpe_match in cves:
                if hasattr(cpe_match, 'cpeMatch'):
                    for cpe in cpe_match.cpeMatch:
                        if version:
                            # Проверяем версию
                            if hasattr(cpe, 'versionStartIncluding') and hasattr(cpe, 'versionEndIncluding'):
                                start = cpe.versionStartIncluding
                                end = cpe.versionEndIncluding
                                if CVESearcher._is_version_vulnerable(version, start or '0.0', end or '999.999'):
                                    results.append({
                                        'product': product,
                                        'cve_id': getattr(cpe, 'cveId', 'Unknown'),
                                        'severity': 'High',
                                        'description': f'Found via nvdlib for {product}'
                                    })
                        else:
                            results.append({
                                'product': product,
                                'cve_id': getattr(cpe, 'cveId', 'Unknown'),
                                'severity': 'High',
                                'description': f'Found via nvdlib for {product}'
                            })
            
            return results[:5]  # Ограничиваем до 5 результатов
        except Exception as e:
            return []


class NmapScanner(ReportBase):
    """Сканер портов и сервисов с использованием Nmap"""
    
    def __init__(self, target, output_base=None, reports_dir=None):
        """
        Инициализация Nmap сканера
        
        Args:
            target: Целевой хост (домен, IP или IP/CIDR)
            output_base: Базовое имя для файлов отчетов
            reports_dir: Директория для отчетов
        """
        super().__init__('nmap', target, Path(reports_dir) if reports_dir else None)
        
        self.target = target
        self.nm = nmap.PortScanner()
        self.nm_results = {}
        self.discovered_hosts = []
        self.open_ports = []
        self.vulnerabilities = []
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.start_time = datetime.now()
        self.end_time = None
        
        # Базовое имя для файлов
        if output_base:
            self.filename_base = output_base
        else:
            safe_target = target.replace('/', '_').replace('\\', '_').replace(':', '_')
            self.filename_base = f"nmap_{safe_target}_{self.scan_id}"
    
    def run_scan(self, arguments: str = "-sV -sC --top-ports 1000") -> bool:
        """
        Запустить Nmap сканирование
        
        Args:
            arguments: Аргументы для Nmap (по умолчанию определение версий и top 1000 портов)
            
        Returns:
            True если сканирование успешно, False в противном случае
        """
        try:
            print(f"{Fore.CYAN}[*] Запускаем Nmap сканирование целевого хоста: {self.target}")
            print(f"{Fore.CYAN}[*] Аргументы: {arguments}")
            
            self.nm.scan(self.target, arguments=arguments, sudo=False)
            self.nm_results = self.nm
            
            print(f"{Fore.GREEN}[+] Сканирование завершено успешно")
            return True
            
        except nmap.PortScannerError as e:
            print(f"{Fore.RED}[!] Ошибка Nmap: {e}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] Ошибка сканирования: {e}")
            return False
    
    def parse_results(self):
        """Парс результатов Nmap сканирования с параллельным поиском CVE"""
        try:
            # Собираем все порты для параллельной обработки
            ports_for_processing = []
            
            for host in self.nm.all_hosts():
                print(f"{Fore.CYAN}[*] Парсим результаты для хоста: {host}")
                
                host_info = {
                    'host': host,
                    'status': self.nm[host].state(),
                    'ports': []
                }
                
                # Проходим по всем портам
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    
                    for port in ports:
                        port_info = {
                            'host': host,
                            'port': port,
                            'protocol': proto,
                            'state': self.nm[host][proto][port]['state'],
                            'service': self.nm[host][proto][port].get('name', 'unknown'),
                            'version': self.nm[host][proto][port].get('version', 'unknown'),
                            'extrainfo': self.nm[host][proto][port].get('extrainfo', ''),
                            'vulnerabilities': []
                        }
                        
                        host_info['ports'].append(port_info)
                        
                        # Если открытый порт - добавляем для поиска CVE
                        if port_info['state'] == 'open':
                            self.open_ports.append(port_info)
                            ports_for_processing.append(port_info)
                
                self.discovered_hosts.append(host_info)
                print(f"{Fore.GREEN}[+] Обнаружено открытых портов на {host}: {len([p for p in host_info['ports'] if p['state'] == 'open'])}")
            
            # Параллельный поиск CVE для всех открытых портов
            if ports_for_processing:
                self._search_cves_parallel(ports_for_processing)
        
        except Exception as e:
            print(f"{Fore.RED}[!] Ошибка при парсе результатов: {e}")
    
    def _search_cves_parallel(self, ports: List[Dict[str, Any]], max_workers: int = 5):
        """
        Параллельный поиск CVE для множества портов
        
        Args:
            ports: Список портов для обработки
            max_workers: Максимальное количество параллельных потоков
        """
        print(f"{Fore.CYAN}[*] Запускаем параллельный поиск CVE для {len(ports)} портов...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            
            for port_info in ports:
                future = executor.submit(self.search_service_cves, port_info)
                futures[future] = port_info
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    port_info = futures[future]
                    print(f"{Fore.YELLOW}[!] Ошибка при обработке {port_info['host']}:{port_info['port']}: {e}")
    
    def search_service_cves(self, port_info: Dict[str, Any]):
        """
        Поиск CVE для обнаруженного сервиса
        Потокобезопасный метод для параллельной обработки
        """
        service = port_info['service']
        version = port_info['version']
        host = port_info.get('host', 'unknown')
        port = port_info['port']
        
        if service and service != 'unknown':
            try:
                cves = CVESearcher.search_cve(service, version if version != 'unknown' else None)
                
                if cves:
                    port_info['vulnerabilities'] = cves
                    
                    # Добавляем в список уязвимостей потокобезопасно
                    for cve in cves:
                        vuln_record = {
                            'host': host,
                            'port': port,
                            'service': service,
                            'version': version,
                            'cve_id': cve.get('cve_id', 'Unknown'),
                            'description': cve.get('description', 'No description'),
                            'severity': cve.get('severity', 'Unknown'),
                            'product': cve.get('product', service)
                        }
                        
                        threading.Lock()
                        self.vulnerabilities.append(vuln_record)
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Ошибка при поиске CVE для {service} на {host}:{port}: {e}")
    
    def print_results(self):
        """Вывести результаты в консоль"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}{'NMAP SCAN RESULTS'.center(80)}")
        print(f"{Fore.CYAN}{'='*80}\n")
        
        print(f"{Fore.YELLOW}[*] Целевой хост: {self.target}")
        print(f"{Fore.YELLOW}[*] Время сканирования: {self.scan_id}\n")
        
        if not self.discovered_hosts:
            print(f"{Fore.RED}[!] Нет обнаруженных хостов")
            return
        
        for host_info in self.discovered_hosts:
            print(f"{Fore.CYAN}[*] Хост: {host_info['host']} ({host_info['status']})\n")
            
            open_ports = [p for p in host_info['ports'] if p['state'] == 'open']
            if open_ports:
                print(f"{Fore.GREEN}[+] Открытые порты ({len(open_ports)}):\n")
                
                for port in open_ports:
                    print(f"  {Fore.CYAN}PORT: {port['port']}/{port['protocol']}")
                    print(f"  {Fore.YELLOW}STATE: {port['state']}")
                    print(f"  {Fore.CYAN}SERVICE: {port['service']}")
                    print(f"  {Fore.YELLOW}VERSION: {port['version']}")
                    
                    if port.get('vulnerabilities'):
                        print(f"  {Fore.RED}VULNERABILITIES ({len(port['vulnerabilities'])}):")
                        for vuln in port['vulnerabilities']:
                            print(f"    - {vuln.get('cve_id')}: {vuln.get('severity')} - {vuln.get('description')}")
                    
                    print()
        
        if self.vulnerabilities:
            print(f"\n{Fore.RED}{'='*80}")
            print(f"{Fore.RED}FOUND VULNERABILITIES: {len(self.vulnerabilities)}")
            print(f"{Fore.RED}{'='*80}\n")
            
            for vuln in self.vulnerabilities:
                print(f"{Fore.RED}[!] {vuln['cve_id']} - {vuln['severity']}")
                print(f"    Host: {vuln['host']}")
                print(f"    Port: {vuln['port']}/{vuln['service']}")
                print(f"    Description: {vuln['description']}\n")
    
    def get_json_report(self) -> Dict[str, Any]:
        """Получить полный отчет в формате JSON"""
        report = {
            'status': 'completed',
            'scan_info': {
                'target': self.target,
                'scan_id': self.scan_id,
                'scan_datetime': self.start_time.isoformat(),
                'tool': 'nmap',
                'nmap_version': self.nm.nmap_version() if hasattr(self.nm, 'nmap_version') else 'unknown'
            },
            'summary': {
                'total_hosts_discovered': len(self.discovered_hosts),
                'total_open_ports': len(self.open_ports),
                'total_vulnerabilities': len(self.vulnerabilities),
                'vulnerabilities_by_severity': self._count_by_severity(),
                'status': 'completed'
            },
            'hosts': self.discovered_hosts,
            'vulnerabilities': self.vulnerabilities,
            'recommendations': self._get_recommendations()
        }
        return report
    
    def get_structured_data(self) -> Dict[str, Any]:
        """
        Получить структурированные данные для интеграции в общий отчет
        Формат совместим с report_utils.py
        """
        return {
            'status': 'completed',
            'scan_info': {
                'target': self.target,
                'scan_datetime': self.start_time.isoformat(),
                'tool': 'nmap'
            },
            'summary': {
                'total_hosts': len(self.discovered_hosts),
                'total_open_ports': len(self.open_ports),
                'total_vulnerabilities': len(self.vulnerabilities),
                'by_severity': self._count_by_severity()
            },
            'hosts': [
                {
                    'address': h['host'],
                    'status': h['status'],
                    'ports_count': len([p for p in h['ports'] if p['state'] == 'open'])
                }
                for h in self.discovered_hosts
            ],
            'ports': self.open_ports,
            'vulnerabilities': [
                {
                    'cve_id': v['cve_id'],
                    'severity': v['severity'],
                    'service': v['service'],
                    'host': v['host'],
                    'port': v['port'],
                    'description': v['description']
                }
                for v in self.vulnerabilities
            ]
        }
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Подсчет уязвимостей по серьезности"""
        severities = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Unknown': 0}
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            if severity in severities:
                severities[severity] += 1
            else:
                severities['Unknown'] += 1
        
        return severities
    
    def _get_recommendations(self) -> List[str]:
        """Получить рекомендации на основе результатов"""
        recommendations = [
            'Закройте ненужные открытые порты с помощью firewall правил',
            'Обновите все обнаруженные сервисы до последних безопасных версий',
            'Используйте минимально необходимые сервисы (принцип least privilege)',
            'Настройте Network segmentation и ограничьте доступ',
            'Регулярно проводите сканирования портов для мониторинга изменений',
            'Используйте IDS/IPS для обнаружения сканирований и атак',
            'Применяйте security patches как можно скорее',
            'Отключите ненужные сервисы и компоненты'
        ]
        
        if self.vulnerabilities:
            recommendations.extend([
                'Некоторые сервисы имеют известные уязвимости - приоритизируйте их обновление',
                'Рассмотрите возможность миграции на альтернативные решения если обновления недоступны'
            ])
        
        return recommendations
    
    def generate_txt_report(self) -> str:
        """Генерировать текстовый отчет"""
        lines = []
        
        lines.append("╔" + "═"*78 + "╗")
        lines.append("║" + "NMAP PORT & SERVICE SCAN REPORT".center(78) + "║")
        lines.append("╚" + "═"*78 + "╝")
        lines.append("")
        
        # Информация о сканировании
        lines.append("📋 ИНФОРМАЦИЯ О СКАНИРОВАНИИ")
        lines.append("─" * 80)
        lines.append(f"  Целевой хост:          {self.target}")
        lines.append(f"  Дата сканирования:     {self.start_time.strftime('%d.%m.%Y %H:%M:%S')}")
        lines.append(f"  Найдено хостов:        {len(self.discovered_hosts)}")
        lines.append(f"  Открытых портов:       {len(self.open_ports)}")
        lines.append(f"  Найдено уязвимостей:   {len(self.vulnerabilities)}")
        lines.append("")
        
        # Обнаруженные хосты и порты
        if self.discovered_hosts:
            lines.append("🖥️ ОБНАРУЖЕННЫЕ ХОСТЫ И ПОРТЫ")
            lines.append("─" * 80)
            
            for host_info in self.discovered_hosts:
                lines.append(f"\n  Хост: {host_info['host']} ({host_info['status']})")
                lines.append("  " + "─" * 76)
                
                open_ports = [p for p in host_info['ports'] if p['state'] == 'open']
                
                if open_ports:
                    lines.append("  Открытые порты:")
                    for port in open_ports:
                        lines.append(f"    • {port['port']}/{port['protocol']:3s} | {port['service']:15s} | {port['version']}")
                        if port.get('vulnerabilities'):
                            for cve in port['vulnerabilities']:
                                lines.append(f"      ⚠️  {cve.get('cve_id')}: {cve.get('severity')}")
                else:
                    lines.append("  Нет открытых портов")
            
            lines.append("")
        
        # Обнаруженные уязвимости
        if self.vulnerabilities:
            lines.append("\n⚠️  ОБНАРУЖЕННЫЕ УЯЗВИМОСТИ")
            lines.append("─" * 80)
            
            severities = self._count_by_severity()
            lines.append(f"  Всего: {len(self.vulnerabilities)}")
            for severity, count in severities.items():
                if count > 0:
                    lines.append(f"    • {severity}: {count}")
            
            lines.append("\n  Детали уязвимостей:")
            for vuln in self.vulnerabilities:
                lines.append(f"\n    CVE ID:    {vuln['cve_id']}")
                lines.append(f"    Хост:      {vuln['host']}")
                lines.append(f"    Порт:      {vuln['port']}/{vuln['service']}")
                lines.append(f"    Версия:    {vuln['version']}")
                lines.append(f"    Серьезность: {vuln['severity']}")
                lines.append(f"    Описание:  {vuln['description']}")
            
            lines.append("")
        
        # Рекомендации
        lines.append("\n💡 РЕКОМЕНДАЦИИ")
        lines.append("─" * 80)
        for i, rec in enumerate(self._get_recommendations(), 1):
            lines.append(f"  {i}. {rec}")
        
        lines.append("")
        lines.append("═" * 80)
        lines.append(f"Дата создания отчета: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
        lines.append("═" * 80)
        
        return "\n".join(lines)
    
    def save_reports(self) -> Dict[str, str]:
        """Сохранить JSON и TXT отчеты"""
        reports = {}
        
        try:
            # Сохраняем JSON отчет
            json_data = self.get_json_report()
            json_path = self.json_dir / f"{self.filename_base}.json"
            
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            
            reports['json'] = str(json_path)
            print(f"{Fore.GREEN}[+] JSON отчет сохранен: {json_path}")
            
            # Сохраняем TXT отчет
            txt_content = self.generate_txt_report()
            txt_path = self.txt_dir / f"{self.filename_base}.txt"
            
            with open(txt_path, 'w', encoding='utf-8') as f:
                f.write(txt_content)
            
            reports['txt'] = str(txt_path)
            print(f"{Fore.GREEN}[+] TXT отчет сохранен: {txt_path}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Ошибка сохранения отчетов: {e}")
        
        return reports


def simple_scan(target: str, reports_dir: str = None) -> Dict[str, Any]:
    """
    Простая функция для сканирования
    
    Args:
        target: Целевой хост
        reports_dir: Директория для отчетов
        
    Returns:
        Словарь с результатами сканирования
    """
    scanner = NmapScanner(target, reports_dir=reports_dir)
    
    # Запускаем сканирование
    if scanner.run_scan():
        scanner.parse_results()
        scanner.print_results()
        scanner.save_reports()
        
        return {
            'status': 'completed',
            'target': target,
            'hosts_discovered': len(scanner.discovered_hosts),
            'open_ports': len(scanner.open_ports),
            'vulnerabilities': len(scanner.vulnerabilities),
            'result': scanner.get_json_report()
        }
    else:
        return {
            'status': 'failed',
            'target': target,
            'error': 'Nmap scan failed'
        }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Nmap Port Scanner with CVE Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
            python nmap_scanner.py example.com
            python nmap_scanner.py 192.168.1.1 -a "-sV -sC -p 1-65535"
            python nmap_scanner.py 192.168.1.0/24 -a "-sn"
        """
    )
    
    parser.add_argument('target', help='Target host/domain/IP for scanning')
    parser.add_argument('-a', '--arguments', default="-sV -sC --top-ports 1000",
                        help='Nmap arguments (default: "-sV -sC --top-ports 1000")')
    parser.add_argument('-o', '--output', help='Output base filename')
    parser.add_argument('-r', '--reports-dir', help='Reports directory')
    
    args = parser.parse_args()
    
    scanner = NmapScanner(args.target, args.output, args.reports_dir)
    
    if scanner.run_scan(args.arguments):
        scanner.parse_results()
        scanner.print_results()
        scanner.save_reports()
    else:
        sys.exit(1)
