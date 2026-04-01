#!/usr/bin/env python3
"""
DNS Scanner Tool - Автоматизированное сканирование DNS записей
Сохраняет отчеты в JSON и TXT форматах
Адаптировано под структуру проекта CyberScope
"""

import dns.resolver
import dns.zone
import dns.query
import dns.update
import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from subprocess import getoutput
from typing import Dict, List, Optional, Any
from colorama import Fore, Style, init

# Инициализация цветного вывода
init(autoreset=True)


class DNSTextReport:
    """Класс для создания текстового отчета DNS"""
    
    def __init__(self, target_domain: str, reports_dir: Path = None):
        """Инициализация текстового отчета"""
        self.target_domain = target_domain
        self.scan_datetime = datetime.now().isoformat()
        self.scan_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Настройка директорий
        if reports_dir is None:
            reports_dir = Path(__file__).parent.parent / "reports"
        else:
            reports_dir = Path(reports_dir)
        
        # Создаем папку dns и txt подпапку
        self.dns_dir = reports_dir / "dns"
        self.txt_dir = self.dns_dir / "txt"
        self.txt_dir.mkdir(parents=True, exist_ok=True)
        
        self.report_path = self.txt_dir / f"dns_{self.scan_time}.txt"
        self.content = []
    
    def add_header(self):
        """Добавить заголовок отчета"""
        self.content.append("┌" + "─" * 78 + "┐")
        self.content.append("│" + " " * 22 + "DNS ENUMERATION - АНАЛИЗ DNS ЗАПИСЕЙ" + " " * 19 + "│")
        self.content.append("└" + "─" * 78 + "┘")
        self.content.append("")
        
        self.content.append("📋 ИНФОРМАЦИЯ О СКАНИРОВАНИИ")
        self.content.append("─" * 80)
        self.content.append(f"  Домен/IP:           {self.target_domain}")
        self.content.append(f"  Дата сканирования:  {datetime.fromisoformat(self.scan_datetime).strftime('%d.%m.%Y')}")
        self.content.append(f"  Время сканирования: {datetime.fromisoformat(self.scan_datetime).strftime('%H:%M:%S')}")
        self.content.append("")
    
    def add_dns_records(self, dns_records: Dict[str, List[str]]):
        """Добавить DNS записи"""
        self.content.append("🔍 DNS ЗАПИСИ")
        self.content.append("─" * 80)
        
        if not dns_records:
            self.content.append("  ⚠️  DNS записи не найдены")
            self.content.append("")
            return
        
        self.content.append(f"  📊 Всего типов записей: {len(dns_records)}")
        self.content.append("")
        
        # Выводим каждый тип записи
        for record_type in sorted(dns_records.keys()):
            records = dns_records[record_type]
            self.content.append(f"  ▼ {record_type}")
            self.content.append("  " + "─" * 76)
            
            for record in records:
                # Обработка разных типов записей
                if isinstance(record, dict):
                    # Для NS записей с IP-адресами
                    if 'nameserver' in record:
                        ns = record['nameserver']
                        ips = record.get('ips', [])
                        if ips:
                            self.content.append(f"     • {ns}")
                            for ip in ips:
                                self.content.append(f"       ├─ {ip}")
                        else:
                            self.content.append(f"     • {ns} (не удалось разрешить)")
                    # Для MX записей
                    elif 'priority' in record:
                        priority = record['priority']
                        server = record['server']
                        self.content.append(f"     • {server} (приоритет: {priority})")
                    else:
                        self.content.append(f"     • {str(record)}")
                else:
                    self.content.append(f"     • {str(record)}")
            
            self.content.append("")
    
    def add_summary(self, dns_records: Dict[str, List[str]], nameservers: List[str] = None):
        """Добавить итоговую сводку"""
        self.content.append("┌" + "─" * 78 + "┐")
        self.content.append("│" + " " * 28 + "ИТОГОВАЯ СВОДКА" + " " * 34 + "│")
        self.content.append("└" + "─" * 78 + "┘")
        self.content.append("")
        
        total_records = sum(len(records) for records in dns_records.values())
        self.content.append(f"  ✅ ВСЕГО НАЙДЕНО ЗАПИСЕЙ: {total_records}")
        self.content.append(f"  ✅ ТИПОВ ЗАПИСЕЙ: {len(dns_records)}")
        
        if nameservers:
            self.content.append(f"  ✅ АВТОРИТЕТНЫЕ NAMESERVERS: {len(nameservers)}")
            for ns in nameservers:
                self.content.append(f"       • {ns}")
        
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


class DNSScanner:
    """Класс для сканирования DNS записей"""
    
    # Стандартные типы DNS записей
    DNS_RECORDS = ['A', 'AAAA', 'NS', 'CNAME', 'SOA', 'PTR', 'MX', 'TXT', 'SRV']
    
    def __init__(self, target_domain: str, reports_dir: str = None):
        """
        Инициализация DNS сканера
        
        Args:
            target_domain: Домен или IP адрес для сканирования
            reports_dir: Директория для сохранения отчетов
        """
        self.target_domain = target_domain.strip()
        self.scan_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.dns_records = {}
        self.nameservers = []
        
        # Директория для отчетов
        if reports_dir is None:
            self.reports_base = Path(__file__).parent.parent / "reports"
        else:
            self.reports_base = Path(reports_dir)
        
        self.reports_base.mkdir(parents=True, exist_ok=True)
    
    def scan(self) -> Dict[str, List[str]]:
        """Выполнить сканирование DNS записей"""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Начинаем сканирование DNS для {self.target_domain}...")
        
        # Получаем NS записи в первую очередь
        self._resolve_record('NS')
        
        # Пытаемся разрешить остальные типы записей
        for record_type in self.DNS_RECORDS:
            if record_type != 'NS':
                self._resolve_record(record_type)
        
        return self.dns_records
    
    def _resolve_record(self, record_type: str):
        """Разрешить конкретный тип DNS записи"""
        try:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Ищем {record_type} записи...")
            query = dns.resolver.resolve(self.target_domain, record_type)
            
            records = []
            
            if record_type == 'NS':
                # Специальная обработка для NS записей - получаем IP адреса
                for answer in query:
                    nameserver = str(answer).rstrip('.')
                    self.nameservers.append(nameserver)
                    
                    # Пытаемся получить IP адреса nameserver
                    ips = []
                    try:
                        a_query = dns.resolver.resolve(nameserver, 'A')
                        for a_record in a_query:
                            ips.append(str(a_record))
                    except Exception:
                        pass
                    
                    try:
                        aaaa_query = dns.resolver.resolve(nameserver, 'AAAA')
                        for aaaa_record in aaaa_query:
                            ips.append(str(aaaa_record))
                    except Exception:
                        pass
                    
                    records.append({
                        'nameserver': nameserver,
                        'ips': ips
                    })
                    
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {record_type}: {nameserver} {' -> ' + ', '.join(ips) if ips else ''}")
            
            elif record_type == 'MX':
                # Специальная обработка для MX записей
                for answer in query:
                    priority = answer.preference
                    server = str(answer.exchange).rstrip('.')
                    records.append({
                        'priority': int(priority),
                        'server': server
                    })
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {record_type}: {server} (приоритет: {priority})")
            
            elif record_type == 'SOA':
                # Специальная обработка для SOA записей
                for answer in query:
                    SOA_info = {
                        'mname': str(answer.mname).rstrip('.'),
                        'rname': str(answer.rname).rstrip('.'),
                        'serial': int(answer.serial),
                        'refresh': int(answer.refresh),
                        'retry': int(answer.retry),
                        'expire': int(answer.expire),
                        'minimum': int(answer.minimum)
                    }
                    records.append(SOA_info)
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {record_type}: {SOA_info['mname']}")
            
            else:
                # Обработка для остальных типов (A, AAAA, CNAME, TXT, SRV)
                for answer in query:
                    record_value = str(answer).rstrip('.')
                    records.append(record_value)
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {record_type}: {record_value}")
            
            if records:
                self.dns_records[record_type] = records
        
        except dns.resolver.NXDOMAIN:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {record_type}: Домен не существует")
        except dns.resolver.NoAnswer:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {record_type}: Нет ответа")
        except dns.resolver.Timeout:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {record_type}: Timeout")
        except Exception as e:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {record_type}: {type(e).__name__}")
    
    def display_results(self):
        """Вывести результаты в консоль"""
        print(f"\n{Fore.CYAN}{'='*100}")
        print(f"РЕЗУЛЬТАТЫ АНАЛИЗА - DNS Enumeration")
        print(f"{'='*100}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Домен:{Style.RESET_ALL} {self.target_domain}")
        print(f"{Fore.YELLOW}Время сканирования:{Style.RESET_ALL} {self.scan_time}")
        print(f"{Fore.YELLOW}Найдено типов записей:{Style.RESET_ALL} {len(self.dns_records)}\n")
        
        if self.dns_records:
            for record_type in sorted(self.dns_records.keys()):
                records = self.dns_records[record_type]
                print(f"{Fore.YELLOW}▼ {record_type.upper()}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'-'*100}{Style.RESET_ALL}")
                
                for record in records:
                    if isinstance(record, dict):
                        if 'nameserver' in record:
                            ns = record['nameserver']
                            ips = record.get('ips', [])
                            print(f"{Fore.GREEN}  {ns:<60} {', '.join(ips) if ips else 'N/A':<40}{Style.RESET_ALL}")
                        elif 'priority' in record:
                            print(f"{Fore.GREEN}  {record['server']:<60} (приоритет: {record['priority']}){Style.RESET_ALL}")
                        else:
                            print(f"{Fore.GREEN}  {str(record)}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}  {str(record)}{Style.RESET_ALL}")
                print()
        else:
            print(f"{Fore.RED}Записи не найдены{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}{'='*100}{Style.RESET_ALL}\n")
    
    def save_txt_report(self) -> str:
        """Сохранить TXT отчет"""
        text_report = DNSTextReport(self.target_domain, self.reports_base)
        text_report.add_header()
        text_report.add_dns_records(self.dns_records)
        text_report.add_summary(self.dns_records, self.nameservers)
        return text_report.save()
    
    def save_json_report(self) -> str:
        """Сохранить JSON отчет"""
        # Создаем директорию если нет
        dns_dir = self.reports_base / "dns"
        json_dir = dns_dir / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        
        # Преобразуем данные для JSON сохранения
        json_records = {}
        for record_type, records in self.dns_records.items():
            json_records[record_type] = []
            for record in records:
                if isinstance(record, dict):
                    json_records[record_type].append(record)
                else:
                    json_records[record_type].append(str(record))
        
        report_data = {
            'scan_info': {
                'target_domain': self.target_domain,
                'scan_datetime': datetime.now().isoformat(),
                'scan_time': self.scan_time
            },
            'summary': {
                'total_record_types': len(self.dns_records),
                'nameservers': self.nameservers
            },
            'dns_records': json_records
        }
        
        # Сохраняем JSON
        json_path = json_dir / f"dns_{self.scan_time}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"[+] JSON отчет сохранен: {json_path}")
        return str(json_path)


def simple_scan(domain: str, reports_dir: str = None) -> Dict[str, Any]:
    """
    Простая функция сканирования для интеграции в другие скрипты
    
    Args:
        domain: Домен или IP адрес для сканирования
        reports_dir: Директория для сохранения отчетов
    
    Returns:
        Словарь с результатами сканирования и путями к отчетам
    """
    scanner = DNSScanner(domain, reports_dir)
    scanner.scan()
    scanner.display_results()
    
    # Сохраняем оба формата
    txt_report = scanner.save_txt_report()
    json_report = scanner.save_json_report()
    
    return {
        'dns_records': scanner.dns_records,
        'nameservers': scanner.nameservers,
        'total': len(scanner.dns_records),
        'reports': {
            'json': json_report,
            'txt': txt_report
        }
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='DNS Scanner - Сканирование DNS записей домена'
    )
    parser.add_argument('domain', help='Домен или IP адрес для сканирования')
    parser.add_argument(
        '--reports-dir',
        help='Директория для сохранения отчетов',
        default=None
    )
    
    args = parser.parse_args()
    
    try:
        result = simple_scan(args.domain, args.reports_dir)
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Ошибка:{Style.RESET_ALL} {e}")
        sys.exit(1)