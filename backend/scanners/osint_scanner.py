#!/usr/bin/env python3
import subprocess
import json
import os
import sys
import time
import threading
from datetime import datetime
from queue import Queue
import signal
from pathlib import Path
from core.report_utils import ReportBase

# Импорт конфигурации сканеров
try:
    from scanner_config import get_amass_profile
except ImportError:
    get_amass_profile = None

class OsintTextReport:
    """Класс для создания единого текстового отчета OSINT"""
    
    def __init__(self, domain: str, reports_base_dir: Path = None):
        """Инициализация текстового отчета"""
        self.domain = domain
        self.scan_datetime = datetime.now().isoformat()
        self.scan_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Настройка директорий
        if reports_base_dir is None:
            reports_base_dir = Path(__file__).parent.parent / "reports"
        else:
            reports_base_dir = Path(reports_base_dir)
        
        # Создаем подпапки osint/txt и osint/json
        self.osint_dir = reports_base_dir / "osint"
        self.txt_dir = self.osint_dir / "txt"
        self.json_dir = self.osint_dir / "json"
        
        self.txt_dir.mkdir(parents=True, exist_ok=True)
        self.json_dir.mkdir(parents=True, exist_ok=True)
        
        self.report_path = self.txt_dir / f"osint_report_{self.scan_time}.txt"
        self.content = []
        
        # Информация об инструментах
        self.tools_info = {
            'amass': {
                'name': 'Amass',
                'description': 'Сканирование поддоменов с использованием API и пассивных источников',
                'type': 'Разведка (Reconnaissance)'
            },
            'subfinder': {
                'name': 'Subfinder',
                'description': 'Поиск поддоменов из различных публичных источников и API',
                'type': 'Разведка (Reconnaissance)'
            },
            'wayback': {
                'name': 'Wayback Machine',
                'description': 'Извлечение исторических URL из архива Internet Archive',
                'type': 'Разведка (Reconnaissance)'
            }
        }
    
    def add_header(self):
        """Добавить подробный заголовок отчета"""
        self.content.append("┌" + "─" * 78 + "┐")
        self.content.append("│" + " " * 20 + "OSINT ОТЧЕТ О СКАНИРОВАНИИ" + " " * 32 + "│")
        self.content.append("└" + "─" * 78 + "┘")
        self.content.append("")
        
        self.content.append("📋 ОСНОВНАЯ ИНФОРМАЦИЯ")
        self.content.append("─" * 80)
        self.content.append(f"  Целевой домен:     {self.domain}")
        self.content.append(f"  Дата сканирования: {datetime.fromisoformat(self.scan_datetime).strftime('%d.%m.%Y')}")
        self.content.append(f"  Время сканирования: {datetime.fromisoformat(self.scan_datetime).strftime('%H:%M:%S')}")
        self.content.append("")
    
    def add_tools_info(self, executed_tools: list):
        """Добавить информацию об используемых инструментах"""
        self.content.append("🔧 ИСПОЛЬЗУЕМЫЕ ИНСТРУМЕНТЫ")
        self.content.append("─" * 80)
        
        if not executed_tools:
            self.content.append("  Инструменты не выполнены")
            self.content.append("")
            return
        
        all_tools = ['amass', 'subfinder', 'wayback']
        
        for tool in all_tools:
            info = self.tools_info.get(tool, {})
            status = "✓ ВЫПОЛНЕН" if tool in executed_tools else "✗ НЕ ВЫПОЛНЕН"
            
            self.content.append(f"")
            self.content.append(f"  [{status}] {info.get('name', tool.upper())}")
            self.content.append(f"      Тип: {info.get('type', 'Неизвестно')}")
            self.content.append(f"      Описание: {info.get('description', 'Нет описания')}")
        
        self.content.append("")
        self.content.append("")
    
    def add_section(self, tool_name: str, results: dict):
        """Добавить подробную секцию инструмента в отчет"""
        tool_info = self.tools_info.get(tool_name, {})
        
        self.content.append("┌" + "─" * 78 + "┐")
        self.content.append(f"│ {tool_info.get('name', tool_name.upper()):^76} │")
        self.content.append("└" + "─" * 78 + "┘")
        self.content.append("")
        
        if not results or results.get('status') == 'no_results':
            self.content.append("  ⚠️  Результатов не найдено")
            self.content.append("")
            return
        
        # Amass
        if tool_name == 'amass' and 'subdomains' in results:
            count = results.get('subdomains_count', 0)
            self.content.append(f"  📊 Статистика:")
            self.content.append(f"     • Найдено поддоменов: {count}")
            
            if results.get('subdomains'):
                self.content.append(f"  ")
                self.content.append(f"  📝 Результаты (показано максимум 50):")
                self.content.append(f"  {'-' * 76}")
                
                for i, subdomain in enumerate(results.get('subdomains', [])[:50], 1):
                    self.content.append(f"     {i:3d}. {subdomain}")
                
                if len(results.get('subdomains', [])) > 50:
                    remaining = len(results.get('subdomains', [])) - 50
                    self.content.append(f"     ... и еще {remaining} поддоменов")
        
        # Subfinder
        elif tool_name == 'subfinder' and 'subdomains' in results:
            count = results.get('subdomains_count', 0)
            self.content.append(f"  📊 Статистика:")
            self.content.append(f"     • Найдено поддоменов: {count}")
            
            if results.get('subdomains'):
                self.content.append(f"  ")
                self.content.append(f"  📝 Результаты (показано максимум 50):")
                self.content.append(f"  {'-' * 76}")
                
                for i, subdomain in enumerate(results.get('subdomains', [])[:50], 1):
                    self.content.append(f"     {i:3d}. {subdomain}")
                
                if len(results.get('subdomains', [])) > 50:
                    remaining = len(results.get('subdomains', [])) - 50
                    self.content.append(f"     ... и еще {remaining} поддоменов")
        
        # Wayback
        elif tool_name == 'wayback' and 'urls' in results:
            count = results.get('urls_count', 0)
            self.content.append(f"  📊 Статистика:")
            self.content.append(f"     • Найдено URL: {count}")
            
            if results.get('urls'):
                self.content.append(f"  ")
                self.content.append(f"  📝 Результаты (показано максимум 30):")
                self.content.append(f"  {'-' * 76}")
                
                for i, url in enumerate(results.get('urls', [])[:30], 1):
                    display_url = url[:70] + '...' if len(url) > 70 else url
                    self.content.append(f"     {i:3d}. {display_url}")
                
                if len(results.get('urls', [])) > 30:
                    remaining = len(results.get('urls', [])) - 30
                    self.content.append(f"     ... и еще {remaining} URL")
        
        self.content.append("")
        self.content.append("")
    
    def add_summary(self, statistics: dict, executed_tools: list):
        """Добавить итоговую сводку"""
        self.content.append("┌" + "─" * 78 + "┐")
        self.content.append("│" + " " * 28 + "ИТОГОВАЯ СВОДКА" + " " * 34 + "│")
        self.content.append("└" + "─" * 78 + "┘")
        self.content.append("")
        
        self.content.append(f"  📈 Общая статистика:")
        self.content.append(f"     • Выполненных инструментов: {len(executed_tools)}/4")
        self.content.append(f"     • Инструменты: {', '.join([t.upper() for t in executed_tools]) if executed_tools else 'Нет'}")
        self.content.append("")
        
        if statistics:
            self.content.append(f"  📊 Детальная статистика по инструментам:")
            for tool, count in sorted(statistics.items()):
                tool_name = self.tools_info.get(tool, {}).get('name', tool.upper())
                self.content.append(f"     • {tool_name:20s}: {count:6d} результатов")
        
        total_results = sum(statistics.values()) if statistics else 0
        self.content.append("")
        self.content.append(f"  ✅ ВСЕГО РЕЗУЛЬТАТОВ: {total_results}")
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

class Spinner:
    """Класс для анимации ожидания"""
    def __init__(self, message="Работаем"):
        self.spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.message = message
        self.running = False
        self.thread = None

    def spin(self):
        while self.running:
            for char in self.spinner:
                sys.stdout.write(f'\r{char} {self.message}...')
                sys.stdout.flush()
                time.sleep(0.1)
                if not self.running:
                    break

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.spin)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
        sys.stdout.write('\r' + ' ' * (len(self.message) + 10) + '\r')
        sys.stdout.flush()

def run_command_with_progress(command, progress_message):
    """Запускает команду с индикатором прогресса"""
    spinner = Spinner(progress_message)
    spinner.start()
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        spinner.stop()
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        spinner.stop()
        return "", str(e)

def count_lines_in_file(filename):
    """Подсчитывает количество строк в файле"""
    try:
        with open(filename, 'r') as f:
            return sum(1 for line in f if line.strip())
    except:
        return 0

def monitor_file_growth(filename, interval=2):
    """Мониторит рост файла и показывает прогресс"""
    if not os.path.exists(filename):
        return
    
    last_size = 0
    while True:
        try:
            current_lines = count_lines_in_file(filename)
            if current_lines > last_size:
                new_found = current_lines - last_size
                sys.stdout.write(f'\r  📊 Найдено {current_lines} результатов (+{new_found} новых)')
                sys.stdout.flush()
                last_size = current_lines
            time.sleep(interval)
        except KeyboardInterrupt:
            break

def run_command_with_live_output(command, output_file, progress_message):
    """Запускает команду и показывает живой прогресс"""
    spinner = Spinner(progress_message)
    spinner.start()
    
    # Запускаем процесс
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Читаем вывод построчно и сохраняем в файл
    with open(output_file, 'w') as f:
        line_count = 0
        last_update = time.time()
        
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                f.write(output)
                f.flush()
                line_count += 1
                
                # Обновляем счетчик каждые 0.5 секунды
                current_time = time.time()
                if current_time - last_update > 0.5:
                    sys.stdout.write(f'\r  📊 Найдено {line_count} результатов')
                    sys.stdout.flush()
                    last_update = current_time
    
    spinner.stop()
    return process.poll()

class AmassReport:
    """Класс для сбора данных Amass"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains = []
        self.results = {
            "scan_info": {"tool": "amass", "target": domain},
            "status": "pending",
            "subdomains": [],
            "subdomains_count": 0
        }
    
    def add_subdomain(self, subdomain: str):
        if subdomain not in self.subdomains:
            self.subdomains.append(subdomain)
    
    def get_json_report(self) -> dict:
        self.results['subdomains'] = self.subdomains
        self.results['subdomains_count'] = len(self.subdomains)
        self.results['status'] = 'completed' if self.subdomains else 'no_results'
        return self.results


class SubfinderReport:
    """Класс для сбора данных Subfinder"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains = []
        self.results = {
            "scan_info": {"tool": "subfinder", "target": domain},
            "status": "pending",
            "subdomains": [],
            "subdomains_count": 0
        }
    
    def add_subdomain(self, subdomain: str):
        if subdomain not in self.subdomains:
            self.subdomains.append(subdomain)
    
    def get_json_report(self) -> dict:
        self.results['subdomains'] = self.subdomains
        self.results['subdomains_count'] = len(self.subdomains)
        self.results['status'] = 'completed' if self.subdomains else 'no_results'
        return self.results


class WaybackReport:
    """Класс для сбора данных Wayback Machine"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.urls = []
        self.results = {
            "scan_info": {"tool": "wayback", "target": domain},
            "status": "pending",
            "urls": [],
            "urls_count": 0
        }
    
    def add_url(self, url: str):
        if url not in self.urls:
            self.urls.append(url)
    
    def get_json_report(self) -> dict:
        self.results['urls'] = self.urls
        self.results['urls_count'] = len(self.urls)
        self.results['status'] = 'completed' if self.urls else 'no_results'
        return self.results




def save_combined_json_report(domain: str, reports_base_dir: Path,
                              executed_tools: list, statistics: dict,
                              amass_report: 'AmassReport',
                              subfinder_report: 'SubfinderReport',
                              wayback_report: 'WaybackReport') -> str:
    """
    Сохраняет комбинированный JSON отчет со всеми результатами
    
    Args:
        domain: Целевой домен
        reports_base_dir: Базовая директория для отчетов
        executed_tools: Список выполненных инструментов
        statistics: Статистика результатов
        amass_report: Объект с результатами Amass
        subfinder_report: Объект с результатами Subfinder
        wayback_report: Объект с результатами Wayback
    
    Returns:
        Путь к сохраненному файлу
    """
    scan_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    combined_report = {
        "scan_info": {
            "tool": "osint_combined",
            "target": domain,
            "scan_datetime": datetime.now().isoformat(),
            "scan_timestamp": scan_time
        },
        "tools_executed": executed_tools,
        "statistics": {
            "executed_tools_count": len(executed_tools),
            "total_results": sum(statistics.values()),
            "results_by_tool": statistics
        },
        "results": {}
    }
    
    # Добавляем результаты каждого инструмента
    if 'amass' in executed_tools and amass_report.subdomains:
        combined_report['results']['amass'] = amass_report.get_json_report()
    
    if 'subfinder' in executed_tools and subfinder_report.subdomains:
        combined_report['results']['subfinder'] = subfinder_report.get_json_report()
    
    if 'wayback' in executed_tools and wayback_report.urls:
        combined_report['results']['wayback'] = wayback_report.get_json_report()
    
    # Сохраняем комбинированный отчет
    json_dir = reports_base_dir / "osint" / "json"
    json_dir.mkdir(parents=True, exist_ok=True)
    
    combined_json_path = json_dir / f"osint_combined_{domain}_{scan_time}.json"
    with open(combined_json_path, 'w', encoding='utf-8') as f:
        json.dump(combined_report, f, ensure_ascii=False, indent=2)
    
    print(f"[+] Комбинированный JSON отчет сохранен: {combined_json_path}")
    return str(combined_json_path)

def simple_scan(domain: str, reports_base_dir: Path = None, amass_profile: str = "standard_passive") -> dict:
    """
    Функция для OSINT сканирования домена
    Создает единый TXT отчет и JSON отчеты по всем инструментам
    
    Args:
        domain: Целевой домен
        reports_base_dir: Базовая директория для отчетов
        amass_profile: Профиль Amass (quick_passive, standard_passive, active_scan, aggressive)
    
    Returns:
        Dict с результатами и путями к отчетам
    """
    reports_base = Path(reports_base_dir) if reports_base_dir else Path(__file__).parent.parent / "reports"
    
    # Создаем папку osint если её нет
    osint_dir = reports_base / "osint"
    osint_dir.mkdir(parents=True, exist_ok=True)
    
    # Получаем параметры Amass из профиля
    amass_timeout = 300
    if get_amass_profile:
        try:
            profile = get_amass_profile(amass_profile)
            amass_timeout = profile.timeout
            print(f"[+] Используется профиль Amass: {profile.name} (режим: {profile.mode}, таймаут: {amass_timeout}s)")
        except Exception as e:
            print(f"[!] Ошибка при загрузке профиля Amass {amass_profile}: {e}. Используем стандартный таймаут.")
    
    print(f"\n[*] Запускаю OSINT сканирование для {domain} (профиль: {amass_profile})")
    print("=" * 80)
    
    # Инициализируем отчеты для каждого инструмента
    amass_report = AmassReport(domain)
    subfinder_report = SubfinderReport(domain)
    wayback_report = WaybackReport(domain)
    
    executed_tools = []
    statistics = {}
    scan_results = {}
    
    # Шаг 1: Amass
    print("\n[1/3] Запускаю Amass (поиск поддоменов)...")
    try:
        amass_cmd = f"amass enum -d {domain} -o /tmp/amass_results.txt 2>/dev/null"
        result = subprocess.run(amass_cmd, shell=True, capture_output=True, text=True, timeout=120)
        
        if os.path.exists('/tmp/amass_results.txt'):
            with open('/tmp/amass_results.txt', 'r') as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain:
                        amass_report.add_subdomain(subdomain)
            os.remove('/tmp/amass_results.txt')
        
        count = len(amass_report.subdomains)
        print(f"[✓] Amass: найдено {count} поддоменов")
        
        if count > 0:
            executed_tools.append('amass')
            statistics['amass'] = count
            scan_results['amass'] = {
                'status': 'completed',
                'count': count,
                'sample': amass_report.subdomains[:5]
            }
        else:
            scan_results['amass'] = {'status': 'no_results', 'count': 0}
    except Exception as e:
        print(f"[!] Ошибка Amass: {e}")
        scan_results['amass'] = {'status': 'error', 'error': str(e)}
    
    # Шаг 2: Subfinder
    print("[2/3] Запускаю Subfinder (поиск поддоменов)...")
    try:
        subfinder_cmd = f"subfinder -d {domain} -o /tmp/subfinder_results.txt 2>/dev/null"
        result = subprocess.run(subfinder_cmd, shell=True, capture_output=True, text=True, timeout=120)
        
        if os.path.exists('/tmp/subfinder_results.txt'):
            with open('/tmp/subfinder_results.txt', 'r') as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain:
                        subfinder_report.add_subdomain(subdomain)
            os.remove('/tmp/subfinder_results.txt')
        
        count = len(subfinder_report.subdomains)
        print(f"[✓] Subfinder: найдено {count} поддоменов")
        
        if count > 0:
            executed_tools.append('subfinder')
            statistics['subfinder'] = count
            scan_results['subfinder'] = {
                'status': 'completed',
                'count': count,
                'sample': subfinder_report.subdomains[:5]
            }
        else:
            scan_results['subfinder'] = {'status': 'no_results', 'count': 0}
    except Exception as e:
        print(f"[!] Ошибка Subfinder: {e}")
        scan_results['subfinder'] = {'status': 'error', 'error': str(e)}
    
    # Шаг 3: Wayback URLs
    print("[3/3] Запускаю Wayback Machine (поиск URL из архива)...")
    try:
        wayback_cmd = f"echo {domain} | waybackurls > /tmp/wayback_results.txt 2>/dev/null"
        result = subprocess.run(wayback_cmd, shell=True, capture_output=True, text=True, timeout=120)
        
        if os.path.exists('/tmp/wayback_results.txt'):
            with open('/tmp/wayback_results.txt', 'r') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        wayback_report.add_url(url)
            os.remove('/tmp/wayback_results.txt')
        
        count = len(wayback_report.urls)
        print(f"[✓] Wayback: найдено {count} URL")
        
        if count > 0:
            executed_tools.append('wayback')
            statistics['wayback'] = count
            scan_results['wayback'] = {
                'status': 'completed',
                'count': count,
                'sample': wayback_report.urls[:5]
            }
        else:
            scan_results['wayback'] = {'status': 'no_results', 'count': 0}
    except Exception as e:
        print(f"[!] Ошибка Wayback: {e}")
        scan_results['wayback'] = {'status': 'error', 'error': str(e)}
    
    # Сохраняем комбинированный JSON отчет
    print("\n[*] Создаю комбинированный JSON отчет...")
    combined_json_path = save_combined_json_report(domain, reports_base, executed_tools, 
                                                    statistics, amass_report, subfinder_report, wayback_report)
    
    # Создаем и сохраняем подробный TXT отчет
    print("[*] Создаю подробный TXT отчет...")
    text_report = OsintTextReport(domain, reports_base)
    text_report.add_header()
    text_report.add_tools_info(executed_tools)
    
    # Добавляем результаты каждого инструмента
    if 'amass' in executed_tools:
        text_report.add_section('amass', amass_report.get_json_report())
    
    if 'subfinder' in executed_tools:
        text_report.add_section('subfinder', subfinder_report.get_json_report())
    
    if 'wayback' in executed_tools:
        text_report.add_section('wayback', wayback_report.get_json_report())
    
    # Добавляем сводку
    text_report.add_summary(statistics, executed_tools)
    
    # Сохраняем TXT отчет
    txt_report_path = text_report.save()
    
    # Формируем финальный результат
    results = {
        'domain': domain,
        'scan_datetime': datetime.now().isoformat(),
        'tools_executed': executed_tools,
        'execution_status': scan_results,
        'statistics': {
            'executed_tools_count': len(executed_tools),
            'total_results': sum(statistics.values()),
            'results_by_tool': statistics
        },
        'reports': {
            'txt_report': txt_report_path,
            'json_report': combined_json_path
        },
        'report_location': str(osint_dir)
    }
    
    # Выводим итоговую информацию
    print("\n" + "=" * 80)
    print("[✓] OSINT сканирование завершено\n")
    print(f"  📊 Выполнено инструментов: {len(executed_tools)}/3")
    print(f"  📝 Используемые инструменты: {', '.join([t.upper() for t in executed_tools]) if executed_tools else 'нет'}")
    print(f"  📈 Всего найдено результатов: {sum(statistics.values())}")
    
    if statistics:
        print(f"\n  📋 Результаты по инструментам:")
        for tool, count in sorted(statistics.items()):
            tool_name = tool.upper()
            print(f"     • {tool_name:15s}: {count:6d} результатов")
    
    print(f"\n  💾 Отчеты сохранены:")
    print(f"     • TXT отчет (подробный): {txt_report_path}")
    print(f"     • JSON отчет (комбинированный): {combined_json_path}")
    
    print(f"\n  📁 Директория с отчетами: {osint_dir}\n")
    print("=" * 80 + "\n")
    
    return results

def main():
    # Обработка Ctrl+C
    def signal_handler(sig, frame):
        print("\n\n[!] Сканирование прервано пользователем")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    if len(sys.argv) != 2:
        print("Использование: python3 osint.py <domain>")
        print("Пример: python3 osint.py example.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    simple_scan(domain)

if __name__ == "__main__":
    main()