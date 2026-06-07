#!/usr/bin/env python3
"""
Автоматизация запуска retire.js для сканирования JavaScript библиотек
на предмет известных уязвимостей.
"""

import subprocess
import sys
import os
import json
import re
import time
from datetime import datetime
from pathlib import Path

# Импорт конфигурации сканеров
try:
    from scanner_config import get_retire_profile
except ImportError:
    get_retire_profile = None


class RetireScanner:
    def __init__(self, target_url, output_dir="scan_results", reports_dir=None, retire_profile="all_except_low"):
        self.target_url = target_url.rstrip('/')
        self.output_dir = output_dir
        self.retire_profile = retire_profile
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.scan_datetime = datetime.now().isoformat()
        self.scan_start_time = datetime.now()
        self.results = {}

        # Отслеживание информации об инструменте
        self.tools_info = {
            'retire': {'status': 'not_run', 'params': {}, 'start_time': None, 'end_time': None, 'count': 0}
        }

        # Настройка директорий для отчетов
        if reports_dir is None:
            reports_dir = Path(__file__).parent.parent / "reports"
        else:
            reports_dir = Path(reports_dir)

        self.retire_reports_dir = reports_dir / "retire"
        self.json_dir = self.retire_reports_dir / "json"
        self.txt_dir = self.retire_reports_dir / "txt"

        # Создаем директории
        for directory in [self.json_dir, self.txt_dir]:
            directory.mkdir(parents=True, exist_ok=True)

        # Filename base для отчетов
        safe_target = target_url.replace(
            '/', '_').replace(':', '_').replace('.', '_').replace('?', '_')
        self.filename_base = f"retire_{safe_target}_{self.timestamp}"

        # Создаем директорию для результатов если нужна
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def download_js_files(self):
        """Скачивание JS файлов с целевого сайта"""
        print(f"\n[+] Загрузка JS файлов с {self.target_url}")
        
        js_dir = f"{self.output_dir}/js_files_{self.timestamp}"
        
        try:
            # Используем wget или curl для скачивания JS файлов
            cmd = [
                "wget",
                "-r",  # рекурсивно
                "-A", "*.js",  # только JS файлы
                "--accept-regex", ".*\\.js$",
                "-P", js_dir,  # директория для сохранения
                "-q",  # тихий режим
                "-np",  # не идти на уровень выше
                self.target_url
            ]
            
            print(f"[*] Команда: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode == 0 or os.path.isdir(js_dir):
                print(f"[+] JS файлы загружены в {js_dir}")
                return js_dir
            else:
                print(f"[-] Ошибка при загрузке JS файлов: {stderr}")
                return None
                
        except FileNotFoundError:
            print("[-] wget не найден. Попытка использовать curl...")
            try:
                # Альтернатива с curl
                cmd = [
                    "curl",
                    "-r", "0-",
                    "-o", f"{js_dir}/index.html",
                    self.target_url
                ]
                result = subprocess.run(cmd, capture_output=True)
                if result.returncode == 0:
                    return js_dir
            except FileNotFoundError:
                print("[-] curl не найден. Невозможно скачать файлы.")
                return None
        except Exception as e:
            print(f"[-] Ошибка при загрузке файлов: {e}")
            return None

    def run_retire(self, include_js=True, severity_filter=None, proxy=None):
        """
        Запуск Retire.js для сканирования JavaScript библиотек

        Аргументы:
            include_js: bool - сканировать JS файлы на сайте
            severity_filter: str - фильтр по серьезности (critical, high, medium, low)
            proxy: str - прокси для запросов
        """
        print(f"\n[+] Запуск Retire для {self.target_url}")

        tool_start = datetime.now()
        self.tools_info['retire']['start_time'] = tool_start.isoformat()

        output_file = f"{self.output_dir}/retire_{self.timestamp}.json"

        try:
            # Сначала загружаем JS файлы с сайта
            scan_dir = self.download_js_files()
            
            if not scan_dir:
                print("[-] Ошибка: не удалось загрузить JS файлы")
                self.tools_info['retire']['status'] = 'error'
                self.tools_info['retire']['error'] = 'Failed to download JS files'
                return

            # Базовые параметры Retire (правильный синтаксис)
            cmd = [
                "retire",
                "--jspath", scan_dir,  # путь к директории для сканирования
                "--outputformat", "json",
                "--output", output_file
            ]

            # Сохраняем параметры Retire
            retire_params = {
                'url': self.target_url,
                'output_format': 'json',
                'scan_js': include_js,
                'severity_filter': severity_filter,
                'mode': 'vulnerability_scan'
            }

            # Добавляем опции в зависимости от параметров
            if proxy:
                cmd.extend(["--proxy", proxy])
                print(f"[+] Используется прокси: {proxy}")

            if not include_js:
                print("[+] JS файлы не будут сканироваться")

            print(f"[*] Команда Retire: {' '.join(cmd)}")

            # Запуск процесса
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate()

            # Логирование вывода для отладки
            if stdout:
                print(f"[*] Retire stdout: {stdout[:300]}")
            if stderr:
                print(f"[*] Retire stderr: {stderr[:300]}")

            # Retire может возвращать 1 если найдены уязвимости
            if process.returncode in [0, 1]:
                print(f"[+] Retire завершен. Результаты сохранены в {output_file}")

                # Подсчет количества найденных уязвимостей
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r', encoding='utf-8') as f:
                            results_data = json.load(f)
                        
                        # Подсчет уязвимостей
                        vulnerability_count = 0
                        if isinstance(results_data, list):
                            vulnerability_count = len(results_data)
                        elif isinstance(results_data, dict):
                            if 'data' in results_data:
                                data = results_data['data']
                                if isinstance(data, list):
                                    for item in data:
                                        if 'vulnerabilities' in item:
                                            vulnerability_count += len(item['vulnerabilities'])
                            elif 'vulnerabilities' in results_data:
                                vulnerability_count = len(results_data['vulnerabilities'])
                        
                        self.tools_info['retire']['count'] = vulnerability_count
                        self.tools_info['retire']['status'] = 'completed'
                        print(f"[+] Найдено уязвимостей: {vulnerability_count}")
                    except json.JSONDecodeError:
                        print("[-] Ошибка при парсинге JSON результатов")
                        self.tools_info['retire']['status'] = 'error'
                        self.tools_info['retire']['error'] = 'Invalid JSON output'
                else:
                    print("[-] Файл результатов не создан")
                    self.tools_info['retire']['status'] = 'error'
                    self.tools_info['retire']['error'] = 'Output file not created'

                self.results['retire'] = output_file
                self.tools_info['retire']['params'] = retire_params
            else:
                print(f"[-] Ошибка Retire (код {process.returncode}): {stderr}")
                self.tools_info['retire']['status'] = 'error'
                self.tools_info['retire']['error'] = f"Return code: {process.returncode}, Error: {stderr}"

        except FileNotFoundError:
            print("[-] Retire не найден. Убедитесь, что он установлен.")
            print("[*] Установка: npm install -g retire")
            self.tools_info['retire']['status'] = 'not_found'
            self.tools_info['retire']['error'] = 'Tool not found'
        except Exception as e:
            print(f"[-] Ошибка при запуске Retire: {e}")
            self.tools_info['retire']['status'] = 'error'
            self.tools_info['retire']['error'] = str(e)
        finally:
            tool_end = datetime.now()
            self.tools_info['retire']['end_time'] = tool_end.isoformat()
            duration = (tool_end - tool_start).total_seconds()
            self.tools_info['retire']['duration_seconds'] = duration

    def save_json_report(self, data):
        """Сохранить JSON отчет в reports/retire/json"""
        json_path = self.json_dir / f"{self.filename_base}.json"

        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"✓ JSON отчет сохранен: {json_path}")
        return str(json_path)

    def save_txt_report(self, content):
        """Сохранить TXT отчет в reports/retire/txt"""
        txt_path = self.txt_dir / f"{self.filename_base}.txt"

        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"✓ TXT отчет сохранен: {txt_path}")
        return str(txt_path)

    def run_all(self, include_js=True, severity_filter=None, proxy=None):
        """Запуск сканирования"""
        print(f"\n{'='*50}")
        print(f"Начало сканирования Retire: {self.target_url}")
        print(f"Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Директория результатов: {self.output_dir}")
        print(f"{'='*50}\n")

        # Запускаем Retire
        self.run_retire(
            include_js=include_js,
            severity_filter=severity_filter,
            proxy=proxy
        )

        # Генерируем итоговый отчет
        self.generate_report()

    def generate_report(self):
        """Генерация итогового отчета в JSON и TXT форматах"""

        # Собираем данные для отчета
        vulnerabilities = []
        libraries = []

        # Читаем результаты из файла результатов Retire
        if 'retire' in self.results and os.path.exists(self.results['retire']):
            try:
                with open(self.results['retire'], 'r', encoding='utf-8') as f:
                    retire_output = json.load(f)
                
                # Парсим результаты в зависимости от формата вывода
                if isinstance(retire_output, list):
                    vulnerabilities = retire_output
                elif isinstance(retire_output, dict):
                    if 'data' in retire_output:
                        data = retire_output['data']
                        if isinstance(data, list):
                            for item in data:
                                if 'vulnerabilities' in item:
                                    lib_info = {
                                        'name': item.get('name', 'Unknown'),
                                        'version': item.get('version', 'Unknown'),
                                        'vulnerabilities': item['vulnerabilities']
                                    }
                                    libraries.append(lib_info)
                                    vulnerabilities.extend(item['vulnerabilities'])
                    else:
                        vulnerabilities = retire_output

            except json.JSONDecodeError:
                print("[-] Ошибка при чтении JSON результатов")
            except Exception as e:
                print(f"[-] Ошибка при парсинге результатов: {e}")

        # Расчет времени сканирования
        scan_end_time = datetime.now()
        total_scan_duration = (
            scan_end_time - self.scan_start_time).total_seconds()

        # Подсчет уязвимостей по серьезности
        severity_summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                severity = vuln.get('severity', 'low').lower()
                if severity in severity_summary:
                    severity_summary[severity] += 1
                else:
                    severity_summary['low'] += 1

        # Создаем JSON отчет с подробной информацией
        json_report = {
            'metadata': {
                'report_version': '1.0',
                'report_type': 'retire_scanner',
                'generated_at': datetime.now().isoformat()
            },
            'scan_info': {
                'target_url': self.target_url,
                'scan_start_time': self.scan_datetime,
                'scan_end_time': scan_end_time.isoformat(),
                'total_duration_seconds': total_scan_duration,
                'scanner_version': '1.0'
            },
            'tools': self.tools_info,
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'total_libraries': len(libraries),
                'by_severity': severity_summary
            },
            'libraries': libraries,
            'vulnerabilities': vulnerabilities
        }

        # Сохраняем JSON отчет
        json_path = self.save_json_report(json_report)

        # Создаем TXT отчет
        txt_content = self._generate_txt_report(
            vulnerabilities, libraries, severity_summary, total_scan_duration)
        txt_path = self.save_txt_report(txt_content)

        # Выводим сводку
        print("\n" + "="*50)
        print("СВОДКА РЕЗУЛЬТАТОВ RETIRE СКАНИРОВАНИЯ:")
        print("="*50)
        print(f"  ВСЕГО УЯЗВИМОСТЕЙ: {len(vulnerabilities)}")
        print(f"  ВСЕГО БИБЛИОТЕК: {len(libraries)}")
        print(f"  КРИТИЧЕСКИХ: {severity_summary['critical']}")
        print(f"  ВЫСОКИХ: {severity_summary['high']}")
        print(f"  СРЕДНИХ: {severity_summary['medium']}")
        print(f"  НИЗКИХ: {severity_summary['low']}")
        print(f"  ВРЕМЯ СКАНИРОВАНИЯ: {total_scan_duration:.2f} сек")
        print("="*50)
        print(f"JSON отчет: {json_path}")
        print(f"TXT отчет: {txt_path}")
        print("="*50)

        return {
            'json': json_path,
            'txt': txt_path,
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'total_libraries': len(libraries),
                'by_severity': severity_summary
            }
        }

    def _generate_txt_report(self, vulnerabilities, libraries, severity_summary, total_duration):
        """Генерировать содержимое TXT отчета с подробной информацией"""
        lines = []

        # Заголовок
        lines.append("=" * 80)
        lines.append("RETIRE.JS REPORT - JAVASCRIPT VULNERABILITIES SCAN")
        lines.append("=" * 80)
        lines.append("")

        # Информация о сканировании
        lines.append("SCAN INFORMATION")
        lines.append("-" * 80)
        lines.append(f"Target URL:        {self.target_url}")
        lines.append(f"Scan Date:         {datetime.fromisoformat(self.scan_datetime).strftime('%Y-%m-%d')}")
        lines.append(f"Scan Time:         {datetime.fromisoformat(self.scan_datetime).strftime('%H:%M:%S')}")
        lines.append(f"Duration:          {total_duration:.2f} seconds")
        lines.append(f"Scanner Version:   1.0")
        lines.append("")

        # Статус инструмента
        lines.append("TOOL STATUS")
        lines.append("-" * 80)
        tool_info = self.tools_info['retire']
        status_map = {
            'completed': 'COMPLETED',
            'error': 'ERROR',
            'not_found': 'NOT FOUND',
            'not_run': 'NOT RUN'
        }
        status_text = status_map.get(tool_info['status'], tool_info['status'].upper())
        duration = tool_info.get('duration_seconds', 0)
        count = tool_info.get('count', 0)

        lines.append(f"Status:            {status_text}")
        lines.append(f"Vulnerabilities:   {count}")
        lines.append(f"Execution Time:    {duration:.2f} seconds")
        lines.append("")

        if tool_info.get('params'):
            lines.append("Parameters:")
            for param, value in tool_info['params'].items():
                lines.append(f"  - {param}: {value}")
            lines.append("")

        if tool_info['status'] == 'error' and tool_info.get('error'):
            lines.append(f"Error: {tool_info['error']}")
            lines.append("")

        # Результаты сканирования
        lines.append("SCAN RESULTS SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Total Vulnerabilities:  {len(vulnerabilities)}")
        lines.append(f"Total Libraries:        {len(libraries)}")
        lines.append("")

        if len(vulnerabilities) > 0:
            lines.append("Severity Breakdown:")
            lines.append(f"  Critical:  {severity_summary['critical']}")
            lines.append(f"  High:      {severity_summary['high']}")
            lines.append(f"  Medium:    {severity_summary['medium']}")
            lines.append(f"  Low:       {severity_summary['low']}")
            lines.append("")

        # Список библиотек с уязвимостями
        if libraries:
            lines.append("DETECTED LIBRARIES WITH VULNERABILITIES")
            lines.append("-" * 80)
            
            for lib in libraries[:30]:
                lib_name = lib.get('name', 'Unknown')
                lib_version = lib.get('version', 'Unknown')
                vuln_count = len(lib.get('vulnerabilities', []))
                
                lines.append(f"\n{lib_name} ({lib_version})")
                lines.append(f"  Vulnerabilities: {vuln_count}")
                
                for i, vuln in enumerate(lib.get('vulnerabilities', [])[:3], 1):
                    if isinstance(vuln, dict):
                        vuln_id = vuln.get('id', 'N/A')
                        severity = vuln.get('severity', 'unknown').upper()
                        info = vuln.get('info', 'No description')[:70]
                        lines.append(f"    {i}. [{severity}] {vuln_id}: {info}")
                
                if len(lib.get('vulnerabilities', [])) > 3:
                    lines.append(f"    ... and {len(lib.get('vulnerabilities', [])) - 3} more")
            
            if len(libraries) > 30:
                lines.append(f"\n... and {len(libraries) - 30} more libraries")
            lines.append("")

        # Детальный список уязвимостей по серьезности
        if vulnerabilities:
            lines.append("DETAILED VULNERABILITIES")
            lines.append("-" * 80)
            
            # Сортируем по серьезности
            critical = [v for v in vulnerabilities if isinstance(v, dict) and v.get('severity', '').lower() == 'critical']
            high = [v for v in vulnerabilities if isinstance(v, dict) and v.get('severity', '').lower() == 'high']
            medium = [v for v in vulnerabilities if isinstance(v, dict) and v.get('severity', '').lower() == 'medium']
            low = [v for v in vulnerabilities if isinstance(v, dict) and v.get('severity', '').lower() == 'low']

            # Критические
            if critical:
                lines.append(f"\nCRITICAL ({len(critical)}):")
                for i, vuln in enumerate(critical[:5], 1):
                    vuln_id = vuln.get('id', 'N/A')
                    info = vuln.get('info', 'No description')
                    lines.append(f"  {i}. {vuln_id}: {info}")
                if len(critical) > 5:
                    lines.append(f"  ... and {len(critical) - 5} more")

            # Высокие
            if high:
                lines.append(f"\nHIGH ({len(high)}):")
                for i, vuln in enumerate(high[:5], 1):
                    vuln_id = vuln.get('id', 'N/A')
                    info = vuln.get('info', 'No description')
                    lines.append(f"  {i}. {vuln_id}: {info}")
                if len(high) > 5:
                    lines.append(f"  ... and {len(high) - 5} more")

            # Средние
            if medium:
                lines.append(f"\nMEDIUM ({len(medium)}):")
                for i, vuln in enumerate(medium[:3], 1):
                    vuln_id = vuln.get('id', 'N/A')
                    info = vuln.get('info', 'No description')
                    lines.append(f"  {i}. {vuln_id}: {info}")
                if len(medium) > 3:
                    lines.append(f"  ... and {len(medium) - 3} more")

        # Завершение
        lines.append("\n" + "=" * 80)
        lines.append(f"Report Generated: {datetime.fromisoformat(self.scan_datetime).strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 80)

        return "\n".join(lines)


def simple_scan(target_url, reports_dir=None, retire_profile="all_except_low"):
    """Функция для запуска retire сканирования из API"""
    try:
        print(f"[*] Запуск Retire сканирования для {target_url} (профиль: {retire_profile})")

        # Получаем параметры из профиля
        severity_filter = None
        include_js = True
        
        if get_retire_profile:
            try:
                profile = get_retire_profile(retire_profile)
                severity_filter = profile.severity_filter
                include_js = profile.include_js
                print(f"[+] Используется профиль: {profile.name}")
            except Exception as e:
                print(f"[!] Ошибка при загрузке профиля {retire_profile}: {e}. Используем стандартные параметры.")

        # Создаем сканер
        scanner = RetireScanner(
            target_url, output_dir="/tmp/retire_scan", reports_dir=reports_dir, retire_profile=retire_profile)

        # Запускаем сканирование
        scanner.run_all(include_js=include_js, severity_filter=severity_filter, proxy=None)

        # Возвращаем результаты
        report_result = scanner.generate_report()
        return {
            'status': 'completed',
            'target_url': target_url,
            'retire_profile': retire_profile,
            'severity_filter': severity_filter,
            'reports': report_result
        }

    except Exception as e:
        print(f"[-] Ошибка при сканировании: {e}")
        return {
            'status': 'error',
            'target_url': target_url,
            'error': str(e)
        }


def check_dependencies():
    """Проверка наличия необходимых инструментов"""
    print("\n" + "="*60)
    print("Проверка зависимостей...")
    print("="*60)

    try:
        result = subprocess.run(
            ["retire", "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        if result.returncode == 0 or "retire" in result.stdout.lower() or "retire" in result.stderr.lower():
            print("[+] Retire найден ✓")
            return True
    except FileNotFoundError:
        print("[-] Retire не найден ✗")
    except Exception as e:
        print(f"[-] Ошибка при проверке retire: {e}")

    print("\n[!] Retire не установлен!")
    print("\nРекомендации по установке:")
    print("  npm install -g retire")
    print("\nДля использования с прокси:")
    print("  retire --proxy http://proxy:port")

    response = input("\nПродолжить без Retire? (y/n): ")
    return response.lower() == 'y'


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Автоматизация запуска retire.js для сканирования JS уязвимостей")
    parser.add_argument("-u", "--url", required=True,
                        help="Целевой URL (например, https://example.com)")
    parser.add_argument("-s", "--severity", choices=['critical', 'high', 'medium', 'low'],
                        help="Фильтр по серьезности")
    parser.add_argument("-p", "--proxy",
                        help="Прокси для запросов (например, http://proxy:8080)")
    parser.add_argument("-o", "--output", default="scan_results",
                        help="Директория для результатов")
    parser.add_argument("--skip-checks", action="store_true",
                        help="Пропустить проверку зависимостей")

    args = parser.parse_args()

    # Проверка зависимостей
    if not args.skip_checks:
        if not check_dependencies():
            print("Сканирование отменено.")
            sys.exit(1)

    # Создаем экземпляр сканера
    scanner = RetireScanner(args.url, args.output)

    # Запускаем сканирование
    scanner.run_all(
        include_js=True,
        severity_filter=args.severity,
        proxy=args.proxy
    )


if __name__ == "__main__":
    main()
