#!/usr/bin/env python3
"""
Автоматизация запуска инструментов для веб-разведки:
- Katana (сканирование URL)
- JSFinder от hellouuuser (поиск URL и поддоменов в JS файлах)
- Gobuster (перебор директорий)
"""

import subprocess
import sys
import os
import argparse
import json
from datetime import datetime
import threading
import time
from pathlib import Path
import re


class WebScanner:
    def __init__(self, target_url, output_dir="scan_results", reports_dir=None):
        self.target_url = target_url.rstrip('/')
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.scan_datetime = datetime.now().isoformat()
        self.scan_start_time = datetime.now()
        self.results = {}

        # Отслеживание информации об инструментах
        self.tools_info = {
            'katana': {'status': 'not_run', 'params': {}, 'start_time': None, 'end_time': None, 'count': 0},
            'jsfinder_urls': {'status': 'not_run', 'params': {}, 'start_time': None, 'end_time': None, 'count': 0},
            'jsfinder_subdomains': {'status': 'not_run', 'params': {}, 'start_time': None, 'end_time': None, 'count': 0},
            'gobuster': {'status': 'not_run', 'params': {}, 'start_time': None, 'end_time': None, 'count': 0}
        }

        # Настройка директорий для отчетов
        if reports_dir is None:
            reports_dir = Path(__file__).parent.parent / "reports"
        else:
            reports_dir = Path(reports_dir)

        self.web_reports_dir = reports_dir / "web"
        self.json_dir = self.web_reports_dir / "json"
        self.txt_dir = self.web_reports_dir / "txt"

        # Создаем директории
        for directory in [self.json_dir, self.txt_dir]:
            directory.mkdir(parents=True, exist_ok=True)

        # Filename base для отчетов
        safe_target = target_url.replace(
            '/', '_').replace(':', '_').replace('.', '_').replace('?', '_')
        self.filename_base = f"web_{safe_target}_{self.timestamp}"

        # Создаем директорию для результатов если нужна
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def run_katana(self):
        """Запуск Katana для сканирования URL"""
        print(f"\n[+] Запуск Katana для {self.target_url}")

        tool_start = datetime.now()
        self.tools_info['katana']['start_time'] = tool_start.isoformat()

        output_file = f"{self.output_dir}/katana_{self.timestamp}.txt"

        try:
            # Базовые параметры Katana (без -fs и -silent которые могут не работать)
            cmd = [
                "katana",
                "-u", self.target_url,
                "-o", output_file,
                "-d", "3",  # глубина сканирования
                "-c", "50"  # количество одновременных запросов
            ]

            # Сохраняем параметры Katana
            self.tools_info['katana']['params'] = {
                'url': self.target_url,
                'depth': '3',
                'concurrency': '50',
                'mode': 'crawl'
            }

            print(f"[*] Команда Katana: {' '.join(cmd)}")

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
                print(f"[*] Katana stdout: {stdout[:200]}")
            if stderr:
                print(f"[*] Katana stderr: {stderr[:200]}")

            if process.returncode == 0:
                print(
                    f"[+] Katana завершен. Результаты сохранены в {output_file}")

                # Подсчет количества найденных URL
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        urls = f.readlines()
                    urls_clean = [u.strip() for u in urls if u.strip()]
                    print(f"[+] Найдено URL: {len(urls_clean)}")

                    self.tools_info['katana']['count'] = len(urls_clean)
                    self.tools_info['katana']['status'] = 'completed'
                else:
                    print(f"[-] Файл результатов не найден: {output_file}")
                    self.tools_info['katana']['count'] = 0
                    self.tools_info['katana']['status'] = 'error'
                    self.tools_info['katana']['error'] = 'Output file not created'
                    return

                self.results['katana'] = output_file
            else:
                print(
                    f"[-] Ошибка Katana (код {process.returncode}): {stderr}")
                self.tools_info['katana']['status'] = 'error'
                self.tools_info['katana']['error'] = f"Return code: {process.returncode}, Error: {stderr}"

        except FileNotFoundError:
            print("[-] Katana не найден. Убедитесь, что он установлен.")
            self.tools_info['katana']['status'] = 'not_found'
            self.tools_info['katana']['error'] = 'Tool not found'
        except Exception as e:
            print(f"[-] Ошибка при запуске Katana: {e}")
            self.tools_info['katana']['status'] = 'error'
            self.tools_info['katana']['error'] = str(e)
        finally:
            tool_end = datetime.now()
            self.tools_info['katana']['end_time'] = tool_end.isoformat()
            duration = (tool_end - tool_start).total_seconds()
            self.tools_info['katana']['duration_seconds'] = duration

    def run_jsfinder(self, deep_scan=False, cookie=None):
        """
        Запуск JSFinder от hellouuuser для поиска URL и поддоменов в JS файлах

        Аргументы:
            deep_scan: bool - выполнять глубокое сканирование (переход по ссылкам)
            cookie: str - cookie для авторизации
        """
        print(f"\n[+] Запуск JSFinder (hellouuuser) для {self.target_url}")

        tool_start_urls = datetime.now()
        self.tools_info['jsfinder_urls']['start_time'] = tool_start_urls.isoformat()
        self.tools_info['jsfinder_subdomains']['start_time'] = tool_start_urls.isoformat()

        # Проверяем наличие JSFinder.py
        jsfinder_path = self.find_jsfinder()
        if not jsfinder_path:
            print(
                "[-] JSFinder.py не найден. Убедитесь, что он находится по пути ../tools/jsfinder/JSFinder.py")
            self.tools_info['jsfinder_urls']['status'] = 'not_found'
            self.tools_info['jsfinder_urls']['error'] = 'JSFinder tool not found'
            self.tools_info['jsfinder_subdomains']['status'] = 'not_found'
            self.tools_info['jsfinder_subdomains']['error'] = 'JSFinder tool not found'
            return

        # Файлы для результатов
        url_output = f"{self.output_dir}/jsfinder_urls_{self.timestamp}.txt"
        subdomain_output = f"{self.output_dir}/jsfinder_subdomains_{self.timestamp}.txt"

        try:
            # Базовые параметры JSFinder
            cmd = [
                sys.executable,  # используем тот же интерпретатор Python
                jsfinder_path,
                "-u", self.target_url
            ]

            # Сохраняем параметры JSFinder
            jsfinder_params = {
                'url': self.target_url,
                'deep_scan': deep_scan,
                'authentication': 'yes' if cookie else 'no',
                'mode': 'js_analysis'
            }

            # Добавляем опции в зависимости от параметров
            if deep_scan:
                cmd.append("-d")
                print("[+] Включен режим глубокого сканирования")

            if cookie:
                cmd.extend(["-c", cookie])
                print("[+] Используются cookies")

            # ВАЖНО: Не используем параметры -ou и -os так как они могут не поддерживаться
            # Вместо этого будем парсить stdout

            print(f"[*] Команда JSFinder: {' '.join(cmd)}")

            # Запуск процесса и捕获 вывод
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Строчный буфер для实时ного вывода
            )

            # Сбор вывода
            stdout_lines = []
            stderr_lines = []

            # Читаем stdout построчно в реальном времени
            for line in process.stdout:
                line = line.strip()
                if line:
                    print(f"  [JSFinder] {line}")
                    stdout_lines.append(line)

            # Читаем stderr
            for line in process.stderr:
                line = line.strip()
                if line:
                    print(f"  [JSFinder Error] {line}")
                    stderr_lines.append(line)

            # Ждем завершения процесса
            process.wait()

            # Объединяем весь вывод
            stdout = '\n'.join(stdout_lines)
            stderr = '\n'.join(stderr_lines)

            print(f"\n[*] JSFinder завершен с кодом: {process.returncode}")

            if process.returncode == 0 or process.returncode == 1:  # Некоторые версии возвращают 1 при успехе
                print(f"[+] JSFinder завершен успешно")

                # Парсим результаты из stdout
                urls = []
                subdomains = []

                # Регулярные выражения для поиска URL и поддоменов
                url_pattern = re.compile(r'https?://[^\s\'"<>]+')
                subdomain_pattern = re.compile(
                    r'[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}')

                for line in stdout_lines:
                    # Ищем URL
                    found_urls = url_pattern.findall(line)
                    for url in found_urls:
                        if url not in urls:
                            urls.append(url)

                    # Ищем поддомены (исключая полные URL)
                    if 'http' not in line:
                        found_subdomains = subdomain_pattern.findall(line)
                        for sub in found_subdomains:
                            if sub not in subdomains and '.' in sub and len(sub) > 3:
                                subdomains.append(sub)

                # Также ищем в строках, которые могут быть прямыми результатами
                for line in stdout_lines:
                    # Если строка похожа на URL или поддомен
                    if '://' in line or line.startswith('www.') or ('.' in line and ' ' not in line):
                        if '://' in line and line not in urls:
                            urls.append(line)
                        elif line not in subdomains and line not in urls:
                            subdomains.append(line)

                # Сохраняем URL в файл
                if urls:
                    with open(url_output, 'w') as f:
                        for url in urls:
                            f.write(f"{url}\n")
                    print(f"[+] Найдено URL: {len(urls)}")
                    print(f"[+] URL сохранены в {url_output}")
                    self.tools_info['jsfinder_urls']['count'] = len(urls)
                    self.tools_info['jsfinder_urls']['status'] = 'completed'
                    self.results['jsfinder_urls'] = url_output

                    # Выводим первые несколько URL
                    print("\n[+] Пример найденных URL:")
                    for url in urls[:5]:
                        print(f"    {url}")
                else:
                    print("[-] URL не найдены")
                    self.tools_info['jsfinder_urls']['count'] = 0
                    self.tools_info['jsfinder_urls']['status'] = 'completed'

                # Сохраняем поддомены в файл
                if subdomains:
                    with open(subdomain_output, 'w') as f:
                        for sub in subdomains:
                            f.write(f"{sub}\n")
                    print(f"[+] Найдено поддоменов: {len(subdomains)}")
                    print(f"[+] Поддомены сохранены в {subdomain_output}")
                    self.tools_info['jsfinder_subdomains']['count'] = len(
                        subdomains)
                    self.tools_info['jsfinder_subdomains']['status'] = 'completed'
                    self.results['jsfinder_subdomains'] = subdomain_output

                    # Выводим первые несколько поддоменов
                    print("\n[+] Пример найденных поддоменов:")
                    for sub in subdomains[:5]:
                        print(f"    {sub}")
                else:
                    print("[-] Поддомены не найдены")
                    self.tools_info['jsfinder_subdomains']['count'] = 0
                    self.tools_info['jsfinder_subdomains']['status'] = 'completed'

                # Сохраняем параметры
                self.tools_info['jsfinder_urls']['params'] = jsfinder_params
                self.tools_info['jsfinder_subdomains']['params'] = jsfinder_params

            else:
                print(f"[-] Ошибка JSFinder (код {process.returncode})")
                if stderr_lines:
                    print(f"[-] Ошибка: {stderr_lines[-1]}")
                if stdout_lines:
                    print(f"[*] Вывод: {stdout_lines[-1]}")

                self.tools_info['jsfinder_urls']['status'] = 'error'
                self.tools_info['jsfinder_urls']['error'] = f"Return code: {process.returncode}"
                self.tools_info['jsfinder_subdomains']['status'] = 'error'
                self.tools_info['jsfinder_subdomains'][
                    'error'] = f"Return code: {process.returncode}"

        except Exception as e:
            print(f"[-] Ошибка при запуске JSFinder: {e}")
            self.tools_info['jsfinder_urls']['status'] = 'error'
            self.tools_info['jsfinder_urls']['error'] = str(e)
            self.tools_info['jsfinder_subdomains']['status'] = 'error'
            self.tools_info['jsfinder_subdomains']['error'] = str(e)
        finally:
            tool_end_urls = datetime.now()
            self.tools_info['jsfinder_urls']['end_time'] = tool_end_urls.isoformat()
            self.tools_info['jsfinder_subdomains']['end_time'] = tool_end_urls.isoformat(
            )
            duration = (tool_end_urls - tool_start_urls).total_seconds()
            self.tools_info['jsfinder_urls']['duration_seconds'] = duration
            self.tools_info['jsfinder_subdomains']['duration_seconds'] = duration

    def find_jsfinder(self):
        """Поиск JSFinder.py с абсолютным путем к ../tools/jsfinder/JSFinder.py"""
        # Используем абсолютный путь от скрипта
        script_dir = Path(__file__).parent
        jsfinder_path = script_dir.parent / "tools" / "jsfinder" / "JSFinder.py"

        print(f"[*] Ищу JSFinder по пути: {jsfinder_path}")

        if jsfinder_path.is_file():
            print(f"[+] JSFinder найден: {jsfinder_path}")
            return str(jsfinder_path)

        # Если не нашли, пробуем альтернативные пути
        alt_paths = [
            script_dir.parent / "tools" / "JSFinder.py",
            Path("../tools/jsfinder/JSFinder.py").resolve(),
            Path("./JSFinder.py").resolve(),
        ]

        for path in alt_paths:
            abs_path = path.resolve()
            print(f"[*] Проверяю альтернативный путь: {abs_path}")
            if abs_path.is_file():
                print(f"[+] JSFinder найден: {abs_path}")
                return str(abs_path)

        print("[-] JSFinder не найден!")
        return None

    def run_gobuster(self, wordlist=None):
        """Запуск Gobuster для перебора директорий"""
        print(f"\n[+] Запуск Gobuster для {self.target_url}")

        tool_start = datetime.now()
        self.tools_info['gobuster']['start_time'] = tool_start.isoformat()

        # Стандартный путь к словарю, если не указан
        if wordlist is None:
            # Ищем common.txt в стандартных местах
            script_dir = Path(__file__).parent
            possible_paths = [
                script_dir / "wordlists" / "common.txt",  # в папке wordlists рядом со скриптом
                script_dir / "../wordlists/common.txt",   # на уровень выше
                # системный путь для Kali/Linux
                Path("/usr/share/wordlists/dirb/common.txt"),
                # альтернативный
                Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
                # SecLists
                Path("/usr/share/seclists/Discovery/Web-Content/common.txt")
            ]

            wordlist_path = None
            for path in possible_paths:
                resolved_path = path.resolve()
                if resolved_path.exists():
                    wordlist_path = str(resolved_path)
                    print(f"[+] Найден словарь: {wordlist_path}")
                    break

            if wordlist_path is None:
                print("[-] Словарь common.txt не найден!")
                print(
                    "[*] Попробуйте указать путь вручную: --wordlist /path/to/wordlist.txt")
                print("[*] Или установите SecLists: sudo apt install seclists")
                self.tools_info['gobuster']['status'] = 'error'
                self.tools_info['gobuster']['error'] = 'Wordlist not found'
                return

            wordlist = wordlist_path

        output_file = f"{self.output_dir}/gobuster_{self.timestamp}.txt"

        try:
            cmd = [
                "gobuster",
                "dir",
                "-u", self.target_url,
                "-w", wordlist,
                "-o", output_file,
                "-t", "50",  # количество потоков
                "-q"  # тихий режим
            ]

            # Сохраняем параметры Gobuster
            self.tools_info['gobuster']['params'] = {
                'url': self.target_url,
                'wordlist': wordlist,
                'threads': '50',
                'mode': 'directory_brute_force',
                'quiet_mode': True
            }

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate()

            if process.returncode == 0:
                print(
                    f"[+] Gobuster завершен. Результаты сохранены в {output_file}")

                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        dirs = f.readlines()
                    dirs = [d.strip() for d in dirs if d.strip()]
                    print(f"[+] Найдено директорий: {len(dirs)}")
                    self.tools_info['gobuster']['count'] = len(dirs)
                    self.tools_info['gobuster']['status'] = 'completed'
                else:
                    self.tools_info['gobuster']['count'] = 0
                    self.tools_info['gobuster']['status'] = 'completed'

                self.results['gobuster'] = output_file
            else:
                print(f"[-] Ошибка Gobuster: {stderr}")
                self.tools_info['gobuster']['status'] = 'error'
                self.tools_info['gobuster']['error'] = stderr

        except FileNotFoundError:
            print("[-] Gobuster не найден. Убедитесь, что он установлен.")
            self.tools_info['gobuster']['status'] = 'not_found'
            self.tools_info['gobuster']['error'] = 'Tool not found'
        except Exception as e:
            print(f"[-] Ошибка при запуске Gobuster: {e}")
            self.tools_info['gobuster']['status'] = 'error'
            self.tools_info['gobuster']['error'] = str(e)
        finally:
            tool_end = datetime.now()
            self.tools_info['gobuster']['end_time'] = tool_end.isoformat()
            duration = (tool_end - tool_start).total_seconds()
            self.tools_info['gobuster']['duration_seconds'] = duration

    def save_json_report(self, data):
        """Сохранить JSON отчет в reports/web/json"""
        json_path = self.json_dir / f"{self.filename_base}.json"

        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"✓ JSON отчет сохранен: {json_path}")
        return str(json_path)

    def save_txt_report(self, content):
        """Сохранить TXT отчет в reports/web/txt"""
        txt_path = self.txt_dir / f"{self.filename_base}.txt"

        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"✓ TXT отчет сохранен: {txt_path}")
        return str(txt_path)

    def run_all(self, jsfinder_deep=False, jsfinder_cookie=None, gobuster_wordlist=None):
        """Запуск всех инструментов последовательно"""
        print(f"\n{'='*50}")
        print(f"Начало сканирования: {self.target_url}")
        print(f"Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Директория результатов: {self.output_dir}")
        print(f"{'='*50}\n")

        # Запускаем инструменты последовательно для избежания конфликтов
        self.run_katana()
        time.sleep(2)  # небольшая пауза между запусками

        self.run_jsfinder(deep_scan=jsfinder_deep, cookie=jsfinder_cookie)
        time.sleep(2)

        self.run_gobuster(wordlist=gobuster_wordlist)

        # Генерируем итоговый отчет
        self.generate_report()

    def generate_report(self):
        """Генерация итогового отчета в JSON и TXT форматах"""

        # Собираем данные для отчета
        summary = {}
        all_data = {
            'katana': [],
            'jsfinder_urls': [],
            'jsfinder_subdomains': [],
            'gobuster': []
        }

        # Читаем результаты из файлов
        for tool, output_file in self.results.items():
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    lines = [line.strip()
                             for line in f.readlines() if line.strip()]

                if 'katana' in tool:
                    all_data['katana'] = lines
                    summary['katana'] = len(lines)
                elif 'jsfinder_urls' in tool:
                    all_data['jsfinder_urls'] = lines
                    summary['jsfinder_urls'] = len(lines)
                elif 'jsfinder_subdomains' in tool:
                    all_data['jsfinder_subdomains'] = lines
                    summary['jsfinder_subdomains'] = len(lines)
                elif 'gobuster' in tool:
                    all_data['gobuster'] = lines
                    summary['gobuster'] = len(lines)

        # Расчет времени сканирования
        scan_end_time = datetime.now()
        total_scan_duration = (
            scan_end_time - self.scan_start_time).total_seconds()

        # Создаем JSON отчет с подробной информацией
        json_report = {
            'metadata': {
                'report_version': '2.0',
                'report_type': 'web_scanner',
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
                'total_results': sum(summary.values()),
                'by_tool': summary,
                'tools_executed': [
                    {'name': tool,
                        'status': info['status'], 'results_count': info['count']}
                    for tool, info in self.tools_info.items()
                ]
            },
            'results': all_data
        }

        # Сохраняем JSON отчет
        json_path = self.save_json_report(json_report)

        # Создаем TXT отчет
        txt_content = self._generate_txt_report(
            summary, all_data, total_scan_duration)
        txt_path = self.save_txt_report(txt_content)

        # Выводим сводку
        print("\n" + "="*50)
        print("СВОДКА РЕЗУЛЬТАТОВ WEB СКАНИРОВАНИЯ:")
        print("="*50)
        for tool, count in summary.items():
            if count > 0:
                tool_display = tool.replace("_", " ").upper()
                print(f"  {tool_display}: {count}")
        print(f"  ВСЕГО: {sum(summary.values())}")
        print(f"  ВРЕМЯ СКАНИРОВАНИЯ: {total_scan_duration:.2f} сек")
        print("="*50)
        print(f"JSON отчет: {json_path}")
        print(f"TXT отчет: {txt_path}")
        print("="*50)

        return {
            'json': json_path,
            'txt': txt_path,
            'summary': summary
        }

    def _generate_txt_report(self, summary, all_data, total_duration):
        """Генерировать содержимое TXT отчета с подробной информацией"""
        lines = []

        # Заголовок
        lines.append("┌" + "─" * 78 + "┐")
        lines.append("│" + " " * 20 + "WEB СКАНИРОВАНИЕ URL" + " " * 38 + "│")
        lines.append("└" + "─" * 78 + "┘")
        lines.append("")

        # Информация о сканировании
        lines.append("📋 ИНФОРМАЦИЯ О СКАНИРОВАНИИ")
        lines.append("─" * 80)
        lines.append(f"  Целевой URL:        {self.target_url}")
        lines.append(
            f"  Дата сканирования:  {datetime.fromisoformat(self.scan_datetime).strftime('%d.%m.%Y')}")
        lines.append(
            f"  Время начала:       {datetime.fromisoformat(self.scan_datetime).strftime('%H:%M:%S')}")
        lines.append(f"  Продолжительность:  {total_duration:.2f} сек")
        lines.append(f"  Версия сканера:     1.0")
        lines.append("")

        # Информация об используемых инструментах
        lines.append("🛠️  ИСПОЛЬЗУЕМЫЕ ИНСТРУМЕНТЫ")
        lines.append("─" * 80)
        for tool_name, tool_info in self.tools_info.items():
            status_symbol = "✓" if tool_info['status'] == 'completed' else "✗" if tool_info['status'] in [
                'error', 'not_found'] else "○"
            tool_display = tool_name.replace("_", " ").upper()
            duration = tool_info.get('duration_seconds', 0)
            count = tool_info.get('count', 0)

            status_text = {
                'completed': 'ЗАВЕРШЕНО',
                'error': 'ОШИБКА',
                'not_found': 'НЕ НАЙДЕН',
                'not_run': 'НЕ ЗАПУЩЕН'
            }.get(tool_info['status'], tool_info['status'])

            lines.append(
                f"  {status_symbol} {tool_display:<30} [{status_text:<12}] {count:>5} результатов ({duration:.2f}сек)")

            if tool_info.get('params'):
                for param, value in tool_info['params'].items():
                    lines.append(f"      └─ {param}: {value}")

            if tool_info['status'] == 'error' and tool_info.get('error'):
                lines.append(f"      └─ Ошибка: {tool_info['error'][:70]}")
        lines.append("")

        # Сводка результатов
        lines.append("📊 СВОДКА РЕЗУЛЬТАТОВ")
        lines.append("─" * 80)
        total = sum(summary.values())
        lines.append(f"  Всего найдено результатов:  {total}")
        for tool, count in summary.items():
            if count > 0:
                tool_display = tool.replace("_", " ").upper()
                lines.append(f"  {tool_display:<25} {count:>5}")
        lines.append("")

        # Результаты по инструментам
        if any(summary.values()):
            lines.append("📝 ДЕТАЛЬНЫЕ РЕЗУЛЬТАТЫ")
            lines.append("─" * 80)
            lines.append("")

            if all_data['katana']:
                lines.append("🔗 KATANA (URL Crawling)")
                lines.append(f"  Найдено URL: {len(all_data['katana'])}")
                lines.append("  " + "-" * 75)
                for i, url in enumerate(all_data['katana'][:100], 1):
                    display_url = url[:70] + "..." if len(url) > 70 else url
                    lines.append(f"    {i:3d}. {display_url}")
                if len(all_data['katana']) > 100:
                    lines.append(
                        f"    ... и еще {len(all_data['katana']) - 100} URL")
                lines.append("")

            if all_data['jsfinder_urls']:
                lines.append("📜 JSFinder URLs (JS Analysis)")
                lines.append(
                    f"  Найдено URL в JS файлах: {len(all_data['jsfinder_urls'])}")
                lines.append("  " + "-" * 75)
                for i, url in enumerate(all_data['jsfinder_urls'][:50], 1):
                    display_url = url[:70] + "..." if len(url) > 70 else url
                    lines.append(f"    {i:3d}. {display_url}")
                if len(all_data['jsfinder_urls']) > 50:
                    lines.append(
                        f"    ... и еще {len(all_data['jsfinder_urls']) - 50} URL")
                lines.append("")

            if all_data['jsfinder_subdomains']:
                lines.append("🌐 JSFinder Subdomains (JS Analysis)")
                lines.append(
                    f"  Найдено поддоменов в JS: {len(all_data['jsfinder_subdomains'])}")
                lines.append("  " + "-" * 75)
                for i, subdomain in enumerate(all_data['jsfinder_subdomains'][:50], 1):
                    lines.append(f"    {i:3d}. {subdomain}")
                if len(all_data['jsfinder_subdomains']) > 50:
                    lines.append(
                        f"    ... и еще {len(all_data['jsfinder_subdomains']) - 50} поддоменов")
                lines.append("")

            if all_data['gobuster']:
                lines.append("📁 GOBUSTER (Directory Brute Force)")
                lines.append(
                    f"  Найдено директорий: {len(all_data['gobuster'])}")
                lines.append("  " + "-" * 75)
                for i, directory in enumerate(all_data['gobuster'][:50], 1):
                    lines.append(f"    {i:3d}. {directory}")
                if len(all_data['gobuster']) > 50:
                    lines.append(
                        f"    ... и еще {len(all_data['gobuster']) - 50} директорий")
                lines.append("")

        # Завершение
        lines.append("─" * 80)
        lines.append(
            f"Отчет создан: {datetime.fromisoformat(self.scan_datetime).strftime('%d.%m.%Y %H:%M:%S')}")
        lines.append("=" * 80)

        return "\n".join(lines)


def simple_scan(target_url, reports_dir=None):
    """Функция для запуска web сканирования из API"""
    try:
        print(f"[*] Запуск Web сканирования для {target_url}")

        # Создаем сканер
        scanner = WebScanner(
            target_url, output_dir="/tmp/web_scan", reports_dir=reports_dir)

        # Запускаем все инструменты
        scanner.run_all(jsfinder_deep=False,
                        jsfinder_cookie=None, gobuster_wordlist=None)

        # Возвращаем результаты
        report_result = scanner.generate_report()
        return {
            'status': 'completed',
            'target_url': target_url,
            'reports': report_result
        }

    except Exception as e:
        print(f"[-] Ошибка при сканировании: {e}")
        return {
            'status': 'error',
            'target_url': target_url,
            'error': str(e)
        }


def setup_jsfinder():
    """Помощь в установке JSFinder от hellouuuser"""
    print("\n[!] JSFinder от hellouuuser не найден!")
    print("\nИнструкция по установке:")
    print("\nОпция 1: Клонировать в backend/tools/jsfinder/")
    print("   git clone https://github.com/hellouuuser/JSFinder.git backend/tools/jsfinder")
    print("\nОпция 2: Скачать файл напрямую")
    print("   mkdir -p backend/tools/jsfinder")
    print("   wget https://raw.githubusercontent.com/hellouuuser/JSFinder/master/JSFinder.py -O backend/tools/jsfinder/JSFinder.py")
    print("\nПосле установки запустите скрипт снова.")


def check_dependencies():
    """Проверка наличия необходимых инструментов"""
    dependencies = {
        "katana": "katana",
        "gobuster": "gobuster"
    }

    missing = []

    print("\n" + "="*60)
    print("Проверка зависимостей...")
    print("="*60)

    for tool_name, cmd in dependencies.items():
        try:
            result = subprocess.run(
                [cmd, "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                print(f"[+] {tool_name} найден ✓")
            else:
                print(
                    f"[-] {tool_name} найден, но может быть неправильная версия")
                missing.append(tool_name)
        except FileNotFoundError:
            print(f"[-] {tool_name} не найден ✗")
            missing.append(tool_name)
        except Exception as e:
            print(f"[-] Ошибка при проверке {tool_name}: {e}")
            missing.append(tool_name)

    # Проверяем JSFinder отдельно
    script_dir = Path(__file__).parent
    jsfinder_path = script_dir.parent / "tools" / "jsfinder" / "JSFinder.py"

    if jsfinder_path.is_file():
        print(f"[+] JSFinder найден ✓ - {jsfinder_path}")
    else:
        print("[-] JSFinder не найден ✗")
        print(f"[*] Ожидаемый путь: {jsfinder_path}")
        setup_jsfinder()
        response = input("\nПродолжить без JSFinder? (y/n): ")
        if response.lower() != 'y':
            return False

    if missing:
        print("\n[!] Отсутствуют следующие инструменты:")
        for tool in missing:
            print(f"    - {tool}")

        print("\nРекомендации по установке:")
        print("  Katana: go install github.com/projectdiscovery/katana/cmd/katana@latest")
        print("  Gobuster: sudo apt install gobuster  # или из исходников")

        response = input(
            "\nПродолжить без отсутствующих инструментов? (y/n): ")
        return response.lower() == 'y'

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Автоматизация запуска инструментов для веб-разведки")
    parser.add_argument("-u", "--url", required=True,
                        help="Целевой URL (например, https://example.com)")
    parser.add_argument(
        "-w", "--wordlist", help="Путь к словарю для Gobuster (по умолчанию: /usr/share/wordlists/dirb/common.txt)")
    parser.add_argument("-o", "--output", default="scan_results",
                        help="Директория для результатов")
    parser.add_argument("--jsfinder-deep", action="store_true",
                        help="Глубокое сканирование JSFinder (переход по ссылкам)")
    parser.add_argument("--jsfinder-cookie",
                        help="Cookie для JSFinder (например: 'session=abc123')")
    parser.add_argument("--skip-checks", action="store_true",
                        help="Пропустить проверку зависимостей")

    args = parser.parse_args()

    # Проверка зависимостей
    if not args.skip_checks:
        if not check_dependencies():
            print("Сканирование отменено.")
            sys.exit(1)

    # Создаем экземпляр сканера
    scanner = WebScanner(args.url, args.output)

    # Запускаем все инструменты
    scanner.run_all(
        jsfinder_deep=args.jsfinder_deep,
        jsfinder_cookie=args.jsfinder_cookie,
        gobuster_wordlist=args.wordlist
    )


if __name__ == "__main__":
    main()
