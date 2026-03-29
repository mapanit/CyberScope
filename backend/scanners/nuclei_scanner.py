"""
Nuclei scanner wrapper for CyberScope
Запускает nuclei и создает отчет в TXT формате
"""

import subprocess
import sys
import json
import re
from datetime import datetime
from pathlib import Path
from os.path import expanduser


def find_templates_directory():
    """Ищет папку с шаблонами nuclei в стандартных местах"""
    possible_paths = [
        Path("/nuclei-templates"),  # Корневая папка Linux
        Path("./nuclei-templates"),  # Текущая директория
        Path("../nuclei-templates"),  # Родительская директория
        Path("../../../../../../nuclei-templates"),  # На 2 уровня вверх
        Path(expanduser("~/nuclei-templates")),  # Домашняя папка
        Path(expanduser("~/.nuclei-templates")),  # Домашняя папка

    ]
    
    for path in possible_paths:
        if path.exists() and path.is_dir():
            print(f"[✓] Найдена папка шаблонов: {path}", file=sys.stderr)
            return str(path.resolve())
    
    print("[!] Папка nuclei-templates не найдена. Используются встроенные шаблоны nuclei.", file=sys.stderr)
    return None


def create_report_directory(reports_base_dir: str = None):
    """Создает директории для отчетов (txt и json) если они не существуют"""
    if reports_base_dir:
        base_dir = Path(reports_base_dir) / "nuclei"
    else:
        base_dir = Path(__file__).parent.parent / "reports" / "nuclei"
    
    # Создаем подпапки для каждого формата
    txt_dir = base_dir / "txt"
    json_dir = base_dir / "json"
    
    txt_dir.mkdir(parents=True, exist_ok=True)
    json_dir.mkdir(parents=True, exist_ok=True)
    
    return base_dir


def save_txt_report(results, summary, url, report_dir, reports_base_dir: str = None):
    """Сохраняет отчет в формате TXT"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"nuclei_scan_{timestamp}.txt"
    
    if reports_base_dir:
        txt_dir = Path(reports_base_dir) / "nuclei" / "txt"
    else:
        txt_dir = Path(__file__).parent.parent / "reports" / "nuclei" / "txt"
    
    txt_dir.mkdir(parents=True, exist_ok=True)
    filepath = txt_dir / filename
    
    content = []
    
    # Заголовок
    content.append("┌" + "─" * 78 + "┐")
    content.append("│" + " " * 15 + "NUCLEI SCANNER - ОТЧЕТ О УЯЗВИМОСТЯХ" + " " * 26 + "│")
    content.append("└" + "─" * 78 + "┘")
    content.append("")
    
    # Информация о сканировании
    content.append("📋 ИНФОРМАЦИЯ О СКАНИРОВАНИИ")
    content.append("─" * 80)
    content.append(f"  URL сайта:          {url}")
    content.append(f"  Время сканирования: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
    content.append(f"  Всего найдено:      {summary['total']} уязвимост(ей)")
    content.append("")
    
    # Сводка по серьезности
    content.append("📊 СТАТИСТИКА ПО СЕРЬЕЗНОСТИ")
    content.append("─" * 80)
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        count = summary['by_severity'].get(severity, 0)
        severity_label = {
            'critical': '🔴 КРИТИЧЕСКИЕ',
            'high': '🟠 ВЫСОКИЕ',
            'medium': '🟡 СРЕДНИЕ',
            'low': '🔵 НИЗКИЕ',
            'info': '⚪ ИНФОРМАЦИОННЫЕ'
        }
        content.append(f"  {severity_label[severity]:30}: {count:3d}")
    content.append("")
    
    # Статистика по типам
    if summary['by_type']:
        content.append("📈 СТАТИСТИКА ПО ТИПАМ")
        content.append("─" * 80)
        for template_type, count in sorted(summary['by_type'].items(), key=lambda x: x[1], reverse=True):
            content.append(f"  {template_type:40}: {count:3d}")
        content.append("")
    
    # Детальные результаты
    if results:
        content.append("🔍 ДЕТАЛЬНЫЕ РЕЗУЛЬТАТЫ")
        content.append("═" * 80)
        
        for idx, result in enumerate(results, 1):
            info = result.get("info", {})
            severity = info.get('severity', 'info').upper()
            name = info.get('name', 'Unknown')
            
            content.append(f"\n[#{idx}] [{severity}] {name}")
            content.append("─" * 80)
            
            # Информация о находке
            content.append(f"  Тип:                {result.get('type', 'unknown')}")
            content.append(f"  URL:                {result.get('matched_at', 'unknown')}")
            content.append(f"  ID шаблона:         {info.get('template-id', 'N/A')}")
            content.append(f"  Категория:          {info.get('classification', {}).get('cwe-id', 'N/A')}")
            
            # Описание
            if info.get('description'):
                description = info['description']
                if len(description) > 300:
                    description = description[:300] + "..."
                content.append(f"\n  Описание:")
                for line in description.split('\n'):
                    content.append(f"    {line}")
            
            # Ссылки для справки
            if info.get('reference'):
                content.append(f"\n  Ссылки для справки:")
                references = info['reference']
                if isinstance(references, list):
                    for ref in references[:3]:  # Ограничиваем до 3 ссылок
                        content.append(f"    • {ref}")
                else:
                    content.append(f"    • {references}")
        
        content.append("\n" + "═" * 80)
    else:
        content.append("\n✓ Уязвимостей не найдено!")
        content.append("═" * 80)
    
    # Общие рекомендации
    content.append("\n📌 ОБЩИЕ РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОСТИ")
    content.append("─" * 80)
    
    recommendations = [
        "Регулярно обновляйте все программные компоненты",
        "Используйте Web Application Firewall (WAF) для защиты",
        "Реализуйте принцип минимальных привилегий",
        "Настройте мониторинг и логирование событий безопасности",
        "Проводите регулярные аудиты и тесты на проникновение",
        "Используйте HTTPS с современными шифрами (TLS 1.2/1.3)",
        "Валидируйте и санитизируйте все пользовательские данные",
        "Используйте параметризованные запросы/ORM для БД",
        "Реализуйте защиту от атак перебора (rate limiting)",
        "Настройте правильные security headers (CSP, HSTS и др.)"
    ]
    
    for i, rec in enumerate(recommendations, 1):
        content.append(f"  {i:2d}. {rec}")
    
    content.append("")
    content.append("═" * 80)
    content.append(f"Дата создания отчета: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
    content.append("═" * 80)
    
    # Сохраняем файл
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(content))
    
    print(f"[+] TXT отчет сохранен: {filepath}", file=sys.stderr)
    return filepath


def save_json_report(results, summary, url, report_dir, reports_base_dir: str = None):
    """Сохраняет отчет в формате JSON"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"nuclei_scan_{timestamp}.json"
    
    if reports_base_dir:
        json_dir = Path(reports_base_dir) / "nuclei" / "json"
    else:
        json_dir = Path(__file__).parent.parent / "reports" / "nuclei" / "json"
    
    json_dir.mkdir(parents=True, exist_ok=True)
    filepath = json_dir / filename
    
    # Формируем JSON отчет
    report_data = {
        "scan_info": {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "total_findings": summary["total"]
        },
        "summary": {
            "total": summary["total"],
            "by_severity": summary["by_severity"],
            "by_type": summary["by_type"]
        },
        "findings": results
    }
    
    # Сохраняем файл
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    print(f"[+] JSON отчет сохранен: {filepath}", file=sys.stderr)
    return filepath


def simple_scan(url, reports_dir: str = None):
    """
    Простое сканирование nuclei - выводит результаты с json форматом

    Args:
        url: URL для сканирования
        reports_dir: Базовая директория для сохранения отчетов

    Returns:
        list: Список результатов (словари)
    """
    try:
        # Убеждаемся что URL имеет схему
        if not re.match(r'^http?://', url, re.I):
            url = f"http://{url}"

        print(f"[*] Запускаем nuclei для сканирования {url}...", file=sys.stderr)

        # Ищем папку с шаблонами
        templates_dir = find_templates_directory()

        # Запускаем nuclei с JSONL выводом (построчный JSON)
        cmd = ["nuclei", "-u", url, "-jsonl"]
        
        # Добавляем шаблоны если найдены
        if templates_dir:
            cmd.extend(["-t", templates_dir])
            print(f"[*] Используются шаблоны из: {templates_dir}", file=sys.stderr)
        else:
            print(f"[*] Используются встроенные шаблоны nuclei", file=sys.stderr)

        print(f"[*] Команда сканирования: {' '.join(cmd)}", file=sys.stderr)

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        results = []
        line_count = 0

        # Читаем JSON результаты построчно
        for line in process.stdout:
            line = line.strip()
            if not line:  # Пропускаем пустые строки
                continue
            
            # Пропускаем предупреждения и логи nuclei (они начинаются с [)
            if line.startswith('['):
                continue
                
            try:
                result = json.loads(line)
                results.append(result)
                line_count += 1
                # Выводим в stderr прогресс
                info = result.get('info', {})
                name = info.get('name', 'Unknown')
                severity = info.get('severity', 'info').upper()
                print(
                    f"[+] Уязвимость #{line_count}: [{severity}] {name}", file=sys.stderr)
            except json.JSONDecodeError:
                # Молча игнорируем строки которые не JSON
                continue

        process.wait()

        print(
            f"[*] Сканирование завершено. Найдено {len(results)} уязвимостей", file=sys.stderr)

        if process.returncode != 0:
            stderr_output = process.stderr.read()
            if stderr_output:
                print(f"[!] Ошибка nuclei: {stderr_output}", file=sys.stderr)

        return results

    except FileNotFoundError:
        print("[ERROR] Nuclei не установлен! Установите через: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest", file=sys.stderr)
        return []
    except KeyboardInterrupt:
        print("[!] Сканирование прервано пользователем", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[ERROR] Ошибка при сканировании: {str(e)}", file=sys.stderr)
        return []


def get_summary(results):
    """
    Получить статистику результатов

    Args:
        results: Список результатов

    Returns:
        dict: Словарь со статистикой
    """
    summary = {
        "total": len(results),
        "by_severity": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        },
        "by_type": {}
    }

    for result in results:
        severity = result.get("info", {}).get("severity", "info").lower()
        if severity in summary["by_severity"]:
            summary["by_severity"][severity] += 1

        template_type = result.get("type", "unknown")
        summary["by_type"][template_type] = summary["by_type"].get(
            template_type, 0) + 1

    return summary


def run_scan(url, save_reports=True, reports_dir: str = None):
    """
    Функция для запуска сканирования с сохранением отчетов
    
    Args:
        url: URL для сканирования
        save_reports: Сохранять ли отчеты
        reports_dir: Базовая директория для сохранения отчетов
        
    Returns:
        dict: Результаты сканирования с путем к отчету
    """
    print(f"\n[*] Подготовка к сканированию {url}...", file=sys.stderr)
    
    # Убеждаемся что URL имеет схему
    if not re.match(r'^https?://', url, re.I):
        url = f"http://{url}"
    
    # Выполняем сканирование
    results = simple_scan(url, reports_dir)
    summary = get_summary(results)
    
    response = {
        'status': 'completed' if summary['total'] > 0 else 'no_findings',
        'url': url,
        'total_findings': summary['total'],
        'by_severity': summary['by_severity'],
        'by_type': summary['by_type'],
        'txt_report': None,
        'json_report': None
    }
    
    # Сохраняем отчеты если требуется
    if save_reports:
        print(f"[*] Создаем отчеты TXT и JSON...", file=sys.stderr)
        report_dir = create_report_directory(reports_dir)
        try:
            txt_path = save_txt_report(results, summary, url, report_dir, reports_dir)
            response['txt_report'] = txt_path
        except Exception as e:
            print(f"[!] Ошибка при сохранении TXT отчета: {e}", file=sys.stderr)
        
        try:
            json_path = save_json_report(results, summary, url, report_dir, reports_dir)
            response['json_report'] = json_path
        except Exception as e:
            print(f"[!] Ошибка при сохранении JSON отчета: {e}", file=sys.stderr)
        
        print(f"[✓] Отчеты успешно созданы", file=sys.stderr)
    
    return response


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python nuclei.py <URL>")
        print("Пример: python nuclei.py http://example.com")
        sys.exit(1)

    url = sys.argv[1]
    
    print("\n" + "="*80)
    print("NUCLEI SCANNER - СКАНИРОВАНИЕ НА УЯЗВИМОСТИ")
    print("="*80)
    
    # Ищем папку с шаблонами
    print("[*] Поиск папки с шаблонами nuclei...", file=sys.stderr)
    templates_dir = find_templates_directory()
    
    # Создаем директорию для отчетов
    print("[*] Создаем директорию для отчетов в reports/nuclei...", file=sys.stderr)
    report_dir = create_report_directory()
    
    # Выполняем сканирование
    print("[*] Запускаем процесс сканирования...", file=sys.stderr)
    results = simple_scan(url)
    summary = get_summary(results)
    
    # Сохраняем отчеты
    print("[*] Генерируем отчеты...", file=sys.stderr)
    txt_report = save_txt_report(results, summary, url, report_dir)
    json_report = save_json_report(results, summary, url, report_dir)
    
    # Выводим результаты в консоль
    print("\n" + "="*80)
    print("РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ")
    print("="*80)
    print(f"URL:                    {url}")
    print(f"Найдено уязвимостей:    {summary['total']}")
    print(f"Путь к TXT отчету:      {txt_report}")
    print(f"Путь к JSON отчету:     {json_report}")

    if summary['total'] > 0:
        print(f"\n📊 СТАТИСТИКА ПО СЕРЬЕЗНОСТИ:")
        print("─" * 80)
        severity_map = {
            'critical': '🔴 КРИТИЧЕСКИЕ',
            'high': '🟠 ВЫСОКИЕ',
            'medium': '🟡 СРЕДНИЕ', 
            'low': '🔵 НИЗКИЕ',
            'info': '⚪ ИНФОРМАЦИОННЫЕ'
        }
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            count = summary["by_severity"].get(sev, 0)
            if count > 0:
                print(f"  {severity_map[sev]:30}: {count:3d}")

        if summary['by_type']:
            print(f"\n📈 СТАТИСТИКА ПО ТИПАМ:")
            print("─" * 80)
            for template_type, count in sorted(summary['by_type'].items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {template_type:50}: {count:3d}")

        print(f"\n🔍 СПИСОК НАЙДЕННЫХ УЯЗВИМОСТЕЙ (первые 10):")
        print("─" * 80)

        for idx, result in enumerate(results[:10], 1):
            info = result.get("info", {})
            severity = info.get('severity', 'info').upper()
            name = info.get('name', 'Unknown')
            print(f"\n[{idx}] [{severity:8s}] {name}")
            print(f"    Тип: {result.get('type', 'unknown')}")
            print(f"    URL: {result.get('matched_at', 'unknown')}")
            if info.get('description'):
                desc = info['description'][:150]
                print(f"    Описание: {desc}")
        
        if len(results) > 10:
            print(f"\n... и еще {len(results) - 10} уязвимостей")
    else:
        print("\n✓ Уязвимостей не найдено!")

    print(f"\n" + "="*80)
    print("ℹ️  ИНФОРМАЦИЯ О ПРОЦЕССЕ:")
    print("="*80)
    print("[✓] 1. Поиск папки с шаблонами nuclei-templates")
    if templates_dir:
        print(f"     └─ Найдена: {templates_dir}")
    else:
        print(f"     └─ Используются встроенные шаблоны nuclei")
    print("[✓] 2. Запуск инструмента nuclei")
    print("[✓] 3. Сканирование целевого URL на предмет известных уязвимостей")
    print(f"[✓] 4. Обработка и анализ {summary['total']} найденных результатов")
    print("[✓] 5. Группировка уязвимостей по серьезности и типам")
    print("[✓] 6. Создание детальных отчетов (TXT и JSON форматы)")
    print("[✓] 7. Добавление рекомендаций по безопасности")
    print("[✓] 8. Сохранение отчетов в reports/nuclei")
    print(f"\n[✓] Сканирование завершено успешно!")
    print("="*80 + "\n")