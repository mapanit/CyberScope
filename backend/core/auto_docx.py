#!/usr/bin/env python3
"""
Интегрированный скрипт для создания объединённых отчетов (JSON, TXT, DOCX)
"""

import sys
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from report_utils import (
    create_combined_report,
    create_combined_report_by_time,
    quick_merge_all_reports,
    DOCX_AVAILABLE
)


def main():
    """Главная функция"""
    parser = argparse.ArgumentParser(
        description='Создать объединённый отчет о сканировании'
    )

    # Основные параметры
    parser.add_argument(
        '-m', '--mode',
        choices=['recent', 'time-window', 'all'],
        default='recent',
        help='Режим сбора отчетов (recent - последние N минут, time-window - во временном окне, all - все отчеты)'
    )

    parser.add_argument(
        '-r', '--recent-minutes',
        type=int,
        default=5,
        help='Количество минут для поиска недавних отчетов (по умолчанию 5)'
    )

    parser.add_argument(
        '-s', '--start-time',
        help='Начало временного окна в формате HH:MM (например: 10:30)',
        default=None
    )

    parser.add_argument(
        '-e', '--end-time',
        help='Конец временного окна в формате HH:MM (например: 11:00)',
        default=None
    )

    parser.add_argument(
        '-o', '--output-name',
        help='Имя выходного файла (без расширения)',
        default=None
    )

    parser.add_argument(
        '--no-docx',
        action='store_true',
        help='Не создавать DOCX версию отчета'
    )

    parser.add_argument(
        '--reports-dir',
        help='Базовая директория с отчетами',
        default=None
    )

    args = parser.parse_args()

    # Проверяем наличие python-docx
    include_docx = not args.no_docx
    if include_docx and not DOCX_AVAILABLE:
        print("[!] Модуль python-docx не установлен.")
        print("[*] DOCX версия не будет создана.")
        print("[*] Установите модуль: pip install python-docx")
        include_docx = False

    # Формируем ID сканирования
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    print("\n" + "=" * 80)
    print("  СОЗДАНИЕ ОБЪЕДИНЁННОГО ОТЧЕТА О СКАНИРОВАНИИ".center(80))
    print("=" * 80)
    print(f"[*] Время: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
    print(f"[*] ID сканирования: {scan_id}")
    print(f"[*] Режим: {args.mode}")
    print(f"[*] Включить DOCX: {'✓ Да' if include_docx else '✗ Нет'}")

    # Выполняем нужный режим
    try:
        if args.mode == 'recent':
            print(f"[*] Поиск отчетов за последние {args.recent_minutes} минут...")
            result = create_combined_report(
                scan_id,
                reports_base_dir=args.reports_dir,
                recent_minutes=args.recent_minutes,
                include_docx=include_docx
            )

        elif args.mode == 'time-window':
            # Парсим время
            if not args.start_time:
                print("[!] Для режима time-window требуется параметр --start-time")
                return 1

            # Парсим время начала
            try:
                start_hour, start_minute = map(int, args.start_time.split(':'))
                start_time = datetime.now().replace(hour=start_hour, minute=start_minute, second=0, microsecond=0)
            except (ValueError, AttributeError):
                print(f"[!] Неверный формат времени: {args.start_time}. Используйте HH:MM")
                return 1

            # Парсим время окончания
            end_time = None
            if args.end_time:
                try:
                    end_hour, end_minute = map(int, args.end_time.split(':'))
                    end_time = datetime.now().replace(hour=end_hour, minute=end_minute, second=0, microsecond=0)
                except (ValueError, AttributeError):
                    print(f"[!] Неверный формат времени: {args.end_time}. Используйте HH:MM")
                    return 1

            print(f"[*] Временное окно: {args.start_time} - {args.end_time or 'текущее время'}")
            result = create_combined_report_by_time(
                scan_id,
                start_time=start_time,
                end_time=end_time,
                reports_base_dir=args.reports_dir,
                include_docx=include_docx
            )

        else:  # all
            print("[*] Объединение всех отчетов...")
            output_name = args.output_name or f"all_reports_{scan_id}"
            result = quick_merge_all_reports(
                reports_base_dir=args.reports_dir,
                output_name=output_name,
                include_docx=include_docx
            )

        # Выводим результаты
        print("\n" + "=" * 80)
        print("  РЕЗУЛЬТАТЫ".center(80))
        print("=" * 80)

        if result.get('json'):
            json_path = Path(result['json'])
            json_size = json_path.stat().st_size / 1024  # в KB
            print(f"✓ JSON:  {result['json']}")
            print(f"          Размер: {json_size:.2f} KB")

        if result.get('txt'):
            txt_path = Path(result['txt'])
            txt_size = txt_path.stat().st_size / 1024
            print(f"✓ TXT:   {result['txt']}")
            print(f"          Размер: {txt_size:.2f} KB")

        if result.get('docx'):
            docx_path = Path(result['docx'])
            docx_size = docx_path.stat().st_size / 1024
            print(f"✓ DOCX:  {result['docx']}")
            print(f"          Размер: {docx_size:.2f} KB")

        print("\n" + "=" * 80)
        print("[✓] Объединённый отчет успешно создан!")
        print("=" * 80 + "\n")

        return 0

    except Exception as e:
        print(f"\n[✗] Ошибка: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
