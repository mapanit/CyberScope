#!/usr/bin/env python3
"""
Скрипт для преобразования TXT отчетов в DOCX (Word)
Использует функции из report_utils.py
"""

import sys
import argparse
from pathlib import Path
from report_utils import txt_to_docx_file, DOCX_AVAILABLE


def main():
    """Главная функция"""
    parser = argparse.ArgumentParser(
        description='Преобразовать TXT отчет в DOCX (Word)'
    )
    parser.add_argument(
        'input_file',
        help='Путь к входному TXT файлу'
    )
    parser.add_argument(
        '-o', '--output',
        help='Путь к выходному DOCX файлу (если не указана, создается рядом с TXT)',
        default=None
    )

    args = parser.parse_args()

    # Проверяем наличие модуля python-docx
    if not DOCX_AVAILABLE:
        print("[!] Модуль python-docx не установлен.")
        print("[*] Установите его командой: pip install python-docx")
        return 1

    # Преобразуем файл
    print(f"[*] Преобразование файла: {args.input_file}")

    result = txt_to_docx_file(args.input_file, args.output)

    if result:
        print(f"[✓] Готово! DOCX файл: {result}")
        return 0
    else:
        print("[✗] Ошибка при преобразовании файла")
        return 1


if __name__ == "__main__":
    sys.exit(main())
