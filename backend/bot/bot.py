import os
import asyncio
import logging
import json
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command, CommandStart
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton, FSInputFile, ReplyKeyboardMarkup, KeyboardButton
from aiogram.fsm.context import FSMContext

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")

if os.path.exists("/app/reports/combined"):
    REPORTS_DIR = Path("/app/reports/combined")
else:
    REPORTS_DIR = Path(__file__).parent.parent / "reports" / "combined"

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN не найден в переменных окружения!")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# Логирование
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_reports_by_type(report_type: str) -> list:
    """Получить список отчетов по типу (json или txt)"""
    type_dir = REPORTS_DIR / report_type
    
    if not type_dir.exists():
        return []
    
    files = sorted(type_dir.glob("*"), key=lambda x: x.stat().st_mtime, reverse=True)
    return [f.name for f in files if f.is_file()]


def get_reports_statistics() -> dict:
    """Получить подробную статистику по отчетам"""
    stats = {
        "json": {"total": 0, "files": [], "total_size_mb": 0},
        "txt": {"total": 0, "files": [], "total_size_kb": 0},
        "by_date": {},
        "latest_report": None
    }
    
    # Статистика по JSON
    json_dir = REPORTS_DIR / "json"
    if json_dir.exists():
        for file in json_dir.glob("*"):
            if file.is_file():
                size_mb = file.stat().st_size / (1024 * 1024)
                mtime = datetime.fromtimestamp(file.stat().st_mtime)
                date_key = mtime.strftime("%Y-%m-%d")
                
                stats["json"]["total"] += 1
                stats["json"]["total_size_mb"] += size_mb
                stats["json"]["files"].append({
                    "name": file.name,
                    "size_mb": size_mb,
                    "date": mtime
                })
                
                # Статистика по датам
                if date_key not in stats["by_date"]:
                    stats["by_date"][date_key] = 0
                stats["by_date"][date_key] += 1
    
    # Статистика по TXT
    txt_dir = REPORTS_DIR / "txt"
    if txt_dir.exists():
        for file in txt_dir.glob("*"):
            if file.is_file():
                size_kb = file.stat().st_size / 1024
                mtime = datetime.fromtimestamp(file.stat().st_mtime)
                
                stats["txt"]["total"] += 1
                stats["txt"]["total_size_kb"] += size_kb
                stats["txt"]["files"].append({
                    "name": file.name,
                    "size_kb": size_kb,
                    "date": mtime
                })
    
    # Находим последний отчет
    all_files = []
    for report_type in ["json", "txt"]:
        for file in stats[report_type]["files"]:
            all_files.append((file["date"], report_type, file["name"]))
    
    if all_files:
        latest = max(all_files, key=lambda x: x[0])
        stats["latest_report"] = {
            "date": latest[0],
            "type": latest[1],
            "name": latest[2]
        }
    
    return stats


def get_main_keyboard():
    """Получить главную клавиатуру"""
    keyboard = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text='📊 Статистика'), KeyboardButton(text='📥 Отчеты')],
            [KeyboardButton(text='❓ Справка')]
        ],
        resize_keyboard=True
    )
    return keyboard


def get_back_keyboard():
    """Получить клавиатуру возврата в главное меню"""
    keyboard = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text='🏠 Главное меню')]
        ],
        resize_keyboard=True
    )
    return keyboard


# Обработчик команды /start
@dp.message(CommandStart())
async def cmd_start(message: Message):
    keyboard = get_main_keyboard()
    await message.answer(
        f"Привет, {message.from_user.first_name}! 👋\n\n"
        "Я CyberScope бот для просмотра и анализа отчетов безопасности.\n\n"
        "*Возможности:*\n"
        "📊 Просмотр статистики отчетов\n"
        "📥 Скачивание отчетов (JSON, TXT)\n"
        "📈 Аналитика по уязвимостям\n"
        "🔍 Поиск по отчетам\n",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )


# Обработчик команды /help
@dp.message(Command("help"))
async def cmd_help(message: Message):
    help_text = """
📋 *Доступные команды:*

/start - главное меню
/stats - статистика отчетов
/search <текст> - поиск по отчетам
/list_json - список JSON отчетов
/list_txt - список TXT отчетов

*Функциональность:*
📊 Просмотр статистики отчетов
📥 Скачивание отчетов (JSON, TXT)
📈 Аналитика по найденным уязвимостям
🔍 Поиск по содержимому отчетов

*Отчеты:*
Отчеты автоматически ищутся в папке:
`reports/combined/json/` - JSON отчеты
`reports/combined/txt/` - TXT отчеты
    """
    keyboard = get_main_keyboard()
    await message.answer(help_text, reply_markup=keyboard, parse_mode="Markdown")


# Обработчик кнопки "📊 Статистика"
@dp.message(F.text == "📊 Статистика")
async def handle_stats_button(message: Message):
    """Обработчик кнопки 'Статистика' - показывает подробную статистику по отчетам"""
    stats = get_reports_statistics()
    
    # Формируем сообщение со статистикой
    stats_text = f"""
📊 *СТАТИСТИКА ОТЧЕТОВ*
{'=' * 30}

📄 *JSON отчеты:*
• Всего: {stats['json']['total']}
• Общий размер: {stats['json']['total_size_mb']:.2f} MB

📝 *TXT отчеты:*
• Всего: {stats['txt']['total']}
• Общий размер: {stats['txt']['total_size_kb']:.1f} KB

{'=' * 30}
📈 *Общая информация:*
• Всего отчетов: {stats['json']['total'] + stats['txt']['total']}
• Общий размер всех отчетов: {(stats['json']['total_size_mb'] + stats['txt']['total_size_kb'] / 1024):.2f} MB
    """
    
    # Добавляем информацию о последнем отчете
    if stats['latest_report']:
        stats_text += f"""
{'=' * 30}
🆕 *Последний отчет:*
• Тип: {stats['latest_report']['type'].upper()}
• Имя: `{stats['latest_report']['name'][:50]}`
• Дата: {stats['latest_report']['date'].strftime('%Y-%m-%d %H:%M:%S')}
    """
    
    # Добавляем статистику по дням
    if stats['by_date']:
        stats_text += f"\n{'=' * 30}\n📅 *Активность по дням:*\n"
        for date, count in sorted(stats['by_date'].items(), reverse=True)[:5]:
            stats_text += f"• {date}: {count} отчет(ов)\n"
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📊 Детальная статистика", callback_data="detailed_stats")],
        [InlineKeyboardButton(text="📥 Перейти к отчетам", callback_data="download_menu")],
        [InlineKeyboardButton(text="🔄 Обновить", callback_data="refresh_stats")]
    ])
    
    await message.answer(stats_text, reply_markup=keyboard, parse_mode="Markdown")


# Обработчик кнопки "📥 Отчеты"
@dp.message(F.text == "📥 Отчеты")
async def handle_reports_button(message: Message):
    """Обработчик кнопки 'Отчеты'"""
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📊 JSON отчеты", callback_data="list_json")],
        [InlineKeyboardButton(text="📝 TXT отчеты", callback_data="list_txt")],
        [InlineKeyboardButton(text="🔍 Поиск по отчетам", callback_data="search_reports")],
        [InlineKeyboardButton(text="📈 Аналитика", callback_data="view_analytics")]
    ])
    
    stats = get_reports_statistics()
    
    await message.answer(
        f"📥 *Меню отчетов*\n\n"
        f"📊 JSON: {stats['json']['total']} файлов | {stats['json']['total_size_mb']:.1f} MB\n"
        f"📝 TXT: {stats['txt']['total']} файлов | {stats['txt']['total_size_kb']:.0f} KB\n\n"
        f"Выберите действие:",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )


#

# Детальная статистика по callback
@dp.callback_query(F.data == "detailed_stats")
async def detailed_stats(callback: types.CallbackQuery):
    """Показать детальную статистику"""
    stats = get_reports_statistics()
    
    stats_text = f"""
📊 *ДЕТАЛЬНАЯ СТАТИСТИКА*
{'=' * 35}

📄 *JSON отчеты (топ 10 по размеру):*
"""
    
    # Топ 10 JSON отчетов по размеру
    sorted_json = sorted(stats['json']['files'], key=lambda x: x['size_mb'], reverse=True)[:10]
    for i, file in enumerate(sorted_json, 1):
        stats_text += f"{i}. `{file['name'][:40]}` - {file['size_mb']:.2f} MB\n"
    
    stats_text += f"\n📝 *TXT отчеты (топ 10 по размеру):*\n"
    
    # Топ 10 TXT отчетов по размеру
    sorted_txt = sorted(stats['txt']['files'], key=lambda x: x['size_kb'], reverse=True)[:10]
    for i, file in enumerate(sorted_txt, 1):
        stats_text += f"{i}. `{file['name'][:40]}` - {file['size_kb']:.1f} KB\n"
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🏠 Назад", callback_data="back_to_stats")]
    ])
    
    await callback.message.edit_text(stats_text, reply_markup=keyboard, parse_mode="Markdown")
    await callback.answer()


# Обновление статистики
@dp.callback_query(F.data == "refresh_stats")
async def refresh_stats(callback: types.CallbackQuery):
    """Обновить статистику"""
    await callback.answer("🔄 Статистика обновлена")
    await handle_stats_button(callback.message)


# Назад к статистике
@dp.callback_query(F.data == "back_to_stats")
async def back_to_stats(callback: types.CallbackQuery):
    """Вернуться к статистике"""
    await handle_stats_button(callback.message)
    await callback.answer()


# Обработчик кнопки "❓ Справка"
@dp.message(F.text == "❓ Справка")
async def handle_help_button(message: Message):
    """Обработчик кнопки 'Справка'"""
    help_text = """
📋 *Доступные команды:*

/start - главное меню
/stats - статистика отчетов
/search <текст> - поиск по отчетам
/list_json - список JSON отчетов
/list_txt - список TXT отчетов

*Функциональность:*
📊 Просмотр статистики отчетов
📥 Скачивание отчетов (JSON, TXT)
🔍 Поиск по содержимому отчетов

*Отчеты:*
Отчеты автоматически ищутся в папке:
`reports/combined/json/` - JSON отчеты
`reports/combined/txt/` - TXT отчеты
    """
    
    keyboard = get_main_keyboard()
    await message.answer(help_text, reply_markup=keyboard, parse_mode="Markdown")


# Обработчик кнопки "🏠 Главное меню"
@dp.message(F.text == "🏠 Главное меню")
async def handle_main_menu_button(message: Message, state: FSMContext):
    """Обработчик кнопки 'Главное меню'"""
    await state.clear()
    keyboard = get_main_keyboard()
    await message.answer(
        "🏠 *Главное меню*\n\n"
        "Выберите действие:",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )


# Список JSON отчетов
@dp.callback_query(F.data == "list_json")
async def list_json_reports(callback: types.CallbackQuery):
    """Список JSON отчетов"""
    json_files = get_reports_by_type("json")
    
    if not json_files:
        await callback.answer("📭 JSON отчетов не найдено", show_alert=True)
        return
    
    # Создаём кнопки для каждого файла
    buttons = []
    for filename in json_files[:15]:
        # Получаем размер файла
        file_path = REPORTS_DIR / "json" / filename
        size_mb = file_path.stat().st_size / (1024 * 1024) if file_path.exists() else 0
        buttons.append([
            InlineKeyboardButton(
                text=f"📄 {filename[:35]}{'...' if len(filename) > 35 else ''} ({size_mb:.1f}MB)",
                callback_data=f"dl_json_{filename}"
            )
        ])
    
    buttons.append([InlineKeyboardButton(text="🔍 Поиск", callback_data="search_reports")])
    buttons.append([InlineKeyboardButton(text="🏠 Назад", callback_data="download_menu")])
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=buttons)
    
    await callback.message.edit_text(
        f"📊 *Найдено {len(json_files)} JSON отчетов*\n\n"
        "Нажмите на файл для скачивания:",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )
    await callback.answer()


# Список TXT отчетов
@dp.callback_query(F.data == "list_txt")
async def list_txt_reports(callback: types.CallbackQuery):
    """Список TXT отчетов"""
    txt_files = get_reports_by_type("txt")
    
    if not txt_files:
        await callback.answer("📭 TXT отчетов не найдено", show_alert=True)
        return
    
    # Создаём кнопки для каждого файла
    buttons = []
    for filename in txt_files[:15]:
        file_path = REPORTS_DIR / "txt" / filename
        size_kb = file_path.stat().st_size / 1024 if file_path.exists() else 0
        buttons.append([
            InlineKeyboardButton(
                text=f"📝 {filename[:35]}{'...' if len(filename) > 35 else ''} ({size_kb:.0f}KB)",
                callback_data=f"dl_txt_{filename}"
            )
        ])
    
    buttons.append([InlineKeyboardButton(text="🔍 Поиск", callback_data="search_reports")])
    buttons.append([InlineKeyboardButton(text="🏠 Назад", callback_data="download_menu")])
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=buttons)
    
    await callback.message.edit_text(
        f"📝 *Найдено {len(txt_files)} TXT отчетов*\n\n"
        "Нажмите на файл для скачивания:",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )
    await callback.answer()


# Скачивание отчетов
@dp.callback_query(F.data.startswith("dl_json_") | F.data.startswith("dl_txt_"))
async def download_report(callback: types.CallbackQuery):
    """Скачивание отчета"""
    try:
        if callback.data.startswith("dl_json_"):
            filename = callback.data.replace("dl_json_", "")
            report_type = "json"
        else:
            filename = callback.data.replace("dl_txt_", "")
            report_type = "txt"
        
        file_path = REPORTS_DIR / report_type / filename
        
        if not file_path.exists():
            await callback.answer("❌ Файл не найден", show_alert=True)
            logger.warning(f"Файл не найден: {file_path}")
            return
        
        # Проверка размера файла
        file_size = file_path.stat().st_size
        if file_size > 50 * 1024 * 1024:  # 50MB лимит
            await callback.answer("❌ Файл слишком большой (более 50MB)", show_alert=True)
            return
        
        await callback.answer("⬇️ Загружаю файл...")
        
        # Отправляем файл
        file = FSInputFile(str(file_path))
        await callback.message.answer_document(
            file,
            caption=f"📄 {filename}\n\nЗагружен: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nРазмер: {file_size / (1024*1024):.2f} MB" if report_type == "json" else f"Размер: {file_size / 1024:.1f} KB",
            parse_mode="Markdown"
        )
        
        logger.info(f"Файл скачан: {filename} пользователем {callback.from_user.id}")
        
    except Exception as e:
        logger.error(f"Ошибка при скачивании файла: {e}")
        await callback.answer(f"❌ Ошибка: {str(e)}", show_alert=True)


# Меню скачивания отчетов
@dp.callback_query(F.data == "download_menu")
async def download_menu(callback: types.CallbackQuery):
    """Меню скачивания отчетов"""
    stats = get_reports_statistics()
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=f"📊 JSON ({stats['json']['total']})", callback_data="list_json")],
        [InlineKeyboardButton(text=f"📝 TXT ({stats['txt']['total']})", callback_data="list_txt")],
        [InlineKeyboardButton(text="🔍 Поиск", callback_data="search_reports")],
        [InlineKeyboardButton(text="🏠 Главное меню", callback_data="back_to_menu")]
    ])
    
    await callback.message.edit_text(
        f"📥 *Меню отчетов*\n\n"
        f"📊 JSON: {stats['json']['total']} файлов | {stats['json']['total_size_mb']:.1f} MB\n"
        f"📝 TXT: {stats['txt']['total']} файлов | {stats['txt']['total_size_kb']:.0f} KB\n\n"
        f"Выберите формат:",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )
    await callback.answer()


# Поиск по отчетам
@dp.callback_query(F.data == "search_reports")
async def search_reports_prompt(callback: types.CallbackQuery):
    """Запрос на ввод поискового запроса"""
    keyboard = get_back_keyboard()
    await callback.message.answer(
        "🔍 *Поиск по отчетам*\n\n"
        "Введите текст для поиска в отчетах:\n"
        "(например: 'XSS', 'critical', 'subdomain', 'example.com')",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )
    await callback.answer()


# Команда поиска
@dp.message(Command("search"))
async def cmd_search(message: Message):
    """Поиск по отчетам"""
    query = message.text.replace("/search", "").strip()
    
    if not query:
        await message.answer("❌ Введите текст для поиска. Пример: `/search XSS`", parse_mode="Markdown")
        return
    
    await message.answer(f"🔍 Ищу `{query}` в отчетах...", parse_mode="Markdown")
    
    results = []
    query_lower = query.lower()
    
    # Поиск в JSON файлах
    json_dir = REPORTS_DIR / "json"
    if json_dir.exists():
        for file in json_dir.glob("*.json"):
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if query_lower in content.lower():
                        # Подсчитываем количество вхождений
                        count = content.lower().count(query_lower)
                        results.append({
                            "name": file.name,
                            "type": "json",
                            "count": count,
                            "size": file.stat().st_size / (1024 * 1024)
                        })
            except Exception as e:
                logger.error(f"Ошибка при поиске в {file}: {e}")
    
    # Поиск в TXT файлах
    txt_dir = REPORTS_DIR / "txt"
    if txt_dir.exists():
        for file in txt_dir.glob("*.txt"):
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if query_lower in content.lower():
                        count = content.lower().count(query_lower)
                        results.append({
                            "name": file.name,
                            "type": "txt",
                            "count": count,
                            "size": file.stat().st_size / 1024
                        })
            except Exception as e:
                logger.error(f"Ошибка при поиске в {file}: {e}")
    
    if not results:
        await message.answer(f"❌ Ничего не найдено по запросу `{query}`", parse_mode="Markdown")
        return
    
    # Сортируем по количеству вхождений
    results.sort(key=lambda x: x["count"], reverse=True)
    
    result_text = f"🔍 *Результаты поиска: '{query}'*\n\n"
    result_text += f"📊 Найдено в {len(results)} файлах:\n\n"
    
    for i, res in enumerate(results[:10], 1):
        size_info = f"{res['size']:.1f}MB" if res['type'] == 'json' else f"{res['size']:.0f}KB"
        result_text += f"{i}. `{res['name'][:50]}`\n"
        result_text += f"   📁 Тип: {res['type'].upper()} | 📦 {size_info} | 🔥 {res['count']} совпад.\n"
    
    if len(results) > 10:
        result_text += f"\n... и еще {len(results) - 10} файлов"
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📥 Скачать найденные", callback_data=f"download_search_{query}")],
        [InlineKeyboardButton(text="🏠 Главное меню", callback_data="back_to_menu")]
    ])
    
    await message.answer(result_text, reply_markup=keyboard, parse_mode="Markdown")


# Команда статистики
@dp.message(Command("stats"))
async def cmd_stats(message: Message):
    """Команда для быстрой статистики"""
    await handle_stats_button(message)


# Команда для быстрого списка JSON отчетов
@dp.message(Command("list_json"))
async def cmd_list_json(message: Message):
    """Команда для быстрого списка JSON отчетов"""
    json_files = get_reports_by_type("json")
    
    if not json_files:
        await message.answer("📭 JSON отчетов не найдено")
        return
    
    text = "📊 *JSON отчеты:*\n\n"
    for i, filename in enumerate(json_files[:20], 1):
        file_path = REPORTS_DIR / "json" / filename
        size_mb = file_path.stat().st_size / (1024 * 1024)
        mtime = datetime.fromtimestamp(file_path.stat().st_mtime).strftime("%Y-%m-%d")
        text += f"{i}. `{filename}` ({size_mb:.2f} MB) - {mtime}\n"
    
    await message.answer(text, parse_mode="Markdown")


# Команда для быстрого списка TXT отчетов
@dp.message(Command("list_txt"))
async def cmd_list_txt(message: Message):
    """Команда для быстрого списка TXT отчетов"""
    txt_files = get_reports_by_type("txt")
    
    if not txt_files:
        await message.answer("📭 TXT отчетов не найдено")
        return
    
    text = "📝 *TXT отчеты:*\n\n"
    for i, filename in enumerate(txt_files[:20], 1):
        file_path = REPORTS_DIR / "txt" / filename
        size_kb = file_path.stat().st_size / 1024
        mtime = datetime.fromtimestamp(file_path.stat().st_mtime).strftime("%Y-%m-%d")
        text += f"{i}. `{filename}` ({size_kb:.1f} KB) - {mtime}\n"
    
    await message.answer(text, parse_mode="Markdown")


# Кнопка "Назад" в главное меню
@dp.callback_query(F.data == "back_to_menu")
async def back_to_menu(callback: types.CallbackQuery):
    """Возврат в главное меню"""
    keyboard = get_main_keyboard()
    
    # Отвечаем на callback и отправляем новое сообщение
    await callback.answer()
    await callback.message.answer(
        "🏠 *Главное меню*\n\nВыберите действие:",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )


@dp.error()
async def error_handler(update: types.Update, exception: Exception):
    """Глобальный обработчик ошибок"""
    logger.error(f"Произошла ошибка: {exception}")
    return True


# Запуск бота
async def main():
    print("=" * 50)
    print("🤖 Бот CyberScope (режим аналитики) запущен")
    print("=" * 50)
    print(f"📁 Папка отчетов: {REPORTS_DIR}")
    
    # Проверяем наличие папки отчетов
    if REPORTS_DIR.exists():
        json_count = len(list((REPORTS_DIR / "json").glob("*"))) if (REPORTS_DIR / "json").exists() else 0
        txt_count = len(list((REPORTS_DIR / "txt").glob("*"))) if (REPORTS_DIR / "txt").exists() else 0
        print(f"📊 Найдено отчетов JSON: {json_count}")
        print(f"📝 Найдено отчетов TXT: {txt_count}")
        print(f"💾 Общий размер: ~{sum(f.stat().st_size for f in (REPORTS_DIR / 'json').glob('*')) / (1024*1024):.1f} MB")
    else:
        print(f"⚠️ Папка отчетов не найдена: {REPORTS_DIR}")
    
    print("=" * 50)
    print("⏳ Ожидание сообщений...")
    print("=" * 50)
    
    try:
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    except Exception as e:
        logger.error(f"Ошибка при запуске бота: {e}")
        print(f"❌ Ошибка подключения: {e}")
    finally:
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n✋ Бот остановлен пользователем")
    except Exception as e:
        logger.critical(f"Критическая ошибка: {e}")
        print(f"❌ Критическая ошибка: {e}")