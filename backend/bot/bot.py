import os
import asyncio
import logging
import aiohttp
import json
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command, CommandStart, StateFilter
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton, FSInputFile
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000/api")
REPORTS_DIR = Path(__file__).parent.parent / "reports" / "combined"

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN не найден в переменных окружения!")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# Логирование
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Хранилище активных сканирований
active_scans = {}


def get_reports_by_type(report_type: str) -> list:
    """Получить список отчетов по типу (json или txt)"""
    type_dir = REPORTS_DIR / report_type
    
    if not type_dir.exists():
        return []
    
    files = sorted(type_dir.glob("*"), key=lambda x: x.stat().st_mtime, reverse=True)
    return [f.name for f in files if f.is_file()]


# Определение состояний для FSM
class ScanForm(StatesGroup):
    target = State()
    tools = State()
    allow_internal = State()
    scanning = State()


class ReportForm(StatesGroup):
    viewing_reports = State()

# Обработчик команды /start
@dp.message(CommandStart())
async def cmd_start(message: Message):
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔍 Начать сканирование", callback_data="start_scan")],
        [InlineKeyboardButton(text="� Скачать отчеты", callback_data="download_menu")],
        [InlineKeyboardButton(text="❓ Справка", callback_data="help_info")]
    ])
    
    await message.answer(
        f"Привет, {message.from_user.first_name}! 👋\n\n"
        "Я CyberScope бот для сканирования безопасности.\n\n"
        "*Возможности:*\n"
        "🔍 Запуск различных сканирований\n"
        "📥 Скачивание отчетов (JSON, TXT)\n"
        "⚡ Быстрая обработка результатов\n",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )


# Обработчик команды /help
@dp.message(Command("help"))
async def cmd_help(message: Message):
    help_text = """
📋 *Доступные команды:*

/start - начать работу
/help - показать эту справку
/scan - запустить сканирование
/reports - получить список отчетов
/cancel - отмена текущей операции

*Доступные инструменты сканирования:*
🔹 wappalyzer - определение технологий
🔹 osint - поиск поддоменов и информации
🔹 web - веб-разведка (URL и директории)
🔹 retire - уязвимости JS библиотек

*Как пользоваться:*
1. Используйте кнопки в главном меню
2. Введите цель сканирования
3. Выберите инструменты
4. Дождитесь завершения
5. Скачайте отчет
    """
    await message.answer(help_text, parse_mode="Markdown")


# Обработчик команды /cancel
@dp.message(Command("cancel"))
async def cmd_cancel(message: Message, state: FSMContext):
    await state.clear()
    await message.answer("❌ Операция отменена.")


# Обработчик callback - начать сканирование
@dp.callback_query(F.data == "start_scan")
async def process_start_scan(callback: types.CallbackQuery, state: FSMContext):
    await callback.message.answer(
        "📍 Введите цель сканирования:\n"
        "(например: example.com или http://example.com:5000)"
    )
    await state.set_state(ScanForm.target)
    await callback.answer()


# Обработчик ввода target
@dp.message(StateFilter(ScanForm.target))
async def process_target(message: Message, state: FSMContext):
    if not message.text or len(message.text.strip()) < 3:
        await message.answer("❌ Некорректный target. Попробуйте еще раз.")
        return
    
    await state.update_data(target=message.text.strip(), user_id=message.from_user.id)
    
    # Выбор инструментов
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔹 Wappalyzer", callback_data="tool_wappalyzer")],
        [InlineKeyboardButton(text="🔹 OSINT", callback_data="tool_osint")],
        [InlineKeyboardButton(text="🔹 Web", callback_data="tool_web")],
        [InlineKeyboardButton(text="🔹 Retire", callback_data="tool_retire")],
        [InlineKeyboardButton(text="✅ Все инструменты", callback_data="tool_all")],
        [InlineKeyboardButton(text="⏭️ Продолжить", callback_data="tools_selected")]
    ])
    
    await message.answer(
        f"✅ Target: `{message.text.strip()}`\n\n"
        "🛠️ Выберите инструменты для сканирования:\n"
        "(Можно нажать несколько раз или выбрать 'Все инструменты')",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )
    await state.set_state(ScanForm.tools)


# Обработчик выбора инструментов
@dp.callback_query(F.data.startswith("tool_"))
async def process_tool_selection(callback: types.CallbackQuery, state: FSMContext):
    data = await state.get_data()
    tools = data.get("tools", [])
    
    tool_map = {
        "tool_wappalyzer": "wappalyzer",
        "tool_osint": "osint",
        "tool_web": "web",
        "tool_retire": "retire",
        "tool_all": ["wappalyzer", "osint", "web", "retire"]
    }
    
    if callback.data == "tool_all":
        tools = ["wappalyzer", "osint", "web", "retire"]
        await callback.message.edit_text(
            f"✅ Выбраны все инструменты: wappalyzer, osint, web, retire\n\n"
            "Нажмите 'Продолжить' для запуска сканирования",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="⏭️ Продолжить", callback_data="tools_selected")]
            ])
        )
    elif callback.data == "tools_selected":
        pass
    else:
        tool = tool_map[callback.data]
        if tool not in tools:
            tools.append(tool)
        else:
            tools.remove(tool)
        
        tools_text = ", ".join(tools) if tools else "не выбраны"
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔹 Wappalyzer", callback_data="tool_wappalyzer")],
            [InlineKeyboardButton(text="🔹 OSINT", callback_data="tool_osint")],
            [InlineKeyboardButton(text="🔹 Web", callback_data="tool_web")],
            [InlineKeyboardButton(text="🔹 Retire", callback_data="tool_retire")],
            [InlineKeyboardButton(text="✅ Все инструменты", callback_data="tool_all")],
            [InlineKeyboardButton(text="⏭️ Продолжить", callback_data="tools_selected")]
        ])
        
        await callback.message.edit_text(
            f"✅ Выбранные инструменты: {tools_text}",
            reply_markup=keyboard
        )
    
    await state.update_data(tools=tools)
    await callback.answer()


# Запуск сканирования
@dp.callback_query(F.data == "tools_selected")
async def process_tools_selected(callback: types.CallbackQuery, state: FSMContext):
    data = await state.get_data()
    tools = data.get("tools", [])
    target = data.get("target")
    user_id = data.get("user_id")
    
    if not tools:
        await callback.answer("❌ Выберите хотя бы один инструмент!", show_alert=True)
        return
    
    tools_str = ",".join(tools)
    scan_id = f"{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    await state.update_data(scan_id=scan_id)
    await state.set_state(ScanForm.scanning)
    
    await callback.message.edit_text(
        f"🔄 Началось сканирование...\n\n"
        f"Target: `{target}`\n"
        f"Инструменты: {tools_str}\n\n"
        f"Scan ID: `{scan_id}`\n\n"
        "⏳ Это может занять несколько минут..."
    )
    await callback.answer()
    
    # Запуск асинхронного сканирования
    asyncio.create_task(run_scan(callback.message, target, tools_str, scan_id, state))


async def run_scan(message: Message, target: str, tools: str, scan_id: str, state: FSMContext):
    """Запуск сканирования через API"""
    try:
        async with aiohttp.ClientSession() as session:
            url = f"{API_BASE_URL}/run-selected-tools"
            params = {
                "target": target,
                "tools": tools,
                "allow_internal": True
            }
            
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=3600)) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    
                    # Формируем отчет о результатах
                    report_text = f"✅ *Сканирование завершено!*\n\n"
                    report_text += f"Scan ID: `{scan_id}`\n"
                    report_text += f"Target: `{target}`\n\n"
                    
                    for tool, tool_result in result.get("results", {}).items():
                        status = "✅" if tool_result.get("status") == "success" else "❌"
                        report_text += f"{status} {tool.upper()}\n"
                    
                    # Кнопки для скачивания отчетов
                    keyboard = InlineKeyboardMarkup(inline_keyboard=[
                        [InlineKeyboardButton(text="📄 Скачать JSON", callback_data=f"download_json_{scan_id}")],
                        [InlineKeyboardButton(text="📝 Скачать TXT", callback_data=f"download_txt_{scan_id}")],
                        [InlineKeyboardButton(text="📊 К отчетам", callback_data="view_reports")],
                        [InlineKeyboardButton(text="🔍 Новое сканирование", callback_data="start_scan")]
                    ])
                    
                    await message.answer(report_text, reply_markup=keyboard, parse_mode="Markdown")
                    await state.clear()
                else:
                    await message.answer(f"❌ Ошибка сканирования: {resp.status}")
                    await state.clear()
    except asyncio.TimeoutError:
        await message.answer("⏱️ Превышено время ожидания сканирования. Попробуйте позже.")
        await state.clear()
    except Exception as e:
        logger.error(f"Ошибка при сканировании: {e}")
        await message.answer(f"❌ Ошибка: {str(e)}")
        await state.clear()


# Меню скачивания отчетов
@dp.callback_query(F.data == "download_menu")
async def download_menu(callback: types.CallbackQuery):
    """Меню скачивания отчетов"""
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📊 JSON отчеты", callback_data="list_json")],
        [InlineKeyboardButton(text="📝 TXT отчеты", callback_data="list_txt")],
        [InlineKeyboardButton(text="🏠 Назад", callback_data="back_to_menu")]
    ])
    
    await callback.message.edit_text(
        "📥 *Меню скачивания отчетов*\n\n"
        "Выберите формат отчета:",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )
    await callback.answer()


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
    for filename in json_files[:10]:
        buttons.append([
            InlineKeyboardButton(
                text=f"📄 {filename[:45]}{'...' if len(filename) > 45 else ''}",
                callback_data=f"dl_json_{filename}"
            )
        ])
    
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
    for filename in txt_files[:10]:
        buttons.append([
            InlineKeyboardButton(
                text=f"📝 {filename[:45]}{'...' if len(filename) > 45 else ''}",
                callback_data=f"dl_txt_{filename}"
            )
        ])
    
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
            caption=f"📄 {filename}\n\nЗагруженo в {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            parse_mode="Markdown"
        )
        
        logger.info(f"Файл скачан: {filename} пользователем {callback.from_user.id}")
        
    except Exception as e:
        logger.error(f"Ошибка при скачивании файла: {e}")
        await callback.answer(f"❌ Ошибка: {str(e)}", show_alert=True)


# Обработчик просмотра отчетов (старый)
@dp.callback_query(F.data == "view_reports")
async def process_view_reports(callback: types.CallbackQuery, state: FSMContext):
    await download_menu(callback)



# Стартовое меню
@dp.callback_query(F.data == "start_menu")
async def process_start_menu(callback: types.CallbackQuery):
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔍 Начать сканирование", callback_data="start_scan")],
        [InlineKeyboardButton(text="� Скачать отчеты", callback_data="download_menu")],
        [InlineKeyboardButton(text="❓ Справка", callback_data="help_info")]
    ])
    
    await callback.message.edit_text(
        "🏠 *Главное меню*\n\n"
        "Выберите действие:",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )
    await callback.answer()


# Кнопка "Назад" в главное меню
@dp.callback_query(F.data == "back_to_menu")
async def back_to_menu(callback: types.CallbackQuery):
    await process_start_menu(callback)


# Справка через callback
@dp.callback_query(F.data == "help_info")
async def process_help_callback(callback: types.CallbackQuery):
    help_text = """
📋 *Доступные команды:*

/start - главное меню
/help - справка
/scan - быстрое сканирование
/list_json - список JSON отчетов
/list_txt - список TXT отчетов
/cancel - отмена операции

*Функциональность:*
🔍 Запуск сканирования через API
📥 Скачивание отчетов (JSON, TXT)
📊 Просмотр доступных отчетов

*Отчеты:*
Отчеты автоматически ищутся в папке:
`reports/combined/json/` - JSON отчеты
`reports/combined/txt/` - TXT отчеты
    """
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🏠 Главное меню", callback_data="start_menu")]
    ])
    
    await callback.message.edit_text(help_text, reply_markup=keyboard, parse_mode="Markdown")
    await callback.answer()


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
        text += f"{i}. `{filename}` ({size_mb:.2f} MB)\n"
    
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
        text += f"{i}. `{filename}` ({size_kb:.1f} KB)\n"
    
    await message.answer(text, parse_mode="Markdown")


@dp.errors()
async def error_handler(update: types.Update, exception: Exception):
    logger.error(f"Произошла ошибка: {exception}")
    return True

# Запуск бота
async def main():
    print("=" * 50)
    print("🤖 Бот CyberScope запущен")
    print("=" * 50)
    print(f"📁 Папка отчетов: {REPORTS_DIR}")
    print(f"API Base URL: {API_BASE_URL}")
    
    # Проверяем наличие папки отчетов
    if REPORTS_DIR.exists():
        json_count = len(list((REPORTS_DIR / "json").glob("*"))) if (REPORTS_DIR / "json").exists() else 0
        txt_count = len(list((REPORTS_DIR / "txt").glob("*"))) if (REPORTS_DIR / "txt").exists() else 0
        print(f"📊 Найдено отчетов JSON: {json_count}")
        print(f"📝 Найдено отчетов TXT: {txt_count}")
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