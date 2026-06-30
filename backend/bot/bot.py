import os
import socket
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
from aiogram.fsm.state import State, StatesGroup

# Добавляем импорт для LM Studio (через OpenAI-совместимый API)
try:
    from openai import OpenAI
    LM_STUDIO_AVAILABLE = True
except ImportError:
    LM_STUDIO_AVAILABLE = False
    print("⚠️ openai не установлен. Установите: pip install openai")

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
# Для SDK LM Studio используем базовый URL без /v1
LM_STUDIO_URL = os.getenv("LM_STUDIO_URL", "http://127.0.0.1:1234")

if os.path.exists("/app/reports/combined"):
    REPORTS_DIR = Path("/app/reports/combined")
else:
    REPORTS_DIR = Path(__file__).parent.parent / "reports" / "combined"

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN не найден в переменных окружения!")

from aiogram.client.session.aiohttp import AiohttpSession
from aiohttp import TCPConnector

# Принудительно используем IPv4 — в Docker IPv6 часто "объявлен", но фактически
# недоступен (Network is unreachable), из-за чего aiohttp подвисает на попытке
# подключения по IPv6 и в итоге ловит таймаут вместо мгновенного фоллбэка на IPv4.
_session = AiohttpSession()
_session._connector_init["family"] = socket.AF_INET

bot = Bot(token=BOT_TOKEN, session=_session)
dp = Dispatcher()

# Логирование
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Состояния для FSM
class ChatStates(StatesGroup):
    ai_chat = State()

# Инициализация LM Studio
lm_client = None
lm_model = None

def init_lm_studio():
    """Инициализация LM Studio"""
    global lm_client, lm_model

    if not LM_STUDIO_AVAILABLE:
        logger.warning("openai пакет не доступен")
        return False

    try:
        logger.info(f"Подключение к LM Studio по адресу: {LM_STUDIO_URL}")

        # Создаем OpenAI-совместимый клиент для LM Studio
        lm_client = OpenAI(base_url=f"{LM_STUDIO_URL}/v1", api_key="lm-studio")

        # Проверяем подключение и берем загруженную модель (если есть)
        try:
            models = lm_client.models.list()
            if models.data:
                lm_model = models.data[0].id
                logger.info(f"LM Studio: используем модель {lm_model}")
            else:
                # Модели не загружены — LM Studio поддерживает just-in-time загрузку.
                # Передаем model=None; при запросе LM Studio сам подберет модель.
                lm_model = None
                logger.warning("LM Studio: модели не загружены, будет использована just-in-time загрузка")
        except Exception:
            lm_model = None

        logger.info("LM Studio клиент успешно инициализирован")
        return True
    except Exception as e:
        logger.error(f"Ошибка инициализации LM Studio: {e}")
        return False


# Инициализируем LM Studio при запуске
lm_ready = init_lm_studio()

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
            [KeyboardButton(text='🤖 Чат с AI'), KeyboardButton(text='📊 Статистика')],
            [KeyboardButton(text='📥 Отчеты'), KeyboardButton(text='❓ Справка')]
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

def get_chat_keyboard():
    """Клавиатура для чата с AI"""
    keyboard = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text='🔄 Очистить историю')],
            [KeyboardButton(text='🏠 Главное меню')]
        ],
        resize_keyboard=True
    )
    return keyboard

# Обработчик команды /start
@dp.message(CommandStart())
async def cmd_start(message: Message):
    keyboard = get_main_keyboard()
    
    # Проверяем статус LM Studio
    lm_status = "✅ Доступен" if lm_ready else "❌ Недоступен"
    
    await message.answer(
        f"Привет, {message.from_user.first_name}! 👋\n\n"
        "Я CyberScope бот для просмотра и анализа отчетов безопасности с AI-помощником.\n\n"
        "*Возможности:*\n"
        "🤖 Чат с AI (LM Studio)\n"
        "📊 Просмотр статистики отчетов\n"
        "📥 Скачивание отчетов (JSON, TXT)\n"
        "📈 Аналитика по уязвимостям\n"
        "🔍 Поиск по отчетам\n\n"
        f"*Статус AI:* {lm_status}",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )

# Обработчик команды /lmstatus
@dp.message(Command("lmstatus"))
async def cmd_lm_status(message: Message):
    """Проверка статуса LM Studio"""
    if lm_ready:
        status_text = (
            "✅ *LM Studio подключен*\n\n"
            f"📍 URL: {LM_STUDIO_URL}\n"
            "📊 Статус: Активен\n"
            "🤖 Модель: Загружена\n\n"
            "💡 Для общения с AI нажмите кнопку '🤖 Чат с AI'"
        )
    else:
        status_text = (
            "❌ *LM Studio не подключен*\n\n"
            f"📍 URL: {LM_STUDIO_URL}\n"
            "📊 Статус: Недоступен\n\n"
            "*Проверьте:*\n"
            "1. Запущен ли LM Studio\n"
            "2. Правильный ли URL (должен быть http://127.0.0.1:1234)\n"
            "3. Загружена ли модель в LM Studio\n"
            "4. Установлен ли пакет: `pip install lmstudio`\n\n"
            "📌 *Инструкция:*\n"
            "- Откройте LM Studio\n"
            "- Перейдите во вкладку 'Developer'\n"
            "- Нажмите 'Start' для запуска сервера\n"
            "- Загрузите модель во вкладке 'Discover'"
        )
    
    await message.answer(status_text, parse_mode="Markdown")

# Обработчик кнопки "🤖 Чат с AI"
@dp.message(F.text == "🤖 Чат с AI")
async def handle_ai_chat_start(message: Message, state: FSMContext):
    """Начать чат с AI"""
    if not lm_ready:
        await message.answer(
            "❌ *AI помощник недоступен*\n\n"
            "Проверьте, что:\n"
            "1. Установлен LM Studio: `pip install lmstudio`\n"
            "2. Запущен сервер LM Studio (вкладка Developer → Start)\n"
            "3. Загружена модель в LM Studio\n\n"
            "Для проверки статуса используйте команду `/lmstatus`\n"
            "После настройки перезапустите бота.",
            parse_mode="Markdown"
        )
        return
    
    # Создаем новый чат для пользователя
    await state.set_state(ChatStates.ai_chat)
    await state.update_data(chat_history=[])
    
    keyboard = get_chat_keyboard()
    
    await message.answer(
        "🤖 *Чат с AI помощником*\n\n"
        "Задайте любой вопрос, и я отвечу с помощью AI.\n"
        "Я специализируюсь на кибербезопасности, но могу помочь и с другими вопросами.\n\n"
        "💡 *Совет:* Для получения наилучших результатов формулируйте вопросы четко.\n"
        "🔄 Используйте кнопку 'Очистить историю', чтобы начать новый диалог.\n"
        "🏠 Для выхода в главное меню нажмите соответствующую кнопку.",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )

# Обработка сообщений в режиме чата с AI
@dp.message(ChatStates.ai_chat)
async def handle_ai_chat(message: Message, state: FSMContext):
    """Обработка сообщений в чате с AI"""
    # Проверка на системные команды
    if message.text == "🔄 Очистить историю":
        await state.update_data(chat_history=[])
        await message.answer(
            "🔄 *История диалога очищена*\n\n"
            "Теперь вы можете начать новый диалог.",
            parse_mode="Markdown"
        )
        return
    
    if message.text == "🏠 Главное меню":
        await state.clear()
        keyboard = get_main_keyboard()
        await message.answer(
            "🏠 *Главное меню*\n\nВыберите действие:",
            reply_markup=keyboard,
            parse_mode="Markdown"
        )
        return
    
    # Отправляем статус "печатает"
    await bot.send_chat_action(message.chat.id, "typing")
    
    try:
        # Получаем историю чата
        data = await state.get_data()
        chat_history = data.get("chat_history", [])
        
        # Добавляем сообщение в историю
        user_msg = message.text
        chat_history.append({"role": "user", "content": user_msg})
        
        # Если история слишком длинная, ограничиваем
        if len(chat_history) > 20:
            chat_history = chat_history[-20:]
        
        # Формируем системный промпт
        system_prompt = (
            "Ты — полезный, дружелюбный и профессиональный ИИ-ассистент. "
            "Ты помогаешь с вопросами по кибербезопасности, анализу отчетов и общим вопросам. "
            "Отвечай кратко и по делу, но будь вежливым."
        )
        
        # Используем глобальные переменные клиента и модели
        global lm_client, lm_model

        # Если модель не определена при старте — пробуем получить актуальный список
        if lm_model is None:
            try:
                models = lm_client.models.list()
                if models.data:
                    lm_model = models.data[0].id
            except Exception:
                pass

        # "auto" — LM Studio сам выберет/загрузит модель (just-in-time)
        model_to_use = lm_model if lm_model else "auto"

        # Формируем список сообщений для API
        messages_for_api = [{"role": "system", "content": system_prompt}]
        for msg in chat_history:
            messages_for_api.append({"role": msg["role"], "content": msg["content"]})

        # Получаем ответ через OpenAI-совместимый API
        completion = lm_client.chat.completions.create(
            model=model_to_use,
            messages=messages_for_api,
            max_tokens=1024,
            temperature=0.7,
        )
        # Безопасное извлечение ответа
        choice = completion.choices[0] if completion.choices else None
        response = None
        if choice:
            response = choice.message.content
            # DeepSeek R1 и reasoning-модели могут класть ответ в reasoning_content
            if not response:
                rc = getattr(choice.message, 'reasoning_content', None)
                if rc:
                    response = rc

        if not response:
            logger.warning(f"Пустой ответ от модели. finish_reason={choice.finish_reason if choice else 'N/A'}")
            response = "⚠️ Модель вернула пустой ответ. Попробуйте переформулировать вопрос."

        # Добавляем ответ в историю
        chat_history.append({"role": "assistant", "content": response})
        await state.update_data(chat_history=chat_history)
        
        # Отправляем ответ
        keyboard = get_chat_keyboard()
        await message.answer(
            f"🤖 *AI:* {response}",
            reply_markup=keyboard,
            parse_mode="Markdown"
        )
        
    except Exception as e:
        logger.error(f"Ошибка в AI чате: {e}")
        await message.answer(
            f"❌ *Произошла ошибка*\n\n"
            f"Текст ошибки: {str(e)}\n\n"
            "Пожалуйста, попробуйте еще раз или очистите историю чата.",
            parse_mode="Markdown"
        )

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
/lmstatus - статус LM Studio

*Функциональность:*
🤖 Чат с AI помощником (LM Studio)
📊 Просмотр статистики отчетов
📥 Скачивание отчетов (JSON, TXT)
🔍 Поиск по содержимому отчетов

*Отчеты:*
Отчеты автоматически ищутся в папке:
`reports/combined/json/` - JSON отчеты
`reports/combined/txt/` - TXT отчеты

*AI помощник:*
Для общения с AI нажмите кнопку "🤖 Чат с AI"
Используйте кнопку "🔄 Очистить историю" для нового диалога

*Настройка LM Studio:*
1. Установите: pip install lmstudio
2. Запустите LM Studio
3. Во вкладке Developer включите сервер (Start)
4. Загрузите модель во вкладке Discover
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
    
    # Проверяем статус LM Studio
    print("=" * 50)
    if lm_ready:
        print(f"✅ LM Studio подключен и готов к работе")
        print(f"📍 URL: {LM_STUDIO_URL}")
    else:
        print("❌ LM Studio не доступен")
        print("   Проверьте:")
        print("   1. Установлен пакет: pip install lmstudio")
        print("   2. Запущен сервер LM Studio (Developer → Start)")
        print("   3. Загружена модель в LM Studio")
        print(f"   4. Правильный URL: {LM_STUDIO_URL}")
        print("\n   📌 Инструкция по настройке:")
        print("   - Откройте LM Studio")
        print("   - Перейдите во вкладку 'Developer'")
        print("   - Нажмите 'Start' для запуска сервера")
        print("   - Загрузите модель во вкладке 'Discover'")
    
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