"""
Планировщик сканирований
Отслеживает и выполняет запланированные задачи сканирования
"""

import asyncio
import datetime
import json
import threading
from pathlib import Path
from typing import Dict, List, Optional, Callable
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ScanScheduler:
    """Планировщик для выполнения запланированных сканирований"""
    
    def __init__(self, data_dir: str = None):
        """
        Инициализация планировщика
        
        Args:
            data_dir: Директория для сохранения статуса задач (по умолчанию backend/)
        """
        if data_dir is None:
            data_dir = Path(__file__).parent
        
        self.data_dir = Path(data_dir)
        self.tasks_file = self.data_dir / "scheduled_tasks.json"
        self.tasks: Dict[str, dict] = {}
        self.running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        self.scan_callbacks: Dict[str, Callable] = {}
        self._load_tasks()
        
    def _load_tasks(self):
        """Загрузить задачи из файла"""
        if self.tasks_file.exists():
            try:
                with open(self.tasks_file, 'r', encoding='utf-8') as f:
                    self.tasks = json.load(f)
                    logger.info(f"✓ Загружено {len(self.tasks)} запланированных задач")
            except Exception as e:
                logger.error(f"✗ Ошибка загрузки задач: {e}")
                self.tasks = {}
        else:
            self.tasks = {}
    
    def _save_tasks(self):
        """Сохранить задачи в файл"""
        try:
            with open(self.tasks_file, 'w', encoding='utf-8') as f:
                json.dump(self.tasks, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"✗ Ошибка сохранения задач: {e}")
    
    def add_task(self, task: dict) -> str:
        """
        Добавить новую задачу
        
        Args:
            task: Словарь с параметрами задачи
            
        Returns:
            task_id: ID добавленной задачи
        """
        task_id = str(task.get('id', int(datetime.datetime.now().timestamp() * 1000)))
        task['status'] = 'pending'
        task['created_at'] = datetime.datetime.now().isoformat()
        task['last_run'] = None
        
        self.tasks[task_id] = task
        self._save_tasks()
        logger.info(f"✓ Задача добавлена: {task_id}")
        return task_id
    
    def update_task(self, task_id: str, task: dict):
        """Обновить существующую задачу"""
        if task_id in self.tasks:
            self.tasks[task_id].update(task)
            self._save_tasks()
            logger.info(f"✓ Задача обновлена: {task_id}")
    
    def remove_task(self, task_id: str) -> bool:
        """Удалить задачу по ID"""
        if task_id in self.tasks:
            del self.tasks[task_id]
            self._save_tasks()
            logger.info(f"✓ Задача удалена: {task_id}")
            return True
        return False
    
    def get_tasks(self) -> List[dict]:
        """Получить все задачи"""
        return list(self.tasks.values())
    
    def get_task(self, task_id: str) -> Optional[dict]:
        """Получить задачу по ID"""
        return self.tasks.get(task_id)
    
    def register_callback(self, tool: str, callback: Callable):
        """
        Зарегистрировать callback функцию для запуска при срабатывании задачи
        
        Args:
            tool: Имя инструмента (scanner, nuclei, osint и т.д.)
            callback: Асинхронная функция для запуска
        """
        self.scan_callbacks[tool] = callback
        logger.info(f"✓ Callback зарегистрирован для {tool}")
    
    def _should_run_task(self, task: dict) -> bool:
        """Проверить должна ли задача запуститься"""
        now = datetime.datetime.now()
        try:
            next_run_str = task.get('nextRun', now.isoformat())
            # Парсим строку как naive datetime (убираем timezone информацию)
            next_run = datetime.datetime.fromisoformat(next_run_str.replace('Z', '+00:00'))
            # Удаляем информацию о часовом поясе если она есть
            if next_run.tzinfo is not None:
                next_run = next_run.replace(tzinfo=None)
        except Exception as e:
            logger.error(f"Ошибка парсинга nextRun: {e}")
            return False
        
        # Если это прошлое время - не запускаем
        if next_run > now:
            return False
        
        # Если уже запускалась в этот момент - не запускаем дважды
        if task.get('last_run'):
            try:
                last_run_str = task['last_run']
                last_run = datetime.datetime.fromisoformat(last_run_str.replace('Z', '+00:00'))
                # Удаляем информацию о часовом поясе если она есть
                if last_run.tzinfo is not None:
                    last_run = last_run.replace(tzinfo=None)
                # Если запускалась менее 5 минут назад - пропускаем
                if (now - last_run).total_seconds() < 300:
                    return False
            except Exception as e:
                logger.error(f"Ошибка парсинга last_run: {e}")
                pass
        
        return True
    
    def _calculate_next_run(self, task: dict) -> datetime.datetime:
        """Рассчитать следующее время запуска задачи"""
        now = datetime.datetime.now()
        # Убеждаемся что now не имеет timezone информации
        if now.tzinfo is not None:
            now = now.replace(tzinfo=None)
        
        schedule_type = task.get('type', 'once')
        schedule_time = task.get('time', '00:00')
        
        try:
            hours, minutes = map(int, schedule_time.split(':'))
        except:
            return now
        
        if schedule_type == 'once':
            # Расписание на один раз - больше не запускаем
            return now + datetime.timedelta(days=365)
        
        elif schedule_type == 'daily':
            next_run = now.replace(hour=hours, minute=minutes, second=0, microsecond=0)
            if next_run <= now:
                next_run += datetime.timedelta(days=1)
            return next_run
        
        elif schedule_type == 'weekly':
            days = [int(d) for d in task.get('days', [])]
            if not days:
                return now + datetime.timedelta(days=1)
            
            next_run = now.replace(hour=hours, minute=minutes, second=0, microsecond=0)
            current_day = now.weekday()
            
            # Найти следующий день недели
            for day in sorted(days):
                if day > current_day:
                    next_run += datetime.timedelta(days=day - current_day)
                    return next_run
            
            # Если не нашли - перейти на первый день на следующей неделе
            first_day = min(days)
            days_until_first = (7 - current_day) + first_day
            next_run += datetime.timedelta(days=days_until_first)
            return next_run
        
        elif schedule_type == 'monthly':
            day = task.get('monthDay', 1)
            next_run = now.replace(day=day, hour=hours, minute=minutes, second=0, microsecond=0)
            if next_run <= now:
                # Перейти на следующий месяц
                if next_run.month == 12:
                    next_run = next_run.replace(year=next_run.year + 1, month=1)
                else:
                    next_run = next_run.replace(month=next_run.month + 1)
            return next_run
        
        return now + datetime.timedelta(days=1)
    
    async def _execute_task(self, task_id: str, task: dict):
        """Выполнить задачу сканирования"""
        logger.info(f"🚀 Запуск задачи: {task_id}")
        logger.info(f"   Цель: {task.get('query')}")
        logger.info(f"   Инструменты: {', '.join(task.get('activeTools', []))}")
        
        # Создаем папку для этого запуска сканирования
        scan_run_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_folder = f"scheduled_{task_id}_{scan_run_id}"
        
        # Обновляем в задаче время последнего запуска
        task['last_run'] = datetime.datetime.now().isoformat()
        task['status'] = 'running'
        task['last_scan_folder'] = scan_folder
        task['last_scan_time'] = scan_run_id
        
        # Вычисляем следующее время запуска
        task['nextRun'] = self._calculate_next_run(task).isoformat()
        self.update_task(task_id, task)
        
        try:
            scan_results = []
            
            # Запускаем каждый инструмент
            for tool in task.get('activeTools', []):
                if tool in self.scan_callbacks:
                    callback = self.scan_callbacks[tool]
                    try:
                        logger.info(f"   ► Запуск {tool}...")
                        result = await callback(
                            target=task['query'],
                            allow_internal=task.get('allowInternal', False),
                            task_id=scan_folder  # Передаем ID папки вместо task_id
                        )
                        scan_results.append({
                            'tool': tool,
                            'status': 'completed',
                            'result': result
                        })
                        logger.info(f"   ✓ {tool} завершен")
                    except Exception as e:
                        logger.error(f"   ✗ Ошибка при запуске {tool}: {e}")
                        scan_results.append({
                            'tool': tool,
                            'status': 'failed',
                            'error': str(e)
                        })
                else:
                    logger.warning(f"   ⚠ Callback для {tool} не зарегистрирован")
            
            task['status'] = 'completed'
            task['scan_results'] = scan_results
            logger.info(f"✓ Задача завершена: {task_id}")
            logger.info(f"   📁 Папка отчетов: {scan_folder}")
            
        except Exception as e:
            task['status'] = 'failed'
            task['error'] = str(e)
            logger.error(f"✗ Ошибка при выполнении задачи {task_id}: {e}")
        
        finally:
            self.update_task(task_id, task)
    
    async def _scheduler_loop(self):
        """Главный цикл планировщика"""
        logger.info("📅 Планировщик запущен")
        
        while self.running:
            try:
                # Проверяем каждую задачу
                for task_id, task in list(self.tasks.items()):
                    if task.get('status') != 'disabled' and self._should_run_task(task):
                        # Запускаем задачу в отдельной задаче asyncio
                        asyncio.create_task(self._execute_task(task_id, task))
                
                # Ждем 60 секунд перед следующей проверкой
                await asyncio.sleep(60)
                
            except Exception as e:
                logger.error(f"✗ Ошибка в цикле планировщика: {e}")
                await asyncio.sleep(60)
    
    def start(self):
        """Запустить планировщик"""
        if self.running:
            logger.warning("⚠ Планировщик уже запущен")
            return
        
        self.running = True
        logger.info("▶ Запуск планировщика...")
        
        # Запускаем цикл планировщика в отдельной корутине asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        # Создаем task для цикла планировщика
        asyncio.create_task(self._scheduler_loop())
    
    def stop(self):
        """Остановить планировщик"""
        self.running = False
        logger.info("⏹ Планировщик остановлен")


# Глобальный экземпляр планировщика
_scheduler: Optional[ScanScheduler] = None


def get_scheduler(data_dir: str = None) -> ScanScheduler:
    """Получить или создать глобальный экземпляр планировщика"""
    global _scheduler
    if _scheduler is None:
        _scheduler = ScanScheduler(data_dir)
    return _scheduler
