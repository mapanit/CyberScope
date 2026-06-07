"""
Асинхронные утилиты для работы с файлами и операциями I/O
Улучшает производительность сервера при обработке одновременных запросов
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, Any, Optional
import aiofiles
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


async def save_json_report_async(
    data: Dict[str, Any],
    filepath: str,
    ensure_ascii: bool = False
) -> str:
    """Асинхронно сохраняет JSON отчет на диск"""
    try:
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        async with aiofiles.open(filepath, mode='w', encoding='utf-8') as f:
            await f.write(json.dumps(data, indent=2, ensure_ascii=ensure_ascii))
        
        logger.info(f"✓ JSON отчет сохранен: {filepath}")
        return str(filepath)
    except Exception as e:
        logger.error(f"Ошибка при сохранении JSON отчета: {e}")
        raise


async def save_txt_report_async(
    content: str,
    filepath: str
) -> str:
    """Асинхронно сохраняет текстовый отчет на диск"""
    try:
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        async with aiofiles.open(filepath, mode='w', encoding='utf-8') as f:
            await f.write(content)
        
        logger.info(f"✓ TXT отчет сохранен: {filepath}")
        return str(filepath)
    except Exception as e:
        logger.error(f"Ошибка при сохранении TXT отчета: {e}")
        raise


async def save_reports_parallel(
    reports: Dict[str, tuple]
) -> Dict[str, str]:
    """
    Сохраняет несколько отчетов параллельно (JSON, TXT, и т.д.)
    
    Args:
        reports: {
            'json': (data_dict, filepath_str),
            'txt': (content_str, filepath_str),
            ...
        }
    
    Returns:
        Dict с путями до сохраненных файлов
    """
    tasks = []
    report_types = []
    
    for report_type, (content, filepath) in reports.items():
        if report_type == 'json':
            tasks.append(save_json_report_async(content, filepath))
        elif report_type == 'txt':
            tasks.append(save_txt_report_async(content, filepath))
        report_types.append(report_type)
    
    # Выполняем все сохранения параллельно
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Обработка результатов
    saved_files = {}
    for report_type, result in zip(report_types, results):
        if isinstance(result, Exception):
            logger.error(f"Ошибка при сохранении {report_type} отчета: {result}")
            saved_files[report_type] = None
        else:
            saved_files[report_type] = result
    
    return saved_files


async def read_report_async(filepath: str) -> str:
    """Асинхронно читает отчет с диска"""
    try:
        async with aiofiles.open(filepath, mode='r', encoding='utf-8') as f:
            content = await f.read()
        return content
    except Exception as e:
        logger.error(f"Ошибка при чтении отчета {filepath}: {e}")
        raise


async def delete_report_async(filepath: str) -> bool:
    """Асинхронно удаляет отчет"""
    try:
        path = Path(filepath)
        if path.exists():
            path.unlink()
            logger.info(f"✓ Отчет удален: {filepath}")
            return True
        return False
    except Exception as e:
        logger.error(f"Ошибка при удалении отчета {filepath}: {e}")
        raise


async def list_reports_async(directory: str) -> list:
    """Асинхронно получает список файлов в директории (в отдельном потоке)"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, list_reports_sync, directory)


def list_reports_sync(directory: str) -> list:
    """Синхронная версия для executor"""
    try:
        path = Path(directory)
        if not path.exists():
            return []
        return [f.name for f in path.iterdir() if f.is_file()]
    except Exception as e:
        logger.error(f"Ошибка при чтении директории {directory}: {e}")
        return []


async def run_command_async(cmd: list, timeout: int = 300) -> tuple:
    """
    Выполняет команду асинхронно
    
    Returns:
        (stdout, stderr, return_code)
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            return (
                stdout.decode(errors='ignore'),
                stderr.decode(errors='ignore'),
                process.returncode
            )
        except asyncio.TimeoutError:
            process.kill()
            logger.error(f"Команда превышила timeout {timeout}s: {' '.join(cmd)}")
            return ("", f"Timeout after {timeout}s", -1)
            
    except Exception as e:
        logger.error(f"Ошибка при выполнении команды {cmd}: {e}")
        return ("", str(e), -1)


class AsyncSessionManager:
    """Управляет асинхронными сессиями сканирования"""
    
    def __init__(self):
        self._sessions = {}
        self._lock = asyncio.Lock()
    
    async def create_session(self, session_id: str) -> Dict[str, Any]:
        """Создает новую сессию"""
        async with self._lock:
            session = {
                'id': session_id,
                'status': 'running',
                'progress': 0,
                'start_time': datetime.now().isoformat(),
                'current_tool': None,
                'results': {}
            }
            self._sessions[session_id] = session
            return session
    
    async def update_session(self, session_id: str, **kwargs):
        """Обновляет параметры сессии"""
        async with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].update(kwargs)
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Получает информацию о сессии"""
        async with self._lock:
            return self._sessions.get(session_id)
    
    async def end_session(self, session_id: str):
        """Завершает сессию"""
        async with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id]['status'] = 'completed'
    
    async def cancel_session(self, session_id: str):
        """Отменяет сессию"""
        async with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id]['status'] = 'cancelled'
    
    async def cleanup_old_sessions(self, max_age_hours: int = 24):
        """Удаляет старые сессии (очистка памяти)"""
        from datetime import datetime, timedelta
        
        async with self._lock:
            current_time = datetime.now()
            to_remove = []
            
            for session_id, session in self._sessions.items():
                start_time = datetime.fromisoformat(session['start_time'])
                age = current_time - start_time
                
                if age > timedelta(hours=max_age_hours):
                    to_remove.append(session_id)
            
            for session_id in to_remove:
                del self._sessions[session_id]
                logger.info(f"✓ Очищена старая сессия: {session_id}")
            
            return len(to_remove)


# Глобальный менеджер сессий
session_manager = AsyncSessionManager()
