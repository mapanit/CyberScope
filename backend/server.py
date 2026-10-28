# server.py
from scheduler import get_scheduler
from core.report_utils import CombinedReport, create_combined_report
from core.reporting import normalize_findings, render_markdown_report
from core.tool_registry import TOOL_IDS, get_tool_catalog
from core.async_utils import (
    save_json_report_async,
    save_txt_report_async,
    save_reports_parallel,
    run_command_async,
    session_manager,
    AsyncSessionManager
)
from scanners.nmap_scanner import NmapScanner, simple_scan as nmap_scan
from scanners.dns_scanner import simple_scan as dns_scan
from scanners.ssl_tls_scanner import SSLTLSScanner
from scanners.cors_scanner import CORSScanner
from scanners.retire_scanner import simple_scan as retire_scan
from scanners.web_url_scanner import simple_scan as web_scan
from scanners.osint_scanner import simple_scan as osint_scan
from scanners.wappalyzer_scanner import simple_scan as wappalyzer_scan, WappalyzerScanner
from scanners.vulnerability_scanner import VulnerabilityScanner
from fastapi import FastAPI, HTTPException, Query, Depends, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, PlainTextResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import text
from sqlalchemy.orm import Session
from urllib.parse import urlparse
import asyncio
import ipaddress
import re
import os
import sys
import subprocess
import tempfile
import shutil
from pathlib import Path
import json
import datetime
import threading
import logging
import hashlib
import uuid
import whois
import aiohttp
import requests
# Auth imports
from auth.database import SessionLocal, engine
from auth import models, schemas, auth
from jose import JWTError, jwt

logger = logging.getLogger(__name__)

SCHEDULED_TOOL_IDS = {
    "scanner", "nuclei", "osint", "wappalyzer", "ssl-tls",
    "nmap", "cors", "dns", "retire", "whois", "web",
}

# Initialize database
models.Base.metadata.create_all(bind=engine)

# Create tables if they don't exist


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def user_reports_dir(username: str) -> Path:
    user_key = hashlib.sha256(username.encode("utf-8")).hexdigest()
    return Path(__file__).parent / "reports" / "users" / user_key


def resolve_user_report_path(username: str, relative_path: str) -> Path:
    reports_base = user_reports_dir(username).resolve()
    report_path = (reports_base / relative_path).resolve()
    try:
        report_path.relative_to(reports_base)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Недопустимый путь к отчету") from exc
    return report_path


# Function to verify JWT token


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> str:
    """Verify JWT token and return username"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, auth.SECRET_KEY,
                             algorithms=[auth.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return username
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Глобальный словарь для отслеживания статуса сканирований
_scan_sessions = {}
_scan_sessions_lock = threading.Lock()


def create_scan_session(
    scan_id: str,
    username: str,
    scan_status: str = "running",
    target: str = None,
    tools: list[str] = None,
) -> dict:
    """Создать сессию сканирования"""
    with _scan_sessions_lock:
        existing = _scan_sessions.get(scan_id)
        if existing and existing.get("active"):
            raise HTTPException(status_code=409, detail="ID сканирования уже используется")
        session = {
            'scan_id': scan_id,
            'username': username,
            'active': True,
            'cancelled': False,
            'status': scan_status,
            'start_time': datetime.datetime.now(),
            'progress': 0,
            'current_tool': None,
            'target': target,
            'tools': tools or [],
            'completed_tools': 0,
            'total_tools': len(tools or []),
            'process': None
        }
        _scan_sessions[scan_id] = session
        return session


def get_scan_session(scan_id: str) -> dict:
    """Получить сессию сканирования"""
    with _scan_sessions_lock:
        return _scan_sessions.get(scan_id)


def is_scan_active(scan_id: str) -> bool:
    """Проверить активна ли сессия сканирования"""
    session = get_scan_session(scan_id)
    if not session:
        return False
    return session['active'] and not session['cancelled']


def cancel_scan_session(scan_id: str) -> bool:
    """Отменить сессию сканирования"""
    with _scan_sessions_lock:
        session = _scan_sessions.get(scan_id)
        if session and session.get('active'):
            session['cancelled'] = True
            session['active'] = False
            session['status'] = 'cancelled'
            process = session.get('process')
            if process and process.returncode is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
            return True
    return False


def end_scan_session(
    scan_id: str,
    scan_status: str = None,
    result: dict = None,
    error: str = None,
):
    """Завершить сессию сканирования"""
    with _scan_sessions_lock:
        if scan_id in _scan_sessions:
            _scan_sessions[scan_id]['active'] = False
            _scan_sessions[scan_id]['end_time'] = datetime.datetime.now()
            session = _scan_sessions[scan_id]
            session['status'] = scan_status or (
                'cancelled' if session['cancelled'] else 'completed'
            )
            if result is not None:
                session['result'] = result
            if error:
                session['error'] = error


def set_scan_process(scan_id: str, process):
    with _scan_sessions_lock:
        session = _scan_sessions.get(scan_id)
        if session and session.get("active"):
            session["process"] = process
        elif process and process.returncode is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass


def normalize_tool_status(tool: str, result: dict, scan_active: bool) -> dict:
    if not scan_active:
        result["status"] = "cancelled"
        result.setdefault("error", "Сканирование отменено")
        return result

    status_value = str(result.get("status", "")).lower()
    error = result.get("error")
    if error:
        error_text = str(error).lower()
        result["status"] = (
            "timeout" if any(
                marker in error_text for marker in ("timeout", "timed out", "таймаут")
            )
            else "error"
        )
        return result
    if status_value in {"timeout", "timed_out"}:
        result["status"] = "timeout"
        return result
    if status_value in {"cancelled", "canceled"}:
        result["status"] = "cancelled"
        return result
    if status_value in {"error", "failed", "unavailable", "not_found"}:
        result["status"] = "error"
        return result
    if status_value in {"no_findings", "no_results"}:
        result["status"] = "no_findings"
        return result

    counts = {
        "wappalyzer": result.get("technologies_found"),
        "nuclei": result.get("count", result.get("total_findings")),
        "amass": (result.get("data") or {}).get("subdomains_count"),
        "scanner": result.get("count"),
        "cors": result.get("count"),
        "ssl-tls": result.get("count"),
        "retire": result.get("vulnerabilities_count"),
        "katana": result.get("count"),
        "nmap": result.get("vulnerabilities"),
    }
    count = counts.get(tool)
    if count == 0:
        result["status"] = "no_findings"
    elif status_value in {"success", "completed"} or count is not None:
        result["status"] = "success"
    else:
        result["status"] = "error"
        result.setdefault("error", "Инструмент завершился без результата")
    return result


# Совместимость со старыми API и wrappers.


def amass_scan(domain: str, mode: str = "passive", timeout: int = 180, reports_dir: str = None,
               process_callback=None) -> dict:
    """Запускает Amass и возвращает поддомены; недоступность инструмента не считается успехом."""
    started = datetime.datetime.now()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as output:
        output_path = output.name

    try:
        process = subprocess.Popen(
            ["amass", "enum", "-d", domain, "-o", output_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if process_callback:
            process_callback(process)
        try:
            _, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.communicate()
            return {
                "status": "timeout",
                "error": f"Amass timed out after {timeout} seconds",
                "subdomains_count": 0,
                "subdomains_sample": [],
            }
        if process.returncode != 0:
            return {
                "status": "failed",
                "error": stderr.strip() or f"Amass exited with code {process.returncode}",
                "subdomains_count": 0,
                "subdomains_sample": [],
            }

        with open(output_path, "r", encoding="utf-8") as result_file:
            subdomains = sorted({line.strip() for line in result_file if line.strip()})
        return {
            "status": "completed",
            "subdomains_count": len(subdomains),
            "subdomains_sample": subdomains[:100],
            "statistics": {},
            "unique_ips": 0,
            "scan_duration": (datetime.datetime.now() - started).total_seconds(),
        }
    except FileNotFoundError:
        return {
            "status": "unavailable",
            "error": "Amass is not installed on the server",
            "subdomains_count": 0,
            "subdomains_sample": [],
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "error": f"Amass timed out after {timeout} seconds",
            "subdomains_count": 0,
            "subdomains_sample": [],
        }
    finally:
        if process_callback:
            process_callback(None)
        Path(output_path).unlink(missing_ok=True)


def nuclei_simple_scan(url: str) -> list:
    """DEPRECATED: используйте scanners.nuclei_scanner.run_scan"""
    from scanners.nuclei_scanner import simple_scan, get_summary
    results = simple_scan(url)
    return results


def nuclei_get_summary(results: list) -> dict:
    """DEPRECATED: используйте scanners.nuclei_scanner.get_summary"""
    from scanners.nuclei_scanner import get_summary
    return get_summary(results)


def nuclei_run_scan(target: str, save_reports: bool = False, reports_dir: str = None, process_callback=None) -> list:
    """DEPRECATED: используйте scanners.nuclei_scanner.run_scan"""
    from scanners.nuclei_scanner import run_scan
    result = run_scan(target, save_reports, reports_dir, process_callback)
    return result


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv("FRONTEND_ORIGINS", "http://localhost:3000").split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:
        logger.exception("Health check failed")
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    return {"status": "ok"}


@app.post("/auth/register", response_model=schemas.UserResponse)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Регистрация нового пользователя"""
    db_user = db.query(models.User).filter(
        models.User.username == user.username).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(
        username=user.username,
        hashed_password=hashed_password,
        # email удален - его нет в модели
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user


@app.post("/auth/login", response_model=schemas.Token)
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    """Вход пользователя и получение JWT токена"""
    db_user = db.query(models.User).filter(
        models.User.username == user.username).first()

    if not db_user or not auth.verify_password(user.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = auth.create_access_token(data={"sub": db_user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/auth/me", response_model=schemas.UserResponse)
def get_current_user(username: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Получить информацию о текущем пользователе"""
    user = db.query(models.User).filter(
        models.User.username == username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    return user

# ========================================================


URL_RE = re.compile(r"^https?://", re.I)


def validate_target(target: str, allow_internal: bool = False) -> str:
    """Validate a target which may be a full URL (http://...) or a bare domain/IP (github.com, 127.0.0.1:8080, localhost).

    By default scanning internal/private/loopback/reserved addresses is forbidden unless allow_internal=True.
    """
    if not target or not isinstance(target, str):
        raise HTTPException(status_code=400, detail="Empty or invalid target")

    # извлекаем хост независимо от формата
    host = extract_domain(target)
    if not host:
        raise HTTPException(
            status_code=400, detail="Невозможно определить хост из target")

    # если host - это ip, проверяем приватность
    try:
        ip = ipaddress.ip_address(host)
        if not allow_internal and (ip.is_private or ip.is_loopback or ip.is_reserved):
            raise HTTPException(
                status_code=400, detail="Сканирование внутренних адресов запрещено")
    except ValueError:
        # не IP — проверим локальный hostname (localhost)
        if host.lower() == 'localhost' and not allow_internal:
            raise HTTPException(
                status_code=400, detail="Сканирование внутренних адресов запрещено")

    # Умышленно НЕ требуем схему http(s): поддерживаем и домены без http://
    return target


def extract_domain(target: str) -> str:
    """Extract host/domain from a URL like https://example.com/path -> example.com"""
    try:
        p = urlparse(target)
        host = p.hostname
        if host:
            return host
    except Exception:
        pass
    # fallback: try naive split
    try:
        return target.split('://', 1)[-1].split('/', 1)[0].split(':')[0]
    except Exception:
        return target


async def sse_stream_sublist3r(target: str):
    # Sublist3r expects a domain (not URL)
    domain = extract_domain(target)
    # путь к скрипту sublist3r.py (относительно папки backend)
    sublist_path = "../tools/Sublist3r/sublist3r.py"
    if not os.path.exists(sublist_path):
        raise HTTPException(
            status_code=500, detail="sublist3r script not found on server")
    # команда: python sublist3r.py -d <domain>
    cmd = ["python", sublist_path, "-d", domain]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=500, detail="Не удалось запустить Python или скрипт sublist3r") from e
    except NotImplementedError as e:
        raise HTTPException(
            status_code=500, detail="Async subprocess не поддерживается в текущем цикле событий (Windows). Установите WindowsProactorEventLoopPolicy.") from e
    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode(errors="ignore").rstrip()
            yield f"data: {text}\n\n"
        await proc.wait()
        yield f"data: [DONE] exit={proc.returncode}\n\n"
    except asyncio.CancelledError:
        proc.kill()
        raise


async def run_command(cmd: list, scan_id: str = None):
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
    except FileNotFoundError:
        return None, "cmd_not_found"
    except NotImplementedError:
        return None, "async_subprocess_unsupported"

    if scan_id:
        set_scan_process(scan_id, proc)
    try:
        stdout, stderr = await proc.communicate()
        return stdout.decode(errors="ignore"), stderr.decode(errors="ignore")
    finally:
        if scan_id:
            set_scan_process(scan_id, None)


# Функции сохранения отчетов (АСИНХРОННЫЕ версии)
async def save_scanner_report_async(scanner: VulnerabilityScanner) -> str:
    """Асинхронно сохранить отчет сканера в JSON и TXT в backend/reports/scanner"""
    # Используем синхронные методы сканера в executor (не блокирует event loop)
    loop = asyncio.get_event_loop()
    json_path = await loop.run_in_executor(None, scanner.save_json_report)
    txt_path = await loop.run_in_executor(None, scanner.save_txt_report)

    logger.info(
        f"✓ Scanner отчеты сохранены: JSON: {json_path}, TXT: {txt_path}")
    return str(json_path)


async def save_whois_report_async(domain: str, output: str, error: str, reports_base: Path = None) -> dict:
    """Асинхронно сохранить отчет whois в JSON и TXT в backend/reports/whois"""
    reports_base = reports_base or Path(__file__).parent / "reports"

    # Создаем директории если нет
    whois_dir = reports_base / "whois"
    json_dir = whois_dir / "json"
    txt_dir = whois_dir / "txt"
    json_dir.mkdir(parents=True, exist_ok=True)
    txt_dir.mkdir(parents=True, exist_ok=True)

    # Создаем filename
    scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename_base = f"whois_{domain}_{scan_id}"

    # Подготавливаем данные
    report_data = {
        'tool': 'whois',
        'domain': domain,
        'scan_datetime': datetime.datetime.now().isoformat(),
        'scan_info': {
            'target': domain,
            'tool': 'whois'
        },
        'output': output,
        'error': error
    }

    # Подготавливаем TXT контент
    txt_content = f"""
╔{'═' * 78}╗
║{'WHOIS REPORT'.center(78)}║
╚{'═' * 78}╝

📋 ИНФОРМАЦИЯ О ЗАПРОСЕ
{'─' * 80}
  Домен:               {domain}
  Дата сканирования:   {datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')}

📊 РЕЗУЛЬТАТЫ WHOIS
{'─' * 80}

{output if output else '(Информация не получена)'}
"""

    if error:
        txt_content += f"""

⚠️  ОШИБКИ
{'─' * 80}
{error}
"""

    txt_content += f"""

{'═' * 80}
Дата создания отчета: {datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')}
{'═' * 80}
"""

    # Сохраняем обе отчеты ПАРАЛЛЕЛЬНО
    json_path = json_dir / f"{filename_base}.json"
    txt_path = txt_dir / f"{filename_base}.txt"

    saved_files = await save_reports_parallel({
        'json': (report_data, str(json_path)),
        'txt': (txt_content, str(txt_path))
    })

    logger.info(
        f"✓ WHOIS отчеты сохранены: JSON: {saved_files.get('json')}, TXT: {saved_files.get('txt')}")
    return {
        'json': saved_files.get('json'),
        'txt': saved_files.get('txt')
    }


async def save_nuclei_report_async(target: str, results: list, reports_base: Path = None) -> str:
    """Асинхронно сохранить отчет nuclei в JSON в backend/reports/nuclei"""
    reports_base = reports_base or Path(__file__).parent / "reports"

    # Создаем директории если нет
    nuclei_dir = reports_base / "nuclei"
    json_dir = nuclei_dir / "json"
    json_dir.mkdir(parents=True, exist_ok=True)

    # Создаем filename
    scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(
        '/', '_').replace(':', '_').replace('.', '_').replace('?', '_')
    filename_base = f"nuclei_{safe_target}_{scan_id}"

    # Подготавливаем JSON данные
    message = "ничего не нашел" if not results else None
    report_data = {
        'tool': 'nuclei',
        'target': target,
        'scan_datetime': datetime.datetime.now().isoformat(),
        'total_findings': len(results),
        'message': message,
        'results': results
    }

    # Сохраняем JSON отчет асинхронно
    json_path = json_dir / f"{filename_base}.json"
    result_path = await save_json_report_async(report_data, str(json_path))

    logger.info(f"✓ JSON отчет Nuclei сохранен: {result_path}")
    return result_path


async def save_amass_report_async(target: str, results: dict, reports_base: Path = None) -> str:
    """Асинхронно сохранить отчет amass в JSON в backend/reports/amass"""
    reports_base = reports_base or Path(__file__).parent / "reports"

    # Создаем директории если нет
    amass_dir = reports_base / "amass"
    json_dir = amass_dir / "json"
    json_dir.mkdir(parents=True, exist_ok=True)

    # Создаем filename
    scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(
        '/', '_').replace(':', '_').replace('.', '_').replace('?', '_')
    filename_base = f"amass_{safe_target}_{scan_id}"

    # Подготавливаем JSON данные
    subdomains = results.get('subdomains_sample', [])
    message = "ничего не нашел" if not subdomains else None
    report_data = {
        'tool': 'amass',
        'target': target,
        'scan_datetime': datetime.datetime.now().isoformat(),
        'subdomains_count': results.get('subdomains_count', 0),
        'message': message,
        'statistics': results.get('statistics', {}),
        'subdomains_sample': subdomains
    }

    # Сохраняем JSON отчет асинхронно
    json_path = json_dir / f"{filename_base}.json"
    result_path = await save_json_report_async(report_data, str(json_path))

    logger.info(f"✓ JSON отчет Amass сохранен: {result_path}")
    return result_path


async def save_cors_report_async(scanner: CORSScanner) -> dict:
    """Асинхронно сохранить отчет CORS в JSON и TXT в backend/reports/cors"""
    # Используем executor для синхронных методов сканера
    loop = asyncio.get_event_loop()
    json_path = await loop.run_in_executor(None, scanner.save_json_report)
    txt_path = await loop.run_in_executor(None, scanner.save_txt_report)

    logger.info(f"✓ CORS отчеты сохранены: JSON: {json_path}, TXT: {txt_path}")
    return {
        'json': str(json_path),
        'txt': str(txt_path)
    }


async def save_ssl_tls_report_async(scanner: SSLTLSScanner) -> dict:
    """Асинхронно сохранить отчет SSL/TLS в JSON и TXT в backend/reports/ssl-tls"""
    # Используем executor для синхронных методов сканера
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, scanner.save_reports)

    # Получаем пути файлов
    json_path = scanner.json_dir / f"{scanner.filename_base}.json"
    txt_path = scanner.txt_dir / f"{scanner.filename_base}.txt"

    logger.info(
        f"✓ SSL/TLS отчеты сохранены: JSON: {json_path}, TXT: {txt_path}")
    return {
        'json': str(json_path),
        'txt': str(txt_path)
    }


@app.get("/api/tool")
async def api_tool(
    tool: str = Query(...),
    q: str = Query(...),
    allow_internal: bool = Query(
        False, description="Allow scanning private/loopback addresses (use with caution)"),
    username: str = Depends(verify_token)  # Require authentication
):
    """Run a non-streaming tool and return JSON result. Supported tools:
    - whois: runs system `whois` (if installed)
    - nuclei: runs system `nuclei` (if installed)

    For dirsearch/sublist3r use the streaming endpoints `/scan` and `/sublist3r`.
    """
    # basic validation
    if not q:
        raise HTTPException(status_code=400, detail="Empty query")

    if tool == "whois":
        domain = extract_domain(q)
        output = ""
        error = ""

        try:
            import whois
        except ImportError:
            raise HTTPException(
                status_code=500,
                detail="Whois library не установлена. Установите: pip install python-whois")

        try:
            logger.info(f"Выполняем WHOIS запрос для домена: {domain}")
            whois_result = await asyncio.to_thread(whois.whois, domain)

            # Проверяем результат
            if whois_result:
                output = str(whois_result)
                logger.info(f"WHOIS результат получен: {len(output)} символов")
            else:
                error = "Whois returned empty result"
                logger.warning(f"WHOIS вернул пустой результат для {domain}")

        except Exception as e:
            error = f"Whois error: {str(e)}"
            logger.error(f"Ошибка WHOIS: {error}")

        # Сохраняем отчет асинхронно
        await save_whois_report_async(domain, output, error, user_reports_dir(username))

        return {"tool": "whois", "output": output, "error": error}

    if tool == "nuclei":
        # validate target
        try:
            validate_target(q, allow_internal=allow_internal)
        except HTTPException:
            raise
        # nuclei works with URLs; ensure target has scheme
        target_url = q if URL_RE.match(q) else f"http://{q}"

        try:
            from scanners.nuclei_scanner import run_scan
            reports_base = user_reports_dir(username)
            result = await asyncio.to_thread(run_scan, target_url, save_reports=True, reports_dir=str(reports_base))
            return {
                "tool": "nuclei",
                "result": result,
                "status": result.get('status', 'completed'),
                "total_findings": result.get('total_findings', 0),
                "by_severity": result.get('by_severity', {}),
                "by_type": result.get('by_type', {}),
                "txt_report": result.get('txt_report'),
                "json_report": result.get('json_report')
            }
        except RuntimeError as e:
            error_msg = str(e)
            if "not installed" in error_msg.lower():
                raise HTTPException(
                    status_code=500, detail="Nuclei не установлен. Установите через: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
            raise HTTPException(
                status_code=500, detail=f"Ошибка Nuclei: {error_msg}")
        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"Ошибка при сканировании Nuclei: {str(e)}")

    raise HTTPException(
        status_code=400, detail=f"Инструмент '{tool}' не найден")


@app.get("/api/scanner")
async def api_scanner(
    target: str = Query(..., description="URL для сканирования"),
    output_name: str = Query(None, description="Имя для файлов отчета"),
    allow_internal: bool = Query(
        False, description="Разрешить сканирование внутренних адресов"),
    selected_tools: str = Query(
        "scanner", description="Выбранные инструменты (comma-separated)"),
    username: str = Depends(verify_token)  # Require authentication
):
    """Запуск сканера уязвимостей с сохранением отчетов"""
    try:
        # Валидация цели
        validate_target(target, allow_internal=allow_internal)

        # Определяем директорию для отчетов инструментов
        reports_base = user_reports_dir(username)

        # Создаем сканер
        scanner = VulnerabilityScanner(target, output_name, str(reports_base))

        # Запускаем все проверки (без сохранения, они будут сохранены ниже)
        scanner.run_all_checks()

        # Сохраняем отчеты явно
        print(f"[DEBUG] Сохраняем JSON отчет...")
        json_report_path = scanner.save_json_report()
        print(f"[DEBUG] JSON путь: {json_report_path}")

        print(f"[DEBUG] Сохраняем TXT отчет...")
        txt_report_path = scanner.save_txt_report()
        print(f"[DEBUG] TXT путь: {txt_report_path}")

        # Получаем JSON отчет
        report = scanner.get_json_report()
        report['vulnerabilities'] = scanner.found_vulnerabilities

        # Создаем объединенный отчет (собираем файлы созданные за последние 10 минут)
        scan_id = scanner.scan_id
        combined_reports = create_combined_report(
            scan_id, reports_base, recent_minutes=10)

        # Возвращаем результат с путями к отчетам
        return {
            "status": "success",
            "report": report,
            "summary": report.get("summary", {}),
            "vulnerabilities": report.get("vulnerabilities", []),
            "scan_id": scanner.scan_id,
            "hostname": scanner.hostname,
            "individual_reports": {
                "json": json_report_path,
                "txt": txt_report_path
            },
            "combined_reports": combined_reports
        }

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка сканирования: {str(e)}")


@app.get("/api/amass")
async def api_amass(
    target: str = Query(..., description="Домен для сканирования"),
    mode: str = Query("passive", description="Режим: passive, active, full"),
    allow_internal: bool = Query(
        False, description="Разрешить сканирование внутренних адресов"),
    timeout: int = Query(180, description="Таймаут в секундах"),
    selected_tools: str = Query(
        "amass", description="Выбранные инструменты (comma-separated)"),
    username: str = Depends(verify_token)
):
    """Запуск Amass для перечисления поддоменов"""
    try:
        validate_target(target, allow_internal=allow_internal)

        domain = extract_domain(target)

        reports_base = user_reports_dir(username)
        result = await asyncio.to_thread(amass_scan, domain, mode, timeout, str(reports_base))

        # Создаем объединённый отчет после сканирования
        scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        await save_amass_report_async(domain, result, reports_base)
        combined_report_paths = await asyncio.to_thread(
            create_combined_report,
            scan_id, reports_base, 10
        )

        return {
            "tool": "amass",
            "status": result.get("status", "failed"),
            "result": result,
            "combined_report": combined_report_paths
        }

    except HTTPException:
        raise
    except RuntimeError as e:
        if "not installed" in str(e).lower():
            raise HTTPException(
                status_code=500,
                detail="Amass не установлен. Установите через: go install -v github.com/owasp-amass/amass/v4/...@master"
            )
        raise HTTPException(status_code=500, detail=f"Ошибка Amass: {str(e)}")
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при запуске Amass: {str(e)}")


@app.get("/api/nuclei")
async def api_nuclei(
    target: str = Query(..., description="URL для сканирования"),
    allow_internal: bool = Query(
        False, description="Разрешить сканирование внутренних адресов"),
    selected_tools: str = Query(
        "nuclei", description="Выбранные инструменты (comma-separated)"),
    username: str = Depends(verify_token)  # Require authentication
):
    """Запуск Nuclei для сканирования на уязвимости"""
    try:
        validate_target(target, allow_internal=allow_internal)

        # Убеждаемся что URL имеет схему
        if not URL_RE.match(target):
            target = f"http://{target}"

        from scanners.nuclei_scanner import run_scan

        reports_base = user_reports_dir(username)
        result = await asyncio.to_thread(run_scan, target, save_reports=True, reports_dir=str(reports_base))

        # Создаем объединённый отчет после сканирования
        scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        combined_report_paths = await asyncio.to_thread(
            create_combined_report,
            scan_id, reports_base, 10
        )

        return {
            "tool": "nuclei",
            "result": result,
            "combined_report": combined_report_paths
        }

    except HTTPException:
        raise
    except RuntimeError as e:
        if "not installed" in str(e).lower():
            raise HTTPException(
                status_code=500,
                detail="Nuclei не установлен. Установите через: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
            )
        raise HTTPException(status_code=500, detail=f"Ошибка Nuclei: {str(e)}")
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при запуске Nuclei: {str(e)}")


@app.get("/api/osint")
async def api_osint(
    target: str = Query(..., description="Домен для OSINT сканирования"),
    allow_internal: bool = Query(
        False, description="Разрешить сканирование внутренних адресов"),
    selected_tools: str = Query(
        "osint", description="Выбранные инструменты (comma-separated)"),
    username: str = Depends(verify_token)
):
    """Запуск OSINT сканирования для поиска поддоменов и информации о домене"""
    try:
        validate_target(target, allow_internal=allow_internal)

        domain = extract_domain(target)

        reports_base = user_reports_dir(username)
        result = await asyncio.to_thread(osint_scan, domain, reports_base)

        # Создаем объединённый отчет после сканирования
        scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        combined_report_paths = await asyncio.to_thread(
            create_combined_report,
            scan_id, reports_base, 10
        )

        return {
            "tool": "osint",
            "domain": domain,
            "result": result,
            "reports": result.get('reports', {}),
            "combined_report": combined_report_paths
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при запуске OSINT: {str(e)}")


@app.get("/api/web")
async def api_web(
    target: str = Query(..., description="URL для веб-разведки сканирования"),
    allow_internal: bool = Query(
        False, description="Разрешить сканирование внутренних адресов"),
    selected_tools: str = Query(
        "web", description="Выбранные инструменты (comma-separated)"),
    username: str = Depends(verify_token)
):
    """Запуск Web сканирования (Katana, JSFinder, Gobuster) для поиска URL и директорий"""
    try:
        validate_target(target, allow_internal=allow_internal)

        # Убеждаемся что URL имеет схему
        if not URL_RE.match(target):
            target = f"http://{target}"

        reports_base = user_reports_dir(username)
        result = await asyncio.to_thread(web_scan, target, str(reports_base))

        # Создаем объединённый отчет после сканирования
        scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        combined_report_paths = await asyncio.to_thread(
            create_combined_report,
            scan_id, reports_base, 10
        )

        return {
            "tool": "web",
            "target": target,
            "status": result.get('status', 'unknown'),
            "result": result,
            "combined_report": combined_report_paths
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при запуске Web сканирования: {str(e)}")


@app.get("/api/retire")
async def api_retire(
    target: str = Query(...,
                        description="URL для сканирования JavaScript библиотек"),
    allow_internal: bool = Query(
        False, description="Разрешить сканирование внутренних адресов"),
    selected_tools: str = Query(
        "retire", description="Выбранные инструменты (comma-separated)"),
    username: str = Depends(verify_token)
):
    """Запуск Retire для сканирования JavaScript библиотек на уязвимости"""
    try:
        validate_target(target, allow_internal=allow_internal)

        # Убеждаемся что URL имеет схему
        if not URL_RE.match(target):
            target = f"http://{target}"

        reports_base = user_reports_dir(username)
        result = await asyncio.to_thread(retire_scan, target, str(reports_base))

        # Создаем объединённый отчет после сканирования
        scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        combined_report_paths = await asyncio.to_thread(
            create_combined_report,
            scan_id, reports_base, 10
        )

        return {
            "tool": "retire",
            "target": target,
            "status": result.get('status', 'unknown'),
            "result": result,
            "combined_report": combined_report_paths
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при запуске Retire сканирования: {str(e)}")


@app.get("/download_report")
async def download_report(file_type: str = Query("docx", description="json или docx"), scan_id: str = Query(..., description="ID сканирования"),
                          username: str = Depends(verify_token)):
    """Скачать отчет по типу и ID сканирования"""
    try:
        reports_base = user_reports_dir(username)

        if file_type == "docx":
            report_dir = reports_base / "word"
            extension = "docx"
        elif file_type == "json":
            report_dir = reports_base / "json"
            extension = "json"
        else:
            raise HTTPException(
                status_code=400, detail="Тип файла должен быть 'json' или 'docx'")

        # Проверяем, что директория существует
        if not report_dir.exists():
            raise HTTPException(
                status_code=404, detail=f"Директория отчетов не найдена: {report_dir}")

        # Ищем файл с соответствующим scan_id
        # Сначала пытаемся найти точное совпадение по pattern: scan_*_<scan_id>.extension
        matching_files = list(report_dir.glob(f"*{scan_id}*.{extension}"))

        if not matching_files:
            # Выводим список доступных файлов для отладки
            available_files = list(report_dir.glob(f"*.{extension}"))
            raise HTTPException(
                status_code=404,
                detail=f"Отчет с ID '{scan_id}' не найден в {report_dir}. Доступные файлы: {[f.name for f in available_files]}"
            )

        file_path = matching_files[0]

        # Определяем MIME тип
        media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document" if file_type == "docx" else "application/json"

        return FileResponse(
            path=file_path,
            media_type=media_type,
            filename=file_path.name
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при скачивании отчета: {str(e)}")


@app.get("/wappalyzer")
async def wappalyzer_endpoint(
    target: str = Query(..., description="URL или домен для анализа"),
    allow_internal: bool = Query(
        False, description="Разрешить сканирование внутренних адресов"),
    selected_tools: str = Query(
        "wappalyzer", description="Выбранные инструменты (comma-separated)"),
    username: str = Depends(verify_token)
):
    """
    Анализ технологий на веб-сайте с помощью Wappalyzer
    Возвращает список обнаруженных технологий и сохраняет отчеты
    """
    try:
        # Валидируем target
        validate_target(target, allow_internal=allow_internal)

        # Определяем директорию для отчетов
        reports_base = user_reports_dir(username)

        # Запускаем сканирование с сохранением отчетов
        result = await asyncio.to_thread(wappalyzer_scan, target, str(reports_base))

        # Создаем объединенный отчет
        scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        combined_reports = create_combined_report(
            scan_id, reports_base, recent_minutes=10)

        return {
            "status": "success",
            "target": target,
            "technologies_found": result.get('total', 0),
            "technologies": result.get('technologies', []),
            "individual_reports": result.get('reports', {}),
            "combined_reports": combined_reports
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при анализе технологий: {str(e)}")


@app.get("/wappalyzer/stream")
async def wappalyzer_stream(target: str = Query(..., description="URL или домен для анализа"), allow_internal: bool = Query(False, description="Разрешить сканирование внутренних адресов"),
                            username: str = Depends(verify_token)):
    """
    Анализ технологий с потоковым выводом результатов (SSE)
    """
    async def stream_wappalyzer():
        try:
            validate_target(target, allow_internal=allow_internal)
            scanner = WappalyzerScanner(target, str(user_reports_dir(username)))

            yield "data: {\"status\": \"Анализируем технологии...\"}\n\n"

            # Не вызывать fetch_page() отдельно! scan() делает это сам
            scanner.scan()

            for tech in scanner.detected_technologies:
                yield f"data: {json.dumps({'technology': tech['technology']})} \n\n"

                # Отправляем каждую обнаруженную технологию
                for tech in scanner.detected_technologies:
                    yield f"data: {json.dumps({{'technology': tech['technology']}})} \n\n"

                # Сохраняем отчеты
                yield "data: {\"status\": \"Сохраняем отчеты...\"}\n\n"
                reports = scanner.save_reports()

                yield f"data: {json.dumps({{'status': 'completed', 'total': len(scanner.detected_technologies), 'reports': reports}})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({{'error': str(e)}})}\n\n"

    return StreamingResponse(stream_wappalyzer(), media_type="text/event-stream")


@app.post("/api/cors")
async def api_cors(
    target: str = Query(..., description="URL для CORS сканирования"),
    allow_internal: bool = Query(
        False, description="Разрешить сканирование внутренних адресов"),
    selected_tools: str = Query(
        "cors", description="Выбранные инструменты (comma-separated)"),
    username: str = Depends(verify_token)
):
    """Запуск CORS сканирования для выявления уязвимостей CORS"""
    try:
        validate_target(target, allow_internal=allow_internal)

        # Убеждаемся что URL имеет схему
        if not URL_RE.match(target):
            target = f"http://{target}"

        reports_base = user_reports_dir(username)

        # Создаем и запускаем сканер
        scanner = CORSScanner(target, None, str(reports_base))
        await asyncio.to_thread(scanner.run_all_checks)

        # Сохраняем отчеты
        reports = await save_cors_report_async(scanner)

        # Создаем объединённый отчет
        scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        combined_reports = create_combined_report(
            scan_id, reports_base, recent_minutes=10)

        return {
            "tool": "cors",
            "target": target,
            "status": "success",
            "report": scanner.get_json_report(),
            "summary": scanner.get_json_report().get('summary', {}),
            "vulnerabilities": scanner.found_vulnerabilities,
            "scan_id": scanner.scan_id,
            "hostname": scanner.hostname,
            "individual_reports": reports,
            "combined_reports": combined_reports
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при CORS сканировании: {str(e)}")



@app.get("/api/ssl-tls")
async def api_ssl_tls(
    target: str = Query(...,
                        description="URL или хост для SSL/TLS сканирования"),
    allow_internal: bool = Query(
        False, description="Разрешить сканирование внутренних адресов"),
    selected_tools: str = Query(
        "ssl-tls", description="Выбранные инструменты (comma-separated)"),
    username: str = Depends(verify_token)
):
    """Запуск детального анализа SSL/TLS конфигурации"""
    try:
        # Валидация цели
        validate_target(target, allow_internal=allow_internal)

        # Определяем директорию для отчетов
        reports_base = user_reports_dir(username)

        # Создаем SSL/TLS сканер
        scanner = SSLTLSScanner(target, reports_dir=str(reports_base))

        # Запускаем сканирование
        scanner.run_scan()

        # Сохраняем отчеты
        reports = await save_ssl_tls_report_async(scanner)

        # Создаем объединённый отчет после сканирования
        scan_id = scanner.scan_id
        combined_reports = create_combined_report(
            scan_id, reports_base, recent_minutes=10)

        return {
            "tool": "ssl-tls",
            "target": target,
            "status": "success",
            "report": scanner.get_json_report(),
            "summary": {
                "overall_score": scanner.overall_score,
                "total_vulnerabilities": len(scanner.vulnerabilities),
                "critical": len([v for v in scanner.vulnerabilities if v['severity'] == 'Critical']),
                "high": len([v for v in scanner.vulnerabilities if v['severity'] == 'High']),
                "medium": len([v for v in scanner.vulnerabilities if v['severity'] == 'Medium']),
                "low": len([v for v in scanner.vulnerabilities if v['severity'] == 'Low'])
            },
            "vulnerabilities": scanner.vulnerabilities,
            "recommendations": scanner.recommendations,
            "ssl_tls_versions": scanner.tls_versions,
            "cipher_suites": scanner.cipher_suites,
            "scan_id": scanner.scan_id,
            "hostname": scanner.hostname,
            "individual_reports": reports,
            "combined_reports": combined_reports
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при SSL/TLS сканировании: {str(e)}")


@app.get("/api/dns")
async def api_dns(
    target: str = Query(...,
                        description="Домен или IP адрес для DNS сканирования"),
    allow_internal: bool = Query(
        False, description="Разрешить сканирование внутренних адресов"),
    selected_tools: str = Query(
        "dns", description="Выбранные инструменты (comma-separated)"),
    username: str = Depends(verify_token)
):
    """Запуск DNS сканирования для перечисления DNS записей"""
    try:
        # Валидируем target
        validate_target(target, allow_internal=allow_internal)

        # Определяем директорию для отчетов
        reports_base = user_reports_dir(username)

        # Запускаем DNS сканирование с сохранением отчетов
        result = await asyncio.to_thread(dns_scan, target, str(reports_base))

        # Создаем объединённый отчет
        scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        combined_reports = create_combined_report(
            scan_id, reports_base, recent_minutes=10)

        return {
            "tool": "dns",
            "target": target,
            "status": "success",
            "dns_records_count": result.get('total', 0),
            "nameservers": result.get('nameservers', []),
            "dns_records": result.get('dns_records', {}),
            "individual_reports": result.get('reports', {}),
            "combined_reports": combined_reports
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при DNS сканировании: {str(e)}")


@app.post("/api/cancel-scan")
async def cancel_scan(scan_id: str = Query(..., description="ID сканирования для отмены"),
                      username: str = Depends(verify_token)):
    """Отменить активное сканирование по ID"""
    try:
        if not scan_id:
            raise HTTPException(
                status_code=400, detail="Не указан ID сканирования")

        session = get_scan_session(scan_id)
        if session and session.get("username") != username:
            raise HTTPException(status_code=404, detail="Сканирование не найдено")
        cancelled = cancel_scan_session(scan_id)

        if cancelled:
            return {
                "status": "success",
                "message": f"Сканирование {scan_id} отменено",
                "scan_id": scan_id
            }
        else:
            return {
                "status": "not_found",
                "message": f"Сканирование {scan_id} не найдено или уже завершено",
                "scan_id": scan_id
            }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при отмене сканирования: {str(e)}")


@app.get("/api/scan-status")
async def get_scan_status(scan_id: str = Query(..., description="ID сканирования"),
                          username: str = Depends(verify_token)):
    """Получить статус сканирования"""
    try:
        session = get_scan_session(scan_id)

        if not session or session.get("username") != username:
            return {
                "status": "not_found",
                "message": "Сканирование не найдено"
            }

        return {
            "status": "success",
            "scan_id": scan_id,
            "active": session['active'],
            "cancelled": session['cancelled'],
            "scan_status": session.get('status', 'running'),
            "current_tool": session.get('current_tool'),
            "progress": session.get('progress', 0),
            "completed_tools": session.get('completed_tools', 0),
            "total_tools": session.get('total_tools', 0),
            "error": session.get("error"),
            "start_time": session['start_time'].isoformat(),
            "duration": (
                (session.get('end_time') or datetime.datetime.now())
                - session['start_time']
            ).total_seconds(),
        }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при получении статуса: {str(e)}")


@app.get("/api/scan-results")
async def get_scan_results(scan_id: str = Query(...), username: str = Depends(verify_token)):
    session = get_scan_session(scan_id)
    if not session or session.get("username") != username:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")
    if session.get("result") is not None:
        return session["result"]
    if session.get("error"):
        return {
            "status": "error",
            "scan_id": scan_id,
            "target": session.get("target"),
            "tools_executed": session.get("tools", []),
            "tools_count": session.get("total_tools", 0),
            "results": {},
            "combined_reports": {},
            "error": session["error"],
        }
    if session.get("cancelled"):
        return {
            "status": "cancelled",
            "scan_id": scan_id,
            "target": session.get("target"),
            "tools_executed": session.get("tools", []),
            "tools_count": session.get("total_tools", 0),
            "results": {},
            "combined_reports": {},
        }
    raise HTTPException(status_code=409, detail="Сканирование еще выполняется")


@app.get("/api/nmap")
async def api_nmap(
    target: str = Query(...,
                        description="Хост, IP адрес или IP диапазон для сканирования"),
    allow_internal: bool = Query(
        False, description="Разрешить сканирование внутренних адресов"),
    arguments: str = Query("-sV -sC --top-ports 1000",
                           description="Аргументы для Nmap"),
    selected_tools: str = Query(
        "nmap", description="Выбранные инструменты (comma-separated)"),
    username: str = Depends(verify_token)  # Require authentication
):
    """Запуск Nmap для сканирования портов и определения сервисов"""
    try:
        # Валидация цели
        validate_target(target, allow_internal=allow_internal)

        # Определяем директорию для отчетов
        reports_base = user_reports_dir(username)

        # Создаем Nmap сканер
        scanner = NmapScanner(target, reports_dir=str(reports_base))

        # Запускаем сканирование
        success = await asyncio.to_thread(scanner.run_scan, arguments)

        if not success:
            raise HTTPException(
                status_code=500, detail="Ошибка при запуске Nmap сканирования")

        # Парсим результаты и ищем CVE
        await asyncio.to_thread(scanner.parse_results)

        # Сохраняем отчеты
        reports = await asyncio.to_thread(scanner.save_reports)

        # Создаем объединённый отчет
        scan_id = scanner.scan_id
        combined_reports = await asyncio.to_thread(
            create_combined_report,
            scan_id, reports_base, 10
        )

        return {
            "tool": "nmap",
            "target": target,
            "status": "success",
            "scan_id": scan_id,
            "summary": {
                "hosts_discovered": len(scanner.discovered_hosts),
                "open_ports": len(scanner.open_ports),
                "vulnerabilities": len(scanner.vulnerabilities),
                "vulnerabilities_by_severity": scanner._count_by_severity()
            },
            "hosts": scanner.discovered_hosts,
            "vulnerabilities": scanner.vulnerabilities,
            "recommendations": scanner._get_recommendations(),
            "individual_reports": reports,
            "combined_reports": combined_reports
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при Nmap сканировании: {str(e)}")


async def _run_queued_scan(scan_id: str, target: str, tools: str,
                           allow_internal: bool, username: str) -> None:
    try:
        async with _scan_queue_semaphore:
            if not is_scan_active(scan_id):
                end_scan_session(scan_id, "cancelled")
                return
            result = await run_selected_tools(
                target=target,
                tools=tools,
                allow_internal=allow_internal,
                scan_id=scan_id,
                username=username,
            )
            end_scan_session(scan_id, result.get("status", "completed"), result)
    except HTTPException as exc:
        logger.error(
            "Фоновое сканирование %s остановлено с HTTP %s: %s",
            scan_id,
            exc.status_code,
            exc.detail,
        )
        end_scan_session(scan_id, "error", error=str(exc.detail))
    except Exception as exc:
        logger.exception(
            "Непредвиденная ошибка фонового сканирования %s", scan_id
        )
        end_scan_session(scan_id, "error", error=str(exc))


@app.post("/api/scans", status_code=202)
async def enqueue_scan(
    target: str = Query(...),
    tools: str = Query(...),
    allow_internal: bool = Query(False),
    scan_id: str = Query(None),
    username: str = Depends(verify_token),
):
    """Queue a scan and return immediately; use scan-status/scan-results to poll it."""
    validate_target(target, allow_internal=allow_internal)
    tools_list = [tool.strip().lower() for tool in tools.split(",") if tool.strip()]
    if not tools_list:
        raise HTTPException(status_code=400, detail="Не указаны инструменты для запуска")
    invalid_tools = sorted(set(tools_list) - TOOL_IDS)
    if invalid_tools:
        raise HTTPException(
            status_code=400,
            detail=f"Неизвестные инструменты: {', '.join(invalid_tools)}",
        )
    if not scan_id:
        scan_id = str(uuid.uuid4())
    else:
        try:
            scan_id = str(uuid.UUID(scan_id))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Некорректный ID сканирования") from exc

    create_scan_session(
        scan_id,
        username,
        scan_status="queued",
        target=target,
        tools=tools_list,
    )
    asyncio.create_task(_run_queued_scan(
        scan_id, target, ",".join(tools_list), allow_internal, username
    ))
    return {
        "status": "queued",
        "scan_id": scan_id,
        "progress": 0,
        "tools": tools_list,
    }


@app.post("/api/run-selected-tools")
async def run_selected_tools(
    target: str = Query(..., description="URL или домен для сканирования"),
    tools: str = Query(...,
                       description="Список инструментов (comma-separated)"),
    allow_internal: bool = Query(
        False, description="Разрешить сканирование внутренних адресов"),
    scan_id: str = Query(None, description="ID сканирования для отслеживания"),
    username: str = Depends(verify_token)  # Require authentication
):
    """
    Запустить выбранные инструменты сканирования и создать единый отчет

    Args:
        target: Целевой URL/домен
        tools: Список инструментов через запятую (wappalyzer, nuclei, katana, amass, scanner, whois, osint, web, retire, cors, ssl-tls)
        allow_internal: Разрешить сканирование внутренних адресов
        scan_id: уникальный ID для отслеживания сканирования

    Returns:
        JSON с результатами всех инструментов и путями к объединенному отчету
    """
    # Создаем сессию сканирования если указан scan_id
    if not scan_id:
        scan_id = str(uuid.uuid4())
    else:
        try:
            scan_id = str(uuid.UUID(scan_id))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Некорректный ID сканирования") from exc
    existing_session = get_scan_session(scan_id)
    if existing_session and existing_session.get("status") == "queued":
        if existing_session.get("username") != username:
            raise HTTPException(status_code=404, detail="Сканирование не найдено")
        with _scan_sessions_lock:
            existing_session["status"] = "running"
            existing_session["start_time"] = datetime.datetime.now()
    else:
        create_scan_session(
            scan_id,
            username,
            target=target,
            tools=[t.strip().lower() for t in tools.split(",") if t.strip()],
        )
    print(f"[*] Создана сессия сканирования: {scan_id}")

    try:
        # Проверяем отмену перед началом
        if not is_scan_active(scan_id):
            return {
                'status': 'cancelled',
                'message': 'Сканирование было отменено до начала',
                'scan_id': scan_id
            }

        # Валидируем target
        validate_target(target, allow_internal=allow_internal)

        # Парсим список инструментов
        tools_list = [t.strip().lower() for t in tools.split(',') if t.strip()]
        if not tools_list:
            raise HTTPException(
                status_code=400, detail="Не указаны инструменты для запуска")

        # Валидируем инструменты
        invalid_tools = [t for t in tools_list if t not in TOOL_IDS]
        if invalid_tools:
            raise HTTPException(
                status_code=400, detail=f"Неизвестные инструменты: {', '.join(invalid_tools)}")

        reports_base = user_reports_dir(username)
        results = {}

        # Запускаем каждый инструмент
        for tool in tools_list:
            try:
                # Проверяем отмену перед каждым инструментом
                if not is_scan_active(scan_id):
                    print(
                        f"[*] Сканирование {scan_id} отменено, пропускаем {tool}")
                    results[tool] = {
                        'status': 'cancelled',
                        'error': 'Сканирование было отменено'
                    }
                    continue

                # Обновляем текущий инструмент
                with _scan_sessions_lock:
                    if scan_id in _scan_sessions:
                        session = _scan_sessions[scan_id]
                        session['current_tool'] = tool
                        session['status'] = 'running'
                        total_tools = max(1, len(tools_list))
                        session['progress'] = int(
                            session.get('completed_tools', 0) * 95 / total_tools
                        )

                print(f"[*] Запускаем {tool}...")

                if tool == 'wappalyzer':
                    result = await asyncio.to_thread(wappalyzer_scan, target, str(reports_base))
                    results[tool] = {
                        'status': 'success',
                        'data': result,
                        'technologies_found': result.get('total', 0)
                    }

                elif tool == 'nuclei':
                    process_callback = lambda process: set_scan_process(scan_id, process)
                    result = await asyncio.to_thread(
                        nuclei_run_scan, target, True, str(reports_base), process_callback)
                    json_path = await save_nuclei_report_async(
                        target, result if isinstance(result, list) else [], reports_base)
                    results[tool] = {
                        'status': 'cancelled' if not is_scan_active(scan_id) else 'success',
                        'data': result,
                        'count': len(result) if isinstance(result, list) else result.get('total_findings', 0),
                        'reports': {
                            'json': json_path
                        }
                    }

                elif tool == 'katana':
                    # Используем командную строку для katana
                    cmd = ["katana", "-u", target, "-json", "-silent"]
                    stdout, stderr = await run_command(cmd, scan_id)
                    if stdout is None:
                        results[tool] = {
                            'status': 'error',
                            'error': f"Не удалось запустить Katana: {stderr}"
                        }
                    elif stdout:
                        try:
                            katana_data = [json.loads(
                                line) for line in stdout.strip().split('\n') if line]
                            results[tool] = {
                                'status': 'success',
                                'urls_found': katana_data,
                                'count': len(katana_data)
                            }
                        except json.JSONDecodeError:
                            results[tool] = {
                                'status': 'success',
                                'output': stdout
                            }
                    else:
                        results[tool] = {
                            'status': 'completed',
                            'urls_found': [],
                            'count': 0
                        }

                elif tool == 'amass':
                    process_callback = lambda process: set_scan_process(scan_id, process)
                    result = await asyncio.to_thread(
                        amass_scan, target, "passive", 300, str(reports_base), process_callback)
                    json_path = await save_amass_report_async(target, result, reports_base)
                    results[tool] = {
                        'status': result.get('status', 'failed'),
                        'data': result,
                        'reports': {
                            'json': json_path
                        }
                    }

                elif tool == 'scanner':
                    output_name = target.replace(
                        '/', '_').replace(':', '_').replace('.', '_')
                    scanner_obj = VulnerabilityScanner(
                        target, output_name, str(reports_base))
                    await asyncio.to_thread(scanner_obj.run_all_checks)
                    json_path = await save_scanner_report_async(scanner_obj)
                    results[tool] = {
                        'status': 'success',
                        'vulnerabilities': scanner_obj.found_vulnerabilities,
                        'count': len(scanner_obj.found_vulnerabilities),
                        'reports': {
                            'json': json_path
                        }
                    }

                elif tool == 'whois':
                    domain = extract_domain(target)
                    output = ""
                    error = ""

                    try:
                        import whois
                        logger.info(
                            f"Выполняем WHOIS запрос для домена: {domain}")
                        whois_result = await asyncio.to_thread(whois.whois, domain)

                        if whois_result:
                            output = str(whois_result)
                            logger.info(
                                f"WHOIS успешно: {len(output)} символов")
                        else:
                            error = "Whois returned empty result"
                            logger.warning(f"WHOIS пуст для {domain}")

                    except ImportError:
                        error = "python-whois library not installed"
                        logger.error(error)
                    except Exception as e:
                        error = f"Whois error: {str(e)}"
                        logger.error(error)

                    reports = await save_whois_report_async(domain, output, error, reports_base)
                    results[tool] = {
                        'status': 'success' if output else 'warning',
                        'output': output,
                        'error': error,
                        'reports': reports
                    }

                elif tool == 'osint':
                    domain = extract_domain(target)
                    result = await asyncio.to_thread(osint_scan, domain, str(reports_base))
                    results[tool] = {
                        'status': 'success',
                        'data': result,
                        'tools_executed': result.get('tools_executed', []),
                        'statistics': result.get('statistics', {}),
                        'reports': result.get('reports', {})
                    }

                elif tool == 'web':
                    result = await asyncio.to_thread(web_scan, target, str(reports_base))
                    results[tool] = {
                        'status': result.get('status', 'unknown'),
                        'target': target,
                        'data': result,
                        'reports': result.get('reports', {})
                    }

                elif tool == 'retire':
                    result = await asyncio.to_thread(retire_scan, target, str(reports_base))
                    results[tool] = {
                        'status': result.get('status', 'unknown'),
                        'target': target,
                        'data': result,
                        'reports': result.get('reports', {}),
                        'vulnerabilities_count': result.get('reports', {}).get('summary', {}).get('total_vulnerabilities', 0) if result else 0
                    }

                elif tool == 'dns':
                    domain = extract_domain(target)
                    result = await asyncio.to_thread(dns_scan, domain, str(reports_base))
                    results[tool] = {
                        'status': 'success',
                        'target': domain,
                        'dns_records_count': result.get('total', 0),
                        'nameservers': result.get('nameservers', []),
                        'dns_records': result.get('dns_records', {}),
                        'data': result,
                        'reports': result.get('reports', {})
                    }

                elif tool == 'cors':
                    scanner = CORSScanner(target, None, str(reports_base))
                    await asyncio.to_thread(scanner.run_all_checks)
                    reports = await save_cors_report_async(scanner)
                    results[tool] = {
                        'status': 'success',
                        'target': target,
                        'vulnerabilities': scanner.found_vulnerabilities,
                        'count': len(scanner.found_vulnerabilities),
                        'reports': reports
                    }

                elif tool == 'ssl-tls':
                    scanner = SSLTLSScanner(
                        target, reports_dir=str(reports_base))
                    await asyncio.to_thread(scanner.run_scan)
                    reports = await save_ssl_tls_report_async(scanner)
                    results[tool] = {
                        'status': 'success',
                        'target': target,
                        'overall_score': scanner.overall_score,
                        'vulnerabilities': scanner.vulnerabilities,
                        'count': len(scanner.vulnerabilities),
                        'recommendations': scanner.recommendations,
                        'ssl_tls_versions': scanner.tls_versions,
                        'cipher_suites': scanner.cipher_suites,
                        'reports': reports
                    }

                elif tool == 'nmap':
                    scanner = NmapScanner(
                        target, reports_dir=str(reports_base))
                    success = await asyncio.to_thread(scanner.run_scan, "-sV -sC --top-ports 1000")

                    if success:
                        await asyncio.to_thread(scanner.parse_results)
                        reports = await asyncio.to_thread(scanner.save_reports)
                        results[tool] = {
                            'status': 'success',
                            'target': target,
                            'hosts_discovered': len(scanner.discovered_hosts),
                            'open_ports': len(scanner.open_ports),
                            'vulnerabilities': len(scanner.vulnerabilities),
                            'vulnerabilities_by_severity': scanner._count_by_severity(),
                            'hosts': scanner.discovered_hosts,
                            'vulnerabilities': scanner.vulnerabilities,
                            'recommendations': scanner._get_recommendations(),
                            'reports': reports
                        }
                    else:
                        results[tool] = {
                            'status': 'error',
                            'error': 'Nmap scan failed'
                        }

              
                if tool in results:
                    results[tool] = normalize_tool_status(
                        tool, results[tool], is_scan_active(scan_id))
                with _scan_sessions_lock:
                    session = _scan_sessions.get(scan_id)
                    if session:
                        session['completed_tools'] = len(results)
                        session['progress'] = int(len(results) * 95 / max(1, len(tools_list)))
                if not is_scan_active(scan_id):
                    results[tool] = {
                        'status': 'cancelled',
                        'error': 'Сканирование было отменено'
                    }
                    break
            except Exception as e:
                results[tool] = {
                    'status': 'timeout' if isinstance(e, (TimeoutError, subprocess.TimeoutExpired)) or "timed out" in str(e).lower() else 'error',
                    'error': str(e)
                }

        cancelled = not is_scan_active(scan_id)
        tool_statuses = {item.get("status") for item in results.values()}
        if cancelled:
            scan_status = "cancelled"
        elif "timeout" in tool_statuses:
            scan_status = "timeout"
        elif "error" in tool_statuses:
            scan_status = "error"
        else:
            scan_status = "success"
        combined_reports = {}
        if not cancelled:
            combined_dir = reports_base / "combined"
            combined_payload = {
                "scan_id": scan_id,
                "target": target,
                "status": scan_status,
                "created_at": datetime.datetime.now().isoformat(),
                "tools_executed": tools_list,
                "tools_count": len(tools_list),
                "results": results,
                "normalized_findings": normalize_findings(results),
            }
            filename_base = f"combined_report_{scan_id}"
            json_path = combined_dir / "json" / f"{filename_base}.json"
            txt_path = combined_dir / "txt" / f"{filename_base}.txt"
            markdown_path = combined_dir / "md" / f"{filename_base}.md"
            json_path.parent.mkdir(parents=True, exist_ok=True)
            txt_path.parent.mkdir(parents=True, exist_ok=True)
            markdown_path.parent.mkdir(parents=True, exist_ok=True)
            json_path.write_text(
                json.dumps(combined_payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

            tool_lines = [
                f"- {tool}: {result.get('status', 'unknown')}"
                + (f" — {result['error']}" if result.get("error") else "")
                for tool, result in results.items()
            ]
            txt_path.write_text(
                "\n".join(
                    [
                        "CYBERSCOPE SCAN REPORT",
                        "=" * 40,
                        f"Target: {target}",
                        f"Scan ID: {scan_id}",
                        f"Overall status: {scan_status}",
                        "",
                        "Tool results:",
                        *(tool_lines or ["- No tool results"]),
                        "",
                        "Full results:",
                        json.dumps(results, ensure_ascii=False, indent=2),
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            markdown_path.write_text(
                render_markdown_report(combined_payload),
                encoding="utf-8",
            )
            docx_path = CombinedReport(
                scan_id, reports_base
            ).txt_to_docx(str(txt_path))
            if not docx_path:
                logger.error("Не удалось создать DOCX отчет для сканирования %s", scan_id)

            combined_reports = {
                "json": str(json_path),
                "txt": str(txt_path),
                "docx": docx_path,
                "md": str(markdown_path),
            }

        # Завершаем сессию сканирования
        end_scan_session(scan_id, scan_status)
        with _scan_sessions_lock:
            session = _scan_sessions.get(scan_id)
            if session:
                session['progress'] = 100 if not cancelled else session.get('progress', 0)
                session['current_tool'] = None
                session['completed_tools'] = len(results)
        print(f"[+] Сканирование {scan_id} завершено успешно")

        return {
            'status': scan_status,
            'target': target,
            'tools_executed': tools_list,
            'tools_count': len(tools_list),
            'results': results,
            'combined_reports': combined_reports,
            'scan_id': scan_id
        }

    except HTTPException as exc:
        end_scan_session(scan_id, "error", error=str(exc.detail))
        raise
    except Exception as e:
        end_scan_session(scan_id, "error", error=str(e))
        raise HTTPException(
            status_code=500, detail=f"Ошибка при запуске инструментов: {str(e)}")


@app.get("/api/txt-reports")
async def get_txt_reports(username: str = Depends(verify_token)):
    """
    Получить список всех файлов .txt из папки reports для всех инструментов
    """
    try:
        reports_dir = user_reports_dir(username)

        if not reports_dir.exists():
            return {"reports": [], "message": "Папка не найдена"}

        # Получаем все файлы .txt из всех папок инструментов
        txt_files = []
        for tool_dir in reports_dir.iterdir():
            if tool_dir.is_dir():
                txt_dir = tool_dir / "txt"
                if txt_dir.exists():
                    for txt_file in txt_dir.glob("*.txt"):
                        txt_files.append({
                            "tool": tool_dir.name,
                            "filename": txt_file.name,
                            "full_path": f"{tool_dir.name}/txt/{txt_file.name}"
                        })

        txt_files = sorted(
            txt_files, key=lambda x: x["filename"], reverse=True)

        return {
            "status": "success",
            "reports": txt_files,
            "count": len(txt_files)
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при получении списка отчетов: {str(e)}")


@app.get("/api/download-word-report")
async def download_word_report(filename: str = Query(..., description="Имя файла для скачивания"),
                               username: str = Depends(verify_token)):
    """
    Скачать файл .docx из папки reports/combined/word
    """
    try:
        # Защита от path traversal
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(
                status_code=400, detail="Недопустимое имя файла")

        file_path = user_reports_dir(username) / \
            "combined" / "word" / filename

        if not file_path.exists() or not file_path.suffix.lower() == ".docx":
            raise HTTPException(status_code=404, detail="Файл не найден")

        return FileResponse(
            path=file_path,
            filename=filename,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при скачивании файла: {str(e)}")


@app.get("/api/download-txt-report")
async def download_txt_report(tool: str = Query(..., description="Название инструмента"), filename: str = Query(..., description="Имя файла для скачивания"),
                              username: str = Depends(verify_token)):
    """
    Скачать файл .txt из папки reports/[tool]/txt
    """
    try:
        # Защита от path traversal
        if ".." in filename or ".." in tool or "/" in filename or "\\" in filename or "/" in tool or "\\" in tool:
            raise HTTPException(
                status_code=400, detail="Недопустимое имя файла")

        file_path = user_reports_dir(username) / tool / "txt" / filename

        if not file_path.exists() or not file_path.suffix.lower() == ".txt":
            raise HTTPException(status_code=404, detail="Файл не найден")

        return FileResponse(
            path=file_path,
            filename=filename,
            media_type="text/plain"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при скачивании файла: {str(e)}")


@app.delete("/api/delete-word-report")
async def delete_word_report(filename: str = Query(None, description="Имя файла для удаления"),
                             username: str = Depends(verify_token)):
    """
    Удалить файл .docx из папки reports/combined/word
    Если filename не указан, удаляет все word-отчеты
    """
    try:
        word_dir = user_reports_dir(username) / "combined" / "word"

        if not word_dir.exists():
            raise HTTPException(
                status_code=404, detail="Папка отчетов не найдена")

        if filename:
            # Защита от path traversal
            if ".." in filename or "/" in filename or "\\" in filename:
                raise HTTPException(
                    status_code=400, detail="Недопустимое имя файла")

            file_path = word_dir / filename
            if not file_path.exists():
                raise HTTPException(status_code=404, detail="Файл не найден")

            file_path.unlink()
            print(f"✓ Удален файл: {file_path}")

            return {
                "status": "success",
                "message": f"Файл {filename} успешно удален"
            }
        else:
            # Удаляем все файлы
            deleted_count = 0
            for file_path in word_dir.glob("*.docx"):
                file_path.unlink()
                deleted_count += 1
                print(f"✓ Удален файл: {file_path}")

            return {
                "status": "success",
                "message": f"Удалено {deleted_count} файлов",
                "deleted": deleted_count
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при удалении файла: {str(e)}")


@app.delete("/api/delete-txt-report")
async def delete_txt_report(tool: str = Query(..., description="Название инструмента"), filename: str = Query(None, description="Имя файла для удаления"),
                            username: str = Depends(verify_token)):
    """
    Удалить файл .txt из папки reports/[tool]/txt
    Если filename не указан, удаляет все файлы инструмента
    """
    try:
        # Защита от path traversal
        if ".." in tool or "/" in tool or "\\" in tool:
            raise HTTPException(
                status_code=400, detail="Недопустимое имя инструмента")

        reports_dir = user_reports_dir(username) / tool / "txt"

        if not reports_dir.exists():
            raise HTTPException(
                status_code=404, detail="Папка отчетов не найдена")

        deleted_files = []

        if filename:
            # Защита от path traversal
            if ".." in filename or "/" in filename or "\\" in filename:
                raise HTTPException(
                    status_code=400, detail="Недопустимое имя файла")

            file_path = reports_dir / filename

            if not file_path.exists() or not file_path.suffix.lower() == ".txt":
                raise HTTPException(status_code=404, detail="Файл не найден")

            file_path.unlink()
            deleted_files.append(filename)
            print(f"✓ Удален файл: {file_path}")
        else:
            # Удаляем все .txt файлы
            for file_path in reports_dir.glob("*.txt"):
                file_path.unlink()
                deleted_files.append(file_path.name)
                print(f"✓ Удален файл: {file_path}")

        return {
            "status": "success",
            "message": f"Удалено файлов: {len(deleted_files)}",
            "deleted_files": deleted_files
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при удалении файла: {str(e)}")


@app.get("/api/combined-reports")
async def get_combined_reports(username: str = Depends(verify_token)):
    """
    Получить список всех скомпилированных отчетов из папки combined
    """
    try:
        reports_dir = user_reports_dir(username) / "combined"

        if not reports_dir.exists():
            return {
                "status": "success",
                "json_reports": [],
                "txt_reports": [],
                "md_reports": [],
                "word_reports": [],
                "count": 0,
                "message": "Папка не найдена"
            }

        def list_reports(directory: Path, pattern: str) -> list[str]:
            if not directory.exists():
                return []
            return [
                path.name
                for path in sorted(
                    directory.glob(pattern),
                    key=lambda path: path.stat().st_mtime,
                    reverse=True,
                )
            ]

        # Newest reports come first so the UI can restore the latest scan.
        json_dir = reports_dir / "json"
        json_files = list_reports(json_dir, "*.json")

        txt_dir = reports_dir / "txt"
        txt_files = list_reports(txt_dir, "*.txt")

        md_dir = reports_dir / "md"
        md_files = list_reports(md_dir, "*.md")

        word_dir = reports_dir / "word"
        word_files = list_reports(word_dir, "*.docx")

        return {
            "status": "success",
            "json_reports": json_files,
            "txt_reports": txt_files,
            "md_reports": md_files,
            "word_reports": word_files,
            "count": len(json_files) + len(txt_files) + len(md_files) + len(word_files)
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при получении списка отчетов: {str(e)}")


@app.get("/api/compare-scans")
async def compare_scans(
    baseline_scan_id: str = Query(...),
    current_scan_id: str = Query(...),
    username: str = Depends(verify_token),
):
    if baseline_scan_id == current_scan_id:
        raise HTTPException(status_code=400, detail="Выберите два разных сканирования")
    try:
        uuid.UUID(baseline_scan_id)
        uuid.UUID(current_scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Некорректный ID сканирования") from exc

    reports_dir = user_reports_dir(username) / "combined" / "json"

    def load_scan(scan_id: str) -> dict:
        report_path = reports_dir / f"combined_report_{scan_id}.json"
        if not report_path.is_file():
            raise HTTPException(status_code=404, detail=f"Отчет сканирования {scan_id} не найден")
        try:
            return json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Не удалось прочитать отчет %s: %s", report_path, exc)
            raise HTTPException(status_code=500, detail="Не удалось прочитать отчет сканирования") from exc

    baseline = load_scan(baseline_scan_id)
    current = load_scan(current_scan_id)
    if baseline.get("target") != current.get("target"):
        raise HTTPException(status_code=400, detail="Сравнивать можно только сканирования одной цели")

    def to_map(report: dict) -> dict[str, dict]:
        findings = report.get("normalized_findings")
        if not isinstance(findings, list):
            findings = normalize_findings(report.get("results", {}))
        return {
            item["fingerprint"]: item
            for item in findings
            if isinstance(item, dict) and item.get("fingerprint")
        }

    baseline_findings = to_map(baseline)
    current_findings = to_map(current)
    added_ids = current_findings.keys() - baseline_findings.keys()
    removed_ids = baseline_findings.keys() - current_findings.keys()
    unchanged_ids = current_findings.keys() & baseline_findings.keys()
    added = [current_findings[key] for key in sorted(added_ids)]
    removed = [baseline_findings[key] for key in sorted(removed_ids)]
    unchanged = [current_findings[key] for key in sorted(unchanged_ids)]
    return {
        "status": "success",
        "target": current.get("target"),
        "baseline_scan_id": baseline_scan_id,
        "current_scan_id": current_scan_id,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "unchanged": len(unchanged),
        },
        "added": added,
        "removed": removed,
        "unchanged": unchanged,
    }


@app.get("/api/word-reports")
async def get_word_reports(username: str = Depends(verify_token)):
    """
    Получить список всех word-отчетов из папки combined/word
    """
    try:
        word_dir = user_reports_dir(username) / "combined" / "word"

        if not word_dir.exists():
            return {
                "status": "success",
                "reports": [],
                "count": 0
            }

        # Получаем все DOCX файлы
        word_files = []
        for file_path in sorted(word_dir.glob("*.docx"), reverse=True):
            word_files.append({
                "filename": file_path.name,
                "size": file_path.stat().st_size,
                "created": file_path.stat().st_mtime
            })

        return {
            "status": "success",
            "reports": word_files,
            "count": len(word_files)
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при получении списка отчетов: {str(e)}")


@app.get("/api/download-combined-report")
async def download_combined_report(filename: str = Query(..., description="Имя файла для скачивания"), report_type: str = Query("json", description="Тип отчета: json, txt, word или docx"),
                                   username: str = Depends(verify_token)):
    """
    Скачать скомпилированный отчет из папки combined
    """
    try:
        # Защита от path traversal
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(
                status_code=400, detail="Недопустимое имя файла")

        if report_type == "json":
            file_path = user_reports_dir(username) / \
                "combined" / "json" / filename
            if not file_path.suffix.lower() == ".json":
                raise HTTPException(
                    status_code=400, detail="Неверный тип файла")
            media_type = "application/json"
        elif report_type == "txt":
            file_path = user_reports_dir(username) / \
                "combined" / "txt" / filename
            if not file_path.suffix.lower() == ".txt":
                raise HTTPException(
                    status_code=400, detail="Неверный тип файла")
            media_type = "text/plain"
        elif report_type in ["md", "markdown"]:
            file_path = user_reports_dir(username) / \
                "combined" / "md" / filename
            if not file_path.suffix.lower() == ".md":
                raise HTTPException(
                    status_code=400, detail="Неверный тип файла")
            media_type = "text/markdown; charset=utf-8"
        elif report_type in ["word", "docx"]:
            file_path = user_reports_dir(username) / \
                "combined" / "word" / filename
            if not file_path.suffix.lower() == ".docx":
                raise HTTPException(
                    status_code=400, detail="Неверный тип файла")
            media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        else:
            raise HTTPException(
                status_code=400, detail="Неизвестный тип отчета")

        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Файл не найден")

        return FileResponse(
            path=file_path,
            filename=filename,
            media_type=media_type
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при скачивании файла: {str(e)}")


@app.delete("/api/delete-combined-report")
async def delete_combined_report(filename: str = Query(..., description="Имя файла для удаления"), report_type: str = Query("json", description="Тип отчета: json, txt, word или docx"),
                                 username: str = Depends(verify_token)):
    """
    Удалить скомпилированный отчет из папки combined
    """
    try:
        # Защита от path traversal
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(
                status_code=400, detail="Недопустимое имя файла")

        if report_type == "json":
            file_path = user_reports_dir(username) / \
                "combined" / "json" / filename
        elif report_type == "txt":
            file_path = user_reports_dir(username) / \
                "combined" / "txt" / filename
        elif report_type in ["word", "docx"]:
            file_path = user_reports_dir(username) / \
                "combined" / "word" / filename
        elif report_type in ["md", "markdown"]:
            file_path = user_reports_dir(username) / \
                "combined" / "md" / filename
        else:
            raise HTTPException(
                status_code=400, detail="Неизвестный тип отчета")

        expected_suffix = {
            "json": ".json",
            "txt": ".txt",
            "word": ".docx",
            "docx": ".docx",
            "md": ".md",
            "markdown": ".md",
        }[report_type]
        if file_path.suffix.lower() != expected_suffix:
            raise HTTPException(status_code=400, detail="Неверный тип файла")

        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Файл не найден")

        file_path.unlink()
        print(f"✓ Удален файл: {file_path}")

        return {
            "status": "success",
            "message": f"Файл {filename} успешно удален"
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при удалении файла: {str(e)}")


@app.delete("/api/clear-all-reports")
async def clear_all_reports(username: str = Depends(verify_token)):
    """
    Очистить ВСЕ отчеты (word, json, combined)
    """
    try:
        reports_base = user_reports_dir(username)

        if not reports_base.exists():
            return {
                "status": "success",
                "message": "Директория отчетов не существует",
                "deleted": 0
            }

        deleted_count = 0
        deleted_files = []

        for file_path in reports_base.rglob("*"):
            if file_path.is_file():
                try:
                    file_path.unlink()
                    deleted_files.append(file_path.name)
                    deleted_count += 1
                except OSError as e:
                    logger.error("Не удалось удалить отчет %s: %s", file_path, e)

        return {
            "status": "success",
            "message": f"Удалено всех файлов: {deleted_count}",
            "deleted": deleted_count,
            "deleted_files": deleted_files
        }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при очистке отчетов: {str(e)}")


# Получиваем глобальный экземпляр планировщика
scheduler = get_scheduler(Path(__file__).parent)
_scan_queue_semaphore = asyncio.Semaphore(
    max(1, int(os.getenv("MAX_CONCURRENT_SCANS", "1")))
)


@app.on_event("startup")
async def startup_events():
    """Инициализация при запуске приложения"""
    global _scan_queue_semaphore
    _scan_queue_semaphore = asyncio.Semaphore(
        max(1, int(os.getenv("MAX_CONCURRENT_SCANS", "1")))
    )
    logger.info("🚀 Запуск приложения...")

    await _register_scan_callbacks()

    # Запускаем планировщик
    scheduler.start()
    logger.info("📅 Планировщик запущен")


@app.on_event("shutdown")
async def shutdown_events():
    """Очистка при завершении приложения"""
    logger.info("🛑 Завершение приложения...")
    scheduler.stop()
    logger.info("📅 Планировщик остановлен")


@app.get("/api/tasks")
async def get_tasks(username: str = Depends(verify_token)):
    """Получить список всех запланированных задач"""
    try:
        tasks = [task for task in scheduler.get_tasks()
                 if task.get("username") == username]
        return {
            "status": "success",
            "tasks": tasks,
            "count": len(tasks)
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при получении задач: {str(e)}")


@app.get("/api/tools")
async def list_tools(username: str = Depends(verify_token)):
    """List runnable scanners and their current local dependency availability."""
    return {"status": "success", "tools": get_tool_catalog()}


@app.get("/api/tasks/{task_id}")
async def get_task(task_id: str, username: str = Depends(verify_token)):
    """Получить конкретную задачу по ID"""
    try:
        task = scheduler.get_task(task_id)
        if not task or task.get("username") != username:
            raise HTTPException(status_code=404, detail="Задача не найдена")

        return {
            "status": "success",
            "task": task
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при получении задачи: {str(e)}")


@app.post("/api/tasks")
async def create_task(task: dict, username: str = Depends(verify_token)):
    """Создать новую запланированную задачу"""
    try:
        # Валидация обязательных полей
        required_fields = ['query', 'activeTools', 'type', 'time']
        for field in required_fields:
            if field not in task:
                raise HTTPException(
                    status_code=400,
                    detail=f"Отсутствует обязательное поле: {field}")

        # Валидация query
        query_value = task.get("query")
        if not isinstance(query_value, str) or not query_value.strip():
            raise HTTPException(
                status_code=400,
                detail="Цель сканирования не может быть пустой")
        query = query_value.strip()

        # Валидация инструментов
        active_tools = task.get("activeTools")
        if not isinstance(active_tools, list) or not active_tools:
            raise HTTPException(
                status_code=400,
                detail="Должен быть выбран хотя бы один инструмент")
        if any(not isinstance(tool, str) for tool in active_tools):
            raise HTTPException(
                status_code=400,
                detail="Некорректный список инструментов",
            )
        active_tools = list(dict.fromkeys(
            tool.strip().lower() for tool in active_tools
        ))
        if not active_tools or any(not tool for tool in active_tools):
            raise HTTPException(
                status_code=400,
                detail="Должен быть выбран хотя бы один инструмент",
            )
        invalid_tools = sorted(set(active_tools) - SCHEDULED_TOOL_IDS)
        if invalid_tools:
            raise HTTPException(
                status_code=400,
                detail=f"Инструменты не поддерживаются планировщиком: {', '.join(invalid_tools)}",
            )

        task["username"] = username
        task["query"] = query
        task["activeTools"] = active_tools
        task.pop("id", None)

        # Регистрируем callbacks для инструментов если они еще не зарегистрированы
        await _register_scan_callbacks()

        # Добавляем задачу в планировщик
        task_id = scheduler.add_task(task)

        logger.info(f"✓ Задача создана: {task_id}")

        return {
            "status": "success",
            "task_id": task_id,
            "message": "Задача успешно создана"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"✗ Ошибка при создании задачи: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при создании задачи: {str(e)}")


@app.put("/api/tasks/{task_id}")
async def update_task(task_id: str, task_data: dict, username: str = Depends(verify_token)):
    """Обновить запланированную задачу"""
    try:
        existing_task = scheduler.get_task(task_id)
        if not existing_task or existing_task.get("username") != username:
            raise HTTPException(status_code=404, detail="Задача не найдена")

        if "activeTools" in task_data:
            active_tools = task_data["activeTools"]
            if not isinstance(active_tools, list) or not active_tools:
                raise HTTPException(
                    status_code=400,
                    detail="Должен быть выбран хотя бы один инструмент",
                )
            if any(not isinstance(tool, str) for tool in active_tools):
                raise HTTPException(
                    status_code=400,
                    detail="Некорректный список инструментов",
                )
            active_tools = list(dict.fromkeys(
                tool.strip().lower() for tool in active_tools
            ))
            if not active_tools or any(not tool for tool in active_tools):
                raise HTTPException(
                    status_code=400,
                    detail="Должен быть выбран хотя бы один инструмент",
                )
            invalid_tools = sorted(set(active_tools) - SCHEDULED_TOOL_IDS)
            if invalid_tools:
                raise HTTPException(
                    status_code=400,
                    detail=f"Инструменты не поддерживаются планировщиком: {', '.join(invalid_tools)}",
                )
            task_data["activeTools"] = active_tools

        # Обновляем задачу
        task_data.pop("username", None)
        scheduler.update_task(task_id, task_data)

        logger.info(f"✓ Задача обновлена: {task_id}")

        return {
            "status": "success",
            "message": "Задача успешно обновлена"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при обновлении задачи: {str(e)}")


@app.delete("/api/tasks/{task_id}")
async def delete_task(task_id: str, username: str = Depends(verify_token)):
    """Удалить запланированную задачу"""
    try:
        task = scheduler.get_task(task_id)
        if not task or task.get("username") != username:
            raise HTTPException(status_code=404, detail="Задача не найдена")
        removed = scheduler.remove_task(task_id)

        logger.info(f"✓ Задача удалена: {task_id}")

        return {
            "status": "success",
            "message": "Задача успешно удалена"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при удалении задачи: {str(e)}")


@app.get("/api/task-results/{task_id}")
async def get_task_results(task_id: str, username: str = Depends(verify_token)):
    """Получить результаты сканирования для задачи"""
    try:
        task = scheduler.get_task(task_id)
        if not task or task.get("username") != username:
            raise HTTPException(status_code=404, detail="Задача не найдена")

        # Возвращаем информацию о последнем сканировании
        return {
            "status": "success",
            "task_id": task_id,
            "task_type": task.get('type'),
            "target": task.get('query'),
            "tools": task.get('activeTools', []),
            "last_scan_folder": task.get('last_scan_folder'),
            "last_scan_time": task.get('last_scan_time'),
            "scan_results": task.get('scan_results', []),
            "next_run": task.get('nextRun'),
            "enabled": task.get('enabled', True)
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при получении результатов: {str(e)}")


async def _register_scan_callbacks():
    """Зарегистрировать callbacks для всех инструментов"""

    # === SCANNER ===
    async def callback_scanner(target, allow_internal=False, task_id=None, username=None):
        """Callback для VulnerabilityScanner"""
        try:
            logger.info(f"🔄 Запуск scanner для {target}")
            from scanners.vulnerability_scanner import VulnerabilityScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(user_reports_dir(username) / (task_id or "scheduled"))
            scanner = VulnerabilityScanner(target, reports_dir)
            scanner.scan()
            # Сохраняем оба формата отчётов
            txt_report = scanner.save_txt_report()
            json_report = scanner.save_json_report()
            logger.info(f"✓ scanner завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске scanner: {e}", exc_info=True)
            raise

    # === NUCLEI ===
    async def callback_nuclei(target, allow_internal=False, task_id=None, username=None):
        """Callback для Nuclei сканера"""
        try:
            logger.info(f"🔄 Запуск nuclei для {target}")
            from scanners.nuclei_scanner import run_scan
            # Создаём путь к папке для этого сканирования
            reports_dir = str(user_reports_dir(username) / (task_id or "scheduled"))
            result = await run_scan(target, save_reports=True, reports_dir=reports_dir)
            logger.info(f"✓ nuclei завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске nuclei: {e}", exc_info=True)
            raise

    # === OSINT ===
    async def callback_osint(target, allow_internal=False, task_id=None, username=None):
        """Callback для OSINT сканера"""
        try:
            logger.info(f"🔄 Запуск osint для {target}")
            from scanners.osint_scanner import simple_scan
            # Создаём путь к папке для этого сканирования
            reports_dir = str(user_reports_dir(username) / (task_id or "scheduled"))
            result = simple_scan(target, reports_dir)
            logger.info(f"✓ osint завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске osint: {e}", exc_info=True)
            raise

    # === WAPPALYZER ===
    async def callback_wappalyzer(target, allow_internal=False, task_id=None, username=None):
        """Callback для Wappalyzer"""
        try:
            logger.info(f"🔄 Запуск wappalyzer для {target}")
            from scanners.wappalyzer_scanner import WappalyzerScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(user_reports_dir(username) / (task_id or "scheduled"))
            scanner = WappalyzerScanner(target, reports_dir)
            scanner.scan()
            scanner.display_results()
            # Сохраняем оба формата отчётов
            txt_report = scanner.save_txt_report()
            json_report = scanner.save_json_report()
            logger.info(f"✓ wappalyzer завершен для {target}")
        except Exception as e:
            logger.error(
                f"✗ Ошибка при запуске wappalyzer: {e}", exc_info=True)
            raise

    # === SSL-TLS ===
    async def callback_ssl_tls(target, allow_internal=False, task_id=None, username=None):
        """Callback для SSL/TLS сканера"""
        try:
            logger.info(f"🔄 Запуск ssl-tls для {target}")
            from scanners.ssl_tls_scanner import SSLTLSScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(user_reports_dir(username) / (task_id or "scheduled"))
            scanner = SSLTLSScanner(target, reports_dir)
            scanner.scan()
            scanner.display_results()
            # Сохраняем оба формата отчётов
            txt_report = scanner.save_txt_report()
            json_report = scanner.save_json_report()
            logger.info(f"✓ ssl-tls завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске ssl-tls: {e}", exc_info=True)
            raise

    # === NMAP ===
    async def callback_nmap(target, allow_internal=False, task_id=None, username=None):
        """Callback для Nmap сканера"""
        try:
            logger.info(f"🔄 Запуск nmap для {target}")
            from scanners.nmap_scanner import NmapScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(user_reports_dir(username) / (task_id or "scheduled"))
            scanner = NmapScanner(target, reports_dir,
                                  allow_internal=allow_internal)
            scanner.scan()
            scanner.display_results()
            # Сохраняем оба формата отчётов
            txt_report = scanner.save_txt_report()
            json_report = scanner.save_json_report()
            logger.info(f"✓ nmap завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске nmap: {e}", exc_info=True)
            raise

    # === CORS ===
    async def callback_cors(target, allow_internal=False, task_id=None, username=None):
        """Callback для CORS сканера"""
        try:
            logger.info(f"🔄 Запуск cors для {target}")
            from scanners.cors_scanner import CORSScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(user_reports_dir(username) / (task_id or "scheduled"))
            scanner = CORSScanner(target, reports_dir)
            scanner.scan()
            scanner.display_results()
            # Сохраняем оба формата отчётов
            txt_report = scanner.save_txt_report()
            json_report = scanner.save_json_report()
            logger.info(f"✓ cors завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске cors: {e}", exc_info=True)
            raise

    # === DNS ===
    async def callback_dns(target, allow_internal=False, task_id=None, username=None):
        """Callback для DNS сканера"""
        try:
            logger.info(f"🔄 Запуск dns для {target}")
            from scanners.dns_scanner import DNSScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(user_reports_dir(username) / (task_id or "scheduled"))
            scanner = DNSScanner(target, reports_dir)
            scanner.scan()
            scanner.display_results()
            # Сохраняем оба формата отчётов
            txt_report = scanner.save_txt_report()
            json_report = scanner.save_json_report()
            logger.info(f"✓ dns завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске dns: {e}", exc_info=True)
            raise

    # === RETIRE ===
    async def callback_retire(target, allow_internal=False, task_id=None, username=None):
        """Callback для Retire.js"""
        try:
            logger.info(f"🔄 Запуск retire для {target}")
            from scanners.retire_scanner import RetireScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(user_reports_dir(username) / (task_id or "scheduled"))
            scanner = RetireScanner(target, reports_dir)
            results = scanner.scan()
            scanner.display_results()
            # Сохраняем оба формата отчётов
            if results:
                txt_report = scanner.save_txt_report(results)
                json_report = scanner.save_json_report(results)
            logger.info(f"✓ retire завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске retire: {e}", exc_info=True)
            raise

    # === WHOIS ===
    async def callback_whois(target, allow_internal=False, task_id=None, username=None):
        """Callback для WHOIS сканера"""
        try:
            domain = extract_domain(target)
            logger.info(f"🔄 Запуск whois для {domain}")
            whois_result = await asyncio.to_thread(whois.whois, domain)
            output = str(whois_result) if whois_result else ""
            error = "" if output else "Whois returned empty result"
            reports_dir = user_reports_dir(username) / (task_id or "scheduled")
            await save_whois_report_async(domain, output, error, reports_dir)
            if error:
                raise RuntimeError(error)
            logger.info(f"✓ whois завершен для {domain}")
            return {"status": "completed", "output": output}
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске whois: {e}", exc_info=True)
            raise

    # === WEB ===
    async def callback_web(target, allow_internal=False, task_id=None, username=None):
        """Callback для Web сканера"""
        try:
            logger.info(f"🔄 Запуск web для {target}")
            from scanners.web_url_scanner import WebScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(user_reports_dir(username) / (task_id or "scheduled"))
            scanner = WebScanner(target, reports_dir)
            results = scanner.scan()
            scanner.display_results()
            # Сохраняем оба формата отчётов
            if results:
                txt_report = scanner.save_txt_report(results)
                json_report = scanner.save_json_report(results)
            logger.info(f"✓ web завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске web: {e}", exc_info=True)
            raise

    # Регистрируем все callbacks
    callbacks_map = {
        'scanner': callback_scanner,
        'nuclei': callback_nuclei,
        'osint': callback_osint,
        'wappalyzer': callback_wappalyzer,
        'ssl-tls': callback_ssl_tls,
        'nmap': callback_nmap,
        'cors': callback_cors,
        'dns': callback_dns,
        'retire': callback_retire,
        'whois': callback_whois,
        'web': callback_web,
    }

    for tool_name, callback in callbacks_map.items():
        if tool_name not in scheduler.scan_callbacks:
            scheduler.register_callback(tool_name, callback)
            logger.info(f"✓ Callback зарегистрирован для {tool_name}")


@app.get("/api/get-report-content")
async def get_report_content(filename: str = Query(..., description="Имя файла отчета"), report_type: str = Query("json", description="Тип отчета: json, txt_report, или combined"),
                            username: str = Depends(verify_token)):
    """
    Получить содержимое отчета для просмотра в браузере
    Args:
        filename: Имя файла отчета
        report_type: Тип отчета:
            - 'json': JSON отчеты из combined/json
            - 'txt_report': TXT отчеты из combined/txt
            - 'combined': Все типы из combined
    Returns:
        Текстовое содержимое файла
    """
    try:
        # Защита от path traversal
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(
                status_code=400, detail="Недопустимое имя файла")

        reports_base = user_reports_dir(username) / "combined"

        if report_type == "json":
            file_path = reports_base / "json" / filename
            if not file_path.exists() or not file_path.suffix.lower() == ".json":
                raise HTTPException(
                    status_code=404, detail="JSON файл не найден")

        elif report_type == "txt_report":
            file_path = reports_base / "txt" / filename
            if not file_path.exists() or not file_path.suffix.lower() == ".txt":
                raise HTTPException(
                    status_code=404, detail="TXT файл не найден")

        elif report_type in {"md", "markdown"}:
            file_path = reports_base / "md" / filename
            if not file_path.exists() or not file_path.suffix.lower() == ".md":
                raise HTTPException(
                    status_code=404, detail="Markdown файл не найден")

        else:
            raise HTTPException(
                status_code=400, detail="Неизвестный тип отчета")

        # Читаем содержимое файла
        try:
            if report_type == "json":
                # Для JSON файлов читаем и парсим
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                # Проверяем, что это валидный JSON
                json.loads(content)
                return PlainTextResponse(content, media_type="text/plain")
            else:
                # Для TXT файлов просто читаем
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                media_type = "text/markdown" if report_type in {"md", "markdown"} else "text/plain"
                return PlainTextResponse(content, media_type=media_type)
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=500, detail="Ошибка при чтении файла (кодировка)")
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=400, detail="Файл не является корректным JSON")
        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"Ошибка при чтении файла: {str(e)}")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при получении содержимого отчета: {str(e)}")


@app.get("/api/available-reports")
async def get_available_reports(username: str = Depends(verify_token)):
    """
    Получить список доступных JSON отчетов для выбора
    """
    try:
        reports_base = user_reports_dir(username)

        # Структура для хранения отчетов
        available_reports = {
            'scanner': [],
            'nuclei': [],
            'nmap': [],
            'web': [],
            'cors': [],
            'osint': [],
            'amass': [],
            'wappalyzer': [],
            'dns': [],
            'retire': [],
            'ssl-tls': [],
            'whois': [],
            'combined': []
        }

        # Поиск отчетов по инструментам
        tools = [
            'scanner', 'nuclei', 'nmap', 'web', 'cors', 'osint',
            'amass', 'wappalyzer', 'dns', 'retire', 'ssl-tls', 'whois'
        ]

        for tool in tools:
            json_dir = reports_base / tool / "json"
            if json_dir.exists():
                for json_file in json_dir.glob("*.json"):
                    try:
                        with open(json_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)

                        # Извлекаем информацию для отображения
                        report_info = {
                            'filename': json_file.name,
                            'path': str(json_file.relative_to(reports_base)),
                            'tool': tool,
                            'scan_datetime': data.get('scan_datetime', ''),
                            'target': data.get('scan_info', {}).get('target_url',
                                                                    data.get('target', 'Unknown')),
                            'total_vulnerabilities': 0,
                            'summary': {}
                        }

                        # Извлекаем статистику в зависимости от типа инструмента
                        if tool == 'scanner':
                            summary = data.get('summary', {})
                            report_info['total_vulnerabilities'] = summary.get(
                                'total_vulnerabilities', 0)
                            report_info['summary'] = summary

                        elif tool == 'nuclei':
                            total = data.get('total_findings', len(
                                data.get('results', [])))
                            report_info['total_vulnerabilities'] = total
                            report_info['summary'] = data.get(
                                'by_severity', {})

                        elif tool == 'nmap':
                            summary = data.get('summary', {})
                            report_info['total_vulnerabilities'] = summary.get(
                                'total_vulnerabilities', 0)
                            report_info['summary'] = summary

                        elif tool == 'web':
                            report_info['total_vulnerabilities'] = len(
                                data.get('vulnerabilities', []))
                            report_info['summary'] = data.get('summary', {})

                        elif tool == 'cors':
                            summary = data.get('summary', {})
                            report_info['total_vulnerabilities'] = summary.get(
                                'total_vulnerabilities', 0)
                            report_info['summary'] = summary

                        elif tool == 'osint':
                            summary = data.get('summary', {})
                            report_info['total_vulnerabilities'] = len(
                                data.get('results', []))
                            report_info['summary'] = summary

                        available_reports[tool].append(report_info)

                    except Exception as e:
                        print(f"Ошибка чтения {json_file}: {e}")
                        continue

        # Поиск комбинированных отчетов
        combined_dir = reports_base / "combined" / "json"
        if combined_dir.exists():
            for json_file in combined_dir.glob("*.json"):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)

                    report_info = {
                        'filename': json_file.name,
                        'path': str(json_file.relative_to(reports_base)),
                        'tool': 'combined',
                        'scan_datetime': data.get('scan_datetime', ''),
                        'targets': data.get('targets', []),
                        'total_vulnerabilities': data.get('summary', {}).get('total_vulnerabilities', 0),
                        'summary': data.get('summary', {})
                    }
                    available_reports['combined'].append(report_info)
                except Exception as e:
                    print(f"Ошибка чтения {json_file}: {e}")
                    continue

        # Сортируем по дате (новые сверху)
        for tool in available_reports:
            available_reports[tool].sort(
                key=lambda x: x.get('scan_datetime', ''), reverse=True)

        return {
            'status': 'success',
            'reports': available_reports
        }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка получения списка отчетов: {str(e)}")


@app.post("/api/analyze-report")
async def analyze_report_endpoint(
    request_body: dict = Body(...),
    username: str = Depends(verify_token)
):
    """
    Анализировать отчет безопасности с помощью LM Studio AI
    
    Принимает путь к файлу отчета и возвращает анализ от ИИ
    с рекомендациями и шагами по исправлению
    """
    try:
        # Получаем данные отчета из файла
        file_path = request_body.get("file_path")
        if not isinstance(file_path, str) or not file_path:
            raise HTTPException(status_code=400, detail="Укажите file_path в теле запроса")
        
        full_path = resolve_user_report_path(username, file_path)
        
        if not full_path.exists():
            raise HTTPException(status_code=404, detail=f"Отчет не найден: {file_path}")
        
        with open(full_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        # Анализируем через LM Studio
        analysis_result = await analyze_report_with_ai(report_data)
        
        return {
            "status": "success",
            "analysis": analysis_result,
            "report_file": file_path,
            "timestamp": datetime.datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in analyze_report_endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/lm-studio-status")
async def lm_studio_status():
    """
    Проверить доступность LM Studio
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{LM_STUDIO_API}/models",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    return {
                        "status": "online",
                        "url": LM_STUDIO_URL,
                        "message": "LM Studio готов к работе"
                    }
                else:
                    return {
                        "status": "error",
                        "url": LM_STUDIO_URL,
                        "message": f"LM Studio вернул статус {response.status}"
                    }
    except Exception as e:
        return {
            "status": "offline",
            "url": LM_STUDIO_URL,
            "message": f"LM Studio не доступен: {str(e)}"
        }


@app.get("/api/report-content")
async def get_report_content(
    report_path: str = Query(...,
                             description="Путь к файлу отчета относительно reports"),
    username: str = Depends(verify_token)
):
    """
    Получить содержимое JSON отчета для аналитики
    """
    try:
        full_path = resolve_user_report_path(username, report_path)

        if not full_path.exists():
            raise HTTPException(status_code=404, detail="Файл не найден")

        with open(full_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        return {
            'status': 'success',
            'data': data,
            'filename': full_path.name,
            'tool': report_path.split('/')[0] if '/' in report_path else 'unknown'
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка чтения отчета: {str(e)}")


def resolve_source_path(source_path: str) -> str:
    """Resolve source path by checking multiple possible locations"""
    from pathlib import Path

    # Если путь уже абсолютный и существует
    if os.path.exists(source_path):
        return source_path

    # Проверяем относительно текущей директории
    current_dir = Path.cwd()
    candidate = current_dir / source_path
    if candidate.exists():
        return str(candidate)

    # Проверяем относительно директории сервера
    server_dir = Path(__file__).parent
    candidate = server_dir / source_path
    if candidate.exists():
        return str(candidate)

    # Проверяем относительно родительской директории
    candidate = server_dir.parent / source_path
    if candidate.exists():
        return str(candidate)

    # Проверяем относительно backend директории (если есть)
    backend_dir = server_dir.parent / "backend"
    if backend_dir.exists():
        candidate = backend_dir / source_path
        if candidate.exists():
            return str(candidate)

    # Если ничего не найдено, возвращаем исходный путь (вызовет ошибку позже)
    return source_path


# ==================== LM Studio Integration ====================

LM_STUDIO_URL = os.getenv("LM_STUDIO_URL", "http://127.0.0.1:1234")
LM_STUDIO_API = f"{LM_STUDIO_URL}/v1"


async def send_to_lm_studio(prompt: str, max_tokens: int = 2000) -> str:
    """
    Отправить промпт в LM Studio и получить ответ
    """
    try:
        async with aiohttp.ClientSession() as session:
            payload = {
                "model": "local-model",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.7,
                "max_tokens": max_tokens,
                "stream": False
            }
            
            async with session.post(
                f"{LM_STUDIO_API}/chat/completions",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data["choices"][0]["message"]["content"]
                else:
                    logger.error(f"LM Studio error: {response.status}")
                    raise HTTPException(
                        status_code=500,
                        detail=f"LM Studio error: {response.status}"
                    )
    except aiohttp.ClientConnectorError:
        raise HTTPException(
            status_code=500,
            detail="LM Studio не доступен. Убедитесь что LM Studio запущен на http://127.0.0.1:1234"
        )
    except Exception as e:
        logger.error(f"Error sending to LM Studio: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


async def analyze_report_with_ai(report_data: dict, report_type: str = "security") -> dict:
    """
    Анализировать отчет безопасности через LM Studio AI и получить рекомендации
    
    Args:
        report_data: Данные отчета в формате JSON
        report_type: Тип отчета (security, vulnerability, etc)
    
    Returns:
        dict с рекомендациями, шагами и анализом
    """
    try:
        # Подготавливаем промпт для анализа
        report_json = json.dumps(report_data, ensure_ascii=False, indent=2)
        
        prompt = f"""Ты эксперт по информационной безопасности. Проанализируй следующий отчет сканирования безопасности и дай детальные рекомендации:

ОТЧЕТ:
{report_json[:3000]}...

Пожалуйста дай ответ в следующем формате на русском языке:

## 📋 АНАЛИЗ
[Краткий анализ найденных проблем]

## ⚠️ КРИТИЧНЫЕ ПРОБЛЕМЫ
[Список критичных проблем если они есть]

## 📋 РЕКОМЕНДАЦИИ
[Детальные рекомендации по исправлению]

## 🔧 ШАГИ ДЛЯ ИСПРАВЛЕНИЯ
1. [Первый шаг]
2. [Второй шаг]
3. [Третий шаг]
и т.д.

## ✅ ПРОВЕРКА
[Как проверить что проблемы исправлены]

## 📊 ПРИОРИТЕТ
[Определи приоритет каждой проблемы: Критичный/Высокий/Средний/Низкий]"""

        # Отправляем в LM Studio
        response = await send_to_lm_studio(prompt, max_tokens=3000)
        
        return {
            "status": "success",
            "analysis": response,
            "model": "LM Studio Local AI",
            "timestamp": datetime.datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error analyzing report: {str(e)}")
        raise





if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
