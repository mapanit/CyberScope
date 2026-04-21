# server.py
from scheduler import get_scheduler
from core.report_utils import create_combined_report
from scanners.nmap_scanner import NmapScanner, simple_scan as nmap_scan
from scanners.dns_scanner import simple_scan as dns_scan
from scanners.ssl_tls_scanner import SSLTLSScanner
from scanners.cors_scanner import CORSScanner
from scanners.retire_scanner import simple_scan as retire_scan
from scanners.web_url_scanner import simple_scan as web_scan
from scanners.osint_scanner import simple_scan as osint_scan
from scanners.wappalyzer_scanner import simple_scan as wappalyzer_scan, WappalyzerScanner
from scanners.vulnerability_scanner import VulnerabilityScanner
from fastapi import FastAPI, HTTPException, Query, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, PlainTextResponse
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

logger = logging.getLogger(__name__)

# from auth.sqlalchemy.orm import Session
# from auth.database import engine, get_db
# from models import Base
# from auth.schemas import UserCreate, UserLogin, UserResponse, Token
# from auth.auth import authenticate_user, create_access_token, get_password_hash, get_current_user
# import models

# Глобальный словарь для отслеживания статуса сканирований
_scan_sessions = {}
_scan_sessions_lock = threading.Lock()


# Base.metadata.create_all(bind=engine)


def create_scan_session(scan_id: str) -> dict:
    """Создать сессию сканирования"""
    with _scan_sessions_lock:
        session = {
            'scan_id': scan_id,
            'active': True,
            'cancelled': False,
            'start_time': datetime.datetime.now(),
            'progress': 0,
            'current_tool': None
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
        if scan_id in _scan_sessions:
            _scan_sessions[scan_id]['cancelled'] = True
            _scan_sessions[scan_id]['active'] = False
            return True
    return False


def end_scan_session(scan_id: str):
    """Завершить сессию сканирования"""
    with _scan_sessions_lock:
        if scan_id in _scan_sessions:
            _scan_sessions[scan_id]['active'] = False
            _scan_sessions[scan_id]['end_time'] = datetime.datetime.now()

# Заглушки для функций которые не реализованы


def amass_scan(domain: str, mode: str = "passive", timeout: int = 180, reports_dir: str = None) -> dict:
    """Заглушка для amass сканирования"""
    return {
        'status': 'completed',
        'subdomains_count': 0,
        'subdomains_sample': [],
        'statistics': {},
        'unique_ips': 0,
        'scan_duration': 0,
        'error': 'Amass не установлен на сервере'
    }


def nuclei_simple_scan(url: str) -> list:
    """DEPRECATED: используйте scanners.nuclei_scanner.run_scan"""
    from scanners.nuclei_scanner import simple_scan, get_summary
    results = simple_scan(url)
    return results


def nuclei_get_summary(results: list) -> dict:
    """DEPRECATED: используйте scanners.nuclei_scanner.get_summary"""
    from scanners.nuclei_scanner import get_summary
    return get_summary(results)


def nuclei_run_scan(target: str, save_reports: bool = False, reports_dir: str = None) -> list:
    """DEPRECATED: используйте scanners.nuclei_scanner.run_scan"""
    from scanners.nuclei_scanner import run_scan
    result = run_scan(target, save_reports, reports_dir)
    return result


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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


async def run_command(cmd: list):
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

    stdout, stderr = await proc.communicate()
    return stdout.decode(errors="ignore"), stderr.decode(errors="ignore")


# Функции сохранения отчетов
def save_scanner_report(scanner: VulnerabilityScanner) -> str:
    """Сохранить отчет сканера в JSON в backend/reports"""
    reports_base = Path(__file__).parent / "reports"

    # Создаем директории если нет
    json_dir = reports_base / "json"
    json_dir.mkdir(parents=True, exist_ok=True)

    # Используем filename_base из объекта scanner
    filename_base = scanner.filename_base

    # Сохраняем JSON отчет
    json_path = json_dir / f"{filename_base}.json"
    report_data = scanner.get_json_report()

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    print(f"✓ JSON отчет сохранен: {json_path}")
    return str(json_path)


def save_whois_report(domain: str, output: str, error: str) -> dict:
    """Сохранить отчет whois в JSON и TXT в backend/reports/whois"""
    reports_base = Path(__file__).parent / "reports"

    # Создаем директории если нет
    whois_dir = reports_base / "whois"
    json_dir = whois_dir / "json"
    txt_dir = whois_dir / "txt"
    json_dir.mkdir(parents=True, exist_ok=True)
    txt_dir.mkdir(parents=True, exist_ok=True)

    # Создаем filename
    scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename_base = f"whois_{domain}_{scan_id}"

    # Сохраняем JSON отчет
    json_path = json_dir / f"{filename_base}.json"
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

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    # Сохраняем TXT отчет
    txt_path = txt_dir / f"{filename_base}.txt"
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

    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write(txt_content)

    print(f"✓ WHOIS отчеты сохранены: JSON: {json_path}, TXT: {txt_path}")
    return {
        'json': str(json_path),
        'txt': str(txt_path)
    }


def save_nuclei_report(target: str, results: list) -> str:
    """Сохранить отчет nuclei в JSON в backend/reports/nuclei"""
    reports_base = Path(__file__).parent / "reports"

    # Создаем директории если нет
    nuclei_dir = reports_base / "nuclei"
    json_dir = nuclei_dir / "json"
    json_dir.mkdir(parents=True, exist_ok=True)

    # Создаем filename
    scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(
        '/', '_').replace(':', '_').replace('.', '_').replace('?', '_')
    filename_base = f"nuclei_{safe_target}_{scan_id}"

    # Сохраняем JSON отчет
    json_path = json_dir / f"{filename_base}.json"

    message = "ничего не нашел" if not results else None
    report_data = {
        'tool': 'nuclei',
        'target': target,
        'scan_datetime': datetime.datetime.now().isoformat(),
        'total_findings': len(results),
        'message': message,
        'results': results
    }

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    print(f"✓ JSON отчет Nuclei сохранен: {json_path}")
    return str(json_path)


def save_amass_report(target: str, results: dict) -> str:
    """Сохранить отчет amass в JSON в backend/reports/amass"""
    reports_base = Path(__file__).parent / "reports"

    # Создаем директории если нет
    amass_dir = reports_base / "amass"
    json_dir = amass_dir / "json"
    json_dir.mkdir(parents=True, exist_ok=True)

    # Создаем filename
    scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(
        '/', '_').replace(':', '_').replace('.', '_').replace('?', '_')
    filename_base = f"amass_{safe_target}_{scan_id}"

    # Сохраняем JSON отчет
    json_path = json_dir / f"{filename_base}.json"

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

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    print(f"✓ JSON отчет Amass сохранен: {json_path}")
    return str(json_path)


def save_cors_report(scanner: CORSScanner) -> dict:
    """Сохранить отчет CORS в JSON и TXT в backend/reports/cors"""
    reports_base = Path(__file__).parent / "reports"

    # Используем родительский класс для сохранения (уже делает сохранение)
    json_path = scanner.save_json_report()
    txt_path = scanner.save_txt_report()

    print(f"✓ CORS отчеты сохранены: JSON: {json_path}, TXT: {txt_path}")
    return {
        'json': str(json_path),
        'txt': str(txt_path)
    }


def save_ssl_tls_report(scanner: SSLTLSScanner) -> dict:
    """Сохранить отчет SSL/TLS в JSON и TXT в backend/reports/ssl-tls"""
    # Используем методы сканера для сохранения отчетов
    scanner.save_reports()

    # Получаем пути файлов
    json_path = scanner.json_dir / f"{scanner.filename_base}.json"
    txt_path = scanner.txt_dir / f"{scanner.filename_base}.txt"

    print(f"✓ SSL/TLS отчеты сохранены: JSON: {json_path}, TXT: {txt_path}")
    return {
        'json': str(json_path),
        'txt': str(txt_path)
    }


@app.get("/api/tool")
async def api_tool(tool: str = Query(...), q: str = Query(...), allow_internal: bool = Query(False, description="Allow scanning private/loopback addresses (use with caution)")):
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
        try:
            import whois
            try:
                whois_result = await asyncio.to_thread(whois.whois, domain)
                output = str(whois_result)
                error = ""
            except Exception as e:
                output = ""
                error = f"Whois error: {str(e)}"

            # Сохраняем отчет
            reports_base = Path(__file__).parent / "reports"
            save_whois_report(domain, output, error)

            return {"tool": "whois", "output": output, "error": error}
        except ImportError:
            raise HTTPException(
                status_code=500,
                detail="Whois library не установлена. Установите: pip install python-whois")

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
            reports_base = Path(__file__).parent / "reports"
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
        "scanner", description="Выбранные инструменты (comma-separated)")
):
    """Запуск сканера уязвимостей с сохранением отчетов"""
    try:
        # Валидация цели
        validate_target(target, allow_internal=allow_internal)

        # Определяем директорию для отчетов инструментов
        reports_base = Path(__file__).parent / "reports"

        # Создаем сканер
        scanner = VulnerabilityScanner(target, output_name, str(reports_base))

        # Запускаем все проверки
        scanner.run_all_checks()

        # Сохраняем отчеты
        scanner.save_json_report()
        scanner.save_docx_report()

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
                "json": str(scanner.json_dir / f"{scanner.filename_base}.json"),
                "docx": str(scanner.word_dir / f"{scanner.filename_base}.docx")
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
        "amass", description="Выбранные инструменты (comma-separated)")
):
    """Запуск Amass для перечисления поддоменов"""
    try:
        validate_target(target, allow_internal=allow_internal)

        domain = extract_domain(target)

        result = await asyncio.to_thread(amass_scan, domain, mode, timeout)

        # Создаем объединённый отчет после сканирования
        scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        reports_base = Path(__file__).parent / "reports"
        combined_report_paths = await asyncio.to_thread(
            create_combined_report,
            scan_id, reports_base, 10
        )

        return {
            "tool": "amass",
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
        "nuclei", description="Выбранные инструменты (comma-separated)")
):
    """Запуск Nuclei для сканирования на уязвимости"""
    try:
        validate_target(target, allow_internal=allow_internal)

        # Убеждаемся что URL имеет схему
        if not URL_RE.match(target):
            target = f"http://{target}"

        from scanners.nuclei_scanner import run_scan

        reports_base = Path(__file__).parent / "reports"
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
        "osint", description="Выбранные инструменты (comma-separated)")
):
    """Запуск OSINT сканирования для поиска поддоменов и информации о домене"""
    try:
        validate_target(target, allow_internal=allow_internal)

        domain = extract_domain(target)

        result = await asyncio.to_thread(osint_scan, domain, Path(__file__).parent / "reports")

        # Создаем объединённый отчет после сканирования
        scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        reports_base = Path(__file__).parent / "reports"
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
        "web", description="Выбранные инструменты (comma-separated)")
):
    """Запуск Web сканирования (Katana, JSFinder, Gobuster) для поиска URL и директорий"""
    try:
        validate_target(target, allow_internal=allow_internal)

        # Убеждаемся что URL имеет схему
        if not URL_RE.match(target):
            target = f"http://{target}"

        reports_base = Path(__file__).parent / "reports"
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
        "retire", description="Выбранные инструменты (comma-separated)")
):
    """Запуск Retire для сканирования JavaScript библиотек на уязвимости"""
    try:
        validate_target(target, allow_internal=allow_internal)

        # Убеждаемся что URL имеет схему
        if not URL_RE.match(target):
            target = f"http://{target}"

        reports_base = Path(__file__).parent / "reports"
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
async def download_report(file_type: str = Query("docx", description="json или docx"), scan_id: str = Query(..., description="ID сканирования")):
    """Скачать отчет по типу и ID сканирования"""
    try:
        reports_base = Path(__file__).parent / "reports"

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
        "wappalyzer", description="Выбранные инструменты (comma-separated)")
):
    """
    Анализ технологий на веб-сайте с помощью Wappalyzer
    Возвращает список обнаруженных технологий и сохраняет отчеты
    """
    try:
        # Валидируем target
        validate_target(target, allow_internal=allow_internal)

        # Определяем директорию для отчетов
        reports_base = Path(__file__).parent / "reports"

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
async def wappalyzer_stream(target: str = Query(..., description="URL или домен для анализа"), allow_internal: bool = Query(False, description="Разрешить сканирование внутренних адресов")):
    """
    Анализ технологий с потоковым выводом результатов (SSE)
    """
    async def stream_wappalyzer():
        try:
            validate_target(target, allow_internal=allow_internal)

            scanner = WappalyzerScanner(target)

            yield "data: {\"status\": \"Загружаем страницу...\"}\n\n"

            html = scanner.fetch_page()
            if not html:
                yield "data: {\"error\": \"Не удалось загрузить страницу\"}\n\n"
                return

            yield "data: {\"status\": \"Анализируем технологии...\"}\n\n"

            scanner.scan()

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
        "cors", description="Выбранные инструменты (comma-separated)")
):
    """Запуск CORS сканирования для выявления уязвимостей CORS"""
    try:
        validate_target(target, allow_internal=allow_internal)

        # Убеждаемся что URL имеет схему
        if not URL_RE.match(target):
            target = f"http://{target}"

        reports_base = Path(__file__).parent / "reports"

        # Создаем и запускаем сканер
        scanner = CORSScanner(target, None, str(reports_base))
        await asyncio.to_thread(scanner.run_all_checks)

        # Сохраняем отчеты
        reports = save_cors_report(scanner)

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
        "ssl-tls", description="Выбранные инструменты (comma-separated)")
):
    """Запуск детального анализа SSL/TLS конфигурации"""
    try:
        # Валидация цели
        validate_target(target, allow_internal=allow_internal)

        # Определяем директорию для отчетов
        reports_base = Path(__file__).parent / "reports"

        # Создаем SSL/TLS сканер
        scanner = SSLTLSScanner(target, reports_dir=str(reports_base))

        # Запускаем сканирование
        scanner.run_scan()

        # Сохраняем отчеты
        reports = save_ssl_tls_report(scanner)

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
        "dns", description="Выбранные инструменты (comma-separated)")
):
    """Запуск DNS сканирования для перечисления DNS записей"""
    try:
        # Валидируем target
        validate_target(target, allow_internal=allow_internal)

        # Определяем директорию для отчетов
        reports_base = Path(__file__).parent / "reports"

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
async def cancel_scan(scan_id: str = Query(..., description="ID сканирования для отмены")):
    """Отменить активное сканирование по ID"""
    try:
        if not scan_id:
            raise HTTPException(
                status_code=400, detail="Не указан ID сканирования")

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
async def get_scan_status(scan_id: str = Query(..., description="ID сканирования")):
    """Получить статус сканирования"""
    try:
        session = get_scan_session(scan_id)

        if not session:
            return {
                "status": "not_found",
                "message": "Сканирование не найдено"
            }

        return {
            "status": "success",
            "scan_id": scan_id,
            "active": session['active'],
            "cancelled": session['cancelled'],
            "current_tool": session.get('current_tool'),
            "progress": session.get('progress', 0),
            "start_time": session['start_time'].isoformat(),
            "duration": (datetime.datetime.now() - session['start_time']).total_seconds()
        }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при получении статуса: {str(e)}")


@app.get("/api/nmap")
async def api_nmap(
    target: str = Query(...,
                        description="Хост, IP адрес или IP диапазон для сканирования"),
    allow_internal: bool = Query(
        False, description="Разрешить сканирование внутренних адресов"),
    arguments: str = Query("-sV -sC --top-ports 1000",
                           description="Аргументы для Nmap"),
    selected_tools: str = Query(
        "nmap", description="Выбранные инструменты (comma-separated)")
):
    """Запуск Nmap для сканирования портов и определения сервисов"""
    try:
        # Валидация цели
        validate_target(target, allow_internal=allow_internal)

        # Определяем директорию для отчетов
        reports_base = Path(__file__).parent / "reports"

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


@app.post("/api/run-selected-tools")
async def run_selected_tools(
    target: str = Query(..., description="URL или домен для сканирования"),
    tools: str = Query(...,
                       description="Список инструментов (comma-separated)"),
    allow_internal: bool = Query(
        False, description="Разрешить сканирование внутренних адресов"),
    scan_id: str = Query(None, description="ID сканирования для отслеживания")
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
    if scan_id:
        create_scan_session(scan_id)
        print(f"[*] Создана сессия сканирования: {scan_id}")
    else:
        scan_id = f"scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        create_scan_session(scan_id)

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
        available_tools = ['wappalyzer', 'nuclei', 'katana',
                           'amass', 'scanner', 'whois', 'osint', 'web', 'retire', 'cors', 'ssl-tls', 'dns', 'nmap']
        invalid_tools = [t for t in tools_list if t not in available_tools]
        if invalid_tools:
            raise HTTPException(
                status_code=400, detail=f"Неизвестные инструменты: {', '.join(invalid_tools)}")

        reports_base = Path(__file__).parent / "reports"
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
                        _scan_sessions[scan_id]['current_tool'] = tool

                print(f"[*] Запускаем {tool}...")

                if tool == 'wappalyzer':
                    result = await asyncio.to_thread(wappalyzer_scan, target, str(reports_base))
                    results[tool] = {
                        'status': 'success',
                        'data': result,
                        'technologies_found': result.get('total', 0)
                    }

                elif tool == 'nuclei':
                    result = await asyncio.to_thread(nuclei_run_scan, target, True, str(reports_base))
                    json_path = save_nuclei_report(
                        target, result if isinstance(result, list) else [])
                    results[tool] = {
                        'status': 'success',
                        'data': result,
                        'count': len(result) if isinstance(result, list) else result.get('total_findings', 0),
                        'reports': {
                            'json': json_path
                        }
                    }

                elif tool == 'katana':
                    # Используем командную строку для katana
                    cmd = ["katana", "-u", target, "-json", "-silent"]
                    stdout, stderr = await run_command(cmd)
                    if stdout:
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
                    result = await asyncio.to_thread(amass_scan, target, "passive", 300, str(reports_base))
                    json_path = save_amass_report(target, result)
                    results[tool] = {
                        'status': 'success',
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
                    json_path = save_scanner_report(scanner_obj)
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
                    try:
                        import whois
                        whois_result = await asyncio.to_thread(whois.whois, domain)
                        output = str(whois_result)
                        error = ""
                    except Exception as e:
                        output = ""
                        error = str(e)

                    reports = await asyncio.to_thread(save_whois_report, domain, output, error)
                    results[tool] = {
                        'status': 'success',
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
                    reports = save_cors_report(scanner)
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
                    reports = save_ssl_tls_report(scanner)
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

            except Exception as e:
                results[tool] = {
                    'status': 'error',
                    'error': str(e)
                }

        # Создаем объединенный отчет (используем существующий scan_id)
        combined_reports = create_combined_report(
            scan_id, reports_base, recent_minutes=10)

        # Завершаем сессию сканирования
        end_scan_session(scan_id)
        print(f"[+] Сканирование {scan_id} завершено успешно")

        return {
            'status': 'success',
            'target': target,
            'tools_executed': tools_list,
            'tools_count': len(tools_list),
            'results': results,
            'combined_reports': combined_reports,
            'scan_id': scan_id
        }

    except HTTPException:
        end_scan_session(scan_id)
        raise
    except Exception as e:
        end_scan_session(scan_id)
        raise HTTPException(
            status_code=500, detail=f"Ошибка при запуске инструментов: {str(e)}")


@app.get("/api/txt-reports")
async def get_txt_reports():
    """
    Получить список всех файлов .txt из папки reports для всех инструментов
    """
    try:
        reports_dir = Path(__file__).parent / "reports"

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
async def download_word_report(filename: str = Query(..., description="Имя файла для скачивания")):
    """
    Скачать файл .docx из папки reports/combined/word
    """
    try:
        # Защита от path traversal
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(
                status_code=400, detail="Недопустимое имя файла")

        file_path = Path(__file__).parent / "reports" / \
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
async def download_txt_report(tool: str = Query(..., description="Название инструмента"), filename: str = Query(..., description="Имя файла для скачивания")):
    """
    Скачать файл .txt из папки reports/[tool]/txt
    """
    try:
        # Защита от path traversal
        if ".." in filename or ".." in tool or "/" in filename or "\\" in filename or "/" in tool or "\\" in tool:
            raise HTTPException(
                status_code=400, detail="Недопустимое имя файла")

        file_path = Path(__file__).parent / "reports" / tool / "txt" / filename

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
async def delete_word_report(filename: str = Query(None, description="Имя файла для удаления")):
    """
    Удалить файл .docx из папки reports/combined/word
    Если filename не указан, удаляет все word-отчеты
    """
    try:
        word_dir = Path(__file__).parent / "reports" / "combined" / "word"

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
async def delete_txt_report(tool: str = Query(..., description="Название инструмента"), filename: str = Query(None, description="Имя файла для удаления")):
    """
    Удалить файл .txt из папки reports/[tool]/txt
    Если filename не указан, удаляет все файлы инструмента
    """
    try:
        # Защита от path traversal
        if ".." in tool or "/" in tool or "\\" in tool:
            raise HTTPException(
                status_code=400, detail="Недопустимое имя инструмента")

        reports_dir = Path(__file__).parent / "reports" / tool / "txt"

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
async def get_combined_reports():
    """
    Получить список всех скомпилированных отчетов из папки combined
    """
    try:
        reports_dir = Path(__file__).parent / "reports" / "combined"

        if not reports_dir.exists():
            return {
                "status": "success",
                "json_reports": [],
                "txt_reports": [],
                "word_reports": [],
                "count": 0,
                "message": "Папка не найдена"
            }

        # Получаем все JSON файлы из папки combined/json
        json_dir = reports_dir / "json"
        if json_dir.exists():
            json_files = sorted(
                [f.name for f in json_dir.glob("*.json")], reverse=True)
        else:
            json_files = []

        # Получаем все TXT файлы из папки combined/txt
        txt_dir = reports_dir / "txt"
        if txt_dir.exists():
            txt_files = sorted(
                [f.name for f in txt_dir.glob("*.txt")], reverse=True)
        else:
            txt_files = []

        # Получаем все DOCX файлы из папки combined/word
        word_dir = reports_dir / "word"
        if word_dir.exists():
            word_files = sorted(
                [f.name for f in word_dir.glob("*.docx")], reverse=True)
        else:
            word_files = []

        return {
            "status": "success",
            "json_reports": json_files,
            "txt_reports": txt_files,
            "word_reports": word_files,
            "count": len(json_files) + len(txt_files) + len(word_files)
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при получении списка отчетов: {str(e)}")


@app.get("/api/word-reports")
async def get_word_reports():
    """
    Получить список всех word-отчетов из папки combined/word
    """
    try:
        word_dir = Path(__file__).parent / "reports" / "combined" / "word"

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
async def download_combined_report(filename: str = Query(..., description="Имя файла для скачивания"), report_type: str = Query("json", description="Тип отчета: json, txt, word или docx")):
    """
    Скачать скомпилированный отчет из папки combined
    """
    try:
        # Защита от path traversal
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(
                status_code=400, detail="Недопустимое имя файла")

        if report_type == "json":
            file_path = Path(__file__).parent / "reports" / \
                "combined" / "json" / filename
            if not file_path.suffix.lower() == ".json":
                raise HTTPException(
                    status_code=400, detail="Неверный тип файла")
            media_type = "application/json"
        elif report_type == "txt":
            file_path = Path(__file__).parent / "reports" / \
                "combined" / "txt" / filename
            if not file_path.suffix.lower() == ".txt":
                raise HTTPException(
                    status_code=400, detail="Неверный тип файла")
            media_type = "text/plain"
        elif report_type in ["word", "docx"]:
            file_path = Path(__file__).parent / "reports" / \
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
async def delete_combined_report(filename: str = Query(..., description="Имя файла для удаления"), report_type: str = Query("json", description="Тип отчета: json, txt, word или docx")):
    """
    Удалить скомпилированный отчет из папки combined
    """
    try:
        # Защита от path traversal
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(
                status_code=400, detail="Недопустимое имя файла")

        if report_type == "json":
            file_path = Path(__file__).parent / "reports" / \
                "combined" / "json" / filename
        elif report_type == "txt":
            file_path = Path(__file__).parent / "reports" / \
                "combined" / "txt" / filename
        elif report_type in ["word", "docx"]:
            file_path = Path(__file__).parent / "reports" / \
                "combined" / "word" / filename
        else:
            raise HTTPException(
                status_code=400, detail="Неизвестный тип отчета")

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
async def clear_all_reports():
    """
    Очистить ВСЕ отчеты (word, json, combined)
    """
    try:
        reports_base = Path(__file__).parent / "reports"

        if not reports_base.exists():
            return {
                "status": "success",
                "message": "Директория отчетов не существует",
                "deleted": 0
            }

        deleted_count = 0
        deleted_files = []

        # Удаляем отчеты из папок: txt, json, combined/txt, combined/json и других инструментов
        dirs_to_clear = [
            reports_base / "txt",
            reports_base / "json",
            reports_base / "combined" / "json",
            reports_base / "combined" / "txt",
            reports_base / "combined" / "word",
            reports_base / "nuclei" / "json",
            reports_base / "nuclei" / "txt",
            reports_base / "wappalyzer" / "json",
            reports_base / "wappalyzer" / "txt",
            reports_base / "amass" / "json",
            reports_base / "amass" / "txt",
            reports_base / "whois" / "json",
            reports_base / "whois" / "txt",
            reports_base / "osint" / "json",
            reports_base / "osint" / "txt",
            reports_base / "scanner" / "json",
            reports_base / "scanner" / "txt",
            reports_base / "word",
        ]

        for dir_path in dirs_to_clear:
            if dir_path.exists() and dir_path.is_dir():
                for file in dir_path.glob("*.*"):
                    try:
                        file.unlink()
                        deleted_files.append(file.name)
                        deleted_count += 1
                    except Exception as e:
                        print(f"[-] Ошибка удаления файла {file}: {e}")

        return {
            "status": "success",
            "message": f"Удалено всех файлов: {deleted_count}",
            "deleted": deleted_count,
            "deleted_files": deleted_files
        }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при очистке отчетов: {str(e)}")


# ============= SCHEDULER ENDPOINTS =============


# Получиваем глобальный экземпляр планировщика
scheduler = get_scheduler(Path(__file__).parent)


@app.on_event("startup")
async def startup_events():
    """Инициализация при запуске приложения"""
    logger.info("🚀 Запуск приложения...")

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
async def get_tasks():
    """Получить список всех запланированных задач"""
    try:
        tasks = scheduler.get_tasks()
        return {
            "status": "success",
            "tasks": tasks,
            "count": len(tasks)
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при получении задач: {str(e)}")


@app.get("/api/tasks/{task_id}")
async def get_task(task_id: str):
    """Получить конкретную задачу по ID"""
    try:
        task = scheduler.get_task(task_id)
        if not task:
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
async def create_task(task: dict):
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
        query = task.get('query', '').strip()
        if not query:
            raise HTTPException(
                status_code=400,
                detail="Цель сканирования не может быть пустой")

        # Валидация инструментов
        if not task.get('activeTools') or not isinstance(task['activeTools'], list):
            raise HTTPException(
                status_code=400,
                detail="Должен быть выбран хотя бы один инструмент")

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
async def update_task(task_id: str, task_data: dict):
    """Обновить запланированную задачу"""
    try:
        existing_task = scheduler.get_task(task_id)
        if not existing_task:
            raise HTTPException(status_code=404, detail="Задача не найдена")

        # Обновляем задачу
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
async def delete_task(task_id: str):
    """Удалить запланированную задачу"""
    try:
        removed = scheduler.remove_task(task_id)
        if not removed:
            raise HTTPException(status_code=404, detail="Задача не найдена")

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
async def get_task_results(task_id: str):
    """Получить результаты сканирования для задачи"""
    try:
        task = scheduler.get_task(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Задача не найдена")

        # Возвращаем информацию о последнем сканировании
        return {
            "status": "success",
            "task_id": task_id,
            "task_type": task.get('type'),
            "target": task.get('query'),
            "tools": task.get('tools', []),
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
    async def callback_scanner(target, allow_internal=False, task_id=None):
        """Callback для VulnerabilityScanner"""
        try:
            logger.info(f"🔄 Запуск scanner для {target}")
            from scanners.vulnerability_scanner import VulnerabilityScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(Path(__file__).parent /
                              "reports" / (task_id or "scheduled"))
            scanner = VulnerabilityScanner(target, reports_dir)
            scanner.scan()
            # Сохраняем оба формата отчётов
            txt_report = scanner.save_txt_report()
            json_report = scanner.save_json_report()
            logger.info(f"✓ scanner завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске scanner: {e}", exc_info=True)

    # === NUCLEI ===
    async def callback_nuclei(target, allow_internal=False, task_id=None):
        """Callback для Nuclei сканера"""
        try:
            logger.info(f"🔄 Запуск nuclei для {target}")
            from scanners.nuclei_scanner import run_scan
            # Создаём путь к папке для этого сканирования
            reports_dir = str(Path(__file__).parent /
                              "reports" / (task_id or "scheduled"))
            result = await run_scan(target, save_reports=True, reports_dir=reports_dir)
            logger.info(f"✓ nuclei завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске nuclei: {e}", exc_info=True)

    # === OSINT ===
    async def callback_osint(target, allow_internal=False, task_id=None):
        """Callback для OSINT сканера"""
        try:
            logger.info(f"🔄 Запуск osint для {target}")
            from scanners.osint_scanner import simple_scan
            # Создаём путь к папке для этого сканирования
            reports_dir = str(Path(__file__).parent /
                              "reports" / (task_id or "scheduled"))
            result = simple_scan(target, reports_dir)
            logger.info(f"✓ osint завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске osint: {e}", exc_info=True)

    # === WAPPALYZER ===
    async def callback_wappalyzer(target, allow_internal=False, task_id=None):
        """Callback для Wappalyzer"""
        try:
            logger.info(f"🔄 Запуск wappalyzer для {target}")
            from scanners.wappalyzer_scanner import WappalyzerScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(Path(__file__).parent /
                              "reports" / (task_id or "scheduled"))
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

    # === SSL-TLS ===
    async def callback_ssl_tls(target, allow_internal=False, task_id=None):
        """Callback для SSL/TLS сканера"""
        try:
            logger.info(f"🔄 Запуск ssl-tls для {target}")
            from scanners.ssl_tls_scanner import SSLTLSScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(Path(__file__).parent /
                              "reports" / (task_id or "scheduled"))
            scanner = SSLTLSScanner(target, reports_dir)
            scanner.scan()
            scanner.display_results()
            # Сохраняем оба формата отчётов
            txt_report = scanner.save_txt_report()
            json_report = scanner.save_json_report()
            logger.info(f"✓ ssl-tls завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске ssl-tls: {e}", exc_info=True)

    # === NMAP ===
    async def callback_nmap(target, allow_internal=False, task_id=None):
        """Callback для Nmap сканера"""
        try:
            logger.info(f"🔄 Запуск nmap для {target}")
            from scanners.nmap_scanner import NmapScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(Path(__file__).parent /
                              "reports" / (task_id or "scheduled"))
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

    # === CORS ===
    async def callback_cors(target, allow_internal=False, task_id=None):
        """Callback для CORS сканера"""
        try:
            logger.info(f"🔄 Запуск cors для {target}")
            from scanners.cors_scanner import CORSScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(Path(__file__).parent /
                              "reports" / (task_id or "scheduled"))
            scanner = CORSScanner(target, reports_dir)
            scanner.scan()
            scanner.display_results()
            # Сохраняем оба формата отчётов
            txt_report = scanner.save_txt_report()
            json_report = scanner.save_json_report()
            logger.info(f"✓ cors завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске cors: {e}", exc_info=True)

    # === DNS ===
    async def callback_dns(target, allow_internal=False, task_id=None):
        """Callback для DNS сканера"""
        try:
            logger.info(f"🔄 Запуск dns для {target}")
            from scanners.dns_scanner import DNSScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(Path(__file__).parent /
                              "reports" / (task_id or "scheduled"))
            scanner = DNSScanner(target, reports_dir)
            scanner.scan()
            scanner.display_results()
            # Сохраняем оба формата отчётов
            txt_report = scanner.save_txt_report()
            json_report = scanner.save_json_report()
            logger.info(f"✓ dns завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске dns: {e}", exc_info=True)

    # === RETIRE ===
    async def callback_retire(target, allow_internal=False, task_id=None):
        """Callback для Retire.js"""
        try:
            logger.info(f"🔄 Запуск retire для {target}")
            from scanners.retire_scanner import RetireScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(Path(__file__).parent /
                              "reports" / (task_id or "scheduled"))
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

    # === WHOIS ===
    async def callback_whois(target, allow_internal=False, task_id=None):
        """Callback для WHOIS сканера"""
        try:
            logger.info(f"🔄 Запуск whois для {target}")
            # whois сканер обычно работает синхронно
            # Нужно добавить импорт и вызов реального сканера
            logger.info(f"✓ whois завершен для {target}")
        except Exception as e:
            logger.error(f"✗ Ошибка при запуске whois: {e}", exc_info=True)

    # === WEB ===
    async def callback_web(target, allow_internal=False, task_id=None):
        """Callback для Web сканера"""
        try:
            logger.info(f"🔄 Запуск web для {target}")
            from scanners.web_url_scanner import WebScanner
            # Создаём путь к папке для этого сканирования
            reports_dir = str(Path(__file__).parent /
                              "reports" / (task_id or "scheduled"))
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
async def get_report_content(filename: str = Query(..., description="Имя файла отчета"), report_type: str = Query("json", description="Тип отчета: json, txt_report, или combined")):
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

        reports_base = Path(__file__).parent / "reports" / "combined"

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
                return PlainTextResponse(content, media_type="text/plain")

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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
