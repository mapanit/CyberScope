import importlib.util
import shutil
from pathlib import Path
from typing import Any


TOOL_CATALOG = [
    {
        "id": "scanner",
        "label": "Scanner",
        "description": "Проверка распространенных веб-уязвимостей и security headers.",
        "dependencies": {"python": ["requests", "bs4"]},
    },
    {
        "id": "nuclei",
        "label": "Nuclei",
        "description": "Проверка известных проблем по шаблонам Nuclei.",
        "dependencies": {"commands": ["nuclei"]},
    },
    {
        "id": "wappalyzer",
        "label": "Wappalyzer",
        "description": "Определение технологий, фреймворков и CMS сайта.",
        "dependencies": {"python": ["Wappalyzer", "requests"]},
    },
    {
        "id": "katana",
        "label": "Katana",
        "description": "Обнаружение страниц и конечных точек сайта.",
        "selectable": False,
        "dependencies": {"commands": ["katana"]},
    },
    {
        "id": "amass",
        "label": "Amass",
        "description": "Поиск поддоменов и сбор данных об инфраструктуре.",
        "selectable": False,
        "dependencies": {"commands": ["amass"]},
    },
    {
        "id": "whois",
        "label": "WHOIS",
        "description": "Получение информации о регистрации домена.",
        "dependencies": {"python": ["whois"]},
    },
    {
        "id": "osint",
        "label": "OSINT",
        "description": "Сбор открытой информации о домене и поддоменах.",
        "dependencies": {
            "python": ["requests"],
            "commands_any": ["amass", "subfinder", "waybackurls"],
        },
    },
    {
        "id": "web",
        "label": "Web",
        "description": "Комплексное обнаружение URL и веб-путей.",
        "dependencies": {
            "commands_any": ["katana", "gobuster"],
            "files": ["tools/jsfinder/JSFinder.py"],
        },
    },
    {
        "id": "retire",
        "label": "Retire.js",
        "description": "Поиск известных уязвимостей в JavaScript-библиотеках.",
        "dependencies": {"commands": ["retire", "wget"]},
    },
    {
        "id": "cors",
        "label": "CORS",
        "description": "Проверка конфигурации CORS.",
        "dependencies": {"python": ["requests"]},
    },
    {
        "id": "ssl-tls",
        "label": "SSL/TLS",
        "description": "Проверка сертификата и конфигурации TLS.",
        "dependencies": {"python": ["ssl"]},
    },
    {
        "id": "dns",
        "label": "DNS",
        "description": "Сбор DNS-записей и nameserver-ов.",
        "dependencies": {"python": ["dns"]},
    },
    {
        "id": "nmap",
        "label": "Nmap",
        "description": "Обнаружение открытых портов и сетевых сервисов.",
        "dependencies": {"commands": ["nmap"], "python": ["nmap"]},
    },
]

TOOL_IDS = {tool["id"] for tool in TOOL_CATALOG}
BACKEND_ROOT = Path(__file__).resolve().parents[1]


def _python_module_available(module_name: str) -> bool:
    if module_name == "ssl":
        return True
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ValueError):
        return False


def get_tool_catalog() -> list[dict[str, Any]]:
    """Return user-facing tool metadata with observable local dependency status."""
    catalog = []
    for tool in TOOL_CATALOG:
        dependencies = tool["dependencies"]
        missing = [
            command
            for command in dependencies.get("commands", [])
            if shutil.which(command) is None
        ]
        missing.extend(
            module
            for module in dependencies.get("python", [])
            if not _python_module_available(module)
        )
        available_any = [
            command for command in dependencies.get("commands_any", [])
            if shutil.which(command) is not None
        ]
        if dependencies.get("commands_any") and not available_any:
            missing.append(
                "one of: " + ", ".join(dependencies["commands_any"])
            )
        missing_optional = [
            command for command in dependencies.get("commands_any", [])
            if command not in available_any
        ]
        missing.extend(
            relative_path
            for relative_path in dependencies.get("files", [])
            if not (BACKEND_ROOT / relative_path).is_file()
        )
        catalog.append(
            {
                "id": tool["id"],
                "label": tool["label"],
                "description": tool["description"],
                "selectable": tool.get("selectable", True),
                "available": not missing,
                "missing_dependencies": missing,
                "missing_optional_dependencies": missing_optional,
            }
        )
    return catalog
