# CyberScope: Быстрый справочник архитектуры

## КРАТКОЕ РЕЗЮМЕ

**CyberScope** — платформа для автоматизированного анализа безопасности веб-ресурсов с интеграцией 9+ сканеров, встроенным планировщиком задач, REST API и Telegram ботом.

---

## 1. КОМАНДЫ БЫСТРОГО СТАРТА

### Локальная разработка
```bash
# Backend
cd backend && python -m venv venv && source venv/bin/activate && pip install -r requirements.txt && uvicorn server:app --reload

# Frontend (новый терминал)
cd frontend && npm install && npm start
```

### Docker
```bash
docker-compose up --build
```

---

## 2. СТРУКТУРА ПРОЕКТА

```
CyberScope/
├── backend/
│   ├── server.py              # FastAPI приложение (250+KB)
│   ├── scheduler.py           # Планировщик задач
│   ├── requirements.txt       # Python зависимости
│   ├── scanners/              # 9 модулей сканеров
│   ├── core/
│   │   └── report_utils.py   # Унификация отчетов
│   ├── bot/                   # Telegram бот
│   └── reports/               # Директория с отчетами
├── frontend/
│   ├── src/
│   │   ├── App.jsx            # Основной компонент
│   │   └── Component/Pages/   # 5 основных страниц
│   └── package.json           # React зависимости
├── docker-compose.yml
├── README.md                  # На русском языке
└── TECHNICAL_DOCUMENTATION.md # Эта документация
```

---

## 3. КОМПОНЕНТЫ И ИХ НАЗНАЧЕНИЕ

| Компонент | Файл | Функция |
|-----------|------|---------|
| **FastAPI Server** | server.py | 20+ REST API endpoints |
| **Scheduler** | scheduler.py | Планирование (+CRUD задач) |
| **Reports Service** | report_utils.py | Унификация отчетов |
| **Vulnerability Scanner** | scanners/vulnerability_scanner.py | Базовое сканирование |
| **Wappalyzer** | scanners/wappalyzer_scanner.py | Определение технологий |
| **CORS Scanner** | scanners/cors_scanner.py | CORS конфигурация |
| **SSL/TLS Scanner** | scanners/ssl_tls_scanner.py | SSL/TLS анализ |
| **DNS Scanner** | scanners/dns_scanner.py | DNS перечисление |
| **OSINT Scanner** | scanners/osint_scanner.py | Поиск поддоменов |
| **Web URL Scanner** | scanners/web_url_scanner.py | Katana + JSFinder + Gobuster |
| **Retire.js Scanner** | scanners/retire_scanner.py | JS уязвимости |
| **Nuclei Scanner** | scanners/nuclei_scanner.py | Template-based scanning |
| **Frontend** | frontend/src/App.jsx | React UI |

---

## 4. ОСНОВНЫЕ API ENDPOINTS (20+)

### Сканирование

| Метод | Endpoint | Описание |
|-------|----------|---------|
| GET | `/api/scanner` | Запуск основного сканера |
| GET | `/api/amass` | Перечисление поддоменов |
| GET | `/api/nuclei` | Уязвимости (templates) |
| GET | `/api/osint` | OSINT разведка |
| GET | `/api/web` | Web разведка |
| GET | `/api/retire` | JS уязвимости |
| GET | `/api/wappalyzer` | Определение технологий |
| GET | `/api/ssl-tls` | SSL/TLS анализ |
| GET | `/api/dns` | DNS перечисление |
| POST | `/api/cors` | CORS проверка |
| GET | `/api/tool` | Одиночный инструмент (whois/nuclei) |

### Управление

| Метод | Endpoint | Описание |
|-------|----------|---------|
| POST | `/api/cancel-scan` | Отмена сканирования |
| GET | `/api/scan-status` | Статус сканирования |
| POST | `/api/run-selected-tools` | Запуск выбранных инструментов |

### Отчеты

| Метод | Endpoint | Описание |
|-------|----------|---------|
| GET | `/api/txt-reports` | Список TXT отчетов |
| GET | `/api/download-txt-report` | Скачать TXT |
| DELETE | `/api/delete-txt-report` | Удалить TXT |
| GET | `/api/combined-reports` | Список объединенных отчетов |
| GET | `/api/download-combined-report` | Скачать объединенный |
| GET | `/download_report` | Generic download |

---

## 5. ТЕСТЫ ФУНКЦИОНАЛЬНОСТИ

### ✅ Проверка сканирования

```bash
# 1. GET запрос базового сканера
curl "http://localhost:8000/api/scanner?target=http://example.com&allow_internal=false"

# 2. Проверка статуса
curl "http://localhost:8000/api/scan-status?scan_id=20260331_202425"

# 3. Загрузка отчетов
curl "http://localhost:8000/api/txt-reports"

# 4. Скачивание отчета
curl "http://localhost:8000/api/download-txt-report?filename=scanner_example.com_20260331_202425.txt" -o report.txt
```

### ✅ Проверка планировщика

```bash
# 1. Проверка файла запланированных задач
cat backend/scheduled_tasks.json

# 2. Проверка отчетов
ls -la backend/reports/
```

### ✅ Проверка валидации

```bash
# Должна вернуть ошибку (внутренний адрес)
curl "http://localhost:8000/api/scanner?target=192.168.1.1"

# Должна вернуть ошибку (localhost)
curl "http://localhost:8000/api/scanner?target=localhost"

# Должна работать с флагом
curl "http://localhost:8000/api/scanner?target=localhost&allow_internal=true"
```

---

## 6. ДИРЕКТИВ ФАЙЛОВ ОТЧЕТОВ

```
backend/reports/
├── combined/json/                    # Объединенные JSON отчеты
├── combined/txt/                     # Объединенные TXT отчеты
├── scanner/json/scanner_*.json       # Основной сканер
├── wappalyzer/json/                  # Wappalyzer отчеты
├── cors/json/ + /txt/                # CORS результаты
├── ssl-tls/json/ + /txt/             # SSL/TLS анализ
├── dns/json/ + /txt/                 # DNS записи
├── osint/json/ + /txt/               # OSINT результаты
├── web/json/ + /txt/                 # Web разведка
├── retire/json/ + /txt/              # JS уязвимости
├── nuclei/json/ + /txt/              # Nuclei findings
└── whois/json/ + /txt/               # WHOIS информация
```

---

## 7. РАСПИСАНИЕ ПЛАНИРОВЩИКА

### Типы расписаний

```python
{
  "type": "once",      # Однократно в указанное время
  "type": "daily",     # Каждый день в указанное время
  "type": "weekly",    # В определенные дни недели
  "type": "monthly"    # В определенный день месяца
}
```

### Пример задачи

```json
{
  "id": "task_1",
  "query": "example.com",
  "type": "daily",
  "time": "02:00",
  "days": [0, 2, 4],
  "activeTools": ["scanner", "nuclei", "wappalyzer"],
  "allowInternal": false,
  "status": "completed",
  "nextRun": "2026-04-01T02:00:00",
  "last_run": "2026-03-31T02:00:15.123456"
}
```

---

## 8. ПАРАМЕТРИЗАЦИЯ API

### Все endpoint'ы используют

```
?target=domain_or_url       # Основной параметр поиска
&allow_internal=false|true  # Разрешить внутренние адреса
&selected_tools=tool1,tool2 # Выбранные инструменты
&output_name=custom_name    # Имя для файлов
&scan_id=id                 # ID сканирования
```

### Примеры вызовов

```bash
# Базовой сканер с выбором инструментов
/api/scanner?target=example.com&selected_tools=scanner,nuclei,wappalyzer

# OSINT с внутренними адресами
/api/osint?target=192.168.1.1&allow_internal=true

# Скачивание отчета
/api/download-txt-report?filename=scanner_example.com_20260331_202425.txt
```

---

## 9. СТРУКТУРА JSON ОТЧЕТА (ПРИМЕР)

```json
{
  "scan_info": {
    "target_url": "http://example.com",
    "hostname": "example.com",
    "scan_id": "20260331_202425",
    "scan_datetime": "2026-03-31T20:24:25.123456"
  },
  "summary": {
    "total_vulnerabilities": 5,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 0
  },
  "vulnerabilities": [
    {
      "name": "Missing Security Headers",
      "severity": "High",
      "description": "..."
    }
  ],
  "recommendations": [...]
}
```

---

## 10. СТРУКТУРА TXT ОТЧЕТА

```
┌──────────────────────────────────────────────────────────────┐
│         SCANNER - ОТЧЕТ О СКАНИРОВАНИИ                      │
└──────────────────────────────────────────────────────────────┘

📋 ИНФОРМАЦИЯ О ЗАПРОСЕ
────────────────────────────────────────────────────────────────
  URL сайта:           http://example.com
  Дата сканирования:   31.03.2026
  Время сканирования:  20:24:25

📊 СТАТИСТИКА
────────────────────────────────────────────────────────────────
  Всего уязвимостей: 5
  🔴 КРИТИЧЕСКИЕ:    1
  🟠 ВЫСОКИЕ:        2
  🟡 СРЕДНИЕ:        2
  🔵 НИЗКИЕ:         0

🔍 НАЙДЕННЫЕ УЯЗВИМОСТИ
────────────────────────────────────────────────────────────────
  1. Missing Security Headers
  2. ...
```

---

## 11. ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ

### Backend (.env)

```
# Опционально (если используется)
DATABASE_URL=postgresql://user:pass@localhost/cyberscope
REDIS_URL=redis://localhost:6379
LOG_LEVEL=INFO
```

### Frontend (REACT_APP_* переменные)

```
REACT_APP_API_URL=http://localhost:8000
REACT_APP_WS_URL=ws://localhost:8000
```

### Bot (.env)

```
BOT_TOKEN=your_telegram_bot_token
API_BASE_URL=http://127.0.0.1:8000/api
```

---

## 12. ЗАВИСИМОСТИ И ВЕРСИИ

| Компонент | Версия | Примечание |
|-----------|--------|-----------|
| Python | 3.9+ | Требуется для backend |
| Node.js | 14+ | Требуется для frontend |
| Go | 1.16+ | Требуется для внешних инструментов |
| FastAPI | latest | Основа backend'а |
| React | 19.1.0 | Frontend библиотека |
| Nuclei | latest | Go инструмент |
| Amass | latest | Go инструмент |

---

## 13. РЕШЕНИЕ ПРОБЛЕМ

### Backend не стартует

```bash
# Проверить Python версию
python --version  # Должна быть 3.9+

# Переустановить зависимости
pip install -r requirements.txt --force-reinstall

# Проверить порт 8000
netstat -tuln | grep 8000  # Посмотреть какой процесс занимает неймер

# Запустить с отладкой
uvicorn server:app --reload --log-level debug
```

### Frontend не компилируется

```bash
# Очистить node_modules
rm -rf node_modules package-lock.json

# Переустановить
npm install

# Проверить Node версию
node --version  # Должна быть 14+
```

### Отчеты не генерируются

```bash
# Проверить права доступа к директории
ls -la backend/reports/

# Создать директории если нет
mkdir -p backend/reports/{combined,scanner,wappalyzer}/{json,txt}

# Проверить места на диске
df -h
```

### Internal tool не найден

```bash
# Nuclei
which nuclei  # Проверить установлен ли

go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

---

## 14. PRODUCTION CHECKLIST

- [ ] Использовать PostgreSQL вместо JSON
- [ ] Включить JWT аутентификацию
- [ ] Ограничить CORS к конкретному домену
- [ ] Добавить rate limiting
- [ ] Включить HTTPS (SSL certificates)
- [ ] Настроить логирование и мониторинг
- [ ] Добавить backup процедуры для отчетов
- [ ] Настроить environment-specific конфигурацию
- [ ] Написать unit tests (минимум 80% coverage)
- [ ] Провести security audit
- [ ] Настроить CI/CD pipeline
- [ ] Добавить health check endpoints
- [ ] Реализовать обработку ошибок
- [ ] Добавить кеширование результатов

---

## 15. ПОЛЕЗНЫЕ РЕСУРСЫ

### Документация
- FastAPI: https://fastapi.tiangolo.com/
- React: https://react.dev/
- Docker: https://docs.docker.com/

### Инструменты
- Nuclei: https://github.com/projectdiscovery/nuclei
- Amass: https://github.com/owasp-amass/amass
- Katana: https://github.com/projectdiscovery/katana
- Retire.js: https://github.com/RetireJS/retire.js

### Security Resources
- OWASP Top 10: https://owasp.org/Top10/
- HackerOne: https://www.hackerone.com/
- PortSwigger Web Security: https://portswigger.net/

---

## 16. МОНИТОРИНГ И ЛОГИРОВАНИЕ

### Просмотр логов
```bash
# Backend
docker logs cyberscope-backend -f

# Frontend  
docker logs cyberscope-frontend -f

# Все
docker-compose logs -f
```

### Отладка
```bash
# Проверка сессий сканирования
cat backend/scheduled_tasks.json | python -m json.tool

# Размер отчетов
du -sh backend/reports/

# Проверка статуса сервиса
curl http://localhost:8000/docs  # Должна работать
```

---

**Быстрый справочник составлен:** 31 марта 2026
**Версия:** 1.0 Quick Reference

