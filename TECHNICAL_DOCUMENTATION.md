# CyberScope: Комплексная платформа для анализа безопасности веб-ресурсов

## Документация для дипломной работы

---

## 1. ОБЗОР ПРОЕКТА

### 1.1 Назначение
CyberScope — это интегрированная веб-платформа для автоматизированного комплексного анализа и разведки веб-сайтов. Платформа предназначена для пентестеров, администраторов безопасности, разработчиков и исследователей безопасности с целью упростить рутинные задачи сканирования на уязвимости, обнаружения скрытых ресурсов и сбора разведывательной информации.

### 1.2 Ключевые характеристики

- **Многофункциональность**: Интеграция более 9 различных сканеров безопасности в единый интерфейс
- **Асинхронная обработка**: Параллельное выполнение сканирований с использованием FastAPI и asyncio
- **Планирование задач**: Встроенный планировщик для автоматизированных периодических сканирований
- **Управление отчетами**: Генерация унифицированных отчетов в JSON и TXT форматах
- **REST API**: Полный набор REST API эндпоинтов для программного взаимодействия
- **Telegram интеграция**: Бот для управления сканированиями и отчетами через Telegram
- **Ответственное использование**: Встроенные валидации для предотвращения сканирования внутренних адресов

### 1.3 Целевая аудитория

1. **Пентестеры** — для автоматизации рутинных операций разведки
2. **SOC специалисты** — для мониторинга безопасности корпоративных ресурсов
3. **Разработчики** — для проверки безопасности собственных приложений
4. **Исследователи** — для проведения научных исследований в области кибербезопасности

---

## 2. АРХИТЕКТУРА И КОМПОНЕНТЫ

### 2.1 Общая архитектура

```
┌─────────────────────────────────────────────────────────────┐
│                    FRONTEND (React)                         │
│  ├─ Home (поиск и запуск сканирований)                     │
│  ├─ AboutTools (описание инструментов)                     │
│  ├─ Task (управление запланированными задачами)           │
│  ├─ Questions (FAQ)                                         │
│  └─ Help (справка)                                          │
└─────────┬──────────────────────────────────────────────────┘
          │ HTTP/WebSocket/SSE
          ↓
┌─────────────────────────────────────────────────────────────┐
│              BACKEND (FastAPI + UVicorn)                    │
│  ├─ REST API endpoints (20+ маршрутов)                    │
│  ├─ CORS middleware (允许跨域запросы)                     │
│  ├─ Session management (отслеживание статуса сканирования) │
│  └─ Reports service (генерация и управление отчетами)     │
└─────┬──────────────────────────────────────────────────────┘
      │
      ├─────────────────────────────┬──────────────────────────┐
      ↓                             ↓                          ↓
┌──────────────────┐  ┌───────────────────────┐  ┌──────────────────┐
│ Scanners Module  │  │ Scheduler Module      │  │ Reports Module   │
├──────────────────┤  ├───────────────────────┤  ├──────────────────┤
│ • Vulnerability  │  │ • Task management     │  │ • ReportBase     │
│ • Wappalyzer     │  │ • Schedule types      │  │ • JSON export    │
│ • CORS           │  │ • Execution engine    │  │ • TXT export     │
│ • SSL/TLS        │  │ • Callback system     │  │ • Combined       │
│ • DNS            │  │ • Persistence layer   │  │   reports        │
│ • OSINT          │  └───────────────────────┘  └──────────────────┘
│ • Web URL        │
│ • Retire.js      │
│ • Nuclei         │
└──────────────────┘

        │
        ├─ External Tools Integration
        │  ├─ Nuclei (Go-based vulnerability scanner)
        │  ├─ Amass (Subdomain enumeration)
        │  ├─ Katana (Web crawling)
        │  ├─ JSFinder (JavaScript enumeration)
        │  ├─ Gobuster (Directory brute-forcing)
        │  └─ retire.js (JavaScript lib vulnerabilities)
        │
        └─ File System
           └─ /reports
              ├─ /combined/{json,txt}
              ├─ /scanner/{json,txt}
              ├─ /wappalyzer/{json,txt}
              ├─ /cors/{json,txt}
              ├─ /ssl-tls/{json,txt}
              ├─ /dns/{json,txt}
              ├─ /osint/{json,txt}
              ├─ /web/{json,txt}
              ├─ /retire/{json,txt}
              ├─ /nuclei/{json,txt}
              └─ /whois/{json,txt}
```

### 2.2 Основные компоненты

#### 2.2.1 Backend Server (server.py)

**Технология**: FastAPI + UVicorn + asyncio

**Ключевые функции**:
- REST API сервер на порту 8000
- CORS middleware для кросс-доменных запросов
- Асинхронная обработка HTTP запросов
- Session management для отслеживания статуса сканирований
- Валидация целей (domain, URL, IP address)

**Основной код**:
```python
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

#### 2.2.2 Frontend (React + Framer Motion)

**Технология**: React 19.1.0 + React Router 6.30.1 + Framer Motion 12.23.24

**Структура**:
- `App.jsx` — корневой компонент с маршрутизацией и анимациями
- `Component/Pages/Home/Home.jsx` — главная страница с формой поиска
- `Component/Modal/Modal.jsx` — модальные диалоги
- `Component/Header/Header.jsx` — навигационная панель
- `Component/Footer/Footer.jsx` — подвал приложения

**Ключевые возможности**:
- Плавные анимации переходов между страницами
- Интерактивная форма поиска
- Управление отчетами
- Расписание сканирований

#### 2.2.3 Scheduler Module (scheduler.py)

**Класс**: `ScanScheduler`

**Функции**:
- Планирование сканирований на одиночное, ежедневное, еженедельное или ежемесячное выполнение
- Управление задачами (добавление, обновление, удаление, получение)
- Регистрация callback функций для различных инструментов
- Асинхронный цикл планировщика с проверкой каждую минуту
- Сохранение состояния задач в JSON файл (`scheduled_tasks.json`)

**Типы расписания**:
- `once` — однократное выполнение
- `daily` — ежедневное в указанное время
- `weekly` — в определенные дни недели
- `monthly` — в определенный день месяца

**Persist слой**:
```python
self.tasks_file = self.data_dir / "scheduled_tasks.json"
```

#### 2.2.4 Reports Module (core/report_utils.py)

**Базовый класс**: `ReportBase`

**Наследники**:
- `VulnerabilityScanner` — отчеты об уязвимостях
- `WappalyzerScanner` — отчеты о технологиях
- `CORSScanner` — CORS отчеты
- `SSLTLSScanner` — SSL/TLS отчеты
- `DNSTextReport` — DNS отчеты
- `OsintTextReport` — OSINT отчеты

**Унификация отчетов**:
```python
class CombinedReport:
    """Объединение отчетов всех инструментов"""
    - Сбор результатов из всех подпапок /reports
    - Генерация объединенного JSON
    - Генерация объединенного TXT
```

---

## 3. СКАНЕРЫ И МОДУЛИ БЕЗОПАСНОСТИ

### 3.1 Встроенные сканеры (9 модулей)

| № | Сканер | Файл | Назначение | Форматы отчетов |
|---|--------|------|-----------|-----------------|
| 1 | **Vulnerability Scanner** | `vulnerability_scanner.py` | Сканирование на основные Web уязвимости (XSS, SQLi, заголовки безопасности) | JSON, TXT |
| 2 | **Wappalyzer** | `wappalyzer_scanner.py` | Определение технологий, CMS, фреймворков, библиотек | JSON, TXT |
| 3 | **CORS Scanner** | `cors_scanner.py` | Проверка неправильной конфигурации CORS политики | JSON, TXT |
| 4 | **SSL/TLS Scanner** | `ssl_tls_scanner.py` | Анализ сертификатов, протоколов, шифров, уязвимостей | JSON, TXT |
| 5 | **DNS Scanner** | `dns_scanner.py` | Перечисление DNS записей (A, MX, NS, TXT и т.д.) | JSON, TXT |
| 6 | **OSINT Scanner** | `osint_scanner.py` | Поиск поддоменов, информация о домене (Wayback Machine, API) | JSON, TXT |
| 7 | **Web URL Scanner** | `web_url_scanner.py` | Сканирование URL (Katana), поиск поддоменов в JS (JSFinder), перебор директорий (Gobuster) | JSON, TXT |
| 8 | **Retire.js Scanner** | `retire_scanner.py` | Обнаружение уязвимостей в JavaScript библиотеках | JSON, TXT |
| 9 | **Nuclei Scanner** | `nuclei_scanner.py` | Шаблонное сканирование на основе Nuclei templates | JSON, TXT |

### 3.2 Интеграция внешних инструментов

#### 3.2.1 Nuclei (Go-based)

Путь установки: `go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`

Функциональность:
- Использование готовых шаблонов для сканирования
- Поддержка множества типов уязвимостей
- Быстрое сканирование большого количества целей

API:
```python
from scanners.nuclei_scanner import run_scan
result = run_scan(target_url, save_reports=True, reports_dir=reports_dir)
```

#### 3.2.2 Amass

Путь установки: `go install -v github.com/owasp-amass/amass/v4/...@master`

Функциональность:
- Пассивный поиск поддоменов
- Активный поиск поддоменов
- Использование публичных API и источников

#### 3.2.3 Katana

Для веб-краулинга и обнаружения URL структуры сайта

#### 3.2.4 JSFinder

Поиск URL и поддоменов в JavaScript файлах и исходном коде

#### 3.2.5 Gobuster

Перебор директорий и файлов с использованием wordlist

---

## 4. FastAPI ENDPOINTS И ФУНКЦИОНАЛЬНОСТЬ

### 4.1 Полный список API маршрутов (20+)

#### 4.1.1 Основные эндпоинты сканирования

**1. GET `/api/tool`**
```
Параметры: tool=whois|nuclei, q=domain_or_url, allow_internal=boolean
Описание: Запуск одиночного инструмента (whois или nuclei)
Возвращает: JSON с результатами
```

**2. GET `/api/scanner`**
```
Параметры: target=url, output_name=string, allow_internal=boolean, selected_tools=comma_separated
Описание: Запуск основного сканера уязвимостей
Возвращает: Объект с отчетом, статистикой и путями к файлам
```

**3. GET `/api/amass`**
```
Параметры: target=domain, mode=passive|active|full, timeout=seconds
Описание: Запуск Amass для перечисления поддоменов
Возвращает: Список поддоменов и статистика
```

**4. GET `/api/nuclei`**
```
Параметры: target=url, allow_internal=boolean
Описание: Запуск Nuclei для сканирования на шаблонные уязвимости
Возвращает: Список найденных уязвимостей с severity
```

**5. GET `/api/osint`**
```
Параметры: target=domain, allow_internal=boolean
Описание: OSINT сканирование (поддомены, информация о домене)
Возвращает: JSON с результатами поиска поддоменов и информацией
```

**6. GET `/api/web`**
```
Параметры: target=url, allow_internal=boolean
Описание: Web разведка (Katana, JSFinder, Gobuster)
Возвращает: Найденные URL, поддомены, директории
```

**7. GET `/api/retire`**
```
Параметры: target=url, allow_internal=boolean
Описание: Сканирование JavaScript библиотек на уязвимости
Возвращает: Список устаревших и уязвимых библиотек
```

#### 4.1.2 Эндпоинты для сканеров

**8. GET `/api/wappalyzer`**
```
Описание: Технологический анализ сайта
Возвращает: Обнаруженные CMS, фреймворки, библиотеки
```

**9. GET `/wappalyzer/stream`**
```
Описание: Streaming версия Wappalyzer с прогрессом
Возвращает: SSE stream с результатами
```

**10. POST `/api/cors`**
```
Параметры: target=url
Описание: Проверка CORS конфигурации
Возвращает: JSON с найденными CORS уязвимостями
```

**11. GET `/api/ssl-tls`**
```
Параметры: target=url
Описание: Анализ SSL/TLS конфигурации
Возвращает: Протоколы, шифры, проблемы безопасности
```

**12. GET `/api/dns`**
```
Параметры: target=domain
Описание: Перечисление DNS записей
Возвращает: A, MX, NS, TXT и другие записи
```

#### 4.1.3 Управление сканированиями

**13. POST `/api/cancel-scan`**
```
Параметры: scan_id=string
Описание: Отмена выполняемого сканирования
Возвращает: Статус отмены
```

**14. GET `/api/scan-status`**
```
Параметры: scan_id=string
Описание: Получение текущего статуса сканирования
Возвращает: Объект с информацией о прогрессе
```

**15. POST `/api/run-selected-tools`**
```
Параметры: target=url, tools=array
Описание: Запуск выбранного набора инструментов параллельно
Возвращает: Объединенный результат от всех инструментов
```

#### 4.1.4 Управление отчетами

**16. GET `/api/txt-reports`**
```
Описание: Получить список всех TXT отчетов
Возвращает: Array с информацией о файлах отчетов
```

**17. GET `/api/download-txt-report`**
```
Параметры: filename=string
Описание: Скачать TXT отчет
Возвращает: File download
```

**18. DELETE `/api/delete-txt-report`**
```
Параметры: filename=string
Описание: Удалить TXT отчет
Возвращает: Статус удаления
```

**19. GET `/api/combined-reports`**
```
Описание: Получить список объединенных отчетов
Возвращает: Array с информацией об объединенных отчетах
```

**20. GET `/api/download-combined-report`**
```
Параметры: filename=string, format=json|txt
Описание: Скачать объединенный отчет
Возвращает: File download
```

**21. GET `/download_report`**
```
Параметры: filepath=string
Описание: Generic эндпоинт для скачивания любого отчета
Возвращает: File download
```

### 4.2 Валидация и безопасность

**Функция `validate_target()`**:
```python
def validate_target(target: str, allow_internal: bool = False) -> str:
    """
    Валидация целей:
    - Проверка пустого значения
    - Проверка приватных IP адресов (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Проверка localhost
    - Проверка зарезервированных адресов
    """
```

**Функция `extract_domain()`**:
```python
def extract_domain(target: str) -> str:
    """Извлечение домена из URL, IP или просто домена"""
```

---

## 5. ПЛАНИРОВЩИК ЗАДАЧ (SCHEDULER)

### 5.1 Архитектура ScanScheduler

```python
class ScanScheduler:
    # Основные методы:
    - add_task(task: dict) → task_id: str
    - update_task(task_id: str, task: dict) → None
    - remove_task(task_id: str) → bool
    - get_tasks() → List[dict]
    - get_task(task_id: str) → Optional[dict]
    - register_callback(tool: str, callback: Callable) → None
    - start() → None
    - stop() → None
```

### 5.2 Структура задачи

```json
{
  "id": "task_0001",
  "query": "example.com",
  "type": "daily",
  "time": "02:00",
  "activeTools": ["scanner", "nuclei", "wappalyzer"],
  "allowInternal": false,
  "status": "completed",
  "nextRun": "2026-04-01T02:00:00",
  "last_run": "2026-03-31T02:00:15.123456",
  "created_at": "2026-03-30T10:30:00"
}
```

### 5.3 Типы расписаний

| Тип | Параметры | Пример |
|-----|-----------|--------|
| `once` | time | Выполнится один раз в указанное время |
| `daily` | time | Ежедневно в 02:00 |
| `weekly` | time, days | Понедельник, среда, пятница в 02:00 |
| `monthly` | time, monthDay | 15-го числа каждого месяца в 02:00 |

### 5.4 Цикл выполнения

```
┌─────────────────────┐
│  Запуск Scheduler   │
└──────────┬──────────┘
           │
    ┌──────▼──────┐
    │  Каждую     │
    │  минуту     │
    └──────┬──────┘
           │
    ┌──────▼────────────────────┐
    │ Проверить все задачи      │
    │ Нужно ли запустить?       │
    └──────┬─────────────────────┘
           │
      YES/ │ \NO
         /   \
        ▼     └─► wait 60 sec ──┐
    ┌─────────────┐              │
    │ Exec Task   │              │
    │ (async)     │              │
    └─────────────┘              │
           │                     │
           └──────────────────┬──┘
                              │
                             loop
```

### 5.5 Persistence слой

Все задачи сохраняются в JSON файл: `backend/scheduled_tasks.json`

**Структура файла**:
```json
{
  "task_001": { /* task object */ },
  "task_002": { /* task object */ },
  ...
}
```

---

## 6. МЕХАНИЗМ ГЕНЕРАЦИИ ОТЧЕТОВ

### 6.1 Структура размещения отчетов

```
backend/reports/
├── combined/
│   ├── json/
│   │   └── combined_report_scan_20260331_202425.json
│   └── txt/
│       └── combined_report_scan_20260331_202425.txt
├── scanner/
│   ├── json/
│   └── txt/
├── wappalyzer/
│   ├── json/
│   └── txt/
├── cors/
│   ├── json/
│   └── txt/
├── ssl-tls/
│   ├── json/
│   └── txt/
├── dns/
│   ├── json/
│   └── txt/
├── osint/
│   ├── json/
│   └── txt/
├── web/
│   ├── json/
│   └── txt/
├── retire/
│   ├── json/
│   └── txt/
├── nuclei/
│   ├── json/
│   └── txt/
└── whois/
    ├── json/
    └── txt/
```

### 6.2 Структура JSON отчета (типовой пример)

```json
{
  "scan_info": {
    "target_url": "http://example.com",
    "hostname": "example.com",
    "scan_id": "20260331_202425",
    "scan_datetime": "2026-03-31T20:24:25.123456",
    "tool": "scanner"
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
      "type": "Security Configuration",
      "severity": "High",
      "location": "/",
      "description": "...",
      "recommendation": "..."
    }
  ],
  "recommendations": [
    "Регулярно обновляйте все компоненты",
    "Используйте WAF (Web Application Firewall)",
    "..."
  ]
}
```

### 6.3 Структура TXT отчета (типовой пример)

```
┌──────────────────────────────────────────────────────────────┐
│         SCANNER - ОТЧЕТ О СКАНИРОВАНИИ                      │
└──────────────────────────────────────────────────────────────┘

📋 ИНФОРМАЦИЯ О ЗАПРОСЕ
────────────────────────────────────────────────────────────────
  URL сайта:           http://example.com
  Хоста:               example.com
  Дата сканирования:   31.03.2026
  Время сканирования:  20:24:25
  ID сканирования:     20260331_202425

📊 СТАТИСТИКА
────────────────────────────────────────────────────────────────
  Всего уязвимостей:   5
  🔴 КРИТИЧЕСКИЕ:      1
  🟠 ВЫСОКИЕ:          2
  🟡 СРЕДНИЕ:          2
  🔵 НИЗКИЕ:           0

🔍 НАЙДЕННЫЕ УЯЗВИМОСТИ
────────────────────────────────────────────────────────────────
  1. Missing Security Headers
     Тип:        Security Configuration
     Серьезность: High
     Описание:   ...
     
  2. ...

💡 РЕКОМЕНДАЦИИ
────────────────────────────────────────────────────────────────
  • Регулярно обновляйте все компоненты
  • Используйте WAF
  • ...

════════════════════════════════════════════════════════════════
Дата создания отчета: 31.03.2026 20:24:25
════════════════════════════════════════════════════════════════
```

### 6.4 Объединенные отчеты (CombinedReport)

**Класс**: `CombinedReport`

**Функция**: Автоматическое объединение отчетов от всех инструментов, которые были запущены в один набор

**Логика**:
1. Сканирование директории `/reports` за все подпапки инструментов
2. Фильтрация файлов по временному диапазону (recent_minutes)
3. Объединение JSON результатов в единый файл
4. Создание сводного TXT отчета

---

## 7. FRONTEND СТРУКТУРА И ВЗАИМОДЕЙСТВИЕ

### 7.1 Структура компонентов

```
src/
├── App.jsx                          # Корневой компонент
├── index.js                         # Entry point
├── index.css                        # Global styles
├── App.scss                         # App styles
├── Component/
│   ├── Header/
│   │   ├── Header.jsx               # Navigation bar
│   │   └── Header.scss
│   ├── Footer/
│   │   ├── Footer.jsx               # Footer component
│   │   └── Footer.scss
│   ├── Modal/
│   │   ├── Modal.jsx                # Модальные диалоги
│   │   └── Modal.scss
│   └── Pages/
│       ├── Home/
│       │   ├── Home.jsx             # Главная страница
│       │   ├── Home.scss
│       │   ├── components/
│       │   │   ├── SearchForm.jsx   # Форма поиска
│       │   │   ├── ReportsPanel.jsx # Панель отчетов
│       │   │   ├── ResultsSection.jsx
│       │   │   └── ReportRow.jsx
│       │   ├── hooks/
│       │   │   ├── useReports.js    # Hook для работы с отчетами
│       │   │   └── useScanState.js  # Hook для состояния сканирования
│       │   ├── services/
│       │   │   └── ... (API вызовы)
│       │   └── ScheduleScanner/
│       │       ├── ScheduleScanner.jsx
│       │       └── ScheduleScanner.scss
│       ├── AboutTools/
│       │   ├── AboutTools.jsx       # Описание инструментов
│       │   └── AboutTools.scss
│       ├── Task/
│       │   ├── Task.jsx             # Управление задачами
│       │   └── Task.scss
│       ├── Questions/
│       │   ├── Questions.jsx        # FAQ
│       │   └── Questions.scss
│       └── Help/
│           ├── Help.jsx             # Справка
│           └── Help.scss
└── Img/                             # Изображения
```

### 7.2 Роутинг и навигация

```jsx
// App.jsx структура
<Router>
  <Routes>
    <Route path="/" element={<Home />} />
    <Route path="/about-tools" element={<AboutTools />} />
    <Route path="/task" element={<Task />} />
    <Route path="/questions" element={<Questions />} />
    <Route path="/help" element={<Help />} />
  </Routes>
</Router>
```

### 7.3 Основные страницы

#### 7.3.1 Страница Home (главная)

**Компоненты**:
- `SearchForm` — интерактивная форма поиска с выбором инструментов
- `ReportsPanel` — панель управления отчетами
- `ResultsSection` — отобрание результатов сканирования
- `ScheduleScanner` — форма планирования задач

**Функциональность**:
- Ввод целевого URL или домена
- Выбор инструментов для запуска
- Запуск сканирования (асинхронно)
- Отслеживание прогресса в реальном времени (SSE)
- Просмотр и скачивание отчетов

#### 7.3.2 Страница AboutTools

Описание всех доступных сканеров и их назначения:
- Vulnerability Scanner
- Wappalyzer
- CORS Scanner
- SSL/TLS Scanner
- DNS Scanner
- OSINT Scanner
- Web URL Scanner  
- Retire.js Scanner
- Nuclei Scanner

#### 7.3.3 Страница Task

Управление запланированными задачами:
- Просмотр всех запланированных сканирований
- Редактирование расписания
- Удаление задач
- Просмотр статуса последнего выполнения

#### 7.3.4 Страница Help и Questions

- FAQ по использованию платформы
- Справка по каждому инструменту
- Рекомендации по безопасному использованию

### 7.4 Взаимодействие Frontend ← → Backend

#### 7.4.1 API вызовы (примеры)

```javascript
// Запуск сканирования
POST /api/scanner
{
  "target": "example.com",
  "selectedTools": "scanner,wappalyzer,ssl-tls"
}

// Получение статуса
GET /api/scan-status?scan_id=20260331_202425

// Получение отчетов
GET /api/txt-reports

// Скачивание отчета
GET /api/download-txt-report?filename=scanner_example.com_20260331_202425.txt
```

#### 7.4.2 Потоковые обновления (SSE)

Для инструментов с длительным выполнением используется Server-Sent Events (SSE):

```javascript
const eventSource = new EventSource(
  `/wappalyzer/stream?target=${encodeURIComponent(target)}`
);

eventSource.addEventListener('message', (event) => {
  console.log('Update:', event.data);
});
```

### 7.5 Состояние приложения

**React Hooks**:
- `useReports()` — управление состоянием отчетов
- `useScanState()` — отслеживание статуса сканирования
- `useState()` — локальное состояние компонентов
- `useEffect()` — побочные эффекты

**Props drilling** минимизирован через Context API

---

## 8. ТЕХНИЧЕСКИЙ СТЕК И ЗАВИСИМОСТИ

### 8.1 Backend dependencies (requirements.txt)

```
# FastAPI
fastapi
uvicorn
aiohttp

# Web Scraping & Parsing
bs4
requests
validators

# Security Scanning
zaproxy
python-nasm
python-whois
Wappalyzer

# Code Quality & Utils
colorama
similar
whatweb

# Data Processing
xmltodict
PyYAML

# Reporting
python-docx

# Geolocation
censys
pydig

# Visualization
pyvis

# Bot Integration
aiogram
python-dotenv
```

### 8.2 Frontend dependencies (package.json)

```json
{
  "react": "^19.1.0",
  "react-dom": "^19.1.0",
  "react-router-dom": "^6.30.1",
  "framer-motion": "^12.23.24",
  "sass": "^1.89.2",
  "testing-library/*": "latest"
}
```

### 8.3 Внешние инструменты (требуют установки)

```bash
# Nuclei (Go)
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Amass (Go)
go install -v github.com/owasp-amass/amass/v4/...@master

# Katana (Go)
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Gobuster (Go)
go install github.com/OJ/gobuster/v3@latest

# retire.js (npm)
npm install -g retire

# JSFinder (Python)
# Включен в проект как tool/jsfinder/ (Custom implementation)
```

---

## 9. DOCKER DEPLOYMENT

### 9.1 Docker Compose конфигурация

```yaml
version: '3.9'

services:
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: cyberscope-backend
    ports:
      - "8000:8000"
    volumes:
      - ./backend:/app
    environment:
      - PYTHONUNBUFFERED=1
    command: uvicorn server:app --host 0.0.0.0 --port 8000 --reload
    networks:
      - cyberscope-network

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: cyberscope-frontend
    ports:
      - "3000:3000"
    volumes:
      - ./frontend/src:/app/src
      - ./frontend/public:/app/public
    environment:
      - REACT_APP_API_URL=http://localhost:8000
      - NODE_ENV=development
    depends_on:
      - backend
    networks:
      - cyberscope-network

networks:
  cyberscope-network:
    driver: bridge
```

### 9.2 Запуск проекта

```bash
# Development
docker-compose up --build

# Production (добавить optimizations)
docker-compose up -d
```

---

## 10. TELEGRAM BOT ИНТЕГРАЦИЯ

### 10.1 Возможности бота

```
/start            — Инициализация бота
/help             — Справка по командам
/scan             — Запуск сканирования
/reports          — Список отчетов
/download_json    — Скачать JSON отчет
/download_txt     — Скачать TXT отчет
/schedule         — Управление расписанием
/status           — Статус сканирования
```

### 10.2 Конфигурация

Файл: `backend/bot/.env`

```
BOT_TOKEN=your_telegram_bot_token
API_BASE_URL=http://127.0.0.1:8000/api
```

### 10.3 Структура бота

```python
from aiogram import Bot, Dispatcher, Router, types
from aiogram.fsm.context import FSMContext

# FSM States для управления диалогом
class ScanStates(StatesGroup):
    waiting_for_target = State()
    waiting_for_tools = State()
    waiting_for_schedule = State()
```

---

## 11. КЛЮЧЕВЫЕ АРХИТЕКТУРНЫЕ РЕШЕНИЯ

### 11.1 Асинхронная обработка

**Решение**: FastAPI + asyncio

**Преимущества**:
- Одновременное выполнение множества сканирований
- Неблокирующие I/O операции
- Улучшенная масштабируемость

```python
@app.get("/api/scanner")
async def api_scanner(...):
    result = await asyncio.to_thread(scanner.run_all_checks)
    return result
```

### 11.2 Session Management

**Решение**: Thread-safe словарь с блокировками

**Структура**:
```python
_scan_sessions = {}
_scan_sessions_lock = threading.Lock()

def create_scan_session(scan_id: str) -> dict:
    with _scan_sessions_lock:
        session = {...}
        _scan_sessions[scan_id] = session
```

### 11.3 Report Unification

**Решение**: Базовый класс `ReportBase` с наследованием

**Преимущества**:
- Единый интерфейс для всех сканеров
- Согласованность форматов отчетов
- Легкость добавления новых сканеров

### 11.4 Validation Layer

**Решение**: Встроенная валидация целей

**Логика**:
1. Проверка format (URL vs domain)
2. Проверка приватности IP (RFC 1918, loopback)
3. Проверка localhost
4. Опциональное разрешение внутренних адресов

### 11.5 Persistence Layer

**Решение**: JSON файлы для хранения состояния

**Преимущества**:
- Простота реализации
- Нет зависимостей от БД
- Легко понять и отладить

**Недостатки** (для production):
- Нет оптимизации для больших объемов
- Race conditions возможны
- Рекомендуется использовать PostgreSQL/MongoDB

---

## 12. БЕЗОПАСНОСТЬ И BEST PRACTICES

### 12.1 Input Validation

✅ **Реализовано**:
- Валидация URL формата
- Проверка на внутренние адреса
- Санитизация параметров

### 12.2 CORS Policy

✅ **Реализовано**:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)
```

⚠️ **Для production**: Ограничить `allow_origins` конкретным доменом

### 12.3 Error Handling

✅ **Реализовано**:
- Try-catch блоки во всех endpoint'ах
- Informative error messages
- HTTP status codes

### 12.4 Rate Limiting

❌ **Не реализовано** (рекомендуется добавить для production)

### 12.5 Authentication

❌ **Не реализовано** (требуется для продакшена)

Рекомендации:
- JWT tokens
- OAuth2
- API key authentication

---

## 13. ПРОИЗВОДИТЕЛЬНОСТЬ И МАСШТАБИРУЕМОСТЬ

### 13.1 Текущие ограничения

1. **JSON persistence** — неэффективно для больших объемов данных
2. **Одноразовый процесс** — нет load balancing
3. **Отсутствие кеширования** — каждый запрос заново вычисляется
4. **Нет обработки очереди задач** — длительные сканирования блокируют ресурсы

### 13.2 Рекомендации для масштабирования

1. **Миграция на БД**: PostgreSQL + SQLAlchemy ORM
2. **Task Queue**: Celery + Redis для асинхронных задач
3. **Кеширование**: Redis для хранения результатов с TTL
4. **Load Balancing**: Nginx с несколькими instance'ами FastAPI
5. **Мониторинг**: Prometheus + Grafana для отслеживания метрик

### 13.3 Примерная архитектура для production

```
                    ┌─────────────┐
                    │   Nginx     │ (Load Balancer)
                    └──────┬──────┘
                    /      │      \
                   /       │       \
            ┌─────▼──┐ ┌──▼────┐ ┌─▼──────┐
            │FastAPI1│ │FastAPI2│ │FastAPI3│
            └────┬───┘ └────┬───┘ └───┬────┘
                 │          │        │
                 └──────────┬────────┘
                            │
                    ┌───────▼───────┐
                    │  Celery Queue │
                    │   (Redis)     │
                    └───┬───────┬───┘
                        │       │
              ┌─────────▼─┐ ┌──▼──────────┐
              │ Worker 1  │ │  Worker 2   │
              └────┬──────┘ └────┬────────┘
                   │            │
            ┌──────▼────────────▼──────┐
            │   PostgreSQL Database    │
            │  (Scan results, tasks)   │
            └─────────────────────────┘
            
                 ┌──────────────┐
                 │  Redis Cache │ (Caching layer)
                 └──────────────┘
```

---

## 14. РАЗВЕРТЫВАНИЕ И ИНСТАЛЛЯЦИЯ

### 14.1 Требования к системе

- **ОС**: Linux (Ubuntu 20.04+), macOS, Windows 10+ (with WSL2)
- **Python**: 3.9+
- **Node.js**: 14+
- **Go**: 1.16+ (для internal tools)
- **RAM**: Минимум 4GB (рекомендуется 8GB)
- **Disk**: Минимум 10GB (в зависимости от объема отчетов)

### 14.2 Инструкция по установке

```bash
# 1. Клонирование репозитория
git clone https://github.com/your-repo/CyberScope.git
cd CyberScope

# 2. Установка системных зависимостей
chmod +x install-tools.sh
./install-tools.sh

# 3. Backend setup
cd backend
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

pip install -r requirements.txt

# 4. Frontend setup
cd ../frontend
npm install

# 5. Запуск backend
cd ../backend
uvicorn server:app --reload

# 6. Запуск frontend (в новом терминале)
cd frontend
npm start
```

### 14.3 Docker deployment

```bash
docker-compose up --build
```

Доступно:
- Frontend: http://localhost:3000
- API: http://localhost:8000
- API Docs: http://localhost:8000/docs

---

## 15. ТЕСТИРОВАНИЕ

### 15.1 Manual Testing Scenarios

1. **Базовое сканирование**
   - Запуск `scanner` на http://localhost:5012
   - Проверка наличия отчета в `/reports/scanner/`

2. **Встроенные ограничения**
   - Попытка сканирования 127.0.0.1 (должна быть ошибка)
   - Попытка сканирования 192.168.x.x (должна быть ошибка)
   - С флагом `allow_internal=true` должно работать

3. **Планирование задач**
   - Создание ежедневной задачи
   - Проверка файла `scheduled_tasks.json`
   - Проверка выполнения в назначенное время

4. **Загрузка отчетов**
   - Скачивание JSON отчета
   - Скачивание TXT отчета
   - Проверка целостности данных

### 15.2 Рекомендуемые Unit Tests

```python
# test_validation.py
def test_validate_internal_ip():
    with pytest.raises(HTTPException):
        validate_target("192.168.1.1", allow_internal=False)

def test_extract_domain():
    assert extract_domain("https://example.com:8080/path") == "example.com"

# test_scheduler.py
def test_add_task():
    scheduler = ScanScheduler()
    task_id = scheduler.add_task({...})
    assert task_id in scheduler.tasks

def test_calculate_next_run_daily():
    scheduler = ScanScheduler()
    task = {"type": "daily", "time": "02:00"}
    next_run = scheduler._calculate_next_run(task)
    assert next_run.hour == 2
```

---

## 16. ДОКУМЕНТИРОВАНИЕ API

### 16.1 OpenAPI/Swagger

FastAPI автоматически генерирует документацию
Доступно по адресу: `http://localhost:8000/docs`

### 16.2 API Schema

Все endpoint'ы документированы с:
- Описанием функции
- Типы параметров
- Примеры ответов
- Коды ошибок

---

## 17. ЗАКЛЮЧЕНИЕ И ВЫВОДЫ

### 17.1 Достижения

✅ **Полнофункциональная платформа** для комплексного анализа безопасности веб-ресурсов

✅ **Интеграция 9 различных сканеров** в единый интерфейс

✅ **Асинхронная обработка** позволяет запускать множество сканирований одновременно

✅ **Гибкое планирование** с поддержкой различных типов расписания

✅ **Унифицированные отчеты** в JSON и TXT форматах

✅ **Настольный Telegram бот** для управления сканированиями

✅ **REST API** для программного взаимодействия

### 17.2 Ограничения и рекомендации

⚠️ **Текущие ограничения**:
1. Отсутствие аутентификации (требуется для production)
2. JSON persistence вместо БД (неэффективно для больших объемов)
3. Отсутствие rate limiting
4. Нет обработки очереди задач
5. CORS policy слишком открыта

✅ **Рекомендации для улучшения**:
1. Внедрить JWT аутентификацию
2. Мигрировать на PostgreSQL
3. Добавить Celery + Redis для work queue
4. Реализовать rate limiting
5. Добавить логирование и мониторинг
6. Написать unit и integration tests
7. Добавить кеширование результатов
8. Реализовать multi-tenancy поддержку

### 17.3 Потенциальные расширения

1. **Web Dashboard**: Расширенная визуализация результатов
2. **Reporting**: PDF экспорт, красивые визуализации
3. **Collaboration**: Командная работа, shared scans
4. **API Integrations**: Slack, Discord уведомления
5. **Advanced Scheduling**: Cron expressions, conditional tasks
6. **Machine Learning**: Анализ паттернов уязвимостей
7. **Multi-target scanning**: Сканирование портфолей сайтов
8. **Custom scanners**: Framework для создания собственных сканеров

---

## ПРИЛОЖЕНИЕ: Полезные команды

### Запуск backend в режиме разработки
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn server:app --reload --log-level debug
```

### Запуск frontend в режиме разработки
```bash
cd frontend
npm install
npm start
```

### Запуск Telegram бота
```bash
cd backend/bot
pip install -r ../requirements.txt
python bot.py
```

### Установка внешних инструментов
```bash
# Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Amass
go install -v github.com/owasp-amass/amass/v4/...@master

# Katana
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Gobuster
go install github.com/OJ/gobuster/v3@latest

# retire.js
npm install -g retire
```

### Просмотр отчетов
```bash
# Список всех отчетов
find backend/reports -type f -name "*.json" | head -20

# Красивый вывод JSON
cat backend/reports/scanner/json/scanner_example.com_*.json | python -m json.tool

# Просмотр TXT отчета
cat backend/reports/scanner/txt/scanner_example.com_*.txt
```

---

**Документ составлен**: 31 марта 2026 года
**Версия**: 1.0
**Статус**: Finalized for Diploma Thesis

