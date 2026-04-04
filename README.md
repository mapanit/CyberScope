# 🌐 CyberScope

Автоматизированная веб-платформа для комплексного анализа безопасности веб-ресурсов. Объединяет множество инструментов пентеста в едином интерфейсе с поддержкой отчётов JSON, TXT и DOCX.


![alt text](image.png)


## 📋 Возможности

**Сканирование:**

- Nmap - сканирование портов и сервисов
- Nuclei - проверка уязвимостей по шаблонам
- Retire.js - поиск устаревших JavaScript библиотек
- Wappalyzer - определение технологического стека
- OSINT - сбор информации о домене
- SSL/TLS - проверка сертификатов
- DNS - анализ DNS записей
- CORS - проверка CORS конфигурации

**Отчётность:**
- Автоматическое объединение результатов всех сканеров
- Экспорт в JSON, TXT, DOCX
- Сохранение истории сканирований
- Планируемые проверки через бота

## 🚀 Быстрый старт

```bash
# Установка зависимостей
chmod +x install-tools.sh
./install-tools.sh

# Backend (FastAPI + Python)
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn server:app --reload

# Frontend (React)
cd frontend
npm install
npm start
```

Или через Docker:
```bash
docker-compose up
```

## 📁 Структура проекта

```
CyberScope/
├── backend/          # Python FastAPI сервер
│   ├── scanners/     # Модули сканеров
│   ├── core/         # Утилиты для отчётов
│   ├── bot/          # Автоматизированный бот
│   └── reports/      # Результаты сканирований
├── frontend/         # React приложение
│   └── src/
│       └── Component/  # UI компоненты
└── docker-compose.yml  # Контейнеризация
```

## ⚖️ Лицензия и использование

CyberScope предназначен только для:
- Тестирования собственные веб-ресурсы
- Легальных пентестов с согласия владельца
- Образовательных и исследовательских целей

**Используйте отвественно! ⚡**
