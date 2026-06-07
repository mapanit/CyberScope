import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from dotenv import load_dotenv
load_dotenv()

# Вариант 1: SQLite
SQLALCHEMY_DATABASE_URL = os.getenv("SQLALCHEMY_DATABASE_URL")

# Вариант 2: PostgreSQL
# SQLALCHEMY_DATABASE_URL = os.getenv("SQLALCHEMY_DATABASE_URL_POSTGRESQL")


# Настройки для SQLite
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL, 
        connect_args={"check_same_thread": False}  # Только для SQLite
    )
# Настройки для PostgreSQL
else:
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        # Для PostgreSQL можно добавить дополнительные параметры:
        pool_size=5,           # Максимальное количество соединений в пуле
        max_overflow=10,       # Дополнительные соединения сверх pool_size
        pool_pre_ping=True,    # Проверка соединения перед использованием
        echo=False             # Установите True для логирования SQL запросов
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

