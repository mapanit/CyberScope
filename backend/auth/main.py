from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .database import SessionLocal, engine
from . import models, schemas, auth
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

try:
    models.Base.metadata.create_all(bind=engine)
    print(f"База данных успешно инициализирована. URL: {engine.url}")
except Exception as e:
    print(f"Ошибка подключения к базе данных: {e}")
    raise

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

