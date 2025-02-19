from fastapi import FastAPI, Request
from pydantic import BaseModel
import platform
import sqlite3
from datetime import datetime
import pytz

# Создание FastAPI приложения
app = FastAPI()

# Установка часового пояса (Екатеринбург)
yekaterinburg_tz = pytz.timezone('Asia/Yekaterinburg')

# Модели Pydantic для DTO
class ServerInfo(BaseModel):
    python_version: str
    system: str
    server_time: str

class ClientInfo(BaseModel):
    ip: str
    useragent: str

class DatabaseInfo(BaseModel):
    database: str
    version: str

# Маршрут для получения информации о сервере
@app.get("/info/server", response_model=ServerInfo)
def get_server_info():
    # Получаем текущее время в часовом поясе Екатеринбурга
    current_time = datetime.now(yekaterinburg_tz).strftime('%Y-%m-%d %H:%M:%S')
    return ServerInfo(
        python_version=platform.python_version(),
        system=platform.system(),
        server_time=current_time
    )

# Маршрут для получения информации о клиенте
@app.get("/info/client", response_model=ClientInfo)
def get_client_info(request: Request):
    return ClientInfo(
        ip=request.client.host,
        useragent=request.headers.get("user-agent")
    )

# Маршрут для получения информации о базе данных
@app.get("/info/database", response_model=DatabaseInfo)
def get_database_info():
    # Подключение к SQLite (пример)
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    cursor.execute("SELECT sqlite_version()")
    db_version = cursor.fetchone()[0]
    return DatabaseInfo(
        database="SQLite",
        version=db_version
    )

# Корневой маршрут
@app.get("/")
def read_root():
    return {"message": "Добро пожаловать в Лабораторную работу №1!"}