from fastapi import FastAPI, HTTPException, Depends, Request, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from datetime import date, datetime, timedelta
from typing import List, Optional
import uuid
import os
import re
from sqlalchemy import create_engine, Column, Integer, String, Date, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import logging
import jwt
from jwt.exceptions import InvalidTokenError

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# JWT settings
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key")  # В продакшене использовать безопасный секретный ключ
JWT_ALGORITHM = "HS256"
TOKEN_LIFETIME = int(os.getenv("TOKEN_LIFETIME", 3600))  # Время жизни токена в секундах

# Настройка базы данных
DATABASE_URL = "sqlite:///users.db"
engine = create_engine(DATABASE_URL)
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Модели базы данных
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    birthday = Column(Date)

class TokenDTO(BaseModel):
    access_token: str

# Создание таблиц
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Переменные окружения
MAX_TOKENS = int(os.getenv("MAX_TOKENS", 5))  # Максимальное количество токенов

# Настройка авторизации
security = HTTPBearer()

# Зависимость для получения сессии базы данных
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
@app.middleware("http")
async def set_locale(request: Request, call_next):
    # Получаем язык из заголовка Accept-Language
    accept_language = request.headers.get("Accept-Language", "ru")
    # Устанавливаем русский язык по умолчанию
    if "ru" not in accept_language:
        accept_language = "ru"
    request.state.locale = accept_language
    print(f"Locale set to: {request.state.locale}")  # Debug statement
    response = await call_next(request)
    return response

def create_token(user_id: int) -> str:
    """Создание JWT токена с информацией о пользователе и временем жизни"""
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(seconds=TOKEN_LIFETIME),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    """Декодирование и валидация JWT токена"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except InvalidTokenError as e:
        raise HTTPException(status_code=401, detail="Недействительный токен")

# Зависимость для проверки токена
async def get_token(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    token = credentials.credentials
    logger.info(f"Проверка токена: {token}")
    if not token:
        logger.error("Токен отсутствует")
        raise HTTPException(status_code=401, detail="Требуется токен")
    
    try:
        payload = decode_token(token)
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Недействительный токен")
        
        # Проверяем существование пользователя
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="Пользователь не найден")
        
        logger.info(f"Токен валиден для пользователя: {user.username}")
        return token
    except Exception as e:
        logger.error(f"Ошибка при проверке токена: {str(e)}")
        raise HTTPException(status_code=401, detail="Недействительный токен")

class LoginRequest(BaseModel):
    username: str
    password: str

    def to_resource(self):
        return {"username": self.username}

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    c_password: str
    birthday: date

    def to_resource(self):
        return {"username": self.username, "email": self.email, "birthday": self.birthday}

    @staticmethod
    def validate_password(password: str):
        """Валидация пароля"""
        if len(password) < 8:
            raise HTTPException(status_code=422, detail="Пароль должен содержать минимум 8 символов")
        if not re.search(r"[A-Z]", password):
            raise HTTPException(status_code=422, detail="Пароль должен содержать минимум одну заглавную букву")
        if not re.search(r"[a-z]", password):
            raise HTTPException(status_code=422, detail="Пароль должен содержать минимум одну строчную букву")
        if not re.search(r"\d", password):
            raise HTTPException(status_code=422, detail="Пароль должен содержать минимум одну цифру")

    @staticmethod
    def validate_age(birthday: date):
        """Валидация возраста пользователя"""
        today = date.today()
        age = today.year - birthday.year - ((today.month, today.day) < (birthday.month, birthday.day))
        logger.info(f"Проверка возраста: birthday={birthday}, age={age}")
        if age < 14:
            raise HTTPException(status_code=422, detail="Пользователь должен быть старше 14 лет")

class UserDTO(BaseModel):
    username: str
    email: Optional[str] = None
    birthday: Optional[date] = None

class AuthController:
    def __init__(self, db: Session):
        self.db = db

    def login(self, request: LoginRequest, db: Session):
        """Авторизация пользователя"""
        user = db.query(User).filter(User.username.ilike(request.username)).first()
        if not user or user.password != request.password:
            raise HTTPException(status_code=422, detail="Неверные учетные данные")
        
        access_token = create_token(user.id)
        logger.info(f"Новый токен создан для пользователя: {user.username}")
        return TokenDTO(access_token=access_token)

    def register(self, request: RegisterRequest, db: Session):
        """Регистрация нового пользователя"""
        logger.info(f"Регистрация пользователя: {request.username}, email: {request.email}, birthday: {request.birthday}")
        if db.query(User).filter(User.username.ilike(request.username)).first():
            raise HTTPException(status_code=422, detail="Имя пользователя уже занято")
        if db.query(User).filter(User.email.ilike(request.email)).first():
            raise HTTPException(status_code=422, detail="Email уже используется")
        if request.password != request.c_password:
            raise HTTPException(status_code=422, detail="Пароли не совпадают")
        RegisterRequest.validate_password(request.password)
        RegisterRequest.validate_age(request.birthday)
        new_user = User(username=request.username, email=request.email, password=request.password, birthday=request.birthday)
        db.add(new_user)
        db.commit()
        logger.info(f"Пользователь сохранен: {new_user.id}, {new_user.username}")
        return UserDTO(**request.to_resource()), status.HTTP_201_CREATED

    def get_me(self, token: str, db: Session):
        """Получение информации о текущем пользователе"""
        payload = decode_token(token)
        user_id = payload.get("user_id")
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="Пользователь не найден")
        return UserDTO(**{"username": user.username, "email": user.email, "birthday": user.birthday})

    def logout(self, token: str, db: Session):
        """Выход пользователя"""
        # В JWT реализации нам не нужно ничего удалять из базы данных
        # Токен становится недействительным после истечения срока действия
        return {"message": "Выход выполнен успешно"}

    def get_tokens(self, token: str, db: Session):
        """Получение информации о текущем токене"""
        payload = decode_token(token)
        user_id = payload.get("user_id")
        exp = payload.get("exp")
        return [{
            "user_id": user_id,
            "expiry": datetime.fromtimestamp(exp).isoformat()
        }]

    def logout_all(self, token: str, db: Session):
        """В JWT реализации все токены становятся недействительными после истечения срока действия"""
        return {"message": "Все токены станут недействительными после истечения срока действия"}

    def refresh(self, refresh_token: str = None, db: Session = Depends(get_db)):
        """Обновление токена доступа"""
        if not refresh_token:
            raise HTTPException(status_code=422, detail="Токен обновления обязателен")
        
        # В JWT реализации мы просто создаем новый токен
        # В реальном приложении здесь должна быть проверка refresh token
        payload = decode_token(refresh_token)
        user_id = payload.get("user_id")
        
        access_token = create_token(user_id)
        logger.info(f"Токен обновлен для пользователя: {user_id}")
        return TokenDTO(access_token=access_token)

    def change_password(self, old_password: str, new_password: str, token: str = Depends(get_token), db: Session = Depends(get_db)):
        """Смена пароля пользователя"""
        payload = decode_token(token)
        user_id = payload.get("user_id")
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user or user.password != old_password:
            raise HTTPException(status_code=422, detail="Неверный старый пароль")
        
        RegisterRequest.validate_password(new_password)
        user.password = new_password
        db.commit()
        logger.info(f"Пароль изменен для пользователя: {user.username}")
        return {"message": "Пароль успешно изменен"}

controller = AuthController(None)

@app.get("/")
def read_root(request: Request):
    locale = request.state.locale
    # Hardcode locale to 'ru' for testing
    locale = "ru"
    if locale == "ru":
        return {"message": "Добро пожаловать в Лабораторную работу №2!"}
    else:
        return {"message": "Welcome to Laboratory Work №2!"}

@app.post("/api/auth/login")
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    return controller.login(request, db)

@app.post("/api/auth/register")
async def register(request: RegisterRequest, db: Session = Depends(get_db)):
    resource, status_code = controller.register(request, db)
    return resource, status_code

@app.get("/api/auth/me")
async def get_me(token: str = Depends(get_token), db: Session = Depends(get_db)):
    return controller.get_me(token, db)

@app.post("/api/auth/logout")
async def logout(token: str = Depends(get_token), db: Session = Depends(get_db)):
    return controller.logout(token, db)

@app.get("/api/auth/tokens")
async def get_tokens(token: str = Depends(get_token), db: Session = Depends(get_db)):
    return controller.get_tokens(token, db)

@app.post("/api/auth/logout-all")
async def logout_all(token: str = Depends(get_token), db: Session = Depends(get_db)):
    return controller.logout_all(token, db)

@app.post("/api/auth/refresh")
async def refresh(refresh_token: str, db: Session = Depends(get_db)):
    return controller.refresh(refresh_token, db)

@app.post("/api/auth/change-password")
async def change_password(old_password: str, new_password: str, token: str = Depends(get_token), db: Session = Depends(get_db)):
    return controller.change_password(old_password, new_password, token, db)