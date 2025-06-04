import json
import os
from fastapi import HTTPException, status
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
from db.schemas import *
from models import TokenModel
from db.database import SessionLocal

load_dotenv()

max_minutes = int(os.getenv("MAX_ACTIVE_MINUTES", 30))
max_days = int(int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 30)))

# Хэширование паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=max_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, "secret_key", algorithm="HS256")
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(days=max_days)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, "secret_key", algorithm="HS256")
    return encoded_jwt

def get_current_user(request: TokenModel):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token is not valid",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(request.access_token, "secret_key", algorithms=["HS256"])
        session_id: str = payload.get("sub")
        if session_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    token_record = SessionLocal.query(Token).filter(Token.session_id == session_id, Token.is_active == True).first()
    if token_record is None:
        raise credentials_exception

    user = SessionLocal.query(User).filter(User.id == token_record.user_id).first()
    if user is None:
        raise credentials_exception
    return user

def check_role_unique(name, code):
    # Проверка имени
    if name:
        role_by_name = SessionLocal.query(Role).filter(Role.name == name).first()
        if role_by_name:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role with name '{name}' already exists."
            )
    # Проверка шифра
    if code:
        role_by_code = SessionLocal.query(Role).filter(Role.code == code).first()
        if role_by_code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role with code '{code}' already exists."
            )
            
def check_permission_unique(name, code):
    # Проверка имени
    if name:
        permission_by_name = SessionLocal.query(Permission).filter(Permission.name == name).first()
        if permission_by_name:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"permission with name '{name}' already exists."
            )
    # Проверка шифра
    if code:
        permission_by_code = SessionLocal.query(Permission).filter(Permission.code == code).first()
        if permission_by_code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"permission with code '{code}' already exists."
            )
            
def has_permission(permission: str, current_user: User):
    # Проверка разрешений пользователя
    user_permissions = SessionLocal.query(Permission).join(RolesAndPermissions).join(Role).join(UsersAndRoles).filter(
        UsersAndRoles.user_id == current_user.id,
        Permission.code == permission
    ).first()

    # Проверка разрешений групп пользователя
    group_permissions = SessionLocal.query(Permission).join(RolesAndPermissions).join(Role).join(UsersAndRoles).filter(
        UsersAndRoles.user_id == current_user.id,
        Permission.code == permission
    ).first()

    if not user_permissions and not group_permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: {permission}"
        )

    return True

# Функция для сериализации объектов, которые не поддерживаются стандартной библиотекой json.
def json_serial(obj):
    if isinstance(obj, set):
        return list(obj)  # Преобразуем множество в список
    raise TypeError(f"Type {type(obj)} not serializable")

# Функция записи логов
def log_change(entity_name: str, entity_id: int, action: str, old_value: dict, new_value: dict, user_id: int):
    old_value_str = json.dumps(old_value, default=json_serial)
    new_value_str = json.dumps(new_value, default=json_serial)
    log_entry = ChangeLogs(
        entity_name=entity_name,
        entity_id=entity_id,
        action=action,
        old_value=old_value_str,
        new_value=new_value_str,
        changed_by=user_id,
        changed_at=datetime.now()
    )
    SessionLocal.add(log_entry)
    SessionLocal.commit()
    
# Функция для преобразования строки в словарь
def parse_values_to_dict(values: str) -> dict:
    if not values:
        return {}

    result = {}
    for pair in values.split(';'):
        if ':' in pair:
            key, value = pair.split(':', 1)
            result[key.strip()] = value.strip()
    return result

def get_log_history(logs):
    history = []
    
    for log in logs:
        # Декодируем старое и новое значение из JSON, если они не None
        old_value = json.loads(log.old_value) if log.old_value else {}
        new_value = json.loads(log.new_value) if log.new_value else {}

        # Проверяем, что old_value и new_value это словари
        if isinstance(old_value, dict) and isinstance(new_value, dict):
            changes = {
                key: (old_value.get(key), new_value.get(key)) 
                for key in new_value if old_value.get(key) != new_value.get(key)
            }
        else:
            changes = {}  # Если old_value или new_value не словари, оставляем изменения пустыми

        entry = {
            "changed_at": log.changed_at,
            "changed_by": log.changed_by,
            "action": log.action,
            "changes": changes  # Используем только измененные значения
        }
        history.append(entry)
        
    return history

# Функция получения старого значения из логов
def get_old_value_from_log(log_id: int) -> dict:
    # Получаем запись лога по ID
    log_entry = SessionLocal.query(ChangeLogs).filter(ChangeLogs.id == log_id).first()
    
    if not log_entry:
        raise HTTPException(status_code=404, detail="Log entry not found")
    
    # Проверяем, является ли действие delete или create
    if log_entry.action in ['delete', 'create']:
        raise HTTPException(status_code=400, detail="Cannot restore entity from a log entry that is a delete or create action.")
    
    # Возвращаем old_value, преобразованное в словарь
    return json.loads(log_entry.old_value) if log_entry.old_value else {}