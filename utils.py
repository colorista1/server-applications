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